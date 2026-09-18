use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mincdc::{Cdc, MinCdc4, MinCdcHash4};
use narjar::nar::{DecodeError, Decoder, Event, EventSink};
use narjar_nar_chunking::{ChunkAlgorithm, ChunkParameters, chunk_reader};
use sha2::{Digest, Sha256};

const DEFAULT_FIXED_CHUNK_SIZE: usize = 8 * 1024;
const CHUNK_DESCRIPTOR_BYTES: u64 = 8 + 8 + 32;
const WHOLE_FILE_DESCRIPTOR_BYTES: u64 = 8 + 32;
const FILE_MANIFEST_HEADER_BYTES: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MeasurementStrategy {
    RawCdc(ChunkAlgorithm),
    SemanticCdc(ChunkAlgorithm),
    FixedSize,
    WholeFileCas,
}

impl MeasurementStrategy {
    fn name(self, fixed_size: usize) -> String {
        match self {
            Self::RawCdc(ChunkAlgorithm::MinCdcHash4) => "raw-mincdc-hash4".to_owned(),
            Self::RawCdc(ChunkAlgorithm::MinCdc4) => "raw-mincdc4".to_owned(),
            Self::SemanticCdc(ChunkAlgorithm::MinCdcHash4) => "semantic-mincdc-hash4".to_owned(),
            Self::SemanticCdc(ChunkAlgorithm::MinCdc4) => "semantic-mincdc4".to_owned(),
            Self::FixedSize => format!("fixed-{fixed_size}"),
            Self::WholeFileCas => "whole-file-cas".to_owned(),
        }
    }
}

#[derive(Debug)]
struct CommandLine {
    corpus: PathBuf,
    min_size: usize,
    max_size: usize,
    fixed_size: usize,
    max_files: Option<usize>,
    semantic_only: bool,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct ChunkMeasurements {
    files: u64,
    logical_bytes: u64,
    chunked_bytes: u64,
    passthrough_bytes: u64,
    chunk_count: u64,
    unique_chunks: HashMap<[u8; 32], u64>,
    manifest_bytes: u64,
    smallest_chunk: Option<u64>,
    largest_chunk: u64,
    #[cfg(test)]
    chunk_sequence: Vec<(u64, [u8; 32])>,
}

impl ChunkMeasurements {
    fn record_input(&mut self, bytes: u64) {
        self.files += 1;
        self.logical_bytes += bytes;
    }

    fn record_chunk(&mut self, bytes: &[u8]) {
        let size = u64::try_from(bytes.len()).expect("slice length fits in u64");
        self.chunked_bytes += size;
        self.chunk_count += 1;
        self.manifest_bytes += CHUNK_DESCRIPTOR_BYTES;
        self.smallest_chunk = Some(self.smallest_chunk.map_or(size, |old| old.min(size)));
        self.largest_chunk = self.largest_chunk.max(size);
        let digest = Sha256::digest(bytes).into();
        #[cfg(test)]
        self.chunk_sequence.push((size, digest));
        self.unique_chunks.entry(digest).or_insert(size);
    }

    fn unique_bytes(&self) -> u64 {
        self.unique_chunks.values().sum()
    }

    fn record_whole_file(&mut self, file_hash: [u8; 32], file_size: u64) {
        self.unique_chunks.entry(file_hash).or_insert(file_size);
        self.chunked_bytes += file_size;
        self.chunk_count += 1;
        self.manifest_bytes += WHOLE_FILE_DESCRIPTOR_BYTES;
        self.smallest_chunk = Some(
            self.smallest_chunk
                .map_or(file_size, |old| old.min(file_size)),
        );
        self.largest_chunk = self.largest_chunk.max(file_size);
    }

    fn record_passthrough(&mut self, bytes: u64) {
        self.passthrough_bytes += bytes;
    }

    fn manifest_bytes(&self) -> u64 {
        self.files * FILE_MANIFEST_HEADER_BYTES + self.manifest_bytes
    }

    fn physical_bytes(&self) -> u64 {
        self.unique_bytes() + self.manifest_bytes() + self.passthrough_bytes
    }

    fn average_chunk_size(&self) -> u64 {
        self.chunked_bytes
            .checked_div(self.chunk_count)
            .unwrap_or(0)
    }
}

#[derive(Debug)]
struct MeasurementResult {
    strategy: MeasurementStrategy,
    measurements: ChunkMeasurements,
    elapsed: Duration,
}

fn main() -> io::Result<()> {
    let command_line = CommandLine::parse(env::args().skip(1))?;
    let files = collect_nar_files(&command_line.corpus, command_line.max_files)?;

    println!(
        "corpus={} files={} min_size={} max_size={} fixed_size={}",
        command_line.corpus.display(),
        files.len(),
        command_line.min_size,
        command_line.max_size,
        command_line.fixed_size,
    );

    let parameters = ChunkParameters::new(command_line.min_size, command_line.max_size);
    let semantic_strategies: &[MeasurementStrategy] = &[
        MeasurementStrategy::SemanticCdc(ChunkAlgorithm::MinCdcHash4),
        MeasurementStrategy::SemanticCdc(ChunkAlgorithm::MinCdc4),
    ];
    let all_strategies: &[MeasurementStrategy] = &[
        MeasurementStrategy::RawCdc(ChunkAlgorithm::MinCdcHash4),
        MeasurementStrategy::RawCdc(ChunkAlgorithm::MinCdc4),
        MeasurementStrategy::SemanticCdc(ChunkAlgorithm::MinCdcHash4),
        MeasurementStrategy::SemanticCdc(ChunkAlgorithm::MinCdc4),
        MeasurementStrategy::FixedSize,
        MeasurementStrategy::WholeFileCas,
    ];
    let strategies = if command_line.semantic_only {
        semantic_strategies
    } else {
        all_strategies
    };
    for &strategy in strategies {
        let result = measure_strategy(&files, strategy, parameters, command_line.fixed_size)?;
        print_result(&result, command_line.fixed_size);
    }

    Ok(())
}

impl CommandLine {
    fn parse(mut arguments: impl Iterator<Item = String>) -> io::Result<Self> {
        let mut corpus = None;
        let mut min_size = 4 * 1024;
        let mut max_size = 12 * 1024;
        let mut fixed_size = DEFAULT_FIXED_CHUNK_SIZE;
        let mut max_files = None;
        let mut semantic_only = false;

        while let Some(argument) = arguments.next() {
            if argument == "--semantic-only" {
                semantic_only = true;
                continue;
            }
            let (option, value) = argument.split_once('=').map_or_else(
                || (argument.as_str(), arguments.next()),
                |(option, value)| (option, Some(value.to_owned())),
            );
            match option {
                "--corpus" => corpus = Some(parse_path(value, option)?),
                "--min-size" => min_size = parse_usize(value, option)?,
                "--max-size" => max_size = parse_usize(value, option)?,
                "--fixed-size" => fixed_size = parse_usize(value, option)?,
                "--max-files" => max_files = Some(parse_usize(value, option)?),
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(invalid_argument(option)),
            }
        }

        let corpus = corpus.ok_or_else(|| invalid_argument("--corpus is required"))?;
        if min_size == 0 || min_size > max_size || fixed_size == 0 {
            return Err(invalid_argument(
                "chunk sizes must be nonzero and min-size must not exceed max-size",
            ));
        }
        Ok(Self {
            corpus,
            min_size,
            max_size,
            fixed_size,
            max_files,
            semantic_only,
        })
    }
}

fn parse_path(value: Option<String>, option: &str) -> io::Result<PathBuf> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| invalid_argument(format!("{option} requires a value")))
}

fn parse_usize(value: Option<String>, option: &str) -> io::Result<usize> {
    value
        .ok_or_else(|| invalid_argument(format!("{option} requires a value")))?
        .parse()
        .map_err(|error| invalid_argument(format!("{option} must be an integer: {error}")))
}

fn invalid_argument(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn print_help() {
    println!(
        "Usage: narjar-nar-chunking --corpus PATH [--min-size BYTES] [--max-size BYTES] [--fixed-size BYTES] [--max-files COUNT] [--semantic-only]\n\nMeasures raw and semantic MinCDC, fixed-size, and whole-file CAS controls over sorted .nar files."
    );
}

fn collect_nar_files(root: &Path, max_files: Option<usize>) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_nar_files_recursively(root, &mut files)?;
    files.sort_unstable();
    if let Some(max_files) = max_files {
        files.truncate(max_files);
    }
    Ok(files)
}

fn collect_nar_files_recursively(root: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_nar_files_recursively(&path, files)?;
        } else if file_type.is_file()
            && path.extension().is_some_and(|extension| extension == "nar")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn measure_strategy(
    files: &[PathBuf],
    strategy: MeasurementStrategy,
    parameters: ChunkParameters,
    fixed_size: usize,
) -> io::Result<MeasurementResult> {
    let start = Instant::now();
    let measurements = match strategy {
        MeasurementStrategy::RawCdc(algorithm) => measure_raw_cdc(files, parameters, algorithm)?,
        MeasurementStrategy::SemanticCdc(algorithm) => {
            measure_semantic_cdc(files, parameters, algorithm)?
        }
        MeasurementStrategy::FixedSize => measure_fixed_size(files, fixed_size)?,
        MeasurementStrategy::WholeFileCas => measure_whole_file_cas(files)?,
    };
    Ok(MeasurementResult {
        strategy,
        measurements,
        elapsed: start.elapsed(),
    })
}

fn measure_raw_cdc(
    files: &[PathBuf],
    parameters: ChunkParameters,
    algorithm: ChunkAlgorithm,
) -> io::Result<ChunkMeasurements> {
    let mut measurements = ChunkMeasurements::default();
    for path in files {
        let expected_size = fs::metadata(path)?.len();
        let manifest = chunk_reader(File::open(path)?, parameters, algorithm, |_, chunk| {
            measurements.record_chunk(chunk);
            Ok(())
        })?;
        if manifest.total_size() != expected_size {
            return Err(invalid_data(format!(
                "{}: manifest size {} differs from file size {expected_size}",
                path.display(),
                manifest.total_size(),
            )));
        }
        measurements.record_input(manifest.total_size());
    }
    Ok(measurements)
}

#[derive(Clone, Copy)]
enum SemanticCdc {
    MinCdcHash4(MinCdcHash4),
    MinCdc4(MinCdc4),
}

impl SemanticCdc {
    fn for_algorithm(algorithm: ChunkAlgorithm) -> Self {
        match algorithm {
            ChunkAlgorithm::MinCdcHash4 => Self::MinCdcHash4(MinCdcHash4::new()),
            #[allow(deprecated)]
            ChunkAlgorithm::MinCdc4 => Self::MinCdc4(MinCdc4::new()),
        }
    }

    fn window_size(self) -> usize {
        match self {
            Self::MinCdcHash4(cdc) => cdc.window_size(),
            Self::MinCdc4(cdc) => cdc.window_size(),
        }
    }

    fn best_splitpoint(self, bytes: &[u8]) -> usize {
        match self {
            Self::MinCdcHash4(cdc) => cdc.best_splitpoint(bytes),
            Self::MinCdc4(cdc) => cdc.best_splitpoint(bytes),
        }
    }
}

struct SemanticCdcSink<'a> {
    measurements: &'a mut ChunkMeasurements,
    min_size: usize,
    max_size: usize,
    cdc: SemanticCdc,
    pending: Vec<u8>,
    declared_file_size: Option<u64>,
    current_file_size: u64,
}

impl<'a> SemanticCdcSink<'a> {
    fn new(
        measurements: &'a mut ChunkMeasurements,
        parameters: ChunkParameters,
        algorithm: ChunkAlgorithm,
    ) -> Self {
        Self {
            measurements,
            min_size: parameters.min_size(),
            max_size: parameters.max_size(),
            cdc: SemanticCdc::for_algorithm(algorithm),
            pending: Vec::new(),
            declared_file_size: None,
            current_file_size: 0,
        }
    }

    fn push_file_bytes(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        self.current_file_size += u64::try_from(bytes.len()).expect("slice length fits in u64");
        self.emit_ready_chunks();
    }

    fn emit_ready_chunks(&mut self) {
        while self.pending.len() > self.max_size {
            self.emit_next_chunk();
        }
    }

    fn finish_file(&mut self) {
        while !self.pending.is_empty() {
            if self.pending.len() <= self.min_size {
                self.measurements.record_chunk(&self.pending);
                self.pending.clear();
                continue;
            }
            self.emit_next_chunk();
        }
        self.measurements.manifest_bytes += FILE_MANIFEST_HEADER_BYTES;
        assert_eq!(
            self.declared_file_size,
            Some(self.current_file_size),
            "decoder event stream must account for every file byte"
        );
        self.declared_file_size = None;
        self.current_file_size = 0;
    }

    fn emit_next_chunk(&mut self) {
        let search_start = self.min_size.saturating_sub(self.cdc.window_size());
        let search_end = self.max_size.min(self.pending.len());
        let search = &self.pending[search_start..search_end];
        let splitpoint = search_start + self.cdc.best_splitpoint(search);
        self.measurements.record_chunk(&self.pending[..splitpoint]);
        self.pending.copy_within(splitpoint.., 0);
        self.pending.truncate(self.pending.len() - splitpoint);
    }
}

impl EventSink for SemanticCdcSink<'_> {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error> {
        match event {
            Event::BeginFile { size, .. } => {
                assert!(self.declared_file_size.is_none());
                self.declared_file_size = Some(size);
            }
            Event::FileChunk(bytes) => self.push_file_bytes(bytes),
            Event::EndFile => self.finish_file(),
            Event::BeginDirectory { .. }
            | Event::Entry { .. }
            | Event::Symlink { .. }
            | Event::EndDirectory => {}
        }
        Ok(())
    }
}

fn measure_semantic_cdc(
    files: &[PathBuf],
    parameters: ChunkParameters,
    algorithm: ChunkAlgorithm,
) -> io::Result<ChunkMeasurements> {
    let mut measurements = ChunkMeasurements::default();
    for path in files {
        let chunked_bytes_before_file = measurements.chunked_bytes;
        let mut sink = SemanticCdcSink::new(&mut measurements, parameters, algorithm);
        let summary = Decoder::new(File::open(path)?)
            .decode(&mut sink)
            .map_err(nar_decode_error)?;
        if sink.declared_file_size.is_some() || !sink.pending.is_empty() {
            return Err(invalid_data(format!(
                "{}: decoder ended inside a regular file",
                path.display()
            )));
        }
        measurements.record_input(summary.raw_size);
        let semantic_bytes = measurements.chunked_bytes - chunked_bytes_before_file;
        let passthrough_bytes = summary
            .raw_size
            .checked_sub(semantic_bytes)
            .ok_or_else(|| invalid_data("semantic file bytes exceed raw NAR size"))?;
        measurements.record_passthrough(passthrough_bytes);
    }
    Ok(measurements)
}

fn nar_decode_error(error: DecodeError<Infallible>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn measure_fixed_size(files: &[PathBuf], fixed_size: usize) -> io::Result<ChunkMeasurements> {
    let mut measurements = ChunkMeasurements::default();
    let mut buffer = vec![0; fixed_size];
    for path in files {
        let mut file = File::open(path)?;
        let mut file_size = 0;
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            measurements.record_chunk(&buffer[..bytes_read]);
            file_size += u64::try_from(bytes_read).expect("read size fits in u64");
        }
        measurements.record_input(file_size);
    }
    Ok(measurements)
}

fn measure_whole_file_cas(files: &[PathBuf]) -> io::Result<ChunkMeasurements> {
    let mut measurements = ChunkMeasurements::default();
    for path in files {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut file_size = 0;
        let mut buffer = [0; 64 * 1024];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            file_size += u64::try_from(bytes_read).expect("read size fits in u64");
        }
        measurements.record_input(file_size);
        measurements.record_whole_file(hasher.finalize().into(), file_size);
    }
    Ok(measurements)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn print_result(result: &MeasurementResult, fixed_size: usize) {
    let measurements = &result.measurements;
    let throughput_mib_per_second = measurements
        .logical_bytes
        .checked_div(1024 * 1024)
        .and_then(|mebibytes| {
            u64::try_from(result.elapsed.as_millis())
                .ok()
                .map(|millis| (mebibytes, millis))
        })
        .map_or(0.0, |(mebibytes, millis)| {
            if millis == 0 {
                0.0
            } else {
                mebibytes as f64 * 1000.0 / millis as f64
            }
        });
    println!(
        "strategy={} files={} logical_bytes={} chunked_bytes={} passthrough_bytes={} chunks={} unique_chunks={} unique_bytes={} manifest_bytes={} physical_bytes={} min_chunk={} avg_chunk={} max_chunk={} elapsed_ms={} throughput_mib_s={throughput_mib_per_second:.2}",
        result.strategy.name(fixed_size),
        measurements.files,
        measurements.logical_bytes,
        measurements.chunked_bytes,
        measurements.passthrough_bytes,
        measurements.chunk_count,
        measurements.unique_chunks.len(),
        measurements.unique_bytes(),
        measurements.manifest_bytes(),
        measurements.physical_bytes(),
        measurements.smallest_chunk.unwrap_or(0),
        measurements.average_chunk_size(),
        measurements.largest_chunk,
        result.elapsed.as_millis(),
    );
}

#[cfg(test)]
mod tests {
    use super::{ChunkAlgorithm, ChunkMeasurements, ChunkParameters, Event, SemanticCdcSink};
    use narjar::nar::EventSink;

    fn measure_segmented_file(input: &[u8], segment_size: usize) -> ChunkMeasurements {
        let mut measurements = ChunkMeasurements::default();
        let mut sink = SemanticCdcSink::new(
            &mut measurements,
            ChunkParameters::eight_kibibyte_window(),
            ChunkAlgorithm::MinCdcHash4,
        );
        sink.event(Event::BeginFile {
            executable: false,
            size: input.len() as u64,
            offset: 0,
        })
        .expect("infallible sink should accept the event");
        for segment in input.chunks(segment_size) {
            sink.event(Event::FileChunk(segment))
                .expect("infallible sink should accept the event");
        }
        sink.event(Event::EndFile)
            .expect("infallible sink should accept the event");
        measurements
    }

    #[test]
    fn semantic_chunking_is_independent_of_decoder_event_sizes() {
        let input: Vec<_> = (0usize..(256 * 1024))
            .map(|index| index.wrapping_mul(37) as u8)
            .collect();

        assert_eq!(
            measure_segmented_file(&input, 31),
            measure_segmented_file(&input, 64 * 1024)
        );
        assert_eq!(
            measure_segmented_file(&input, 31),
            measure_segmented_file(&input, input.len())
        );
    }
}
