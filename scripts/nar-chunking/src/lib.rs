use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use mincdc::{Cdc, MinCdc4, MinCdcHash4, ReadChunker};
use sha2::{Digest, Sha256};

const DEFAULT_MIN_CHUNK_SIZE: usize = 8 * 1024;
const DEFAULT_MAX_CHUNK_SIZE: usize = 24 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkParameters {
    min_size: usize,
    max_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkAlgorithm {
    MinCdcHash4,
    MinCdc4,
}

impl ChunkParameters {
    #[must_use]
    pub const fn new(min_size: usize, max_size: usize) -> Self {
        assert!(min_size > 0 && min_size <= max_size);
        Self { min_size, max_size }
    }

    #[must_use]
    pub const fn selected_window() -> Self {
        Self::new(DEFAULT_MIN_CHUNK_SIZE, DEFAULT_MAX_CHUNK_SIZE)
    }

    #[must_use]
    pub const fn min_size(self) -> usize {
        self.min_size
    }

    #[must_use]
    pub const fn max_size(self) -> usize {
        self.max_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDescriptor {
    offset: u64,
    size: u64,
    sha256: [u8; 32],
}

impl ChunkDescriptor {
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkManifest {
    total_size: u64,
    chunks: Vec<ChunkDescriptor>,
}

const MANIFEST_MAGIC: &[u8] = b"NARJ83M\0";

/// A file-backed store used only by the NARJ-83 experiment.
pub struct ResearchChunkStore {
    root: PathBuf,
}

/// On-disk usage for a [`ResearchChunkStore`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StoreUsage {
    files: u64,
    directories: u64,
    apparent_bytes: u64,
    allocated_bytes: u64,
}

impl StoreUsage {
    #[must_use]
    pub const fn files(self) -> u64 {
        self.files
    }

    #[must_use]
    pub const fn directories(self) -> u64 {
        self.directories
    }

    #[must_use]
    pub const fn apparent_bytes(self) -> u64 {
        self.apparent_bytes
    }

    #[must_use]
    pub const fn allocated_bytes(self) -> u64 {
        self.allocated_bytes
    }
}

impl ChunkManifest {
    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    #[must_use]
    pub fn chunks(&self) -> &[ChunkDescriptor] {
        &self.chunks
    }
}

impl ResearchChunkStore {
    /// Creates the experiment store layout without deleting existing data.
    pub fn create(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        if root.exists() && fs::read_dir(&root)?.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "research chunk store root must be empty",
            ));
        }
        fs::create_dir_all(root.join("chunks"))?;
        fs::create_dir_all(root.join("manifests"))?;
        Ok(Self { root })
    }

    /// Stores one content-addressed chunk, verifying an existing duplicate.
    pub fn store_chunk(&self, descriptor: ChunkDescriptor, bytes: &[u8]) -> io::Result<()> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if descriptor.size != u64::try_from(bytes.len()).expect("slice length fits in u64")
            || descriptor.sha256 != digest
        {
            return Err(invalid_chunk("descriptor does not match chunk bytes"));
        }
        let path = self.chunk_path(descriptor.sha256);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => file.write_all(bytes),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = fs::read(path)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(invalid_chunk(
                        "existing chunk differs from its content hash",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Writes an ordered binary manifest for one input file.
    pub fn store_manifest(&self, index: u64, manifest: &ChunkManifest) -> io::Result<()> {
        let mut file = File::create(self.manifest_path(index))?;
        file.write_all(MANIFEST_MAGIC)?;
        file.write_all(&manifest.total_size.to_le_bytes())?;
        file.write_all(
            &u64::try_from(manifest.chunks.len())
                .expect("manifest chunk count fits in u64")
                .to_le_bytes(),
        )?;
        for chunk in &manifest.chunks {
            file.write_all(&chunk.offset.to_le_bytes())?;
            file.write_all(&chunk.size.to_le_bytes())?;
            file.write_all(&chunk.sha256)?;
        }
        Ok(())
    }

    /// Hashes the exact bytes selected by a logical range in a manifest.
    pub fn hash_range(&self, manifest: &ChunkManifest, range: Range<u64>) -> io::Result<[u8; 32]> {
        validate_range(manifest, &range)?;
        let mut writer = DigestWriter(Sha256::new());
        self.write_range(manifest, range, &mut writer)?;
        Ok(writer.0.finalize().into())
    }

    /// Writes the exact bytes selected by a logical range in a manifest.
    pub fn write_range<W: Write>(
        &self,
        manifest: &ChunkManifest,
        range: Range<u64>,
        writer: &mut W,
    ) -> io::Result<()> {
        validate_range(manifest, &range)?;
        for chunk in &manifest.chunks {
            let chunk_end = chunk
                .offset
                .checked_add(chunk.size)
                .ok_or_else(|| invalid_chunk("chunk range overflows u64"))?;
            let write_start = range.start.max(chunk.offset);
            let write_end = range.end.min(chunk_end);
            if write_start >= write_end {
                continue;
            }
            let bytes = fs::read(self.chunk_path(chunk.sha256))?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if bytes.len() != usize::try_from(chunk.size).expect("chunk size fits in usize")
                || digest != chunk.sha256
            {
                return Err(invalid_chunk("stored chunk failed descriptor verification"));
            }
            let start = usize::try_from(write_start - chunk.offset).expect("range fits usize");
            let end = usize::try_from(write_end - chunk.offset).expect("range fits usize");
            writer.write_all(&bytes[start..end])?;
        }
        Ok(())
    }

    /// Measures apparent and allocated bytes under the experiment root.
    pub fn usage(&self) -> io::Result<StoreUsage> {
        measure_store_usage(&self.root)
    }

    fn chunk_path(&self, digest: [u8; 32]) -> PathBuf {
        self.root.join("chunks").join(hex_digest(digest))
    }

    fn manifest_path(&self, index: u64) -> PathBuf {
        self.root.join("manifests").join(format!("{index:020}.bin"))
    }
}

fn validate_range(manifest: &ChunkManifest, range: &Range<u64>) -> io::Result<()> {
    validate_manifest(manifest)?;
    if range.start > range.end || range.end > manifest.total_size {
        return Err(invalid_chunk("range is outside the manifest"));
    }
    Ok(())
}

fn validate_manifest(manifest: &ChunkManifest) -> io::Result<()> {
    let mut expected_offset = 0;
    for chunk in &manifest.chunks {
        if chunk.offset != expected_offset {
            return Err(invalid_chunk(
                "manifest chunks are not ordered and contiguous",
            ));
        }
        expected_offset = chunk
            .offset
            .checked_add(chunk.size)
            .ok_or_else(|| invalid_chunk("manifest chunk range overflows u64"))?;
    }
    if expected_offset != manifest.total_size {
        return Err(invalid_chunk(
            "manifest total size does not match its chunks",
        ));
    }
    Ok(())
}

fn invalid_chunk(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn measure_store_usage(root: &Path) -> io::Result<StoreUsage> {
    fs::metadata(root)?;
    let mut usage = StoreUsage {
        directories: 1,
        ..StoreUsage::default()
    };
    measure_store_usage_recursively(root, &mut usage)?;
    Ok(usage)
}

fn measure_store_usage_recursively(directory: &Path, usage: &mut StoreUsage) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            usage.directories += 1;
            measure_store_usage_recursively(&entry.path(), usage)?;
        } else if metadata.is_file() {
            usage.files += 1;
            usage.apparent_bytes += metadata.len();
            usage.allocated_bytes += allocated_bytes(&metadata);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn chunk_reader<R, StoreChunk>(
    reader: R,
    parameters: ChunkParameters,
    algorithm: ChunkAlgorithm,
    store_chunk: StoreChunk,
) -> io::Result<ChunkManifest>
where
    R: Read,
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    match algorithm {
        ChunkAlgorithm::MinCdcHash4 => {
            chunk_reader_with_cdc(reader, parameters, MinCdcHash4::new(), store_chunk)
        }
        #[allow(deprecated)]
        ChunkAlgorithm::MinCdc4 => {
            chunk_reader_with_cdc(reader, parameters, MinCdc4::new(), store_chunk)
        }
    }
}

fn chunk_reader_with_cdc<R, C, StoreChunk>(
    reader: R,
    parameters: ChunkParameters,
    cdc: C,
    mut store_chunk: StoreChunk,
) -> io::Result<ChunkManifest>
where
    R: Read,
    C: Cdc,
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    let mut chunker = ReadChunker::new(reader, parameters.min_size, parameters.max_size, cdc);
    let mut manifest = ChunkManifest {
        total_size: 0,
        chunks: Vec::new(),
    };

    while let Some(chunk) = chunker.next()? {
        record_chunk(&mut manifest, &mut store_chunk, &chunk)?;
    }
    Ok(manifest)
}

fn record_chunk<StoreChunk>(
    manifest: &mut ChunkManifest,
    store_chunk: &mut StoreChunk,
    chunk: &[u8],
) -> io::Result<()>
where
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    let descriptor = ChunkDescriptor {
        offset: manifest.total_size,
        size: u64::try_from(chunk.len()).expect("slice length fits in u64"),
        sha256: Sha256::digest(chunk).into(),
    };
    store_chunk(descriptor, chunk)?;
    manifest.total_size += descriptor.size;
    manifest.chunks.push(descriptor);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io::{self, Read};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{ChunkAlgorithm, ChunkManifest, ChunkParameters, ResearchChunkStore, chunk_reader};

    struct FixedReadSize<'a> {
        bytes: &'a [u8],
        read_size: usize,
    }

    impl Read for FixedReadSize<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let read_size = self.read_size.min(output.len()).min(self.bytes.len());
            output[..read_size].copy_from_slice(&self.bytes[..read_size]);
            self.bytes = &self.bytes[read_size..];
            Ok(read_size)
        }
    }

    fn chunk_input(input: &[u8], read_size: usize) -> (ChunkManifest, Vec<Vec<u8>>) {
        let mut chunks = Vec::new();
        let manifest = chunk_reader(
            FixedReadSize {
                bytes: input,
                read_size,
            },
            ChunkParameters::selected_window(),
            ChunkAlgorithm::MinCdcHash4,
            |_, chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            },
        )
        .expect("test input should be readable");
        (manifest, chunks)
    }

    fn test_input() -> Vec<u8> {
        (0usize..(256 * 1024))
            .map(|index| index.wrapping_mul(37) as u8)
            .collect()
    }

    fn incompressible_test_input(length: usize) -> Vec<u8> {
        let mut state = 0x9e3779b97f4a7c15_u64;
        (0..length)
            .map(|_| {
                state ^= state << 7;
                state ^= state >> 9;
                state ^= state << 8;
                state as u8
            })
            .collect()
    }

    fn temporary_store_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "narj83-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ))
    }

    fn assert_chunking_reconstructs_input(
        input: &[u8],
        algorithm: ChunkAlgorithm,
        read_size: usize,
    ) {
        let mut reconstructed = Vec::new();
        let manifest = chunk_reader(
            FixedReadSize {
                bytes: input,
                read_size,
            },
            ChunkParameters::selected_window(),
            algorithm,
            |_, chunk| {
                reconstructed.extend_from_slice(chunk);
                Ok(())
            },
        )
        .expect("test input should be readable");

        assert_eq!(manifest.total_size(), input.len() as u64);
        assert_eq!(reconstructed, input);
        assert!(
            manifest
                .chunks()
                .windows(2)
                .all(|chunks| { chunks[0].offset() + chunks[0].size() == chunks[1].offset() })
        );
    }

    fn store_test_input(label: &str) -> (PathBuf, ResearchChunkStore, ChunkManifest, Vec<u8>) {
        let root = temporary_store_root(label);
        let store = ResearchChunkStore::create(&root).expect("store should be created");
        let input = test_input();
        let manifest = chunk_reader(
            input.as_slice(),
            ChunkParameters::selected_window(),
            ChunkAlgorithm::MinCdcHash4,
            |descriptor, chunk| store.store_chunk(descriptor, chunk),
        )
        .expect("test input should be readable");
        store
            .store_manifest(0, &manifest)
            .expect("manifest should be writable");
        (root, store, manifest, input)
    }

    #[test]
    fn chunking_handles_empty_tiny_incompressible_and_shifted_inputs() {
        let repeated = vec![0xa5; 3 * ChunkParameters::selected_window().max_size() + 17];
        let incompressible = incompressible_test_input(1024 * 1024);
        let shifted = {
            let mut input = test_input();
            input.splice(17..17, [0x7f]);
            input
        };
        let inputs = [vec![], vec![0], repeated, incompressible, shifted];

        for input in &inputs {
            for algorithm in [ChunkAlgorithm::MinCdcHash4, ChunkAlgorithm::MinCdc4] {
                for read_size in [1, 37, 64 * 1024] {
                    assert_chunking_reconstructs_input(input, algorithm, read_size);
                }
            }
        }
    }

    #[test]
    fn reconstruction_preserves_the_raw_nar_bytes() {
        let input = test_input();
        let (_, chunks) = chunk_input(&input, 97);
        let reconstructed = chunks.concat();

        assert_eq!(reconstructed, input);
    }

    #[test]
    fn boundaries_are_independent_of_input_read_sizes() {
        let input = test_input();
        let (small_reads, _) = chunk_input(&input, 31);
        let (large_reads, _) = chunk_input(&input, 64 * 1024);

        assert_eq!(small_reads, large_reads);
    }

    #[test]
    fn descriptors_cover_the_input_and_hash_each_chunk() {
        let input = test_input();
        let (manifest, chunks) = chunk_input(&input, 4096);
        let selected_window = ChunkParameters::selected_window();

        assert_eq!(manifest.total_size(), input.len() as u64);
        assert_eq!(manifest.chunks().len(), chunks.len());
        assert_eq!(
            manifest.chunks().first().map(|chunk| chunk.offset()),
            Some(0)
        );
        assert!(
            manifest
                .chunks()
                .iter()
                .all(|chunk| chunk.size() <= selected_window.max_size() as u64)
        );
        assert!(
            manifest
                .chunks()
                .iter()
                .zip(&chunks)
                .all(|(descriptor, chunk)| descriptor.size() == chunk.len() as u64)
        );
    }

    #[test]
    fn both_min_cdc_implementations_reconstruct_the_input() {
        let input = test_input();

        for algorithm in [ChunkAlgorithm::MinCdcHash4, ChunkAlgorithm::MinCdc4] {
            let mut reconstructed = Vec::new();
            chunk_reader(
                FixedReadSize {
                    bytes: &input,
                    read_size: 4096,
                },
                ChunkParameters::selected_window(),
                algorithm,
                |_, chunk| {
                    reconstructed.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .expect("test input should be readable");

            assert_eq!(reconstructed, input);
        }
    }

    #[test]
    fn mincdc_hash4_cut_points_are_stable_for_the_selected_parameters() {
        let input: Vec<_> = (0usize..(32 * 1024))
            .map(|index| index.wrapping_mul(37) as u8)
            .collect();
        let mut descriptors = Vec::new();

        chunk_reader(
            input.as_slice(),
            ChunkParameters::selected_window(),
            ChunkAlgorithm::MinCdcHash4,
            |descriptor, _| {
                descriptors.push((descriptor.offset(), descriptor.size()));
                Ok(())
            },
        )
        .expect("test input should be readable");

        assert_eq!(
            descriptors,
            vec![(0, 8367), (8367, 8192), (16559, 8192), (24751, 8017),]
        );
    }

    #[test]
    fn research_store_reconstructs_full_and_resumed_ranges() {
        let (root, store, manifest, input) = store_test_input("ranges");

        let mut reconstructed = Vec::new();
        store
            .write_range(&manifest, 0..manifest.total_size(), &mut reconstructed)
            .expect("full range should be readable");
        assert_eq!(reconstructed, input);

        let resume_start = manifest.total_size() * 9 / 10;
        let mut resumed = Vec::new();
        store
            .write_range(&manifest, resume_start..manifest.total_size(), &mut resumed)
            .expect("resumed range should be readable");
        assert_eq!(resumed, input[resume_start as usize..]);

        let usage = store.usage().expect("store usage should be readable");
        let unique_chunks = manifest
            .chunks()
            .iter()
            .map(|chunk| (chunk.sha256(), chunk.size()))
            .collect::<HashMap<_, _>>();
        assert_eq!(usage.files(), unique_chunks.len() as u64 + 1);
        assert_eq!(usage.directories(), 3);
        let manifest_bytes = 8 + 8 + 8 + manifest.chunks().len() as u64 * (8 + 8 + 32);
        assert_eq!(
            usage.apparent_bytes(),
            unique_chunks.values().sum::<u64>() + manifest_bytes
        );
        assert!(usage.allocated_bytes() > 0);

        let mut reordered = manifest.clone();
        reordered.chunks.swap(0, 1);
        assert!(
            store
                .hash_range(&reordered, 0..reordered.total_size())
                .is_err()
        );
        fs::remove_dir_all(root).expect("test store should be removable");
    }

    #[test]
    fn research_store_rejects_missing_corrupt_and_mismatched_chunks() {
        let (missing_root, missing_store, missing_manifest, _) = store_test_input("missing");
        let missing_chunk = missing_manifest
            .chunks()
            .first()
            .expect("test input should have a chunk");
        fs::remove_file(missing_store.chunk_path(missing_chunk.sha256()))
            .expect("chunk should be removable");
        assert!(
            missing_store
                .hash_range(&missing_manifest, 0..missing_manifest.total_size())
                .is_err()
        );
        fs::remove_dir_all(missing_root).expect("missing test store should be removable");

        let (corrupt_root, corrupt_store, corrupt_manifest, _) = store_test_input("corrupt");
        let corrupt_chunk = corrupt_manifest
            .chunks()
            .first()
            .expect("test input should have a chunk");
        fs::write(corrupt_store.chunk_path(corrupt_chunk.sha256()), [0xa5; 32])
            .expect("chunk should be corruptible");
        assert!(
            corrupt_store
                .hash_range(&corrupt_manifest, 0..corrupt_manifest.total_size())
                .is_err()
        );
        fs::remove_dir_all(corrupt_root).expect("corrupt test store should be removable");

        let (duplicate_root, duplicate_store, duplicate_manifest, duplicate_input) =
            store_test_input("duplicate");
        let duplicate_chunk = duplicate_manifest
            .chunks()
            .first()
            .expect("test input should have a chunk");
        let start = duplicate_chunk.offset() as usize;
        let end = start + duplicate_chunk.size() as usize;
        assert!(
            duplicate_store
                .store_chunk(*duplicate_chunk, &duplicate_input[start..end])
                .is_ok()
        );
        let mut different_bytes = duplicate_input[start..end].to_vec();
        different_bytes[0] ^= 1;
        assert!(
            duplicate_store
                .store_chunk(*duplicate_chunk, &different_bytes)
                .is_err()
        );
        fs::remove_dir_all(duplicate_root).expect("duplicate test store should be removable");
    }

    #[test]
    fn research_store_rejects_invalid_ranges_and_reordered_manifests() {
        let (root, store, manifest, _) = store_test_input("invalid-ranges");

        let invalid_range_start = 1;
        let invalid_range_end = 0;
        assert!(
            store
                .hash_range(&manifest, invalid_range_start..invalid_range_end)
                .is_err()
        );
        assert!(
            store
                .hash_range(&manifest, 0..manifest.total_size() + 1)
                .is_err()
        );

        let mut reordered = manifest.clone();
        reordered.chunks.swap(0, 1);
        assert!(
            store
                .hash_range(&reordered, 0..reordered.total_size())
                .is_err()
        );
        fs::remove_dir_all(root).expect("invalid-range test store should be removable");
    }
}
