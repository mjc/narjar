use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

use crate::narinfo::{MAX_NARINFO_BYTES, NarInfoClaims};
use crate::object::{NarFileName, WireEncoding};

use super::{
    Storage, StorageError, StoreHash, for_each_dir_name,
    fs::{open_directory_at, open_regular_at},
};

const TRANSACTION_DIRECTORY: &str = ".narjar-transactions";
const TEMPORARY_DIRECTORY: &str = ".tmp";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PopulationCounts {
    pub(crate) scanned_entries: u64,
    pub(crate) ignored_entries: u64,
    pub(crate) disappeared_entries: u64,
    pub(crate) errors: u64,
    pub(crate) structurally_valid_narinfo_entries: u64,
    pub(crate) malformed_narinfo_filenames: u64,
    pub(crate) malformed_narinfo_contents: u64,
    pub(crate) malformed_nar_files: u64,
    pub(crate) malformed_nar_bytes: u64,
    pub(crate) narinfo_files: u64,
    pub(crate) narinfo_read_errors: u64,
    pub(crate) narinfo_bytes: u64,
    pub(crate) narinfo_claimed_nar_bytes: u64,
    pub(crate) raw_files: u64,
    pub(crate) raw_bytes: u64,
    pub(crate) xz_files: u64,
    pub(crate) xz_bytes: u64,
    pub(crate) zstd_files: u64,
    pub(crate) zstd_bytes: u64,
    pub(crate) chunk_files: u64,
    pub(crate) chunk_bytes: u64,
    pub(crate) manifest_files: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) chunked_nars: u64,
    pub(crate) chunked_nar_bytes: u64,
    pub(crate) ingestion_receipt_files: u64,
    pub(crate) ingestion_receipt_bytes: u64,
    pub(crate) egress_receipt_files: u64,
    pub(crate) egress_receipt_bytes: u64,
    pub(crate) validation_files: u64,
    pub(crate) validation_bytes: u64,
    pub(crate) transaction_files: u64,
    pub(crate) transaction_bytes: u64,
    pub(crate) temporary_files: u64,
    pub(crate) temporary_bytes: u64,
    pub(crate) apparent_file_bytes: u64,
}

impl PopulationCounts {
    fn add_chunk_store(
        &mut self,
        chunks: super::chunk_store::ChunkPopulationCounts,
    ) -> io::Result<()> {
        self.scanned_entries = checked_add(self.scanned_entries, chunks.scanned_entries)?;
        self.ignored_entries = checked_add(self.ignored_entries, chunks.ignored_entries)?;
        self.disappeared_entries =
            checked_add(self.disappeared_entries, chunks.disappeared_entries)?;
        self.errors = checked_add(self.errors, chunks.errors)?;
        self.chunk_files = chunks.chunk_files;
        self.chunk_bytes = chunks.chunk_bytes;
        self.manifest_files = chunks.manifest_files;
        self.manifest_bytes = chunks.manifest_bytes;
        self.chunked_nars = chunks.chunked_nars;
        self.chunked_nar_bytes = chunks.chunked_nar_bytes;
        self.apparent_file_bytes = checked_add(
            self.apparent_file_bytes,
            checked_add(chunks.chunk_bytes, chunks.manifest_bytes)?,
        )?;
        Ok(())
    }
}

impl Storage {
    pub fn population_counts(
        &self,
        stopping: &AtomicBool,
    ) -> Result<PopulationCounts, StorageError> {
        let mut population = PopulationCounts::default();
        self.scan_narinfos(&mut population, stopping)?;
        self.scan_nar_files(&mut population, stopping)?;
        if let Some(chunk_store) = self.payloads.chunk_store() {
            population.add_chunk_store(chunk_store.population_counts(stopping)?)?;
        }
        self.scan_support_files(&mut population, stopping)?;
        Ok(population)
    }

    fn scan_narinfos(
        &self,
        population: &mut PopulationCounts,
        stopping: &AtomicBool,
    ) -> Result<(), StorageError> {
        let root = self.root_directory()?;
        scan_files(&root, population, stopping, |name| {
            let store_hash = name.to_str()?.strip_suffix(".narinfo")?;
            Some(match StoreHash::parse(store_hash) {
                Ok(store) => FileKind::NarInfo(store),
                Err(_) => FileKind::MalformedNarInfo,
            })
        })?;
        Ok(())
    }

    fn scan_nar_files(
        &self,
        population: &mut PopulationCounts,
        stopping: &AtomicBool,
    ) -> Result<(), StorageError> {
        let nar_directory = self.nar_directory()?;
        scan_files(&nar_directory, population, stopping, |name| {
            let text = name.to_str()?;
            if text == TEMPORARY_DIRECTORY {
                return None;
            }
            let kind = match NarFileName::parse(text) {
                Ok(name) => match name.encoding() {
                    WireEncoding::Raw => FileKind::Raw,
                    WireEncoding::Compressed(crate::object::CompressionCodec::Xz) => FileKind::Xz,
                    WireEncoding::Compressed(crate::object::CompressionCodec::Zstd) => {
                        FileKind::Zstd
                    }
                },
                Err(_) if is_nar_filename(text) => FileKind::MalformedNar,
                Err(_) => return None,
            };
            Some(kind)
        })?;
        Ok(())
    }

    fn scan_support_files(
        &self,
        population: &mut PopulationCounts,
        stopping: &AtomicBool,
    ) -> Result<(), StorageError> {
        let root = self.root_directory()?;
        let nar = self.nar_directory()?;
        let root_temporary = open_directory_at(&root, OsStr::new(TEMPORARY_DIRECTORY))?;
        let nar_temporary = open_directory_at(&nar, OsStr::new(TEMPORARY_DIRECTORY))?;
        let realisation_temporary = self.realisations_temp_directory()?;
        let transactions = open_directory_at(&root, OsStr::new(TRANSACTION_DIRECTORY))?;
        scan_directory(
            &self.ingestion_receipt_directory()?,
            population,
            stopping,
            FileKind::IngestionReceipt,
        )?;
        scan_directory(
            &self.egress_receipt_directory()?,
            population,
            stopping,
            FileKind::EgressReceipt,
        )?;
        scan_directory(
            &self.validation_directory()?,
            population,
            stopping,
            FileKind::Validation,
        )?;
        scan_directory(&transactions, population, stopping, FileKind::Transaction)?;
        scan_directory(&root_temporary, population, stopping, FileKind::Temporary)?;
        scan_directory(&nar_temporary, population, stopping, FileKind::Temporary)?;
        scan_directory(
            &realisation_temporary,
            population,
            stopping,
            FileKind::Temporary,
        )?;
        Ok(())
    }
}

fn is_nar_filename(name: &str) -> bool {
    [".nar", ".nar.xz", ".nar.zst"]
        .into_iter()
        .any(|suffix| name.ends_with(suffix))
}

fn scan_directory(
    directory: &File,
    population: &mut PopulationCounts,
    stopping: &AtomicBool,
    kind: FileKind,
) -> io::Result<()> {
    scan_files(directory, population, stopping, |_| Some(kind))
}

fn scan_files(
    directory: &File,
    population: &mut PopulationCounts,
    stopping: &AtomicBool,
    classify: impl Fn(&OsStr) -> Option<FileKind>,
) -> io::Result<()> {
    let mut interrupted = false;
    for_each_dir_name(directory, |name| {
        if stopping.load(Ordering::Relaxed) {
            interrupted = true;
            return Ok(false);
        }
        population.scanned_entries = checked_add(population.scanned_entries, 1)?;
        if population.scanned_entries.is_multiple_of(256) {
            thread::yield_now();
        }
        let Some(kind) = classify(name) else {
            population.ignored_entries = checked_add(population.ignored_entries, 1)?;
            return Ok(true);
        };
        record_classified_entry(directory, population, name, kind)?;
        Ok(true)
    })?;
    match interrupted {
        true => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "population scan cancelled",
        )),
        false => Ok(()),
    }
}

fn record_classified_entry(
    directory: &File,
    population: &mut PopulationCounts,
    name: &OsStr,
    kind: FileKind,
) -> io::Result<()> {
    let file = match open_regular_at(directory, name) {
        Ok(file) => file,
        Err(error) => return record_entry_access_result(population, kind, error),
    };
    match record_open_file(population, kind, file) {
        Ok(()) => Ok(()),
        Err(error) => record_entry_access_result(population, kind, error),
    }
}

fn record_entry_access_result(
    population: &mut PopulationCounts,
    kind: FileKind,
    error: io::Error,
) -> io::Result<()> {
    match error.kind() {
        io::ErrorKind::NotFound => {
            population.disappeared_entries = checked_add(population.disappeared_entries, 1)?;
            Ok(())
        }
        _ => record_entry_error(population, kind),
    }
}

fn record_open_file(
    population: &mut PopulationCounts,
    kind: FileKind,
    file: File,
) -> io::Result<()> {
    match kind {
        FileKind::NarInfo(store) => record_narinfo(population, store, file),
        other => record_file(population, other, file.metadata()?.len()),
    }
}

fn record_narinfo(
    population: &mut PopulationCounts,
    store: StoreHash,
    file: File,
) -> io::Result<()> {
    let file_size = file.metadata()?.len();
    population.apparent_file_bytes = checked_add(population.apparent_file_bytes, file_size)?;
    population.narinfo_bytes = checked_add(population.narinfo_bytes, file_size)?;
    population.narinfo_files = checked_add(population.narinfo_files, 1)?;
    if file_size > MAX_NARINFO_BYTES {
        population.malformed_narinfo_contents =
            checked_add(population.malformed_narinfo_contents, 1)?;
        return Ok(());
    }
    let mut contents = Vec::with_capacity(file_size as usize);
    file.take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_NARINFO_BYTES {
        population.malformed_narinfo_contents =
            checked_add(population.malformed_narinfo_contents, 1)?;
        return Ok(());
    }
    match NarInfoClaims::parse_external_narinfo(&store, contents) {
        Ok(claims) => {
            population.structurally_valid_narinfo_entries =
                checked_add(population.structurally_valid_narinfo_entries, 1)?;
            population.narinfo_claimed_nar_bytes = checked_add(
                population.narinfo_claimed_nar_bytes,
                claims.identity().size().get(),
            )?;
        }
        Err(_) => {
            population.malformed_narinfo_contents =
                checked_add(population.malformed_narinfo_contents, 1)?;
        }
    }
    Ok(())
}

fn record_file(population: &mut PopulationCounts, kind: FileKind, bytes: u64) -> io::Result<()> {
    population.apparent_file_bytes = checked_add(population.apparent_file_bytes, bytes)?;
    record_category_file(population, kind, bytes)
}

fn record_category_file(
    population: &mut PopulationCounts,
    kind: FileKind,
    bytes: u64,
) -> io::Result<()> {
    match kind {
        FileKind::NarInfo(_) => Err(io::Error::other(
            "narinfo entries require structural parsing",
        )),
        FileKind::MalformedNarInfo => record_malformed_narinfo_filename(population, bytes),
        FileKind::Raw => {
            record_file_count_and_bytes(&mut population.raw_files, &mut population.raw_bytes, bytes)
        }
        FileKind::Xz => {
            record_file_count_and_bytes(&mut population.xz_files, &mut population.xz_bytes, bytes)
        }
        FileKind::Zstd => record_file_count_and_bytes(
            &mut population.zstd_files,
            &mut population.zstd_bytes,
            bytes,
        ),
        FileKind::MalformedNar => record_file_count_and_bytes(
            &mut population.malformed_nar_files,
            &mut population.malformed_nar_bytes,
            bytes,
        ),
        FileKind::IngestionReceipt => record_file_count_and_bytes(
            &mut population.ingestion_receipt_files,
            &mut population.ingestion_receipt_bytes,
            bytes,
        ),
        FileKind::EgressReceipt => record_file_count_and_bytes(
            &mut population.egress_receipt_files,
            &mut population.egress_receipt_bytes,
            bytes,
        ),
        FileKind::Validation => record_file_count_and_bytes(
            &mut population.validation_files,
            &mut population.validation_bytes,
            bytes,
        ),
        FileKind::Transaction => record_file_count_and_bytes(
            &mut population.transaction_files,
            &mut population.transaction_bytes,
            bytes,
        ),
        FileKind::Temporary => record_file_count_and_bytes(
            &mut population.temporary_files,
            &mut population.temporary_bytes,
            bytes,
        ),
    }
}

fn record_malformed_narinfo_filename(
    population: &mut PopulationCounts,
    bytes: u64,
) -> io::Result<()> {
    population.malformed_narinfo_filenames =
        checked_add(population.malformed_narinfo_filenames, 1)?;
    record_file_count_and_bytes(
        &mut population.narinfo_files,
        &mut population.narinfo_bytes,
        bytes,
    )
}

fn record_file_count_and_bytes(
    files: &mut u64,
    category_bytes: &mut u64,
    bytes: u64,
) -> io::Result<()> {
    *files = checked_add(*files, 1)?;
    *category_bytes = checked_add(*category_bytes, bytes)?;
    Ok(())
}

fn record_entry_error(population: &mut PopulationCounts, kind: FileKind) -> io::Result<()> {
    population.errors = checked_add(population.errors, 1)?;
    if kind.is_narinfo() {
        population.narinfo_read_errors = checked_add(population.narinfo_read_errors, 1)?;
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| io::Error::other("cache population counter overflow"))
}

#[derive(Clone, Copy)]
enum FileKind {
    NarInfo(StoreHash),
    MalformedNarInfo,
    Raw,
    Xz,
    Zstd,
    MalformedNar,
    IngestionReceipt,
    EgressReceipt,
    Validation,
    Transaction,
    Temporary,
}

impl FileKind {
    fn is_narinfo(self) -> bool {
        match self {
            Self::NarInfo(_) | Self::MalformedNarInfo => true,
            Self::Raw
            | Self::Xz
            | Self::Zstd
            | Self::MalformedNar
            | Self::IngestionReceipt
            | Self::EgressReceipt
            | Self::Validation
            | Self::Transaction
            | Self::Temporary => false,
        }
    }
}
