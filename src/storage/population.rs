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
        self.disappeared_entries = self
            .disappeared_entries
            .checked_add(chunks.disappeared_entries)
            .ok_or_else(|| io::Error::other("cache population counter overflow"))?;
        self.errors = checked_add(self.errors, chunks.errors)?;
        self.chunk_files = chunks.chunk_files;
        self.chunk_bytes = chunks.chunk_bytes;
        self.manifest_files = chunks.manifest_files;
        self.manifest_bytes = chunks.manifest_bytes;
        self.chunked_nars = chunks.chunked_nars;
        self.chunked_nar_bytes = chunks.chunked_nar_bytes;
        self.apparent_file_bytes = self
            .apparent_file_bytes
            .checked_add(chunks.chunk_bytes)
            .and_then(|bytes| bytes.checked_add(chunks.manifest_bytes))
            .ok_or_else(|| io::Error::other("cache population counter overflow"))?;
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
        match open_regular_at(directory, name) {
            Ok(file) => match record_open_file(population, kind, file) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    population.disappeared_entries =
                        checked_add(population.disappeared_entries, 1)?;
                }
                Err(_) => record_entry_error(population, kind)?,
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                population.disappeared_entries = checked_add(population.disappeared_entries, 1)?;
            }
            Err(_) => record_entry_error(population, kind)?,
        }
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
    match kind {
        FileKind::NarInfo(_) => {
            return Err(io::Error::other(
                "narinfo entries require structural parsing",
            ));
        }
        FileKind::MalformedNarInfo => {
            population.malformed_narinfo_filenames =
                checked_add(population.malformed_narinfo_filenames, 1)?;
            population.narinfo_files = checked_add(population.narinfo_files, 1)?;
            population.narinfo_bytes = checked_add(population.narinfo_bytes, bytes)?;
        }
        FileKind::Raw => {
            population.raw_files = checked_add(population.raw_files, 1)?;
            population.raw_bytes = checked_add(population.raw_bytes, bytes)?;
        }
        FileKind::Xz => {
            population.xz_files = checked_add(population.xz_files, 1)?;
            population.xz_bytes = checked_add(population.xz_bytes, bytes)?;
        }
        FileKind::Zstd => {
            population.zstd_files = checked_add(population.zstd_files, 1)?;
            population.zstd_bytes = checked_add(population.zstd_bytes, bytes)?;
        }
        FileKind::MalformedNar => {
            population.malformed_nar_files = checked_add(population.malformed_nar_files, 1)?;
            population.malformed_nar_bytes = checked_add(population.malformed_nar_bytes, bytes)?;
        }
        FileKind::IngestionReceipt => {
            population.ingestion_receipt_files =
                checked_add(population.ingestion_receipt_files, 1)?;
            population.ingestion_receipt_bytes =
                checked_add(population.ingestion_receipt_bytes, bytes)?;
        }
        FileKind::EgressReceipt => {
            population.egress_receipt_files = checked_add(population.egress_receipt_files, 1)?;
            population.egress_receipt_bytes = checked_add(population.egress_receipt_bytes, bytes)?;
        }
        FileKind::Validation => {
            population.validation_files = checked_add(population.validation_files, 1)?;
            population.validation_bytes = checked_add(population.validation_bytes, bytes)?;
        }
        FileKind::Transaction => {
            population.transaction_files = checked_add(population.transaction_files, 1)?;
            population.transaction_bytes = checked_add(population.transaction_bytes, bytes)?;
        }
        FileKind::Temporary => {
            population.temporary_files = checked_add(population.temporary_files, 1)?;
            population.temporary_bytes = checked_add(population.temporary_bytes, bytes)?;
        }
    }
    Ok(())
}

fn record_entry_error(population: &mut PopulationCounts, kind: FileKind) -> io::Result<()> {
    population.errors = checked_add(population.errors, 1)?;
    match kind {
        FileKind::NarInfo(_) | FileKind::MalformedNarInfo => {
            population.narinfo_read_errors = checked_add(population.narinfo_read_errors, 1)?;
        }
        FileKind::Raw
        | FileKind::Xz
        | FileKind::Zstd
        | FileKind::MalformedNar
        | FileKind::IngestionReceipt
        | FileKind::EgressReceipt
        | FileKind::Validation
        | FileKind::Transaction
        | FileKind::Temporary => {}
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
