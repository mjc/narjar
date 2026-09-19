use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

use mincdc::{MinCdcHash4, SliceChunker};
use sha2::{Digest, Sha256};

use crate::object::{NarHash, NarIdentity};

use super::{
    CHUNK_DIRECTORY, MANIFEST_DIRECTORY,
    chunked::{
        ChunkHash, ChunkManifest, ChunkProfile, MANIFEST_CHECKSUM_BYTES, MANIFEST_HEADER_BYTES,
        MANIFEST_RECORD_BYTES, ManifestError, ManifestReader, write_manifest_header,
    },
    fs::{
        ensure_directory_at, files_equal_at, hard_link_at, open_at, open_directory_at,
        open_regular_at, read_dir_names, unlink_at,
    },
    publication::{StagingReservation, StorageError},
};

const CHUNK_TEMP_PREFIX: &str = "chunk";
const MANIFEST_TEMP_PREFIX: &str = "manifest";
const GC_MARK_DIRECTORY: &str = ".gc-marks";
const GC_MANIFEST_MARK_DIRECTORY: &str = "manifests";
pub(crate) const MAX_CHUNK_MANIFEST_BYTES: u64 = 128 * 1024 * 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct ChunkStore {
    chunks: File,
    manifests: File,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChunkSweepReport {
    pub(crate) deleted_manifests: usize,
    pub(crate) deleted_chunks: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChunkPhysicalBytes {
    pub(crate) chunks: u64,
    pub(crate) manifests: u64,
}

impl ChunkStore {
    pub(crate) fn initialize(root: &File) -> io::Result<Self> {
        let manifests = ensure_directory_at(
            root,
            OsStr::new(MANIFEST_DIRECTORY),
            "chunk manifest directory",
        )?;
        remove_abandoned_manifest_temps(&manifests)?;
        let chunks = ensure_directory_at(root, OsStr::new(CHUNK_DIRECTORY), "chunk directory")?;
        remove_abandoned_chunk_temps(&chunks)?;
        Ok(Self { chunks, manifests })
    }

    pub(crate) fn store_nar<R: Read>(
        &self,
        mut source: R,
        identity: NarIdentity,
        profile: ChunkProfile,
    ) -> Result<ChunkManifest, ChunkStoreError> {
        let mut writer = self.begin_ingest(profile)?;
        io::copy(&mut source, &mut writer)?;
        writer
            .finish(identity)
            .map(|completed| completed.manifest())
    }

    pub(crate) fn begin_ingest(
        &self,
        profile: ChunkProfile,
    ) -> Result<ChunkingWriter<'_>, ChunkStoreError> {
        self.begin_ingest_with_optional_reservation(profile, None, 0)
    }

    pub(crate) fn begin_ingest_with_reservation(
        &self,
        profile: ChunkProfile,
        reservation: StagingReservation,
        min_free_bytes: u64,
    ) -> Result<ChunkingWriter<'_>, ChunkStoreError> {
        self.begin_ingest_with_optional_reservation(profile, Some(reservation), min_free_bytes)
    }

    fn begin_ingest_with_optional_reservation(
        &self,
        profile: ChunkProfile,
        reservation: Option<StagingReservation>,
        min_free_bytes: u64,
    ) -> Result<ChunkingWriter<'_>, ChunkStoreError> {
        let record_name = temporary_name("manifest-records");
        let record_file = open_at(
            &self.manifests,
            &record_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        Ok(ChunkingWriter {
            store: self,
            profile,
            pending: Vec::new(),
            record_file,
            record_name,
            chunk_count: 0,
            previous_end: 0,
            previous_length: None,
            hasher: Sha256::new(),
            size: 0,
            reservation,
            min_free_bytes,
        })
    }

    pub(crate) fn open_chunk(&self, hash: ChunkHash) -> io::Result<Option<File>> {
        let shard = match self.open_shard(hash) {
            Ok(shard) => shard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        match open_regular_at(&shard, &chunk_name(hash)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_manifest(&self, hash: NarHash) -> io::Result<Option<File>> {
        match open_regular_at(&self.manifests, &manifest_name(hash)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn manifest_identity(
        &self,
        hash: NarHash,
    ) -> Result<Option<super::chunked::ChunkManifest>, ChunkStoreError> {
        let Some(file) = self.open_manifest(hash)? else {
            return Ok(None);
        };
        Ok(Some(
            ManifestReader::new(file, MAX_CHUNK_MANIFEST_BYTES)?.manifest(),
        ))
    }

    pub(crate) fn validate_manifest(
        &self,
        hash: NarHash,
    ) -> Result<Option<super::chunked::ChunkManifest>, ChunkStoreError> {
        let Some(file) = self.open_manifest(hash)? else {
            return Ok(None);
        };
        let reader = ManifestReader::new(file, MAX_CHUNK_MANIFEST_BYTES)?;
        let manifest = reader.manifest();
        reader.finish_remaining()?;
        Ok(Some(manifest))
    }

    pub(crate) fn open_reader(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
    ) -> Result<ChunkedNarReader<'_>, ChunkStoreError> {
        let manifest_file = self
            .open_manifest(hash)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let manifest = ManifestReader::new(manifest_file, max_manifest_bytes)?;
        let identity = manifest.manifest().identity();
        if identity.hash() != hash {
            return Err(ChunkStoreError::Manifest(ManifestError::InvalidHeader));
        }
        validate_range(&manifest.manifest(), &range)?;
        Ok(ChunkedNarReader {
            store: self,
            manifest: Some(manifest),
            range_cursor: range.start,
            range_end: range.end,
            next_chunk_start: 0,
            current_chunk: None,
        })
    }

    pub(crate) fn read_range<W: Write>(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
        destination: &mut W,
    ) -> Result<(), ChunkStoreError> {
        let mut reader = self.open_reader(hash, range, max_manifest_bytes)?;
        io::copy(&mut reader, destination)?;
        Ok(())
    }

    pub(crate) fn sweep_unreachable<I>(
        &self,
        live_manifests: I,
    ) -> Result<ChunkSweepReport, ChunkStoreError>
    where
        I: IntoIterator<Item = NarHash>,
    {
        let marks = self.prepare_gc_marks()?;
        let result = (|| {
            live_manifests
                .into_iter()
                .try_for_each(|hash| self.mark_live_manifest(&marks, hash))?;
            let manifests = self.delete_unmarked_manifests(&marks)?;
            let chunks = self.delete_unmarked_chunks(&marks)?;
            Ok(ChunkSweepReport {
                deleted_manifests: manifests.deleted_manifests,
                deleted_chunks: chunks.deleted_chunks,
            })
        })();
        let cleanup = clear_gc_mark_files(&marks);
        match (result, cleanup) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    pub(crate) fn reachable_chunk_bytes<I>(&self, live_manifests: I) -> Result<u64, ChunkStoreError>
    where
        I: IntoIterator<Item = NarHash>,
    {
        let marks = self.prepare_gc_marks()?;
        let result = (|| {
            live_manifests
                .into_iter()
                .try_for_each(|hash| self.mark_live_manifest(&marks, hash))?;
            self.marked_chunk_bytes(&marks)
        })();
        let cleanup = clear_gc_mark_files(&marks);
        match (result, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    pub(crate) fn physical_bytes(&self) -> Result<ChunkPhysicalBytes, ChunkStoreError> {
        let manifests = sum_regular_file_bytes(&self.manifests)?;
        let chunks =
            read_dir_names(&self.chunks)?
                .into_iter()
                .try_fold(0_u64, |total, shard_name| {
                    if !is_chunk_shard_name(&shard_name) {
                        return Ok(total);
                    }
                    let shard = open_directory_at(&self.chunks, &shard_name)?;
                    total
                        .checked_add(sum_regular_file_bytes(&shard)?)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk byte count overflow")
                        })
                })?;
        Ok(ChunkPhysicalBytes { chunks, manifests })
    }

    fn prepare_gc_marks(&self) -> Result<File, ChunkStoreError> {
        let marks = ensure_directory_at(
            &self.chunks,
            OsStr::new(GC_MARK_DIRECTORY),
            "chunk GC mark directory",
        )?;
        clear_gc_mark_files(&marks)?;
        ensure_directory_at(
            &marks,
            OsStr::new(GC_MANIFEST_MARK_DIRECTORY),
            "manifest GC mark directory",
        )?;
        Ok(marks)
    }

    fn mark_live_manifest(&self, marks: &File, hash: NarHash) -> Result<(), ChunkStoreError> {
        let manifest_marks = open_directory_at(marks, OsStr::new(GC_MANIFEST_MARK_DIRECTORY))?;
        mark_gc_file(&manifest_marks, &manifest_name(hash))?;
        let manifest_file = self
            .open_manifest(hash)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let mut reader = ManifestReader::new(manifest_file, MAX_CHUNK_MANIFEST_BYTES)?;
        while let Some(record) = reader.next_record()? {
            self.mark_live_chunk(marks, record.hash())?;
        }
        reader.finish_remaining()?;
        Ok(())
    }

    fn mark_live_chunk(&self, marks: &File, hash: ChunkHash) -> io::Result<()> {
        let shard =
            ensure_directory_at(marks, OsStr::new(&shard_name(hash)), "chunk GC mark shard")?;
        mark_gc_file(&shard, &chunk_name(hash))
    }

    fn delete_unmarked_manifests(&self, marks: &File) -> Result<ChunkSweepReport, ChunkStoreError> {
        let manifest_marks = open_directory_at(marks, OsStr::new(GC_MANIFEST_MARK_DIRECTORY))?;
        let deleted_manifests =
            read_dir_names(&self.manifests)?
                .into_iter()
                .try_fold(0, |deleted, name| {
                    if !is_manifest_name(&name)
                        || !super::fs::entry_is_regular_at(&self.manifests, &name)?
                        || gc_marker_exists(&manifest_marks, &name)?
                    {
                        return Ok::<_, io::Error>(deleted);
                    }
                    unlink_at(&self.manifests, &name)?;
                    Ok(deleted + 1)
                })?;
        if deleted_manifests > 0 {
            self.manifests.sync_all()?;
        }
        Ok(ChunkSweepReport {
            deleted_manifests,
            deleted_chunks: 0,
        })
    }

    fn delete_unmarked_chunks(&self, marks: &File) -> Result<ChunkSweepReport, ChunkStoreError> {
        let deleted_chunks = read_dir_names(&self.chunks)?
            .into_iter()
            .filter(|name| is_chunk_shard_name(name))
            .try_fold(0, |deleted, shard_name| {
                let shard = open_directory_at(&self.chunks, &shard_name)?;
                let marked_shard = match open_directory_at(marks, &shard_name) {
                    Ok(directory) => Some(directory),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                };
                let deleted_from_shard = read_dir_names(&shard)?.into_iter().try_fold(
                    0,
                    |deleted_from_shard, name| {
                        if !is_chunk_name(&name) || !super::fs::entry_is_regular_at(&shard, &name)?
                        {
                            return Ok::<_, io::Error>(deleted_from_shard);
                        }
                        let marked = marked_shard
                            .as_ref()
                            .map_or(Ok(false), |directory| gc_marker_exists(directory, &name))?;
                        if marked {
                            return Ok(deleted_from_shard);
                        }
                        unlink_at(&shard, &name)?;
                        Ok(deleted_from_shard + 1)
                    },
                )?;
                if deleted_from_shard > 0 {
                    shard.sync_all()?;
                }
                Ok(deleted + deleted_from_shard)
            })?;
        Ok(ChunkSweepReport {
            deleted_manifests: 0,
            deleted_chunks,
        })
    }

    fn marked_chunk_bytes(&self, marks: &File) -> Result<u64, ChunkStoreError> {
        Ok(read_dir_names(marks)?
            .into_iter()
            .try_fold(0_u64, |total, shard_name| {
                if !is_chunk_shard_name(&shard_name) {
                    return Ok(total);
                }
                let marked_shard = open_directory_at(marks, &shard_name)?;
                read_dir_names(&marked_shard)?
                    .into_iter()
                    .try_fold(total, |total, name| {
                        if !is_chunk_name(&name) {
                            return Ok(total);
                        }
                        let chunk_shard = open_directory_at(&self.chunks, &shard_name)?;
                        let chunk = open_regular_at(&chunk_shard, &name)?;
                        total.checked_add(chunk.metadata()?.len()).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk byte count overflow")
                        })
                    })
            })?)
    }

    fn store_chunk(&self, hash: ChunkHash, bytes: &[u8]) -> io::Result<()> {
        let shard = self.open_or_create_shard(hash)?;
        publish_immutable_bytes(&shard, &chunk_name(hash), CHUNK_TEMP_PREFIX, bytes)
    }

    fn open_or_create_shard(&self, hash: ChunkHash) -> io::Result<File> {
        ensure_directory_at(&self.chunks, OsStr::new(&shard_name(hash)), "chunk shard")
    }

    fn open_shard(&self, hash: ChunkHash) -> io::Result<File> {
        super::fs::open_directory_at(&self.chunks, OsStr::new(&shard_name(hash)))
    }
}

pub(crate) struct ChunkedNarReader<'store> {
    store: &'store ChunkStore,
    manifest: Option<ManifestReader<File>>,
    range_cursor: u64,
    range_end: u64,
    next_chunk_start: u64,
    current_chunk: Option<LoadedChunk>,
}

struct LoadedChunk {
    bytes: Vec<u8>,
    position: usize,
    end: u64,
}

impl ChunkedNarReader<'_> {
    fn load_next_overlapping_chunk(&mut self) -> io::Result<bool> {
        loop {
            let Some(manifest) = self.manifest.as_mut() else {
                return Ok(false);
            };
            let Some(descriptor) = manifest.next_record().map_err(io_for_manifest_error)? else {
                let manifest = self.manifest.take().expect("manifest reader is present");
                manifest.finish_remaining().map_err(io_for_manifest_error)?;
                return Ok(false);
            };
            let chunk_start = self.next_chunk_start;
            self.next_chunk_start = descriptor.end();
            if self.range_cursor >= descriptor.end() || self.range_end <= chunk_start {
                continue;
            }
            let bytes = read_verified_chunk(
                self.store,
                descriptor,
                chunk_start,
                self.range_cursor,
                self.range_end,
            )?;
            self.current_chunk = Some(LoadedChunk {
                bytes,
                position: 0,
                end: self.range_end.min(descriptor.end()),
            });
            return Ok(true);
        }
    }

    fn finish_manifest(&mut self) -> io::Result<()> {
        let Some(manifest) = self.manifest.take() else {
            return Ok(());
        };
        manifest.finish_remaining().map_err(io_for_manifest_error)
    }
}

impl Read for ChunkedNarReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(chunk) = self.current_chunk.as_mut() {
                let remaining = &chunk.bytes[chunk.position..];
                let copied = remaining.len().min(output.len());
                output[..copied].copy_from_slice(&remaining[..copied]);
                chunk.position += copied;
                if chunk.position == chunk.bytes.len() {
                    self.range_cursor = chunk.end;
                    self.current_chunk = None;
                }
                return Ok(copied);
            }
            if self.range_cursor == self.range_end {
                self.finish_manifest()?;
                return Ok(0);
            }
            if !self.load_next_overlapping_chunk()? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "chunk manifest ended before the requested range",
                ));
            }
        }
    }
}

fn read_verified_chunk(
    store: &ChunkStore,
    descriptor: super::chunked::ChunkDescriptor,
    chunk_start: u64,
    range_start: u64,
    range_end: u64,
) -> io::Result<Vec<u8>> {
    let chunk_length = descriptor
        .end()
        .checked_sub(chunk_start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end moved backwards"))?;
    let mut file = store
        .open_chunk(descriptor.hash())?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let mut chunk = Vec::new();
    (&mut file).take(chunk_length).read_to_end(&mut chunk)?;
    if chunk.len() as u64 != chunk_length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "chunk ended before its manifest length",
        ));
    }
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk contains bytes beyond its manifest length",
        ));
    }
    let actual_hash = ChunkHash::from_digest(Sha256::digest(&chunk).into());
    if actual_hash != descriptor.hash() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk hash does not match its manifest record",
        ));
    }
    let start = usize::try_from(range_start.max(chunk_start) - chunk_start)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "chunk offset is too large"))?;
    let end = usize::try_from(range_end.min(descriptor.end()) - chunk_start)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "chunk offset is too large"))?;
    Ok(chunk[start..end].to_vec())
}

fn io_for_manifest_error(error: ManifestError) -> io::Error {
    match error {
        ManifestError::Io(error) => error,
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn validate_range(manifest: &ChunkManifest, range: &Range<u64>) -> Result<(), ChunkStoreError> {
    if range.start > range.end || range.end > manifest.identity().size().get() {
        return Err(ChunkStoreError::InvalidRange {
            start: range.start,
            end: range.end,
            size: manifest.identity().size().get(),
        });
    }
    Ok(())
}

pub(crate) struct ChunkingWriter<'store> {
    store: &'store ChunkStore,
    profile: ChunkProfile,
    pending: Vec<u8>,
    record_file: File,
    record_name: OsString,
    chunk_count: u64,
    previous_end: u64,
    previous_length: Option<u64>,
    hasher: Sha256,
    size: u64,
    reservation: Option<StagingReservation>,
    min_free_bytes: u64,
}

pub(crate) struct CompletedChunkedIngest {
    manifest: ChunkManifest,
    outcome: super::publication::PublishOutcome,
    reservation: Option<StagingReservation>,
}

impl CompletedChunkedIngest {
    pub(crate) const fn manifest(&self) -> ChunkManifest {
        self.manifest
    }

    pub(crate) const fn outcome(&self) -> super::publication::PublishOutcome {
        self.outcome
    }

    pub(crate) fn release_reservation(self) {
        drop(self.reservation);
    }
}

impl ChunkingWriter<'_> {
    pub(crate) fn finish(
        mut self,
        expected: NarIdentity,
    ) -> Result<CompletedChunkedIngest, ChunkStoreError> {
        self.publish_pending_chunk()?;
        let actual = NarIdentity::new(
            NarHash::from_digest(self.hasher.clone().finalize().into()),
            self.size.into(),
        );
        if actual != expected {
            return Err(if actual.hash() != expected.hash() {
                ChunkStoreError::NarHashMismatch {
                    expected: expected.hash(),
                    actual: actual.hash(),
                }
            } else {
                ChunkStoreError::NarSizeMismatch {
                    expected: expected.size().get(),
                    actual: actual.size().get(),
                }
            });
        }
        if self.previous_end != actual.size().get() {
            return Err(ChunkStoreError::NarSizeMismatch {
                expected: actual.size().get(),
                actual: self.previous_end,
            });
        }
        let manifest = ChunkManifest::new(actual, self.profile, self.chunk_count);
        let manifest_bytes = MANIFEST_HEADER_BYTES
            .checked_add(
                usize::try_from(self.chunk_count)
                    .map_err(|_| ChunkStoreError::Manifest(ManifestError::LengthOverflow))?
                    .checked_mul(MANIFEST_RECORD_BYTES)
                    .ok_or(ChunkStoreError::Manifest(ManifestError::LengthOverflow))?,
            )
            .and_then(|bytes| bytes.checked_add(MANIFEST_CHECKSUM_BYTES))
            .ok_or(ChunkStoreError::Manifest(ManifestError::LengthOverflow))?;
        self.reserve_before_materialization(&self.store.manifests, manifest_bytes as u64)?;
        let outcome = self.publish_manifest_from_records(&manifest)?;
        self.release_materialized_bytes(manifest_bytes as u64);
        Ok(CompletedChunkedIngest {
            manifest,
            outcome,
            reservation: self.reservation.take(),
        })
    }

    fn publish_manifest_from_records(
        &mut self,
        manifest: &ChunkManifest,
    ) -> Result<super::publication::PublishOutcome, ChunkStoreError> {
        self.record_file.sync_all()?;
        self.record_file.seek(SeekFrom::Start(0))?;
        let temporary_name = temporary_name(MANIFEST_TEMP_PREFIX);
        let result = (|| -> Result<_, ChunkStoreError> {
            let mut temporary = open_at(
                &self.store.manifests,
                &temporary_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            let checksum = {
                let mut digesting = DigestingWriter::new(&mut temporary);
                write_manifest_header(&mut digesting, *manifest)?;
                io::copy(&mut self.record_file, &mut digesting)?;
                digesting.finish()
            };
            temporary.write_all(&checksum)?;
            temporary.sync_all()?;
            Ok(publish_temporary_file(
                &self.store.manifests,
                &temporary_name,
                &manifest_name(manifest.identity().hash()),
            )?)
        })();
        let cleanup = remove_temporary_file(&self.store.manifests, &temporary_name);
        match (result, cleanup) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn publish_complete_chunks(&mut self) -> io::Result<()> {
        while self.pending.len() >= self.profile.max_size() as usize {
            self.publish_next_chunk()?;
        }
        Ok(())
    }

    fn publish_pending_chunk(&mut self) -> Result<(), ChunkStoreError> {
        while !self.pending.is_empty() {
            self.publish_next_chunk().map_err(ChunkStoreError::from)?;
        }
        Ok(())
    }

    fn publish_next_chunk(&mut self) -> io::Result<()> {
        let chunk_length = SliceChunker::new(
            &self.pending,
            self.profile.min_size() as usize,
            self.profile.max_size() as usize,
            MinCdcHash4::new(),
        )
        .next()
        .expect("a non-empty pending buffer produces a chunk")
        .len();
        let hash = ChunkHash::from_digest(Sha256::digest(&self.pending[..chunk_length]).into());
        self.reserve_before_materialization(&self.store.chunks, chunk_length as u64)?;
        self.store
            .store_chunk(hash, &self.pending[..chunk_length])?;
        self.release_materialized_bytes(chunk_length as u64);
        let remaining = u64::try_from(self.pending.len() - chunk_length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk buffer is too large"))?;
        let end = self
            .size
            .checked_sub(remaining)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end underflow"))?;
        let length = end - self.previous_end;
        if self
            .previous_length
            .is_some_and(|previous| previous < self.profile.min_size())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-final chunk is too small",
            ));
        }
        self.record_file.write_all(&end.to_le_bytes())?;
        self.record_file.write_all(&hash.bytes())?;
        self.previous_end = end;
        self.previous_length = Some(length);
        self.chunk_count = self
            .chunk_count
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "too many chunks"))?;
        self.pending.drain(..chunk_length);
        Ok(())
    }

    fn reserve_before_materialization(&mut self, directory: &File, bytes: u64) -> io::Result<()> {
        let Some(reservation) = self.reservation.as_mut() else {
            return Ok(());
        };
        reservation
            .grow_to(
                directory,
                self.min_free_bytes,
                reservation.reserved_bytes().saturating_add(bytes),
            )
            .map_err(io_for_storage_error)
    }

    fn release_materialized_bytes(&mut self, bytes: u64) {
        if let Some(reservation) = self.reservation.as_mut() {
            reservation.record_materialized_bytes(bytes);
        }
    }
}

impl Write for ChunkingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hasher.update(bytes);
        self.size = self
            .size
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        self.pending.extend_from_slice(bytes);
        self.publish_complete_chunks()?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ChunkingWriter<'_> {
    fn drop(&mut self) {
        let _ = unlink_at(&self.store.manifests, &self.record_name);
    }
}

struct DigestingWriter<'a, W> {
    inner: &'a mut W,
    hasher: Sha256,
}

impl<'a, W: Write> DigestingWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<W: Write> Write for DigestingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write_all(bytes)?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn publish_immutable_bytes(
    directory: &File,
    name: &OsStr,
    temp_prefix: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let temporary_name = temporary_name(temp_prefix);
    let result = write_temporary_file(directory, &temporary_name, bytes).and_then(|()| {
        match hard_link_at(directory, &temporary_name, directory, name) {
            Ok(()) => directory.sync_all(),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if files_equal_at(directory, &temporary_name, directory, name)? {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "content-addressed storage collision",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    });
    let cleanup = unlink_at(directory, &temporary_name);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(_cleanup_error)) => Err(error),
    }
}

fn publish_temporary_file(
    directory: &File,
    temporary_name: &OsStr,
    name: &OsStr,
) -> io::Result<super::publication::PublishOutcome> {
    let result = match hard_link_at(directory, temporary_name, directory, name) {
        Ok(()) => directory
            .sync_all()
            .map(|()| super::publication::PublishOutcome::Created),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if files_equal_at(directory, temporary_name, directory, name)? {
                Ok(super::publication::PublishOutcome::Identical)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "content-addressed storage collision",
                ))
            }
        }
        Err(error) => Err(error),
    };
    let cleanup = unlink_at(directory, temporary_name);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) | (Err(error), Err(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn write_temporary_file(directory: &File, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_at(
        directory,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn remove_temporary_file(directory: &File, name: &OsStr) -> io::Result<()> {
    match unlink_at(directory, name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn temporary_name(prefix: &str) -> OsString {
    format!(
        ".{prefix}-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
    .into()
}

fn mark_gc_file(directory: &File, name: &OsStr) -> io::Result<()> {
    match open_at(
        directory,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    ) {
        Ok(_file) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn gc_marker_exists(directory: &File, name: &OsStr) -> io::Result<bool> {
    match super::fs::entry_is_regular_at(directory, name) {
        Ok(exists) => Ok(exists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn sum_regular_file_bytes(directory: &File) -> io::Result<u64> {
    read_dir_names(directory)?
        .into_iter()
        .try_fold(0_u64, |total, name| {
            if !super::fs::entry_is_regular_at(directory, &name)? {
                return Ok(total);
            }
            let file = open_regular_at(directory, &name)?;
            total.checked_add(file.metadata()?.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "file byte count overflow")
            })
        })
}

fn clear_gc_mark_files(directory: &File) -> io::Result<()> {
    read_dir_names(directory)?.into_iter().try_for_each(|name| {
        match open_directory_at(directory, &name) {
            Ok(child) => clear_gc_mark_files(&child),
            Err(error)
                if error.kind() == io::ErrorKind::NotADirectory
                    || error.kind() == io::ErrorKind::InvalidData =>
            {
                unlink_at(directory, &name)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    })
}

fn is_manifest_name(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".manifest"))
        .is_some_and(|hash| NarHash::parse(hash).is_ok())
}

fn is_chunk_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn remove_abandoned_manifest_temps(directory: &File) -> io::Result<()> {
    let removed = read_dir_names(directory)?
        .into_iter()
        .try_fold(false, |removed, name| {
            let is_temporary = name
                .to_str()
                .is_some_and(|name| name.starts_with(".manifest-"));
            if is_temporary {
                unlink_at(directory, &name)?;
            }
            Ok::<_, io::Error>(removed || is_temporary)
        })?;
    if removed {
        directory.sync_all()?;
    }
    Ok(())
}

fn remove_abandoned_chunk_temps(directory: &File) -> io::Result<()> {
    let removed =
        read_dir_names(directory)?
            .into_iter()
            .try_fold(false, |removed, shard_name| {
                if !is_chunk_shard_name(&shard_name) {
                    return Ok::<_, io::Error>(removed);
                }
                let shard = super::fs::open_directory_at(directory, &shard_name)?;
                let removed_from_shard = remove_abandoned_temps(&shard, ".chunk-")?;
                Ok(removed || removed_from_shard)
            })?;
    if removed {
        directory.sync_all()?;
    }
    Ok(())
}

fn remove_abandoned_temps(directory: &File, prefix: &str) -> io::Result<bool> {
    let removed = read_dir_names(directory)?
        .into_iter()
        .try_fold(false, |removed, name| {
            let is_temporary = name.to_str().is_some_and(|name| name.starts_with(prefix));
            if is_temporary {
                unlink_at(directory, &name)?;
            }
            Ok::<_, io::Error>(removed || is_temporary)
        })?;
    if removed {
        directory.sync_all()?;
    }
    Ok(removed)
}

fn is_chunk_shard_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.len() == 2 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn io_for_storage_error(error: StorageError) -> io::Error {
    match error {
        StorageError::InsufficientSpace | StorageError::InsufficientInodes => {
            io::Error::from_raw_os_error(libc::ENOSPC)
        }
        StorageError::Io(error) => error,
        error => io::Error::other(error),
    }
}

fn shard_name(hash: ChunkHash) -> String {
    hex_name(hash.bytes())[..2].to_owned()
}

fn chunk_name(hash: ChunkHash) -> OsString {
    hex_name(hash.bytes()).into()
}

fn manifest_name(hash: NarHash) -> OsString {
    format!("{}.manifest", hash).into()
}

fn hex_name(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [0_u8; 64];
    bytes.iter().enumerate().for_each(|(index, byte)| {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    });
    String::from_utf8(output.to_vec()).expect("hexadecimal bytes are valid UTF-8")
}

#[derive(Debug)]
pub(crate) enum ChunkStoreError {
    InvalidRange { start: u64, end: u64, size: u64 },
    Io(io::Error),
    Manifest(ManifestError),
    NarHashMismatch { expected: NarHash, actual: NarHash },
    NarSizeMismatch { expected: u64, actual: u64 },
}

impl From<io::Error> for ChunkStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ManifestError> for ChunkStoreError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl std::fmt::Display for ChunkStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRange { start, end, size } => {
                write!(formatter, "range {start}..{end} is outside NAR size {size}")
            }
            Self::Io(error) => error.fmt(formatter),
            Self::Manifest(error) => error.fmt(formatter),
            Self::NarHashMismatch { .. } => formatter.write_str("chunked NAR hash mismatch"),
            Self::NarSizeMismatch { .. } => formatter.write_str("chunked NAR size mismatch"),
        }
    }
}

impl std::error::Error for ChunkStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::InvalidRange { .. }
            | Self::NarHashMismatch { .. }
            | Self::NarSizeMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Read, Write},
    };

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{ChunkStore, ChunkStoreError};
    use crate::{
        object::{NarHash, NarIdentity, NarSize},
        storage::{
            chunked::{ChunkHash, ChunkProfile},
            directory::Directory,
        },
    };

    #[test]
    fn stores_deduplicated_chunks_and_a_round_trippable_manifest() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));

        let manifest = store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V1)
            .unwrap();
        let manifest_file = store.open_manifest(hash).unwrap().unwrap();
        let bytes = super::super::fs::read_bounded_regular_file(
            &store.manifests,
            &super::manifest_name(hash),
            1_000_000,
        )
        .unwrap();
        let bytes = match bytes {
            super::super::fs::BoundedRegularFile::Valid(bytes) => bytes,
            _ => panic!("manifest should be readable"),
        };
        assert_eq!(
            super::super::chunked::ChunkManifest::decode(&bytes).unwrap(),
            manifest
        );
        assert_eq!(manifest_file.metadata().unwrap().len(), bytes.len() as u64);
        assert!(manifest.chunk_count() > 0);

        let mut reconstructed = Vec::new();
        store
            .read_range(hash, 0..input.len() as u64, 1_000_000, &mut reconstructed)
            .unwrap();
        assert_eq!(reconstructed, input);

        let mut range = Vec::new();
        store
            .read_range(hash, 12_345..54_321, 1_000_000, &mut range)
            .unwrap();
        assert_eq!(range, input[12_345..54_321]);

        let invalid_start = 54_321;
        let invalid_end = 12_345;
        assert!(matches!(
            store.read_range(hash, invalid_start..invalid_end, 1_000_000, &mut range),
            Err(ChunkStoreError::InvalidRange { .. })
        ));
    }

    #[test]
    fn rejects_a_nar_identity_that_does_not_match_the_stream() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = b"not the declared nar";
        let identity = NarIdentity::new(
            NarHash::from_digest([0; 32]),
            NarSize::new(input.len() as u64),
        );

        assert!(matches!(
            store.store_nar(Cursor::new(input), identity, ChunkProfile::MinCdcHash4V1),
            Err(ChunkStoreError::NarHashMismatch { .. })
        ));
    }

    #[test]
    fn chunk_reader_rejects_a_corrupt_chunk() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V1)
            .unwrap();

        let shard = fs::read_dir(directory.path().join(super::super::CHUNK_DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let chunk = fs::read_dir(shard).unwrap().next().unwrap().unwrap().path();
        let mut bytes = fs::read(&chunk).unwrap();
        bytes[0] ^= 1;
        fs::write(chunk, bytes).unwrap();

        let mut reader = store
            .open_reader(hash, 0..identity.size().get(), 1_000_000)
            .unwrap();
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
    }

    #[test]
    fn manifest_validation_rejects_a_corrupt_checksum() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V1)
            .unwrap();

        let manifest_path = directory
            .path()
            .join(super::super::MANIFEST_DIRECTORY)
            .join(format!("{hash}.manifest"));
        let mut bytes = fs::read(&manifest_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&manifest_path, bytes).unwrap();

        assert!(matches!(
            store.validate_manifest(hash),
            Err(ChunkStoreError::Manifest(
                super::super::chunked::ManifestError::ChecksumMismatch
            ))
        ));
    }

    #[test]
    fn sweep_keeps_live_manifest_chunks_and_removes_unreachable_objects() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let first = vec![b'a'; 100_000];
        let second = vec![b'b'; 100_000];
        let first_hash = NarHash::from_digest(Sha256::digest(&first).into());
        let second_hash = NarHash::from_digest(Sha256::digest(&second).into());

        store
            .store_nar(
                Cursor::new(&first),
                NarIdentity::new(first_hash, (first.len() as u64).into()),
                ChunkProfile::MinCdcHash4V1,
            )
            .unwrap();
        store
            .store_nar(
                Cursor::new(&second),
                NarIdentity::new(second_hash, (second.len() as u64).into()),
                ChunkProfile::MinCdcHash4V1,
            )
            .unwrap();

        assert!(
            store
                .reachable_chunk_bytes([first_hash, second_hash])
                .unwrap()
                > 0
        );
        let report = store.sweep_unreachable([first_hash]).unwrap();
        assert_eq!(report.deleted_manifests, 1);
        assert!(report.deleted_chunks > 0);
        assert!(store.open_manifest(first_hash).unwrap().is_some());
        assert!(store.open_manifest(second_hash).unwrap().is_none());
    }

    #[test]
    fn restart_removes_abandoned_chunk_and_manifest_temps() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let shard = store
            .open_or_create_shard(ChunkHash::from_digest([0; 32]))
            .unwrap();
        let chunk_temp = std::ffi::OsStr::new(".chunk-crashed");
        let manifest_temp = std::ffi::OsStr::new(".manifest-crashed");
        let mut chunk = super::super::fs::open_at(
            &shard,
            chunk_temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        chunk.write_all(b"abandoned").unwrap();
        let mut manifest = super::super::fs::open_at(
            &store.manifests,
            manifest_temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        manifest.write_all(b"abandoned").unwrap();
        drop(store);

        let restarted = ChunkStore::initialize(root.file()).unwrap();
        let shard = restarted
            .open_shard(ChunkHash::from_digest([0; 32]))
            .unwrap();
        assert!(super::super::fs::open_regular_at(&shard, chunk_temp).is_err());
        assert!(super::super::fs::open_regular_at(&restarted.manifests, manifest_temp).is_err());
    }
}
