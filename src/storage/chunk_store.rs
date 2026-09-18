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
    fs::{ensure_directory_at, files_equal_at, hard_link_at, open_at, open_regular_at, unlink_at},
    publication::{StagingReservation, StorageError},
};

const CHUNK_TEMP_PREFIX: &str = "chunk";
const MANIFEST_TEMP_PREFIX: &str = "manifest";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct ChunkStore {
    chunks: File,
    manifests: File,
}

impl ChunkStore {
    pub(crate) fn initialize(root: &File) -> io::Result<Self> {
        Ok(Self {
            chunks: ensure_directory_at(root, OsStr::new(CHUNK_DIRECTORY), "chunk directory")?,
            manifests: ensure_directory_at(
                root,
                OsStr::new(MANIFEST_DIRECTORY),
                "chunk manifest directory",
            )?,
        })
    }

    pub(crate) fn store_nar<R: Read>(
        &self,
        mut source: R,
        identity: NarIdentity,
        profile: ChunkProfile,
    ) -> Result<ChunkManifest, ChunkStoreError> {
        let mut writer = self.begin_ingest(profile)?;
        io::copy(&mut source, &mut writer)?;
        writer.finish(identity)
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

    pub(crate) fn read_range<W: Write>(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
        destination: &mut W,
    ) -> Result<(), ChunkStoreError> {
        let manifest_file = self
            .open_manifest(hash)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let reader = ManifestReader::new(manifest_file, max_manifest_bytes)?;
        let manifest = reader.manifest();
        if manifest.identity().hash() != hash {
            return Err(ChunkStoreError::Manifest(ManifestError::InvalidHeader));
        }
        write_manifest_range(self, reader, range, destination)
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

fn write_manifest_range<W: Write>(
    store: &ChunkStore,
    reader: ManifestReader<File>,
    range: Range<u64>,
    destination: &mut W,
) -> Result<(), ChunkStoreError> {
    validate_range(&reader.manifest(), &range)?;
    let mut chunk_start = 0_u64;
    reader.read_records(|chunk| {
        let current_start = chunk_start;
        chunk_start = chunk.end();
        if !(range.start < chunk.end() && range.end > current_start) {
            return Ok(());
        }
        let chunk_start = current_start;
        let chunk_end = chunk.end();
        let read_start = range.start.max(chunk_start);
        let read_end = range.end.min(chunk_end);
        let mut file = store
            .open_chunk(chunk.hash())?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        file.seek(SeekFrom::Start(read_start - chunk_start))?;
        io::copy(&mut file.take(read_end - read_start), destination)?;
        Ok(())
    })?;
    Ok(())
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

impl ChunkingWriter<'_> {
    pub(crate) fn finish(
        mut self,
        expected: NarIdentity,
    ) -> Result<ChunkManifest, ChunkStoreError> {
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
        self.publish_manifest_from_records(&manifest)?;
        self.release_materialized_bytes(manifest_bytes as u64);
        Ok(manifest)
    }

    fn publish_manifest_from_records(
        &mut self,
        manifest: &ChunkManifest,
    ) -> Result<(), ChunkStoreError> {
        self.record_file.sync_all()?;
        self.record_file.seek(SeekFrom::Start(0))?;
        let temporary_name = temporary_name(MANIFEST_TEMP_PREFIX);
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
        publish_temporary_file(
            &self.store.manifests,
            &temporary_name,
            &manifest_name(manifest.identity().hash()),
        )?;
        Ok(())
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
) -> io::Result<()> {
    let result = match hard_link_at(directory, temporary_name, directory, name) {
        Ok(()) => directory.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if files_equal_at(directory, temporary_name, directory, name)? {
                Ok(())
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
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Err(error), Err(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error),
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

fn temporary_name(prefix: &str) -> OsString {
    format!(
        ".{prefix}-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
    .into()
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{ChunkStore, ChunkStoreError};
    use crate::{
        object::{NarHash, NarIdentity, NarSize},
        storage::{chunked::ChunkProfile, directory::Directory},
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
}
