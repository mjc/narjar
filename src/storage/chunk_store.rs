use std::{
    collections::{HashMap, VecDeque},
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::SystemTime,
};

use crate::cache::filesystem::FileStamp;

use crate::cache::filesystem::{FileAccess, FileCreation, FilePrivacy};

use mincdc::{MinCdcHash4, SliceChunker};
use sha2::{Digest, Sha256};

use crate::cache::object::{NarHash, NarIdentity};

use super::{
    CHUNK_DIRECTORY, MANIFEST_DIRECTORY,
    backend::ChunkDurability,
    chunked::{
        ChunkHash, ChunkManifest, ChunkProfile, MANIFEST_CHECKSUM_BYTES, MANIFEST_HEADER_BYTES,
        MANIFEST_RECORD_BYTES, ManifestError, ManifestReader, write_manifest_header,
    },
    fs::{
        DirectoryEntryAction, DirectoryScanOutcome, ImmutableLinkOutcome, ensure_directory_at,
        for_each_dir_name, link_or_compare_immutable, open_at, open_directory_at, open_regular_at,
        read_dir_names, rename_at, require_directory_at, unlink_at,
    },
    publication::StagingReservation,
    state::StorageActivity,
};

const CHUNK_TEMP_PREFIX: &str = "chunk";
const MANIFEST_TEMP_PREFIX: &str = "manifest";
const GC_MARK_DIRECTORY: &str = ".gc-marks";
const GC_MANIFEST_MARK_DIRECTORY: &str = "manifests";
// 16 * 1 MiB bounds the pending raw tail below 16 MiB while keeping chunk
// publication work bounded for the active content-defined profile.
const CHUNK_PUBLICATION_BATCH_SIZE: usize = 16;
const CHUNK_PUBLICATION_WORKER_BATCH_SIZE: usize = 16;
pub(crate) const MAX_CHUNK_MANIFEST_BYTES: u64 = 128 * 1024 * 1024;
const VERIFIED_CHUNK_CACHE_CAPACITY: usize = 4096;
const VERIFIED_NAR_CACHE_CAPACITY: usize = 256;
const CHUNK_REPAIR_LOCK_COUNT: usize = 64;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct ChunkStore {
    chunks: File,
    manifests: File,
    activity: Arc<StorageActivity>,
    durability: ChunkDurability,
    gc_marks: Mutex<()>,
    chunk_repair_locks: [Mutex<()>; CHUNK_REPAIR_LOCK_COUNT],
    chunk_repair_activity: [ChunkRepairActivity; CHUNK_REPAIR_LOCK_COUNT],
    verified_chunks: Mutex<VerifiedChunkProofs>,
    verified_nars: Mutex<VerifiedNarProofs>,
    #[cfg(test)]
    nar_content_hashes: AtomicU64,
}

#[derive(Debug, Default)]
struct ChunkRepairActivity {
    generation: AtomicU64,
    active_operations: AtomicUsize,
    pending_markers: AtomicUsize,
}

struct ChunkRepairOperation<'store>(&'store ChunkRepairActivity);

impl ChunkRepairActivity {
    fn begin_operation(&self) -> ChunkRepairOperation<'_> {
        self.active_operations.fetch_add(1, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        ChunkRepairOperation(self)
    }

    fn can_open_without_repair_lock(&self) -> Option<u64> {
        let generation = self.generation.load(Ordering::SeqCst);
        (self.active_operations.load(Ordering::SeqCst) == 0
            && self.pending_markers.load(Ordering::SeqCst) == 0)
            .then_some(generation)
    }

    fn remained_quiescent(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == generation
            && self.active_operations.load(Ordering::SeqCst) == 0
            && self.pending_markers.load(Ordering::SeqCst) == 0
    }
}

impl Drop for ChunkRepairOperation<'_> {
    fn drop(&mut self) {
        self.0.active_operations.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
struct VerifiedChunkProofs {
    by_hash: HashMap<ChunkHash, FileStamp>,
    insertion_order: VecDeque<ChunkHash>,
}

#[derive(Debug, Default)]
struct VerifiedNarProofs {
    by_hash: HashMap<NarHash, VerifiedNarProof>,
    insertion_order: VecDeque<NarHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedNarProof {
    identity: NarIdentity,
    manifest_stamp: FileStamp,
    chunk_stamps: [u8; 32],
}

struct GcMarks<'store> {
    directory: Option<File>,
    _exclusive: MutexGuard<'store, ()>,
}

impl GcMarks<'_> {
    fn file(&self) -> &File {
        self.directory.as_ref().expect("unfinished mark directory")
    }

    fn finish(mut self) -> io::Result<()> {
        clear_gc_mark_files(&self.directory.take().expect("unfinished mark directory"))
    }
}

impl Drop for GcMarks<'_> {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            let _ = clear_gc_mark_files(directory);
        }
    }
}

/// All retained manifests are marked before retirement starts.
pub(super) struct MarkedChunkSweep<'store> {
    store: &'store ChunkStore,
    marks: GcMarks<'store>,
}

impl MarkedChunkSweep<'_> {
    pub(super) fn sweep(self) -> Result<ChunkSweepReport, ChunkStoreError> {
        let result = (|| {
            let manifests = self.store.delete_unmarked_manifests(self.marks.file())?;
            let chunks = self.store.delete_unmarked_chunks(self.marks.file())?;
            Ok(ChunkSweepReport {
                deleted_manifests: manifests.deleted_manifests,
                deleted_chunks: chunks.deleted_chunks,
            })
        })();
        match (result, self.marks.finish()) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkManifestFile {
    pub(crate) name: OsString,
    pub(crate) hash: NarHash,
    pub(crate) bytes: u64,
    pub(crate) modified: SystemTime,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChunkPopulationCounts {
    pub(crate) scanned_entries: u64,
    pub(crate) ignored_entries: u64,
    pub(crate) disappeared_entries: u64,
    pub(crate) errors: u64,
    pub(crate) chunk_files: u64,
    pub(crate) chunk_bytes: u64,
    pub(crate) manifest_files: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) chunked_nars: u64,
    pub(crate) chunked_nar_bytes: u64,
}

impl ChunkStore {
    #[cfg(all(test, target_os = "linux"))]
    fn initialize(root: &File) -> io::Result<Self> {
        Self::initialize_with_activity(root, Arc::new(StorageActivity::default()))
    }

    #[cfg(all(test, target_os = "linux"))]
    fn initialize_with_activity(root: &File, activity: Arc<StorageActivity>) -> io::Result<Self> {
        let manifests = ensure_directory_at(
            root,
            OsStr::new(MANIFEST_DIRECTORY),
            "chunk manifest directory",
        )?;
        let chunks = ensure_directory_at(root, OsStr::new(CHUNK_DIRECTORY), "chunk directory")?;
        let super::backend::BackendSupport::Chunked(durability) =
            super::SupportedStorageBackend::try_from(super::StorageBackend::Chunked)
                .expect("Linux supports chunk publication")
                .0
        else {
            unreachable!("chunked selection must contain a chunk capability")
        };
        let pending_repairs = pending_chunk_repair_counts(&chunks)?;
        Ok(Self {
            chunks,
            manifests,
            activity,
            durability,
            gc_marks: Mutex::new(()),
            chunk_repair_locks: std::array::from_fn(|_| Mutex::new(())),
            chunk_repair_activity: repair_activity_by_stripe(pending_repairs),
            verified_chunks: Mutex::new(VerifiedChunkProofs::default()),
            verified_nars: Mutex::new(VerifiedNarProofs::default()),
            #[cfg(test)]
            nar_content_hashes: AtomicU64::new(0),
        })
    }

    pub(super) fn open(
        root: &File,
        durability: ChunkDurability,
        activity: Arc<StorageActivity>,
    ) -> io::Result<Self> {
        let chunks = require_directory_at(root, CHUNK_DIRECTORY)?;
        let pending_repairs = pending_chunk_repair_counts(&chunks)?;
        Ok(Self {
            chunks,
            manifests: require_directory_at(root, MANIFEST_DIRECTORY)?,
            activity,
            durability,
            gc_marks: Mutex::new(()),
            chunk_repair_locks: std::array::from_fn(|_| Mutex::new(())),
            chunk_repair_activity: repair_activity_by_stripe(pending_repairs),
            verified_chunks: Mutex::new(VerifiedChunkProofs::default()),
            verified_nars: Mutex::new(VerifiedNarProofs::default()),
            #[cfg(test)]
            nar_content_hashes: AtomicU64::new(0),
        })
    }

    pub(crate) fn remove_abandoned_temporary_files(&self) -> io::Result<()> {
        remove_abandoned_temps(&self.manifests, ".manifest-")?;
        remove_abandoned_chunk_temps(&self.chunks)
    }

    pub(crate) fn population_counts(
        &self,
        stopping: &AtomicBool,
    ) -> io::Result<ChunkPopulationCounts> {
        let mut counts = ChunkPopulationCounts::default();
        scan_chunk_shards(&self.chunks, stopping, &mut counts)?;
        scan_manifests(&self.manifests, stopping, &mut counts)?;
        Ok(counts)
    }

    #[cfg(test)]
    pub(crate) fn store_nar<R: Read>(
        &self,
        mut source: R,
        identity: NarIdentity,
        profile: ChunkProfile,
    ) -> Result<ChunkManifest, ChunkStoreError> {
        let mut writer = self.begin_ingest_with_optional_reservation(profile, None, 0)?;
        io::copy(&mut source, &mut writer)?;
        writer
            .finish(identity)
            .map(|completed| completed.manifest())
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
            FileAccess::ReadWrite,
            FileCreation::CreateNew,
            FilePrivacy::Private,
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
            durability: ChunkDurabilityObligation::Empty,
        })
    }

    pub(crate) fn open_chunk(&self, hash: ChunkHash) -> io::Result<Option<File>> {
        let _repair_lock = self.chunk_repair_lock(hash);
        self.open_chunk_while_repair_locked(hash)
    }

    fn open_serving_chunk(&self, hash: ChunkHash) -> io::Result<Option<File>> {
        let activity = self.chunk_repair_activity(hash);
        if let Some(generation) = activity.can_open_without_repair_lock() {
            let opened = self.open_chunk_without_repair_lock(hash);
            if activity.remained_quiescent(generation) {
                return opened;
            }
        }
        self.open_chunk(hash)
    }

    fn open_chunk_without_repair_lock(&self, hash: ChunkHash) -> io::Result<Option<File>> {
        let shard = match self.open_shard(hash) {
            Ok(shard) => shard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        match open_regular_at(&shard, chunk_name(hash)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open_chunk_while_repair_locked(&self, hash: ChunkHash) -> io::Result<Option<File>> {
        let shard = match self.open_shard(hash) {
            Ok(shard) => shard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        self.finish_pending_chunk_repair(&shard, hash, &mut |directory| directory.sync_all())?;
        match open_regular_at(&shard, chunk_name(hash)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_manifest(&self, hash: NarHash) -> io::Result<Option<File>> {
        match open_regular_at(&self.manifests, manifest_name(hash)) {
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

    pub(crate) fn acquire_durable_manifest(
        &self,
        hash: NarHash,
    ) -> Result<Option<super::chunked::ChunkManifest>, ChunkStoreError> {
        self.acquire_manifest_with_directory_sync(hash, || self.manifests.sync_all())
    }

    fn acquire_manifest_with_directory_sync(
        &self,
        hash: NarHash,
        sync_directory: impl FnOnce() -> io::Result<()>,
    ) -> Result<Option<super::chunked::ChunkManifest>, ChunkStoreError> {
        self.validate_manifest(hash)?
            .map(|manifest| {
                // Chunks are durable before a manifest can become visible.
                // Complete a failed publisher's manifest-directory barrier.
                sync_directory()?;
                Ok(manifest)
            })
            .transpose()
    }

    pub(crate) fn check_nar_availability(
        &self,
        identity: NarIdentity,
    ) -> Result<(), ChunkStoreError> {
        let mut reader = self.open_manifest_reader(identity)?;
        let manifest = reader.manifest();
        validate_manifest_identity(manifest.identity(), identity)?;
        self.check_manifest_chunk_sizes(&mut reader, manifest.chunk_count())?;
        reader.finish_remaining()?;
        Ok(())
    }

    pub(crate) fn verify_nar_content(&self, identity: NarIdentity) -> Result<(), ChunkStoreError> {
        let manifest_file = self
            .open_manifest(identity.hash())?
            .ok_or(ChunkStoreError::MissingNar)?;
        let manifest_stamp = FileStamp::from_file(&manifest_file)?;
        let manifest_for_stamp = manifest_file.try_clone()?;
        let mut reader = ManifestReader::new(manifest_file, MAX_CHUNK_MANIFEST_BYTES)?;
        let manifest = reader.manifest();
        validate_manifest_identity(manifest.identity(), identity)?;
        let mut chunk_stamps = Sha256::new();
        chunk_stamps.update(identity.hash().as_bytes());
        chunk_stamps.update(identity.size().get().to_le_bytes());
        manifest_stamp.update_identity_digest(&mut chunk_stamps);
        (0..manifest.chunk_count()).try_fold(0_u64, |start, _| {
            let descriptor = reader.next_record()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest ended before its chunk count",
                )
            })?;
            let file = self
                .open_chunk(descriptor.hash())?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let expected = descriptor.end() - start;
            let actual = file.metadata()?.len();
            if actual != expected {
                return Err(ChunkStoreError::NarSizeMismatch { expected, actual });
            }
            FileStamp::from_file(&file)?.update_identity_digest(&mut chunk_stamps);
            Ok(descriptor.end())
        })?;
        reader.finish_remaining()?;
        if FileStamp::from_file(&manifest_for_stamp)? != manifest_stamp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk manifest changed during validation",
            )
            .into());
        }
        let proof = VerifiedNarProof {
            identity,
            manifest_stamp,
            chunk_stamps: chunk_stamps.finalize().into(),
        };
        if self.nar_content_is_verified(proof) {
            return Ok(());
        }

        #[cfg(test)]
        self.nar_content_hashes.fetch_add(1, Ordering::Relaxed);
        let mut reader = self.open_verified_reader(
            identity.hash(),
            0..identity.size().get(),
            MAX_CHUNK_MANIFEST_BYTES,
        )?;
        let mut actual = NarIdentityHasher::default();
        io::copy(&mut reader, &mut actual)?;
        let actual = actual.finish();
        if actual.size() != identity.size() {
            return Err(ChunkStoreError::NarSizeMismatch {
                expected: identity.size().get(),
                actual: actual.size().get(),
            });
        }
        if actual.hash() != identity.hash() {
            return Err(ChunkStoreError::NarHashMismatch {
                expected: identity.hash(),
                actual: actual.hash(),
            });
        }
        self.cache_verified_nar(proof);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn nar_content_hashes(&self) -> u64 {
        self.nar_content_hashes.load(Ordering::Relaxed)
    }

    fn nar_content_is_verified(&self, proof: VerifiedNarProof) -> bool {
        self.verified_nars
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_hash
            .get(&proof.identity.hash())
            == Some(&proof)
    }

    fn cache_verified_nar(&self, proof: VerifiedNarProof) {
        let mut proofs = self
            .verified_nars
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hash = proof.identity.hash();
        if proofs.by_hash.insert(hash, proof).is_none() {
            proofs.insertion_order.push_back(hash);
        }
        while proofs.by_hash.len() > VERIFIED_NAR_CACHE_CAPACITY {
            if let Some(expired) = proofs.insertion_order.pop_front() {
                proofs.by_hash.remove(&expired);
            }
        }
    }

    fn open_manifest_reader(
        &self,
        identity: NarIdentity,
    ) -> Result<ManifestReader<File>, ChunkStoreError> {
        let file = self
            .open_manifest(identity.hash())?
            .ok_or(ChunkStoreError::MissingNar)?;
        ManifestReader::new(file, MAX_CHUNK_MANIFEST_BYTES).map_err(Into::into)
    }

    fn check_manifest_chunk_sizes(
        &self,
        reader: &mut ManifestReader<File>,
        chunk_count: u64,
    ) -> Result<(), ChunkStoreError> {
        (0..chunk_count).try_fold(0_u64, |start, _| {
            let descriptor = reader.next_record()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest ended before its chunk count",
                )
            })?;
            let file = self
                .open_chunk(descriptor.hash())?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let expected = descriptor.end() - start;
            let actual = file.metadata()?.len();
            if actual != expected {
                return Err(ChunkStoreError::NarSizeMismatch { expected, actual });
            }
            Ok(descriptor.end())
        })?;
        Ok(())
    }

    fn chunk_stamp_is_verified(&self, hash: ChunkHash, stamp: FileStamp) -> bool {
        let proofs = self
            .verified_chunks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proofs.by_hash.get(&hash) == Some(&stamp)
    }

    fn cache_verified_chunk(
        &self,
        hash: ChunkHash,
        file: &File,
        stamp: FileStamp,
        bytes: &[u8],
    ) -> io::Result<()> {
        let actual_hash = ChunkHash::from_digest(Sha256::digest(bytes).into());
        if actual_hash != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk hash does not match its manifest record",
            ));
        }

        if FileStamp::from_file(file)? != stamp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk changed while its content was being verified",
            ));
        }
        let mut proofs = self
            .verified_chunks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if proofs.by_hash.insert(hash, stamp).is_none() {
            proofs.insertion_order.push_back(hash);
        }
        while proofs.by_hash.len() > VERIFIED_CHUNK_CACHE_CAPACITY {
            if let Some(expired) = proofs.insertion_order.pop_front() {
                proofs.by_hash.remove(&expired);
            }
        }
        Ok(())
    }

    pub(crate) fn open_reader(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
    ) -> Result<ChunkedNarReader<'_>, ChunkStoreError> {
        self.open_reader_with_mode(hash, range, max_manifest_bytes, ChunkReadMode::Serving)
    }

    pub(crate) fn open_verified_reader(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
    ) -> Result<ChunkedNarReader<'_>, ChunkStoreError> {
        self.open_reader_with_mode(hash, range, max_manifest_bytes, ChunkReadMode::Verified)
    }

    fn open_reader_with_mode(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
        mode: ChunkReadMode,
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
            mode,
        })
    }

    pub(crate) fn read_range<W: Write>(
        &self,
        hash: NarHash,
        range: Range<u64>,
        max_manifest_bytes: u64,
        destination: &mut W,
    ) -> Result<(), ChunkStoreError> {
        let mut reader = self.open_verified_reader(hash, range, max_manifest_bytes)?;
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
        self.mark_retained_manifests(live_manifests)?.sweep()
    }

    pub(super) fn mark_retained_manifests(
        &self,
        live_manifests: impl IntoIterator<Item = NarHash>,
    ) -> Result<MarkedChunkSweep<'_>, ChunkStoreError> {
        let marks = self.prepare_gc_marks()?;
        live_manifests
            .into_iter()
            .try_for_each(|hash| self.mark_live_manifest(marks.file(), hash))?;
        Ok(MarkedChunkSweep { store: self, marks })
    }

    pub(crate) fn reachable_chunk_bytes<I>(&self, live_manifests: I) -> Result<u64, ChunkStoreError>
    where
        I: IntoIterator<Item = NarHash>,
    {
        let marks = self.prepare_gc_marks()?;
        let result = (|| {
            live_manifests
                .into_iter()
                .try_for_each(|hash| self.mark_live_manifest(marks.file(), hash))?;
            self.marked_chunk_bytes(marks.file())
        })();
        let cleanup = marks.finish();
        match (result, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    pub(crate) fn physical_bytes(&self) -> Result<ChunkPhysicalBytes, ChunkStoreError> {
        self.physical_bytes_matching(|_| true, |_| true)
    }

    /// Bytes deliberately excluded from the collector's filename contract.
    pub(crate) fn preserved_bytes(&self) -> Result<ChunkPhysicalBytes, ChunkStoreError> {
        self.physical_bytes_matching(|name| !is_manifest_name(name), |name| !is_chunk_name(name))
    }

    fn physical_bytes_matching(
        &self,
        manifest_filter: impl Fn(&OsStr) -> bool,
        chunk_filter: impl Fn(&OsStr) -> bool,
    ) -> Result<ChunkPhysicalBytes, ChunkStoreError> {
        let manifests = sum_regular_file_bytes_matching(&self.manifests, manifest_filter)?;
        let chunks =
            read_dir_names(&self.chunks)?
                .into_iter()
                .try_fold(0_u64, |total, shard_name| {
                    if !is_chunk_shard_name(&shard_name) {
                        return Ok(total);
                    }
                    let shard = open_directory_at(&self.chunks, &shard_name)?;
                    total
                        .checked_add(sum_regular_file_bytes_matching(&shard, &chunk_filter)?)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk byte count overflow")
                        })
                })?;
        Ok(ChunkPhysicalBytes { chunks, manifests })
    }

    pub(crate) fn manifest_files(&self) -> io::Result<Vec<ChunkManifestFile>> {
        read_dir_names(&self.manifests)?
            .into_iter()
            .filter_map(|name| {
                let hash = name
                    .to_str()?
                    .strip_suffix(".manifest")
                    .and_then(|hash| NarHash::parse(hash).ok())?;
                Some((name, hash))
            })
            .map(|(name, hash)| {
                if !super::fs::entry_is_regular_at(&self.manifests, &name)? {
                    return Ok(None);
                }
                let metadata = open_regular_at(&self.manifests, &name)?.metadata()?;
                Ok(Some(ChunkManifestFile {
                    name,
                    hash,
                    bytes: metadata.len(),
                    modified: metadata.modified()?,
                }))
            })
            .filter_map(Result::transpose)
            .collect()
    }

    fn prepare_gc_marks(&self) -> Result<GcMarks<'_>, ChunkStoreError> {
        let exclusive = self
            .gc_marks
            .lock()
            .map_err(|_| io::Error::other("chunk collection marks lock poisoned"))?;
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
        Ok(GcMarks {
            directory: Some(marks),
            _exclusive: exclusive,
        })
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
                        let hash = parse_chunk_hash_name(&name)
                            .expect("valid chunk names contain a SHA-256 digest");
                        let _repair_lock = self.chunk_repair_lock(hash);
                        self.finish_pending_chunk_repair(&shard, hash, &mut |directory| {
                            directory.sync_all()
                        })?;
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

    fn store_chunk(&self, hash: ChunkHash, bytes: &[u8]) -> io::Result<ChunkPublication> {
        self.store_chunk_with_sync(hash, bytes, |directory| directory.sync_all())
    }

    fn store_chunk_with_sync(
        &self,
        hash: ChunkHash,
        bytes: &[u8],
        mut synchronize_shard: impl FnMut(&File) -> io::Result<()>,
    ) -> io::Result<ChunkPublication> {
        let _repair_activity = self.chunk_repair_activity(hash).begin_operation();
        let _repair_lock = self.chunk_repair_lock(hash);
        let shard = self.open_or_create_shard(hash)?;
        self.finish_pending_chunk_repair(&shard, hash, &mut synchronize_shard)?;
        let temporary = temporary_name(CHUNK_TEMP_PREFIX);
        let result = write_temporary_file(&shard, &temporary, bytes).and_then(|()| {
            match link_or_compare_immutable(&shard, &temporary, &shard, &chunk_name(hash))? {
                ImmutableLinkOutcome::Created => Ok(super::publication::PublishOutcome::Created),
                ImmutableLinkOutcome::Identical => {
                    Ok(super::publication::PublishOutcome::Identical)
                }
                ImmutableLinkOutcome::Collision => self.replace_corrupt_chunk(
                    &shard,
                    &temporary,
                    hash,
                    bytes.len() as u64,
                    &mut synchronize_shard,
                ),
            }
        });
        let cleanup = remove_temporary_file(&shard, &temporary);
        match (result, cleanup) {
            (Ok(outcome), Ok(())) => Ok(ChunkPublication { outcome }),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn replace_corrupt_chunk(
        &self,
        shard: &File,
        temporary: &OsStr,
        hash: ChunkHash,
        expected_size: u64,
        synchronize_shard: &mut impl FnMut(&File) -> io::Result<()>,
    ) -> io::Result<super::publication::PublishOutcome> {
        let destination = chunk_name(hash);
        match self.open_chunk_while_repair_locked(hash)? {
            Some(mut file) => match chunk_file_matches_identity(&mut file, hash, expected_size)? {
                true => {
                    let temporary_file = open_regular_at(shard, temporary)?;
                    if files_have_identical_contents(&mut file, temporary_file)? {
                        Ok(super::publication::PublishOutcome::Identical)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "content-addressed chunk collision",
                        ))
                    }
                }
                false => {
                    open_regular_at(shard, temporary)?.sync_all()?;
                    let marker = create_chunk_repair_marker(&self.chunks, hash)?;
                    self.chunk_repair_activity(hash)
                        .pending_markers
                        .fetch_add(1, Ordering::SeqCst);
                    marker.sync_all()?;
                    self.chunks.sync_all()?;
                    rename_at(shard, temporary, shard, &destination)?;
                    synchronize_shard(shard)?;
                    unlink_at(&self.chunks, &chunk_repair_marker_name(hash))?;
                    self.chunk_repair_activity(hash)
                        .pending_markers
                        .fetch_sub(1, Ordering::SeqCst);
                    self.chunks.sync_all()?;
                    Ok(super::publication::PublishOutcome::Created)
                }
            },
            None => match link_or_compare_immutable(shard, temporary, shard, &destination)? {
                ImmutableLinkOutcome::Created => Ok(super::publication::PublishOutcome::Created),
                ImmutableLinkOutcome::Identical => {
                    Ok(super::publication::PublishOutcome::Identical)
                }
                ImmutableLinkOutcome::Collision => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk destination changed during repair",
                )),
            },
        }
    }

    fn finish_pending_chunk_repair(
        &self,
        shard: &File,
        hash: ChunkHash,
        synchronize_shard: &mut impl FnMut(&File) -> io::Result<()>,
    ) -> io::Result<()> {
        let marker = chunk_repair_marker_name(hash);
        match open_regular_at(&self.chunks, &marker) {
            Ok(_pending) => {
                synchronize_shard(shard)?;
                unlink_at(&self.chunks, &marker)?;
                self.chunk_repair_activity(hash)
                    .pending_markers
                    .fetch_sub(1, Ordering::SeqCst);
                self.chunks.sync_all()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn chunk_repair_lock(&self, hash: ChunkHash) -> MutexGuard<'_, ()> {
        let lock = chunk_repair_stripe(hash);
        self.chunk_repair_locks[lock]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn chunk_repair_activity(&self, hash: ChunkHash) -> &ChunkRepairActivity {
        &self.chunk_repair_activity[chunk_repair_stripe(hash)]
    }

    fn open_or_create_shard(&self, hash: ChunkHash) -> io::Result<File> {
        ensure_directory_at(&self.chunks, OsStr::new(&shard_name(hash)), "chunk shard")
    }

    fn open_shard(&self, hash: ChunkHash) -> io::Result<File> {
        super::fs::open_directory_at(&self.chunks, OsStr::new(&shard_name(hash)))
    }
}

fn validate_manifest_identity(
    actual: NarIdentity,
    expected: NarIdentity,
) -> Result<(), ChunkStoreError> {
    if actual.hash() != expected.hash() {
        return Err(ChunkStoreError::NarHashMismatch {
            expected: expected.hash(),
            actual: actual.hash(),
        });
    }
    if actual.size() != expected.size() {
        return Err(ChunkStoreError::NarSizeMismatch {
            expected: expected.size().get(),
            actual: actual.size().get(),
        });
    }
    Ok(())
}

fn scan_chunk_shards(
    chunks_directory: &File,
    stopping: &AtomicBool,
    counts: &mut ChunkPopulationCounts,
) -> io::Result<()> {
    let outcome = for_each_dir_name(chunks_directory, |shard_name| {
        if stopping.load(Ordering::Relaxed) {
            return Ok(DirectoryEntryAction::Stop);
        }
        counts.scanned_entries = checked_population_add(counts.scanned_entries, 1)?;
        if !is_lower_hex(shard_name, 2) {
            counts.ignored_entries = checked_population_add(counts.ignored_entries, 1)?;
            return Ok(DirectoryEntryAction::Continue);
        }
        match open_directory_at(chunks_directory, shard_name) {
            Ok(shard) => {
                let outcome = scan_chunk_files(&shard, stopping, counts)?;
                if outcome == DirectoryScanOutcome::StoppedEarly {
                    return Ok(DirectoryEntryAction::Stop);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                counts.disappeared_entries = checked_population_add(counts.disappeared_entries, 1)?;
            }
            Err(_) => counts.errors = checked_population_add(counts.errors, 1)?,
        }
        Ok(DirectoryEntryAction::Continue)
    })?;
    population_scan_result(outcome)
}

fn scan_chunk_files(
    shard: &File,
    stopping: &AtomicBool,
    counts: &mut ChunkPopulationCounts,
) -> io::Result<DirectoryScanOutcome> {
    for_each_dir_name(shard, |name| {
        if stopping.load(Ordering::Relaxed) {
            return Ok(DirectoryEntryAction::Stop);
        }
        counts.scanned_entries = checked_population_add(counts.scanned_entries, 1)?;
        if counts.scanned_entries.is_multiple_of(256) {
            thread::yield_now();
        }
        if !is_lower_hex(name, 64) {
            counts.ignored_entries = checked_population_add(counts.ignored_entries, 1)?;
            return Ok(DirectoryEntryAction::Continue);
        }
        match open_regular_at(shard, name) {
            Ok(file) => {
                counts.chunk_files = checked_population_add(counts.chunk_files, 1)?;
                counts.chunk_bytes =
                    checked_population_add(counts.chunk_bytes, file.metadata()?.len())?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                counts.disappeared_entries = checked_population_add(counts.disappeared_entries, 1)?;
            }
            Err(_) => counts.errors = checked_population_add(counts.errors, 1)?,
        }
        Ok(DirectoryEntryAction::Continue)
    })
}

fn scan_manifests(
    manifests_directory: &File,
    stopping: &AtomicBool,
    counts: &mut ChunkPopulationCounts,
) -> io::Result<()> {
    let outcome = for_each_dir_name(manifests_directory, |name| {
        if stopping.load(Ordering::Relaxed) {
            return Ok(DirectoryEntryAction::Stop);
        }
        counts.scanned_entries = checked_population_add(counts.scanned_entries, 1)?;
        if counts.scanned_entries.is_multiple_of(256) {
            thread::yield_now();
        }
        let Some(hash) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".manifest"))
            .and_then(|hash| NarHash::parse(hash).ok())
        else {
            counts.ignored_entries = checked_population_add(counts.ignored_entries, 1)?;
            return Ok(DirectoryEntryAction::Continue);
        };
        match open_regular_at(manifests_directory, name) {
            Ok(file) => record_manifest(file, hash, counts)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                counts.disappeared_entries = checked_population_add(counts.disappeared_entries, 1)?;
            }
            Err(_) => counts.errors = checked_population_add(counts.errors, 1)?,
        }
        Ok(DirectoryEntryAction::Continue)
    })?;
    population_scan_result(outcome)
}

fn record_manifest(
    file: File,
    hash: NarHash,
    counts: &mut ChunkPopulationCounts,
) -> io::Result<()> {
    let apparent_bytes = file.metadata()?.len();
    counts.manifest_files = checked_population_add(counts.manifest_files, 1)?;
    counts.manifest_bytes = checked_population_add(counts.manifest_bytes, apparent_bytes)?;
    let manifest = match ManifestReader::new(file, MAX_CHUNK_MANIFEST_BYTES) {
        Ok(reader) => reader,
        Err(_) => {
            counts.errors = checked_population_add(counts.errors, 1)?;
            return Ok(());
        }
    };
    let identity = manifest.manifest().identity();
    if identity.hash() != hash || manifest.finish_remaining().is_err() {
        counts.errors = checked_population_add(counts.errors, 1)?;
        return Ok(());
    }
    counts.chunked_nars = checked_population_add(counts.chunked_nars, 1)?;
    counts.chunked_nar_bytes =
        checked_population_add(counts.chunked_nar_bytes, identity.size().get())?;
    Ok(())
}

fn is_lower_hex(value: &OsStr, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .as_encoded_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn checked_population_add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| io::Error::other("chunk population counter overflow"))
}

fn population_scan_result(outcome: DirectoryScanOutcome) -> io::Result<()> {
    match outcome {
        DirectoryScanOutcome::Complete => Ok(()),
        DirectoryScanOutcome::StoppedEarly => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "population scan cancelled",
        )),
    }
}

pub(crate) struct ChunkedNarReader<'store> {
    store: &'store ChunkStore,
    manifest: Option<ManifestReader<File>>,
    range_cursor: u64,
    range_end: u64,
    next_chunk_start: u64,
    current_chunk: Option<LoadedChunk>,
    mode: ChunkReadMode,
}

#[derive(Clone, Copy)]
enum ChunkReadMode {
    Serving,
    Verified,
}

enum LoadedChunk {
    Serving {
        file: File,
        remaining: u64,
        nar_end: u64,
    },
    Verified {
        bytes: Vec<u8>,
        position: usize,
        end_position: usize,
        nar_end: u64,
    },
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
            let start = usize::try_from(self.range_cursor.max(chunk_start) - chunk_start).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidInput, "chunk offset is too large"),
            )?;
            let end = usize::try_from(self.range_end.min(descriptor.end()) - chunk_start).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidInput, "chunk offset is too large"),
            )?;
            self.current_chunk = Some(match self.mode {
                ChunkReadMode::Serving => open_serving_chunk(
                    self.store,
                    descriptor,
                    chunk_start,
                    start,
                    end,
                    self.range_end.min(descriptor.end()),
                )?,
                ChunkReadMode::Verified => LoadedChunk::Verified {
                    bytes: read_verified_chunk(self.store, descriptor, chunk_start)?,
                    position: start,
                    end_position: end,
                    nar_end: self.range_end.min(descriptor.end()),
                },
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
                match chunk {
                    LoadedChunk::Serving {
                        file,
                        remaining,
                        nar_end,
                    } => {
                        let requested = usize::try_from(*remaining)
                            .unwrap_or(output.len())
                            .min(output.len());
                        let read = file.read(&mut output[..requested])?;
                        if read == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "chunk ended before its manifest length",
                            ));
                        }
                        *remaining -= read as u64;
                        if *remaining == 0 {
                            self.range_cursor = *nar_end;
                            self.current_chunk = None;
                        }
                        return Ok(read);
                    }
                    LoadedChunk::Verified {
                        bytes,
                        position,
                        end_position,
                        nar_end,
                    } => {
                        let remaining = &bytes[*position..*end_position];
                        let copied = remaining.len().min(output.len());
                        output[..copied].copy_from_slice(&remaining[..copied]);
                        *position += copied;
                        if *position == *end_position {
                            self.range_cursor = *nar_end;
                            self.current_chunk = None;
                        }
                        return Ok(copied);
                    }
                }
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

fn open_serving_chunk(
    store: &ChunkStore,
    descriptor: super::chunked::ChunkDescriptor,
    chunk_start: u64,
    start: usize,
    end: usize,
    nar_end: u64,
) -> io::Result<LoadedChunk> {
    let chunk_length = descriptor
        .end()
        .checked_sub(chunk_start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end moved backwards"))?;
    let mut file = store
        .open_serving_chunk(descriptor.hash())?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if file.metadata()?.len() != chunk_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk length does not match its manifest record",
        ));
    }
    file.seek(SeekFrom::Start(start as u64))?;
    Ok(LoadedChunk::Serving {
        file,
        remaining: (end - start) as u64,
        nar_end,
    })
}

fn read_verified_chunk(
    store: &ChunkStore,
    descriptor: super::chunked::ChunkDescriptor,
    chunk_start: u64,
) -> io::Result<Vec<u8>> {
    let chunk_length = descriptor
        .end()
        .checked_sub(chunk_start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end moved backwards"))?;
    let mut file = store
        .open_chunk(descriptor.hash())?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if file.metadata()?.len() != chunk_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk length does not match its manifest record",
        ));
    }
    let stamp = FileStamp::from_file(&file)?;
    let cached = store.chunk_stamp_is_verified(descriptor.hash(), stamp);
    let chunk = read_chunk_bytes(&mut file, chunk_length)?;
    if FileStamp::from_file(&file)? != stamp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk changed while it was being read",
        ));
    }
    if !cached {
        store.cache_verified_chunk(descriptor.hash(), &file, stamp, &chunk)?;
    }
    Ok(chunk)
}

fn read_chunk_bytes(file: &mut File, chunk_length: u64) -> io::Result<Vec<u8>> {
    let chunk_length = usize::try_from(chunk_length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk is too large"))?;
    let mut chunk = vec![0; chunk_length];
    file.read_exact(&mut chunk)?;
    Ok(chunk)
}

fn chunk_file_matches_identity(
    file: &mut File,
    expected_hash: ChunkHash,
    expected_size: u64,
) -> io::Result<bool> {
    if file.metadata()?.len() != expected_size {
        return Ok(false);
    }
    let bytes = read_chunk_bytes(file, expected_size)?;
    Ok(ChunkHash::from_digest(Sha256::digest(bytes).into()) == expected_hash)
}

fn files_have_identical_contents(left: &mut File, mut right: File) -> io::Result<bool> {
    let length = left.metadata()?.len();
    if right.metadata()?.len() != length {
        return Ok(false);
    }
    left.seek(SeekFrom::Start(0))?;
    right.seek(SeekFrom::Start(0))?;
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(left_buffer.len() as u64))
            .expect("bounded chunk comparison fits usize");
        left.read_exact(&mut left_buffer[..count])?;
        right.read_exact(&mut right_buffer[..count])?;
        if left_buffer[..count] != right_buffer[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    Ok(true)
}

#[derive(Default)]
struct NarIdentityHasher {
    hash: Sha256,
    size: u64,
}

impl NarIdentityHasher {
    fn finish(self) -> NarIdentity {
        NarIdentity::new(
            NarHash::from_digest(self.hash.finalize().into()),
            self.size.into(),
        )
    }
}

impl Write for NarIdentityHasher {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    durability: ChunkDurabilityObligation,
}

#[derive(Clone, Copy)]
enum ChunkDurabilityObligation {
    Empty,
    Reused,
    NewlyPublished,
}

impl ChunkDurabilityObligation {
    fn record_publication(&mut self, outcome: super::publication::PublishOutcome) {
        *self = match outcome {
            super::publication::PublishOutcome::Created => Self::NewlyPublished,
            super::publication::PublishOutcome::Identical => match *self {
                Self::Empty | Self::Reused => Self::Reused,
                Self::NewlyPublished => Self::NewlyPublished,
            },
        };
    }
}

struct FinishedChunks<'store> {
    writer: ChunkingWriter<'store>,
}
struct VerifiedChunks<'store> {
    writer: ChunkingWriter<'store>,
    manifest: ChunkManifest,
}
struct DurableChunks<'store> {
    writer: ChunkingWriter<'store>,
    manifest: ChunkManifest,
}

impl<'store> FinishedChunks<'store> {
    fn verify_identity_and_record_coverage(
        mut self,
        expected: NarIdentity,
    ) -> Result<VerifiedChunks<'store>, ChunkStoreError> {
        let actual = NarIdentity::new(
            NarHash::from_digest(std::mem::take(&mut self.writer.hasher).finalize().into()),
            self.writer.size.into(),
        );
        verify_streamed_nar_identity(actual, expected)?;
        verify_chunk_record_coverage(self.writer.previous_end, actual)?;
        let manifest = ChunkManifest::new(actual, self.writer.profile, self.writer.chunk_count);
        Ok(VerifiedChunks {
            writer: self.writer,
            manifest,
        })
    }
}

impl<'store> VerifiedChunks<'store> {
    fn make_chunks_durable(
        self,
        synchronize: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<DurableChunks<'store>, ChunkStoreError> {
        match self.writer.durability {
            ChunkDurabilityObligation::Empty => {}
            ChunkDurabilityObligation::Reused => {
                self.synchronize_unless_a_completed_manifest_proves_durability(synchronize)?;
            }
            ChunkDurabilityObligation::NewlyPublished => synchronize(&self.writer.store.chunks)?,
        }
        Ok(DurableChunks {
            writer: self.writer,
            manifest: self.manifest,
        })
    }

    fn synchronize_unless_a_completed_manifest_proves_durability(
        &self,
        synchronize: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), ChunkStoreError> {
        match self
            .writer
            .store
            .validate_manifest(self.manifest.identity().hash())?
        {
            Some(existing) if existing == self.manifest => Ok(()),
            Some(_) | None => synchronize(&self.writer.store.chunks).map_err(Into::into),
        }
    }
}

impl DurableChunks<'_> {
    fn publish_manifest(mut self) -> Result<CompletedChunkedIngest, ChunkStoreError> {
        let bytes = encoded_manifest_size(self.manifest.chunk_count())?;
        self.writer
            .reserve_before_materialization(&self.writer.store.manifests, bytes)?;
        let outcome = self.publish_manifest_from_records()?;
        self.writer.release_materialized_bytes(bytes);
        Ok(CompletedChunkedIngest {
            manifest: self.manifest,
            outcome,
            reservation: self.writer.reservation.take(),
        })
    }

    fn publish_manifest_from_records(
        &mut self,
    ) -> Result<super::publication::PublishOutcome, ChunkStoreError> {
        self.writer.record_file.sync_all()?;
        self.writer.record_file.seek(SeekFrom::Start(0))?;
        let directory = &self.writer.store.manifests;
        let name = temporary_name(MANIFEST_TEMP_PREFIX);
        let result = (|| {
            let mut temporary = open_at(
                directory,
                &name,
                FileAccess::Write,
                FileCreation::CreateNew,
                FilePrivacy::Private,
            )?;
            write_complete_manifest(&mut temporary, self.manifest, &mut self.writer.record_file)?;
            temporary.sync_all()?;
            Ok(publish_temporary_file(
                directory,
                &name,
                &manifest_name(self.manifest.identity().hash()),
            )?)
        })();
        let cleanup = remove_temporary_file(directory, &name);
        match (result, cleanup) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}

fn verify_streamed_nar_identity(
    actual: NarIdentity,
    expected: NarIdentity,
) -> Result<(), ChunkStoreError> {
    match (
        actual.hash() == expected.hash(),
        actual.size() == expected.size(),
    ) {
        (false, _) => Err(ChunkStoreError::NarHashMismatch {
            expected: expected.hash(),
            actual: actual.hash(),
        }),
        (true, false) => Err(ChunkStoreError::NarSizeMismatch {
            expected: expected.size().get(),
            actual: actual.size().get(),
        }),
        (true, true) => Ok(()),
    }
}

fn verify_chunk_record_coverage(end: u64, identity: NarIdentity) -> Result<(), ChunkStoreError> {
    match end == identity.size().get() {
        true => Ok(()),
        false => Err(ChunkStoreError::NarSizeMismatch {
            expected: identity.size().get(),
            actual: end,
        }),
    }
}

fn encoded_manifest_size(chunk_count: u64) -> Result<u64, ManifestError> {
    chunk_count
        .checked_mul(MANIFEST_RECORD_BYTES as u64)
        .and_then(|bytes| {
            bytes.checked_add((MANIFEST_HEADER_BYTES + MANIFEST_CHECKSUM_BYTES) as u64)
        })
        .ok_or(ManifestError::LengthOverflow)
}

fn write_complete_manifest(
    destination: &mut File,
    manifest: ChunkManifest,
    records: &mut File,
) -> Result<(), ChunkStoreError> {
    let checksum = {
        let mut digesting = digest_io::HashWriter::<Sha256, _>::new(&mut *destination);
        write_manifest_header(&mut digesting, manifest)?;
        io::copy(records, &mut digesting)?;
        <[u8; 32]>::from(digesting.finalize())
    };
    destination.write_all(&checksum)?;
    Ok(())
}

struct ChunkSpecification {
    start: usize,
    end: usize,
    hash: ChunkHash,
    nar_end: u64,
    length: u64,
}

impl ChunkSpecification {
    fn from_byte_range(
        byte_range: Range<usize>,
        hash: ChunkHash,
        previous_nar_end: u64,
        nar_end: u64,
    ) -> io::Result<Self> {
        let range_length = byte_range
            .end
            .checked_sub(byte_range.start)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk range underflow"))?;
        let length = u64::try_from(range_length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk length overflow"))?;
        let expected_nar_end = previous_nar_end
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end overflow"))?;
        if expected_nar_end != nar_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk byte range does not match its absolute NAR offsets",
            ));
        }
        Ok(Self {
            start: byte_range.start,
            end: byte_range.end,
            hash,
            nar_end,
            length,
        })
    }
}

struct PendingChunk<'a> {
    bytes: &'a [u8],
    hash: ChunkHash,
    end: u64,
    length: u64,
}

struct ChunkPublication {
    outcome: super::publication::PublishOutcome,
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

impl<'store> ChunkingWriter<'store> {
    pub(crate) fn finish(
        self,
        expected: NarIdentity,
    ) -> Result<CompletedChunkedIngest, ChunkStoreError> {
        let durability = self.store.durability;
        self.finish_with(expected, |directory| durability.synchronize(directory))
    }

    fn finish_with(
        self,
        expected: NarIdentity,
        sync_chunks: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<CompletedChunkedIngest, ChunkStoreError> {
        self.finish_pending_chunks()?
            .verify_identity_and_record_coverage(expected)?
            .make_chunks_durable(sync_chunks)?
            .publish_manifest()
    }

    fn finish_pending_chunks(mut self) -> Result<FinishedChunks<'store>, ChunkStoreError> {
        self.publish_pending_chunk()?;
        Ok(FinishedChunks { writer: self })
    }

    fn publish_complete_chunks(&mut self) -> io::Result<()> {
        let batch_bytes = self
            .profile
            .max_size()
            .checked_mul(CHUNK_PUBLICATION_BATCH_SIZE as u64)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "chunk batch is too large")
            })?;
        while self.pending.len() >= batch_bytes {
            self.publish_next_batch(false)?;
        }
        Ok(())
    }

    fn publish_pending_chunk(&mut self) -> Result<(), ChunkStoreError> {
        while !self.pending.is_empty() {
            self.publish_next_batch(true)
                .map_err(ChunkStoreError::from)?;
        }
        Ok(())
    }

    fn publish_next_batch(&mut self, final_batch: bool) -> io::Result<()> {
        let specifications = self.next_chunk_specifications(final_batch)?;
        let batch_bytes = specifications
            .iter()
            .try_fold(0_u64, |total, specification| {
                total.checked_add(specification.length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "chunk batch size overflow")
                })
            })?;
        self.reserve_before_materialization(&self.store.chunks, batch_bytes)?;
        let batch = specifications
            .iter()
            .map(|specification| PendingChunk {
                bytes: &self.pending[specification.start..specification.end],
                hash: specification.hash,
                end: specification.nar_end,
                length: specification.length,
            })
            .collect::<Vec<_>>();

        let publications = self.publish_chunk_batch(&batch)?;
        specifications
            .iter()
            .zip(&publications)
            .for_each(|(specification, publication)| {
                self.store
                    .activity
                    .record_chunk_publication(publication.outcome, specification.length);
            });
        publications
            .iter()
            .for_each(|publication| self.durability.record_publication(publication.outcome));
        drop(batch);
        for specification in &specifications {
            self.release_materialized_bytes(specification.length);
            self.record_published_chunk(specification)?;
        }
        let drained = specifications
            .last()
            .map_or(0, |specification| specification.end);
        self.pending.drain(..drained);
        Ok(())
    }

    fn next_chunk_specifications(&self, final_batch: bool) -> io::Result<Vec<ChunkSpecification>> {
        let mut specifications = Vec::with_capacity(CHUNK_PUBLICATION_BATCH_SIZE);
        let mut start = 0;
        let mut previous_end = self.previous_end;
        let mut previous_length = self.previous_length;
        while start < self.pending.len() && specifications.len() < CHUNK_PUBLICATION_BATCH_SIZE {
            let remaining = self.pending.len() - start;
            if !final_batch && remaining < self.profile.max_size() as usize {
                break;
            }
            let chunk_length = SliceChunker::new(
                &self.pending[start..],
                self.profile.min_size() as usize,
                self.profile.max_size() as usize,
                MinCdcHash4::new(),
            )
            .next()
            .expect("a non-empty pending buffer produces a chunk")
            .len();
            if previous_length.is_some_and(|previous| previous < self.profile.min_size()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-final chunk is too small",
                ));
            }
            let end = start
                .checked_add(chunk_length)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end overflow"))?;
            let remaining_after_chunk = u64::try_from(self.pending.len() - end).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "remaining chunk bytes overflow")
            })?;
            let nar_end = self
                .size
                .checked_sub(remaining_after_chunk)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end underflow"))?;
            let hash = ChunkHash::from_digest(Sha256::digest(&self.pending[start..end]).into());
            let specification =
                ChunkSpecification::from_byte_range(start..end, hash, previous_end, nar_end)?;
            previous_end = specification.nar_end;
            previous_length = Some(specification.length);
            specifications.push(specification);
            start = end;
        }
        if specifications.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk batch has no complete chunk",
            ));
        }
        Ok(specifications)
    }

    fn publish_chunk_batch(&self, batch: &[PendingChunk<'_>]) -> io::Result<Vec<ChunkPublication>> {
        batch.chunks(CHUNK_PUBLICATION_WORKER_BATCH_SIZE).try_fold(
            Vec::with_capacity(batch.len()),
            |mut publications, worker_batch| {
                publications.extend(self.publish_chunk_worker_batch(worker_batch)?);
                Ok(publications)
            },
        )
    }

    fn publish_chunk_worker_batch(
        &self,
        worker_batch: &[PendingChunk<'_>],
    ) -> io::Result<Vec<ChunkPublication>> {
        std::thread::scope(|scope| {
            let handles = worker_batch
                .iter()
                .map(|chunk| scope.spawn(|| self.store.store_chunk(chunk.hash, chunk.bytes)))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| io::Error::other("chunk publication thread panicked"))?
                })
                .collect()
        })
    }

    fn record_published_chunk(&mut self, specification: &ChunkSpecification) -> io::Result<()> {
        self.record_file
            .write_all(&specification.nar_end.to_le_bytes())?;
        self.record_file.write_all(specification.hash.as_bytes())?;
        self.previous_end = specification.nar_end;
        self.previous_length = Some(specification.length);
        self.chunk_count = self
            .chunk_count
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "too many chunks"))?;
        Ok(())
    }

    fn reserve_before_materialization(&mut self, directory: &File, bytes: u64) -> io::Result<()> {
        let Some(reservation) = self.reservation.as_mut() else {
            return Ok(());
        };
        reservation
            .grow_to(directory, self.min_free_bytes, bytes)
            .map_err(io::Error::from)
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

fn publish_immutable_bytes_without_directory_sync(
    directory: &File,
    name: &OsStr,
    temp_prefix: &str,
    bytes: &[u8],
) -> io::Result<super::publication::PublishOutcome> {
    let temporary_name = temporary_name(temp_prefix);
    let result = write_temporary_file(directory, &temporary_name, bytes).and_then(|()| {
        publish_temporary_file_without_directory_sync(directory, &temporary_name, name)
    });
    let cleanup = unlink_at(directory, &temporary_name);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_outcome), Err(error)) => Err(error),
        (Err(error), Err(_cleanup_error)) => Err(error),
    }
}

fn publish_temporary_file_without_directory_sync(
    directory: &File,
    temporary_name: &OsStr,
    name: &OsStr,
) -> io::Result<super::publication::PublishOutcome> {
    match link_or_compare_immutable(directory, temporary_name, directory, name)? {
        ImmutableLinkOutcome::Created => Ok(super::publication::PublishOutcome::Created),
        ImmutableLinkOutcome::Identical => Ok(super::publication::PublishOutcome::Identical),
        ImmutableLinkOutcome::Collision => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content-addressed storage collision",
        )),
    }
}

fn publish_temporary_file(
    directory: &File,
    temporary_name: &OsStr,
    name: &OsStr,
) -> io::Result<super::publication::PublishOutcome> {
    publish_temporary_file_with_sync(directory, temporary_name, name, || directory.sync_all())
}

fn publish_temporary_file_with_sync(
    directory: &File,
    temporary_name: &OsStr,
    name: &OsStr,
    sync_directory: impl FnOnce() -> io::Result<()>,
) -> io::Result<super::publication::PublishOutcome> {
    let result = publish_temporary_file_without_directory_sync(directory, temporary_name, name)
        .and_then(|outcome| {
            // An identical entry may have been left by a failed durability barrier.
            sync_directory()?;
            Ok(outcome)
        });
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
        FileAccess::Write,
        FileCreation::CreateNew,
        FilePrivacy::Private,
    )?;
    file.write_all(bytes)
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

fn chunk_repair_marker_name(hash: ChunkHash) -> OsString {
    format!(".repair-{}", hex_name(*hash.as_bytes())).into()
}

fn chunk_repair_stripe(hash: ChunkHash) -> usize {
    usize::from(hash.as_bytes()[0]) % CHUNK_REPAIR_LOCK_COUNT
}

fn repair_activity_by_stripe(
    pending_markers: [usize; CHUNK_REPAIR_LOCK_COUNT],
) -> [ChunkRepairActivity; CHUNK_REPAIR_LOCK_COUNT] {
    std::array::from_fn(|stripe| ChunkRepairActivity {
        pending_markers: AtomicUsize::new(pending_markers[stripe]),
        ..ChunkRepairActivity::default()
    })
}

fn pending_chunk_repair_counts(directory: &File) -> io::Result<[usize; CHUNK_REPAIR_LOCK_COUNT]> {
    read_dir_names(directory)?.into_iter().try_fold(
        [0_usize; CHUNK_REPAIR_LOCK_COUNT],
        |mut counts, name| {
            if let Some(hash) = parse_chunk_repair_marker_name(&name) {
                let stripe = chunk_repair_stripe(hash);
                counts[stripe] = counts[stripe].checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "repair marker count overflow")
                })?;
            }
            Ok(counts)
        },
    )
}

fn parse_chunk_repair_marker_name(name: &OsStr) -> Option<ChunkHash> {
    let name = name.to_str()?;
    let hex = name.strip_prefix(".repair-")?;
    parse_chunk_hash(hex)
}

fn parse_chunk_hash_name(name: &OsStr) -> Option<ChunkHash> {
    parse_chunk_hash(name.to_str()?)
}

fn parse_chunk_hash(hex: &str) -> Option<ChunkHash> {
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    for (byte, pair) in digest.iter_mut().zip(pairs) {
        *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(ChunkHash::from_digest(digest))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn create_chunk_repair_marker(directory: &File, hash: ChunkHash) -> io::Result<File> {
    open_at(
        directory,
        &chunk_repair_marker_name(hash),
        FileAccess::Write,
        FileCreation::CreateNew,
        FilePrivacy::Private,
    )
}

fn mark_gc_file(directory: &File, name: &OsStr) -> io::Result<()> {
    match open_at(
        directory,
        name,
        FileAccess::Write,
        FileCreation::CreateNew,
        FilePrivacy::Private,
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

fn sum_regular_file_bytes_matching(
    directory: &File,
    include: impl Fn(&OsStr) -> bool,
) -> io::Result<u64> {
    read_dir_names(directory)?
        .into_iter()
        .filter(|name| include(name))
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

fn shard_name(hash: ChunkHash) -> String {
    hex_name(*hash.as_bytes())[..2].to_owned()
}

fn chunk_name(hash: ChunkHash) -> OsString {
    hex_name(*hash.as_bytes()).into()
}

fn manifest_name(hash: NarHash) -> OsString {
    format!("{}.manifest", hash).into()
}

fn hex_name(bytes: [u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(&bytes)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ChunkStoreError {
    #[error("chunked NAR is missing")]
    MissingNar,
    #[error("range {start}..{end} is outside NAR size {size}")]
    InvalidRange { start: u64, end: u64, size: u64 },
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Manifest(#[from] ManifestError),
    #[error("chunked NAR hash mismatch")]
    NarHashMismatch { expected: NarHash, actual: NarHash },
    #[error("chunked NAR size mismatch")]
    NarSizeMismatch { expected: u64, actual: u64 },
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        ffi::OsStr,
        fs::{self, OpenOptions},
        io::{Cursor, Read, Seek, Write},
        sync::{Arc, Barrier, atomic::Ordering, mpsc},
        time::Duration,
    };

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{ChunkStore, ChunkStoreError, FileStamp, remove_abandoned_temps};
    use crate::cache::filesystem::{FileAccess, FileCreation, FilePrivacy};
    use crate::cache::{
        object::{NarHash, NarIdentity, NarSize},
        storage::{
            StorageBackend,
            capacity::StorageCapacity,
            chunked::{ChunkHash, ChunkProfile, ManifestReader},
            directory::Directory,
            publication::{StagingBudget, StagingReservation},
            state::StorageActivity,
        },
    };

    #[test]
    fn chunk_specifications_measure_each_range_not_the_cumulative_batch_end() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let profile = ChunkProfile::MinCdcHash4V2;
        let mut writer = store
            .begin_ingest_with_optional_reservation(profile, None, 0)
            .unwrap();
        let first_nar_offset = 37;
        writer.pending = deterministic_chunk_fixture(profile.max_size() as usize * 3);
        writer.previous_end = first_nar_offset;
        writer.previous_length = Some(profile.min_size());
        writer.size = first_nar_offset + writer.pending.len() as u64;

        let specifications = writer.next_chunk_specifications(true).unwrap();

        assert!(
            specifications.len() >= 3,
            "fixture must span several chunks"
        );
        let exact_capacity = StorageCapacity {
            total_bytes: writer.pending.len() as u64,
            available_bytes: writer.pending.len() as u64,
            inodes: crate::cache::storage::InodeCapacity::Measured {
                total: 2,
                available: 2,
            },
            read_only: false,
        };
        let mut capacity = StagingBudget::default();
        specifications
            .iter()
            .try_for_each(|specification| capacity.reserve(exact_capacity, 0, specification.length))
            .unwrap();
        assert_eq!(
            capacity.outstanding_bytes(),
            writer.pending.len() as u64,
            "each chunk reserves only its own byte range"
        );
        assert!(capacity.reserve(exact_capacity, 0, 1).is_err());
        let mut previous_end = first_nar_offset;
        let mut previous_range_end = 0;
        let mut chunk_lengths = Vec::with_capacity(specifications.len());
        for specification in specifications {
            assert_eq!(specification.start, previous_range_end);
            assert_eq!(
                specification.length,
                (specification.end - specification.start) as u64
            );
            assert_eq!(specification.length, specification.nar_end - previous_end);
            chunk_lengths.push(specification.length);
            previous_end = specification.nar_end;
            previous_range_end = specification.end;
        }
        chunk_lengths.sort_unstable();
        chunk_lengths.dedup();
        assert!(
            chunk_lengths.len() > 1,
            "fixture includes unequal chunk lengths"
        );
    }

    #[test]
    fn chunked_ingestion_spends_admitted_credit_before_requesting_more_space() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let profile = ChunkProfile::MinCdcHash4V2;
        let input = deterministic_chunk_fixture(profile.max_size() as usize * 18);
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        let budget = std::sync::Arc::new(std::sync::Mutex::new(StagingBudget::default()));
        let capacity = StorageCapacity {
            total_bytes: input.len() as u64 + 10,
            available_bytes: input.len() as u64 + 10,
            inodes: crate::cache::storage::InodeCapacity::Measured {
                total: 100,
                available: 100,
            },
            read_only: false,
        };
        let reservation = crate::cache::storage::capacity::reserve_staging_bytes_for_test(
            &budget,
            10,
            input.len() as u64,
            || Ok(capacity),
        )
        .unwrap();
        // No growth can pass this floor. The admitted credit must cover all
        // payload batches even as those bytes become materialized on disk.
        let mut writer = store
            .begin_ingest_with_reservation(profile, reservation, u64::MAX)
            .unwrap();
        writer
            .write_all(&input)
            .expect("already admitted payload must fit");
        writer.publish_pending_chunk().unwrap();
        assert_eq!(budget.lock().unwrap().outstanding_bytes(), 0);
        assert_eq!(writer.reservation.as_ref().unwrap().reserved_bytes(), 0);
        // The manifest is an additional, separately budgeted allocation.
        writer.min_free_bytes = 0;
        let completed = writer.finish(identity).unwrap();
        completed.release_reservation();
        store.check_nar_availability(identity).unwrap();
    }

    #[test]
    fn multi_batch_ingest_accounts_each_chunk_and_reconstructs_exact_bytes() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let activity = std::sync::Arc::new(StorageActivity::default());
        let store = ChunkStore::initialize_with_activity(root.file(), activity.clone()).unwrap();
        let profile = ChunkProfile::MinCdcHash4V2;
        let input = deterministic_chunk_fixture(profile.max_size() as usize * 18);
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        let staging_budget = std::sync::Arc::new(std::sync::Mutex::new(StagingBudget::default()));
        let reservation = StagingReservation::empty(staging_budget.clone());
        let mut writer = store
            .begin_ingest_with_reservation(profile, reservation, 0)
            .unwrap();
        writer.write_all(&input).unwrap();
        let completed = writer.finish(identity).unwrap();
        completed.release_reservation();

        let mut manifest_reader = ManifestReader::new(
            store.open_manifest(identity.hash()).unwrap().unwrap(),
            super::MAX_CHUNK_MANIFEST_BYTES,
        )
        .unwrap();
        let manifest = manifest_reader.manifest();
        assert!(
            manifest.chunk_count() > 16,
            "fixture crosses publication batches"
        );
        let descriptors = (0..manifest.chunk_count())
            .map(|_| manifest_reader.next_record().unwrap().unwrap())
            .collect::<Vec<_>>();
        manifest_reader.finish_remaining().unwrap();

        let mut previous_end = 0;
        let mut lengths = descriptors
            .iter()
            .map(|descriptor| {
                let length = descriptor.end() - previous_end;
                previous_end = descriptor.end();
                length
            })
            .collect::<Vec<_>>();
        assert_eq!(previous_end, input.len() as u64);
        lengths.sort_unstable();
        assert!(lengths.windows(2).any(|pair| pair[0] != pair[1]));

        let after_creation = activity.snapshot(StorageBackend::Chunked);
        assert_eq!(
            after_creation.chunk_bytes_created + after_creation.chunk_bytes_reused,
            input.len() as u64
        );
        assert_eq!(
            after_creation.chunks_created + after_creation.chunks_reused,
            manifest.chunk_count()
        );
        assert_eq!(staging_budget.lock().unwrap().outstanding_bytes(), 0);

        let mut reconstructed = Vec::new();
        store
            .read_range(
                identity.hash(),
                0..identity.size().get(),
                super::MAX_CHUNK_MANIFEST_BYTES,
                &mut reconstructed,
            )
            .unwrap();
        assert_eq!(reconstructed, input);

        let first_boundary = descriptors[0].end() as usize;
        let range = first_boundary - 113..first_boundary + 271;
        let mut crossing_range = Vec::new();
        store
            .read_range(
                identity.hash(),
                range.start as u64..range.end as u64,
                super::MAX_CHUNK_MANIFEST_BYTES,
                &mut crossing_range,
            )
            .unwrap();
        assert_eq!(crossing_range, input[range]);

        store
            .store_nar(Cursor::new(&input), identity, profile)
            .unwrap();
        let after_reuse = activity.snapshot(StorageBackend::Chunked);
        assert_eq!(
            after_reuse.chunk_bytes_reused - after_creation.chunk_bytes_reused,
            input.len() as u64
        );
        assert_eq!(
            after_reuse.chunks_reused - after_creation.chunks_reused,
            manifest.chunk_count()
        );
        assert_eq!(staging_budget.lock().unwrap().outstanding_bytes(), 0);

        let equal_length_input = vec![0; profile.max_size() as usize * 3];
        let equal_length_identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&equal_length_input).into()),
            NarSize::new(equal_length_input.len() as u64),
        );
        let equal_length_manifest = store
            .store_nar(
                Cursor::new(&equal_length_input),
                equal_length_identity,
                profile,
            )
            .unwrap();
        let mut equal_length_reader = ManifestReader::new(
            store
                .open_manifest(equal_length_identity.hash())
                .unwrap()
                .unwrap(),
            super::MAX_CHUNK_MANIFEST_BYTES,
        )
        .unwrap();
        let equal_chunk_lengths = (0..equal_length_manifest.chunk_count())
            .map(|_| {
                let descriptor = equal_length_reader.next_record().unwrap().unwrap();
                descriptor.end()
            })
            .scan(0, |previous_end, end| {
                let length = end - *previous_end;
                *previous_end = end;
                Some(length)
            })
            .collect::<Vec<_>>();
        equal_length_reader.finish_remaining().unwrap();
        assert!(equal_chunk_lengths.len() > 1);
        assert!(
            equal_chunk_lengths
                .iter()
                .all(|length| *length == equal_chunk_lengths[0])
        );
    }

    fn deterministic_chunk_fixture(length: usize) -> Vec<u8> {
        let equal_chunk_prefix = (ChunkProfile::MinCdcHash4V2.min_size() * 2) as usize;
        let prefix_length = equal_chunk_prefix.min(length);
        let mut input = vec![0; prefix_length];
        let mut random_state = 0x31f2_87a4_6c09_5bd1_u64;
        input.extend((prefix_length..length).map(|_| {
            random_state ^= random_state << 13;
            random_state ^= random_state >> 7;
            random_state ^= random_state << 17;
            random_state as u8
        }));
        input
    }

    #[test]
    fn chunk_ingest_is_independent_of_source_read_boundaries() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first_root = Directory::open(first_directory.path()).unwrap();
        let second_root = Directory::open(second_directory.path()).unwrap();
        let first_store = ChunkStore::initialize(first_root.file()).unwrap();
        let second_store = ChunkStore::initialize(second_root.file()).unwrap();
        let profile = ChunkProfile::MinCdcHash4V2;
        let input = deterministic_chunk_fixture(
            profile.max_size() as usize * (super::CHUNK_PUBLICATION_BATCH_SIZE + 1) + 17,
        );
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));
        let first = first_store
            .store_nar(Cursor::new(&input), identity, profile)
            .unwrap();
        let second = second_store
            .store_nar(
                FragmentedReader {
                    reader: Cursor::new(&input),
                    fragment: 17,
                },
                identity,
                profile,
            )
            .unwrap();
        assert_eq!(first, second);
        assert!(first.chunk_count() > super::CHUNK_PUBLICATION_BATCH_SIZE as u64);

        let mut first_reader = ManifestReader::new(
            first_store.open_manifest(hash).unwrap().unwrap(),
            super::MAX_CHUNK_MANIFEST_BYTES,
        )
        .unwrap();
        let mut second_reader = ManifestReader::new(
            second_store.open_manifest(hash).unwrap().unwrap(),
            super::MAX_CHUNK_MANIFEST_BYTES,
        )
        .unwrap();
        for _ in 0..first.chunk_count() {
            assert_eq!(
                first_reader.next_record().unwrap(),
                second_reader.next_record().unwrap()
            );
        }
        first_reader.finish_remaining().unwrap();
        second_reader.finish_remaining().unwrap();
        for store in [&first_store, &second_store] {
            let mut reader = store
                .open_verified_reader(
                    hash,
                    0..identity.size().get(),
                    super::MAX_CHUNK_MANIFEST_BYTES,
                )
                .unwrap();
            let mut reconstructed = Vec::new();
            reader.read_to_end(&mut reconstructed).unwrap();
            assert_eq!(reconstructed, input);
        }
    }

    struct FragmentedReader<R> {
        reader: R,
        fragment: usize,
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = self.fragment.min(output.len());
            self.reader.read(&mut output[..length])
        }
    }

    #[test]
    fn identical_manifests_still_require_a_successful_directory_sync() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let temporary_name = OsStr::new("manifest.part");
        let final_name = OsStr::new("manifest");
        std::fs::write(directory.path().join(final_name), b"manifest bytes").unwrap();
        std::fs::write(directory.path().join(temporary_name), b"manifest bytes").unwrap();

        let error = super::publish_temporary_file_with_sync(
            root.file(),
            temporary_name,
            final_name,
            || Err(std::io::Error::other("injected directory sync failure")),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "injected directory sync failure");
        assert!(!directory.path().join(temporary_name).exists());
        assert_eq!(
            std::fs::read(directory.path().join(final_name)).unwrap(),
            b"manifest bytes"
        );

        std::fs::write(directory.path().join(temporary_name), b"manifest bytes").unwrap();
        let syncs = std::cell::Cell::new(0);
        let outcome = super::publish_temporary_file_with_sync(
            root.file(),
            temporary_name,
            final_name,
            || {
                syncs.set(syncs.get() + 1);
                root.file().sync_all()
            },
        )
        .unwrap();
        assert_eq!(outcome, crate::cache::storage::PublishOutcome::Identical);
        assert_eq!(syncs.get(), 1);
        assert!(!directory.path().join(temporary_name).exists());
    }

    #[test]
    fn stores_deduplicated_chunks_and_a_round_trippable_manifest() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));

        let manifest = store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();
        let manifest_file = store.open_manifest(hash).unwrap().unwrap();
        assert_eq!(
            manifest_file.metadata().unwrap().len(),
            super::encoded_manifest_size(manifest.chunk_count()).unwrap()
        );
        let reader = ManifestReader::new(manifest_file, 1_000_000).unwrap();
        assert_eq!(reader.manifest(), manifest);
        reader.finish_remaining().unwrap();
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
    fn canonical_manifest_acquisition_cannot_skip_a_failed_directory_barrier() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = b"canonical chunked NAR";
        let hash = NarHash::from_digest(Sha256::digest(input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));
        store
            .store_nar(Cursor::new(input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();

        let result = store.acquire_manifest_with_directory_sync(hash, || {
            Err(std::io::Error::other(
                "injected manifest directory sync failure",
            ))
        });
        assert!(matches!(result, Err(ChunkStoreError::Io(error))
            if error.to_string() == "injected manifest directory sync failure"));
        assert_eq!(
            store
                .acquire_durable_manifest(hash)
                .unwrap()
                .unwrap()
                .identity(),
            identity
        );

        let missing = NarHash::from_digest([0; 32]);
        assert!(
            store
                .acquire_manifest_with_directory_sync(missing, || {
                    panic!("missing manifests must not run a publication barrier")
                })
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn filesystem_sync_failure_never_publishes_the_manifest() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        let mut writer = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        writer.write_all(&input).unwrap();

        let result = writer.finish_with(identity, |_| {
            Err(std::io::Error::from_raw_os_error(
                crate::cache::test_support::InjectedIoFailure::ReadFailure.code(),
            ))
        });

        assert!(matches!(
            result,
            Err(ChunkStoreError::Io(error)) if error.raw_os_error() == Some(crate::cache::test_support::InjectedIoFailure::ReadFailure.code())
        ));
        assert!(store.open_manifest(identity.hash()).unwrap().is_none());
        assert!(
            fs::read_dir(directory.path().join(super::super::MANIFEST_DIRECTORY))
                .unwrap()
                .next()
                .is_none(),
            "a failed chunk durability barrier must leave no manifest or staging record"
        );
    }

    #[test]
    fn reusing_durable_chunks_does_not_require_another_filesystem_barrier() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        store
            .store_nar(input.as_slice(), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();
        let mut writer = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        writer.write_all(&input).unwrap();
        let completed = writer
            .finish_with(identity, |_| {
                panic!("existing durable chunks must not request a barrier")
            })
            .unwrap();
        assert_eq!(
            completed.outcome(),
            super::super::publication::PublishOutcome::Identical
        );
    }

    #[test]
    fn chunks_left_by_a_failed_barrier_must_be_synchronized_on_retry() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        let mut failed = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        failed.write_all(&input).unwrap();
        assert!(
            failed
                .finish_with(identity, |_| Err(std::io::Error::from_raw_os_error(
                    crate::cache::test_support::InjectedIoFailure::ReadFailure.code()
                )))
                .is_err()
        );
        let mut retry = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        retry.write_all(&input).unwrap();
        let synchronized = std::cell::Cell::new(false);
        retry
            .finish_with(identity, |directory| {
                synchronized.set(true);
                store.durability.synchronize(directory)
            })
            .unwrap();
        assert!(
            synchronized.get(),
            "identical chunk bytes left by a failed barrier are not durability evidence"
        );
        assert!(store.validate_manifest(identity.hash()).unwrap().is_some());
    }

    #[test]
    fn chunks_linked_by_an_unfinished_upload_are_not_durability_evidence() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        let mut first = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        first.write_all(&input).unwrap();
        let unfinished = first
            .finish_pending_chunks()
            .unwrap()
            .verify_identity_and_record_coverage(identity)
            .unwrap();
        assert!(store.open_manifest(identity.hash()).unwrap().is_none());
        let mut second = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        second.write_all(&input).unwrap();
        let synchronized = std::cell::Cell::new(false);
        second
            .finish_with(identity, |directory| {
                synchronized.set(true);
                store.durability.synchronize(directory)
            })
            .unwrap();
        assert!(
            synchronized.get(),
            "the second upload cannot inherit the first upload's incomplete durability transition"
        );
        drop(unfinished);
        assert!(store.validate_manifest(identity.hash()).unwrap().is_some());
    }

    #[test]
    fn incorrect_identity_or_record_coverage_cannot_reach_the_durability_barrier() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        for expected in [
            NarIdentity::new(NarHash::from_digest([0; 32]), identity.size()),
            NarIdentity::new(identity.hash(), NarSize::new(1)),
        ] {
            let mut writer = store
                .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
                .unwrap();
            writer.write_all(&input).unwrap();
            assert!(
                writer
                    .finish_with(expected, |_| panic!(
                        "invalid identities cannot synchronize or publish"
                    ))
                    .is_err()
            );
        }
        let mut writer = store
            .begin_ingest_with_optional_reservation(ChunkProfile::MinCdcHash4V2, None, 0)
            .unwrap();
        writer.write_all(&input).unwrap();
        let mut finished = writer.finish_pending_chunks().unwrap();
        finished.writer.previous_end -= 1;
        assert!(matches!(
            finished.verify_identity_and_record_coverage(identity),
            Err(super::ChunkStoreError::NarSizeMismatch { .. })
        ));
        assert!(store.open_manifest(identity.hash()).unwrap().is_none());
        assert!(
            fs::read_dir(directory.path().join(super::super::MANIFEST_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );
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
            store.store_nar(Cursor::new(input), identity, ChunkProfile::MinCdcHash4V2),
            Err(ChunkStoreError::NarHashMismatch { .. })
        ));
    }

    #[test]
    fn failed_chunked_ingest_publishes_no_manifest_or_staging_record() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 2 * 1024 * 1024];
        let wrong_identity = NarIdentity::new(
            NarHash::from_digest([0; 32]),
            NarSize::new(input.len() as u64),
        );

        assert!(matches!(
            store.store_nar(
                Cursor::new(&input),
                wrong_identity,
                ChunkProfile::MinCdcHash4V2
            ),
            Err(ChunkStoreError::NarHashMismatch { .. })
        ));
        assert_eq!(
            fs::read_dir(directory.path().join(super::super::MANIFEST_DIRECTORY))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().unwrap().is_file())
                .count(),
            0,
            "failed ingestion must not publish a manifest"
        );

        drop(store);
        let restarted = ChunkStore::initialize(root.file()).unwrap();
        assert_eq!(
            fs::read_dir(directory.path().join(super::super::MANIFEST_DIRECTORY))
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            0,
            "restart must remove the private manifest record"
        );
        drop(restarted);
        assert!(
            fs::read_dir(directory.path().join(super::super::CHUNK_DIRECTORY))
                .unwrap()
                .flat_map(|shard| {
                    fs::read_dir(shard.unwrap().path())
                        .unwrap()
                        .filter_map(Result::ok)
                })
                .any(|entry| entry.file_type().unwrap().is_file()),
            "independently valid orphan chunks may remain for GC"
        );
    }

    struct FailingReader {
        bytes: Vec<u8>,
        sent: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.sent {
                return Err(std::io::Error::from_raw_os_error(
                    crate::cache::test_support::InjectedIoFailure::ReadFailure.code(),
                ));
            }
            let length = output.len().min(self.bytes.len());
            output[..length].copy_from_slice(&self.bytes[..length]);
            self.bytes.drain(..length);
            self.sent = true;
            Ok(length)
        }
    }

    #[test]
    fn source_failure_publishes_no_chunked_manifest_or_staging_record() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'y'; 2 * 1024 * 1024];
        let expected = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );

        assert!(matches!(
            store.store_nar(
                FailingReader {
                    bytes: input,
                    sent: false,
                },
                expected,
                ChunkProfile::MinCdcHash4V2
            ),
            Err(ChunkStoreError::Io(error)) if error.raw_os_error() == Some(crate::cache::test_support::InjectedIoFailure::ReadFailure.code())
        ));
        assert!(store.open_manifest(expected.hash()).unwrap().is_none());
        assert_eq!(
            fs::read_dir(directory.path().join(super::super::MANIFEST_DIRECTORY))
                .unwrap()
                .count(),
            0,
            "source failure must remove the manifest record"
        );
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
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
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
            .open_verified_reader(hash, 0..identity.size().get(), 1_000_000)
            .unwrap();
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
    }

    #[test]
    fn reingesting_repairs_a_corrupt_content_addressed_chunk() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();

        let shard = fs::read_dir(directory.path().join(super::super::CHUNK_DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let chunk = fs::read_dir(shard).unwrap().next().unwrap().unwrap().path();
        let mut corrupt = fs::read(&chunk).unwrap();
        corrupt[0] ^= 1;
        fs::write(chunk, corrupt).unwrap();

        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();
        store.verify_nar_content(identity).unwrap();
    }

    #[test]
    fn concurrent_reingests_accept_the_same_corrupt_chunk_repair() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();
        let hash = ChunkHash::from_digest(Sha256::digest(&input).into());
        let chunk_path = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::shard_name(hash))
            .join(super::chunk_name(hash));
        let mut corrupted = fs::read(&chunk_path).unwrap();
        corrupted[0] ^= 1;
        fs::write(&chunk_path, corrupted).unwrap();

        let start = Arc::new(Barrier::new(3));
        let outcomes = std::thread::scope(|scope| {
            let store = &store;
            let input = &input;
            let workers = (0..2)
                .map(|_| {
                    let start = Arc::clone(&start);
                    scope.spawn(move || {
                        start.wait();
                        store.store_chunk(hash, input)
                    })
                })
                .collect::<Vec<_>>();
            start.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap().unwrap().outcome)
                .collect::<Vec<_>>()
        });

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| matches!(
            outcome,
            super::super::publication::PublishOutcome::Created
                | super::super::publication::PublishOutcome::Identical
        )));
        let mut verified = store
            .open_verified_reader(identity.hash(), 0..identity.size().get(), 1_000_000)
            .unwrap();
        let mut repaired = Vec::new();
        verified.read_to_end(&mut repaired).unwrap();
        assert_eq!(repaired, input);
    }

    #[test]
    fn serving_open_skips_repair_lock_when_no_repair_is_active() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = Arc::new(ChunkStore::initialize(root.file()).unwrap());
        let bytes = b"verified chunk";
        let hash = ChunkHash::from_digest(Sha256::digest(bytes).into());
        store.store_chunk(hash, bytes).unwrap();

        let repair_lock = store.chunk_repair_lock(hash);
        let (sender, receiver) = mpsc::channel();
        let open_thread = std::thread::spawn({
            let store = Arc::clone(&store);
            move || sender.send(store.open_serving_chunk(hash)).unwrap()
        });
        let opened = receiver.recv_timeout(Duration::from_secs(2));
        drop(repair_lock);
        open_thread.join().unwrap();

        assert!(opened.unwrap().unwrap().is_some());
    }

    #[test]
    fn completed_repair_invalidates_an_open_started_before_it() {
        let activity = super::ChunkRepairActivity::default();
        let generation = activity.can_open_without_repair_lock().unwrap();

        drop(activity.begin_operation());

        assert!(!activity.remained_quiescent(generation));
    }

    #[test]
    fn collecting_a_chunk_also_clears_its_orphaned_repair_marker() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let orphaned_bytes = b"orphaned chunk";
        let orphaned_hash = ChunkHash::from_digest(Sha256::digest(orphaned_bytes).into());
        store.store_chunk(orphaned_hash, orphaned_bytes).unwrap();
        let orphaned_path = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::shard_name(orphaned_hash))
            .join(super::chunk_name(orphaned_hash));
        let mut corrupt_bytes = fs::read(&orphaned_path).unwrap();
        corrupt_bytes[0] ^= 1;
        fs::write(&orphaned_path, corrupt_bytes).unwrap();
        assert!(
            store
                .store_chunk_with_sync(orphaned_hash, orphaned_bytes, |_| {
                    Err(std::io::Error::from_raw_os_error(
                        crate::cache::test_support::InjectedIoFailure::ReadFailure.code(),
                    ))
                })
                .is_err()
        );

        let unrelated_bytes = (0..256)
            .map(|candidate| format!("retained chunk {candidate}").into_bytes())
            .find(|bytes| {
                let hash = ChunkHash::from_digest(Sha256::digest(bytes).into());
                super::chunk_repair_stripe(orphaned_hash) == super::chunk_repair_stripe(hash)
            })
            .expect("a matching repair stripe exists");
        let unrelated_identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&unrelated_bytes).into()),
            NarSize::new(unrelated_bytes.len() as u64),
        );
        let unrelated_hash = ChunkHash::from_digest(Sha256::digest(&unrelated_bytes).into());
        assert_eq!(
            super::chunk_repair_stripe(orphaned_hash),
            super::chunk_repair_stripe(unrelated_hash)
        );
        store
            .store_nar(
                Cursor::new(&unrelated_bytes),
                unrelated_identity,
                super::ChunkProfile::MinCdcHash4V2,
            )
            .unwrap();

        let marker = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::chunk_repair_marker_name(orphaned_hash));
        assert!(marker.exists());
        store
            .sweep_unreachable([unrelated_identity.hash()])
            .unwrap();

        assert!(!marker.exists());
        assert_eq!(
            store
                .chunk_repair_activity(unrelated_hash)
                .pending_markers
                .load(Ordering::SeqCst),
            0
        );
        let _repair_lock = store.chunk_repair_lock(unrelated_hash);
        assert!(store.open_serving_chunk(unrelated_hash).unwrap().is_some());
    }

    #[test]
    fn failed_chunk_repair_sync_is_retried_before_existing_manifest_is_reused() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'y'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();
        let hash = ChunkHash::from_digest(Sha256::digest(&input).into());
        let chunk_path = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::shard_name(hash))
            .join(super::chunk_name(hash));
        let mut corrupted = fs::read(&chunk_path).unwrap();
        corrupted[0] ^= 1;
        fs::write(&chunk_path, corrupted).unwrap();

        let failed_repair = store.store_chunk_with_sync(hash, &input, |_| {
            Err(std::io::Error::from_raw_os_error(
                crate::cache::test_support::InjectedIoFailure::ReadFailure.code(),
            ))
        });
        assert!(failed_repair.is_err());
        let marker = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::chunk_repair_marker_name(hash));
        assert!(
            marker.exists(),
            "failed repair retains its durability marker"
        );
        assert!(store.validate_manifest(identity.hash()).unwrap().is_some());

        drop(store);
        let store = ChunkStore::initialize(root.file()).unwrap();
        assert_eq!(
            store
                .chunk_repair_activity(hash)
                .pending_markers
                .load(Ordering::SeqCst),
            1,
            "reopening counts a durable repair marker before enabling serving fast paths"
        );

        let synchronized = std::cell::Cell::new(false);
        let retry = store
            .store_chunk_with_sync(hash, &input, |shard| {
                synchronized.set(true);
                shard.sync_all()
            })
            .unwrap();
        assert_eq!(
            retry.outcome,
            super::super::publication::PublishOutcome::Identical
        );
        assert!(synchronized.get(), "retry settles the pending repair first");
        assert!(!marker.exists());
        assert_eq!(
            store
                .chunk_repair_activity(hash)
                .pending_markers
                .load(Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn read_through_validation_reuses_the_complete_nar_proof() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let input = vec![b'x'; 100_000];
        let identity = NarIdentity::new(
            NarHash::from_digest(Sha256::digest(&input).into()),
            NarSize::new(input.len() as u64),
        );
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();

        store.verify_nar_content(identity).unwrap();
        store.verify_nar_content(identity).unwrap();

        assert_eq!(store.nar_content_hashes(), 1);
    }

    #[test]
    fn chunk_proof_is_not_cached_if_the_file_changes_after_its_bytes_were_read() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let path = directory.path().join("racing-chunk");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let verified_bytes = b"verified chunk contents";
        file.write_all(verified_bytes).unwrap();
        file.sync_all().unwrap();
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut observed_bytes = vec![0; verified_bytes.len()];
        file.read_exact(&mut observed_bytes).unwrap();
        let observed_stamp = FileStamp::from_file(&file).unwrap();
        let hash = ChunkHash::from_digest(Sha256::digest(&observed_bytes).into());

        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.write_all(b"bad data chunk contents").unwrap();
        file.sync_all().unwrap();

        assert!(
            store
                .cache_verified_chunk(hash, &file, observed_stamp, &observed_bytes)
                .is_err()
        );
        assert!(!store.chunk_stamp_is_verified(hash, FileStamp::from_file(&file).unwrap()));
    }

    #[test]
    fn range_reader_does_not_open_chunks_outside_the_requested_range() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let store = ChunkStore::initialize(root.file()).unwrap();
        let mut state = 0x1234_5678_u32;
        let input = (0..(3 * 1024 * 1024))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect::<Vec<_>>();
        let hash = NarHash::from_digest(Sha256::digest(&input).into());
        let identity = NarIdentity::new(hash, NarSize::new(input.len() as u64));
        store
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
            .unwrap();

        let manifest_file = store.open_manifest(hash).unwrap().unwrap();
        let mut manifest = ManifestReader::new(manifest_file, 1_000_000).unwrap();
        let first = manifest.next_record().unwrap().unwrap();
        let second = manifest.next_record().unwrap().unwrap();
        assert_ne!(first.hash(), second.hash());

        let second_chunk = directory
            .path()
            .join(super::super::CHUNK_DIRECTORY)
            .join(super::shard_name(second.hash()))
            .join(super::chunk_name(second.hash()));
        fs::remove_file(second_chunk).unwrap();

        let mut output = Vec::new();
        store
            .read_range(hash, 0..first.end(), 1_000_000, &mut output)
            .unwrap();
        assert_eq!(output, input[..first.end() as usize]);
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
            .store_nar(Cursor::new(&input), identity, ChunkProfile::MinCdcHash4V2)
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
                ChunkProfile::MinCdcHash4V2,
            )
            .unwrap();
        store
            .store_nar(
                Cursor::new(&second),
                NarIdentity::new(second_hash, (second.len() as u64).into()),
                ChunkProfile::MinCdcHash4V2,
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
    fn abandoned_temp_cleanup_preserves_nonmatching_entries_and_symlink_targets() {
        for prefix in [".manifest-", ".chunk-"] {
            let root = tempdir().unwrap();
            let directory = crate::cache::filesystem::open_directory(root.path()).unwrap();
            std::fs::write(root.path().join("keep"), b"published content").unwrap();
            std::fs::write(root.path().join(".unrelated"), b"unrelated content").unwrap();
            let temporary = format!("{prefix}abandoned");
            let link = format!("{prefix}link");
            std::fs::write(root.path().join(&temporary), b"staging").unwrap();
            std::os::unix::fs::symlink("keep", root.path().join(&link)).unwrap();

            assert!(remove_abandoned_temps(&directory, prefix).unwrap());
            assert_eq!(
                std::fs::read(root.path().join("keep")).unwrap(),
                b"published content"
            );
            assert_eq!(
                std::fs::read(root.path().join(".unrelated")).unwrap(),
                b"unrelated content"
            );
            assert!(!root.path().join(temporary).exists());
            assert!(std::fs::symlink_metadata(root.path().join(link)).is_err());
            assert!(
                !remove_abandoned_temps(&directory, prefix).unwrap(),
                "retry finds no staged entries"
            );
        }
    }

    #[test]
    fn recovery_completion_removes_abandoned_chunk_and_manifest_temps() {
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
            FileAccess::Write,
            FileCreation::CreateNew,
            FilePrivacy::Private,
        )
        .unwrap();
        chunk.write_all(b"abandoned").unwrap();
        let mut manifest = super::super::fs::open_at(
            &store.manifests,
            manifest_temp,
            FileAccess::Write,
            FileCreation::CreateNew,
            FilePrivacy::Private,
        )
        .unwrap();
        manifest.write_all(b"abandoned").unwrap();
        drop(store);

        let restarted = ChunkStore::initialize(root.file()).unwrap();
        let shard = restarted
            .open_shard(ChunkHash::from_digest([0; 32]))
            .unwrap();
        assert!(
            super::super::fs::open_regular_at(&shard, chunk_temp).is_ok(),
            "storage construction must leave journal-owned staging intact"
        );
        restarted.remove_abandoned_temporary_files().unwrap();
        assert!(super::super::fs::open_regular_at(&shard, chunk_temp).is_err());
        assert!(super::super::fs::open_regular_at(&restarted.manifests, manifest_temp).is_err());
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &ChunkStoreError::InvalidRange {
                    start: 3,
                    end: 9,
                    size: 8,
                },
                "range 3..9 is outside NAR size 8",
            ),
            (
                &ChunkStoreError::NarHashMismatch {
                    expected: NarHash::from_digest([1; 32]),
                    actual: NarHash::from_digest([2; 32]),
                },
                "chunked NAR hash mismatch",
            ),
            (
                &ChunkStoreError::NarSizeMismatch {
                    expected: 8,
                    actual: 9,
                },
                "chunked NAR size mismatch",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_manifest_source_chain_keeps_each_layer() {
        use std::error::Error as _;
        let error = ChunkStoreError::from(ManifestError::from(io::Error::other("read failure")));
        assert_eq!(error.to_string(), "read failure");
        let manifest = error.source().unwrap();
        assert!(manifest.is::<ManifestError>());
        assert_eq!(manifest.to_string(), "read failure");
        let io = manifest.source().unwrap();
        assert!(io.is::<io::Error>());
        assert_eq!(io.to_string(), "read failure");
        assert!(io.source().is_none());
        let direct = ChunkStoreError::from(io::Error::other("direct failure"));
        assert_eq!(direct.to_string(), "direct failure");
        assert!(direct.source().unwrap().is::<io::Error>());
    }
}
