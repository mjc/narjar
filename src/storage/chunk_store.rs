use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use crate::object::{NarHash, NarIdentity};

use super::{
    chunked::{ChunkHash, ChunkManifest, ChunkProfile, ManifestError, chunk_stream},
    fs::{ensure_directory_at, files_equal_at, hard_link_at, open_at, open_regular_at, unlink_at},
};

const CHUNK_DIRECTORY: &str = ".narjar-chunks";
const MANIFEST_DIRECTORY: &str = ".narjar-manifests";
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
        source: R,
        identity: NarIdentity,
        profile: ChunkProfile,
    ) -> Result<ChunkManifest, ChunkStoreError> {
        let mut manifest = ChunkManifest::new(identity, profile);
        let mut nar_hasher = Sha256::new();
        let total_size = chunk_stream(source, profile, |end, hash, bytes| {
            nar_hasher.update(bytes);
            self.store_chunk(hash, bytes)?;
            manifest.push_chunk(end, hash).map_err(io_for_manifest)
        })?;
        let actual_size = identity.size().get();
        if total_size != actual_size {
            return Err(ChunkStoreError::NarSizeMismatch {
                expected: actual_size,
                actual: total_size,
            });
        }
        let actual_hash = NarHash::from_digest(nar_hasher.finalize().into());
        if actual_hash != identity.hash() {
            return Err(ChunkStoreError::NarHashMismatch {
                expected: identity.hash(),
                actual: actual_hash,
            });
        }
        let manifest = manifest.finish()?;
        self.publish_manifest(&manifest)?;
        Ok(manifest)
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

    fn store_chunk(&self, hash: ChunkHash, bytes: &[u8]) -> io::Result<()> {
        let shard = self.open_or_create_shard(hash)?;
        publish_immutable_bytes(&shard, &chunk_name(hash), CHUNK_TEMP_PREFIX, bytes)
    }

    fn publish_manifest(&self, manifest: &ChunkManifest) -> Result<(), ChunkStoreError> {
        let bytes = manifest.encode()?;
        publish_immutable_bytes(
            &self.manifests,
            &manifest_name(manifest.identity().hash()),
            MANIFEST_TEMP_PREFIX,
            &bytes,
        )
        .map_err(Into::into)
    }

    fn open_or_create_shard(&self, hash: ChunkHash) -> io::Result<File> {
        ensure_directory_at(&self.chunks, OsStr::new(&shard_name(hash)), "chunk shard")
    }

    fn open_shard(&self, hash: ChunkHash) -> io::Result<File> {
        super::fs::open_directory_at(&self.chunks, OsStr::new(&shard_name(hash)))
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

fn io_for_manifest(error: ManifestError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[derive(Debug)]
pub(crate) enum ChunkStoreError {
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
        assert!(
            manifest
                .chunks()
                .iter()
                .all(|chunk| store.open_chunk(chunk.hash()).unwrap().is_some())
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
            store.store_nar(Cursor::new(input), identity, ChunkProfile::MinCdcHash4V1),
            Err(ChunkStoreError::NarHashMismatch { .. })
        ));
    }
}
