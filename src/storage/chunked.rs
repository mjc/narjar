use std::{fmt, io, io::Read};

use mincdc::{MinCdcHash4, ReadChunker};
use sha2::{Digest, Sha256};

use crate::object::{NarHash, NarIdentity, NarSize};

const MANIFEST_MAGIC: &[u8; 8] = b"NARJCHNK";
const MANIFEST_VERSION: u8 = 1;
const MANIFEST_HEADER_BYTES: usize = 60;
const MANIFEST_RECORD_BYTES: usize = 40;
const MANIFEST_CHECKSUM_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ChunkHash([u8; 32]);

impl ChunkHash {
    pub(crate) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChunkProfile {
    MinCdcHash4V1,
}

impl ChunkProfile {
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::MinCdcHash4V1 => 1,
        }
    }

    pub(crate) const fn min_size(self) -> u64 {
        match self {
            Self::MinCdcHash4V1 => 8 * 1024,
        }
    }

    pub(crate) const fn max_size(self) -> u64 {
        match self {
            Self::MinCdcHash4V1 => 24 * 1024,
        }
    }

    fn from_id(id: u8) -> Result<Self, ManifestError> {
        match id {
            1 => Ok(Self::MinCdcHash4V1),
            _ => Err(ManifestError::UnsupportedProfile(id)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChunkDescriptor {
    end: u64,
    hash: ChunkHash,
}

impl ChunkDescriptor {
    pub(crate) const fn end(self) -> u64 {
        self.end
    }

    pub(crate) const fn hash(self) -> ChunkHash {
        self.hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkManifest {
    identity: NarIdentity,
    profile: ChunkProfile,
    chunks: Vec<ChunkDescriptor>,
}

impl ChunkManifest {
    pub(crate) fn new(identity: NarIdentity, profile: ChunkProfile) -> Self {
        Self {
            identity,
            profile,
            chunks: Vec::new(),
        }
    }

    pub(crate) fn push_chunk(&mut self, end: u64, hash: ChunkHash) -> Result<(), ManifestError> {
        let previous_end = self.chunks.last().map_or(0, |chunk| chunk.end);
        let length = end
            .checked_sub(previous_end)
            .ok_or(ManifestError::NonMonotonicEnds)?;
        if length == 0 || length > self.profile.max_size() || end > self.identity.size().get() {
            return Err(ManifestError::InvalidChunkLength);
        }
        self.chunks.push(ChunkDescriptor { end, hash });
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Self, ManifestError> {
        let final_end = self.chunks.last().map_or(0, |chunk| chunk.end);
        if final_end != self.identity.size().get() {
            return Err(ManifestError::FinalSizeMismatch {
                expected: self.identity.size().get(),
                actual: final_end,
            });
        }
        let non_final_chunk_is_too_small = self
            .chunks
            .iter()
            .scan(0_u64, |previous_end, chunk| {
                let length = chunk.end - *previous_end;
                *previous_end = chunk.end;
                Some(length)
            })
            .take(self.chunks.len().saturating_sub(1))
            .any(|length| length < self.profile.min_size());
        if non_final_chunk_is_too_small {
            return Err(ManifestError::InvalidChunkLength);
        }
        Ok(self)
    }

    pub(crate) const fn identity(&self) -> NarIdentity {
        self.identity
    }

    pub(crate) const fn profile(&self) -> ChunkProfile {
        self.profile
    }

    pub(crate) fn chunks(&self) -> &[ChunkDescriptor] {
        &self.chunks
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut bytes = Vec::with_capacity(
            MANIFEST_HEADER_BYTES
                .checked_add(
                    self.chunks
                        .len()
                        .checked_mul(MANIFEST_RECORD_BYTES)
                        .ok_or(ManifestError::LengthOverflow)?,
                )
                .and_then(|length| length.checked_add(MANIFEST_CHECKSUM_BYTES))
                .ok_or(ManifestError::LengthOverflow)?,
        );
        bytes.extend_from_slice(MANIFEST_MAGIC);
        bytes.push(MANIFEST_VERSION);
        bytes.push(self.profile.id());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&self.identity.hash().bytes_for_storage());
        bytes.extend_from_slice(&self.identity.size().get().to_le_bytes());
        let chunk_count =
            u64::try_from(self.chunks.len()).map_err(|_| ManifestError::LengthOverflow)?;
        bytes.extend_from_slice(&chunk_count.to_le_bytes());
        for chunk in &self.chunks {
            bytes.extend_from_slice(&chunk.end.to_le_bytes());
            bytes.extend_from_slice(&chunk.hash.bytes());
        }
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() < MANIFEST_HEADER_BYTES + MANIFEST_CHECKSUM_BYTES {
            return Err(ManifestError::Truncated);
        }
        if &bytes[..MANIFEST_MAGIC.len()] != MANIFEST_MAGIC {
            return Err(ManifestError::InvalidMagic);
        }
        if bytes[8] != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion(bytes[8]));
        }
        if bytes[10..12] != [0, 0] {
            return Err(ManifestError::InvalidHeader);
        }

        let profile = ChunkProfile::from_id(bytes[9])?;
        let nar_hash = NarHash::from_storage_bytes(bytes[12..44].try_into().unwrap());
        let nar_size = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
        let chunk_count = u64::from_le_bytes(bytes[52..60].try_into().unwrap());
        let chunk_count =
            usize::try_from(chunk_count).map_err(|_| ManifestError::LengthOverflow)?;
        let records_bytes = chunk_count
            .checked_mul(MANIFEST_RECORD_BYTES)
            .ok_or(ManifestError::LengthOverflow)?;
        let content_bytes = MANIFEST_HEADER_BYTES
            .checked_add(records_bytes)
            .ok_or(ManifestError::LengthOverflow)?;
        let expected_length = content_bytes
            .checked_add(MANIFEST_CHECKSUM_BYTES)
            .ok_or(ManifestError::LengthOverflow)?;
        if bytes.len() != expected_length {
            return Err(if bytes.len() < expected_length {
                ManifestError::Truncated
            } else {
                ManifestError::TrailingBytes
            });
        }
        let expected_checksum = Sha256::digest(&bytes[..content_bytes]);
        if bytes[content_bytes..] != expected_checksum[..] {
            return Err(ManifestError::ChecksumMismatch);
        }

        let identity = NarIdentity::new(nar_hash, NarSize::new(nar_size));
        let mut manifest = Self::new(identity, profile);
        let (records, remainder) =
            bytes[MANIFEST_HEADER_BYTES..content_bytes].as_chunks::<MANIFEST_RECORD_BYTES>();
        debug_assert!(remainder.is_empty());
        for record in records {
            let end = u64::from_le_bytes(record[..8].try_into().unwrap());
            let hash = ChunkHash::from_digest(record[8..].try_into().unwrap());
            manifest.push_chunk(end, hash)?;
        }
        manifest.finish()
    }
}

pub(crate) fn chunk_stream<R, F>(source: R, profile: ChunkProfile, on_chunk: F) -> io::Result<u64>
where
    R: Read,
    F: FnMut(u64, ChunkHash, &[u8]) -> io::Result<()>,
{
    match profile {
        ChunkProfile::MinCdcHash4V1 => chunk_stream_with(source, MinCdcHash4::new(), on_chunk),
    }
}

fn chunk_stream_with<R, C, F>(source: R, cdc: C, mut on_chunk: F) -> io::Result<u64>
where
    R: Read,
    C: mincdc::Cdc,
    F: FnMut(u64, ChunkHash, &[u8]) -> io::Result<()>,
{
    let mut chunker = ReadChunker::new(source, 8 * 1024, 24 * 1024, cdc);
    let mut end = 0_u64;
    while let Some(chunk) = chunker.next()? {
        let chunk_bytes: &[u8] = &chunk;
        let chunk_length = u64::try_from(chunk_bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk is too large"))?;
        end = end
            .checked_add(chunk_length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        let hash = ChunkHash::from_digest(Sha256::digest(chunk_bytes).into());
        on_chunk(end, hash, chunk_bytes)?;
    }
    Ok(end)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ManifestError {
    ChecksumMismatch,
    FinalSizeMismatch { expected: u64, actual: u64 },
    InvalidChunkLength,
    InvalidHeader,
    InvalidMagic,
    LengthOverflow,
    NonMonotonicEnds,
    TrailingBytes,
    Truncated,
    UnsupportedProfile(u8),
    UnsupportedVersion(u8),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChecksumMismatch => formatter.write_str("chunk manifest checksum mismatch"),
            Self::FinalSizeMismatch { expected, actual } => write!(
                formatter,
                "chunk manifest ends at {actual} bytes, expected {expected}"
            ),
            Self::InvalidChunkLength => formatter.write_str("invalid chunk length"),
            Self::InvalidHeader => formatter.write_str("invalid chunk manifest header"),
            Self::InvalidMagic => formatter.write_str("invalid chunk manifest magic"),
            Self::LengthOverflow => formatter.write_str("chunk manifest length overflow"),
            Self::NonMonotonicEnds => formatter.write_str("chunk manifest ends are not increasing"),
            Self::TrailingBytes => formatter.write_str("trailing bytes after chunk manifest"),
            Self::Truncated => formatter.write_str("truncated chunk manifest"),
            Self::UnsupportedProfile(profile) => {
                write!(formatter, "unsupported chunk profile {profile}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported chunk manifest version {version}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{ChunkHash, ChunkManifest, ChunkProfile, ManifestError, chunk_stream};
    use crate::object::{NarHash, NarIdentity, NarSize};

    const HASH: NarHash = NarHash::from_digest([7; 32]);

    fn manifest(size: u64) -> ChunkManifest {
        ChunkManifest::new(
            NarIdentity::new(HASH, NarSize::new(size)),
            ChunkProfile::MinCdcHash4V1,
        )
    }

    #[test]
    fn manifest_round_trips_repeated_chunk_hashes() {
        let hash = ChunkHash::from_digest([9; 32]);
        let mut manifest = manifest(8_200);
        manifest.push_chunk(8_192, hash).unwrap();
        manifest.push_chunk(8_200, hash).unwrap();
        let manifest = manifest.finish().unwrap();
        let decoded = ChunkManifest::decode(&manifest.encode().unwrap()).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.identity(), manifest.identity());
        assert_eq!(decoded.profile(), ChunkProfile::MinCdcHash4V1);
        assert_eq!(decoded.chunks()[0].end(), 8_192);
        assert_eq!(decoded.chunks()[0].hash(), hash);
    }

    #[test]
    fn manifest_rejects_bad_checksum_and_trailing_bytes() {
        let hash = ChunkHash::from_digest([9; 32]);
        let mut manifest = manifest(8);
        manifest.push_chunk(8, hash).unwrap();
        let manifest = manifest.finish().unwrap();
        let encoded = manifest.encode().unwrap();
        let mut corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assert_eq!(
            ChunkManifest::decode(&corrupt),
            Err(ManifestError::ChecksumMismatch)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ChunkManifest::decode(&trailing),
            Err(ManifestError::TrailingBytes)
        );
    }

    #[test]
    fn chunk_stream_is_independent_of_source_read_boundaries() {
        let input = vec![b'x'; 100_000];
        let mut first = Vec::new();
        let mut second = Vec::new();
        chunk_stream(
            Cursor::new(&input),
            ChunkProfile::MinCdcHash4V1,
            |end, hash, _| {
                first.push((end, hash));
                Ok(())
            },
        )
        .unwrap();
        chunk_stream(
            FragmentedReader::new(&input, 17),
            ChunkProfile::MinCdcHash4V1,
            |end, hash, _| {
                second.push((end, hash));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(first, second);
    }

    struct FragmentedReader<'a> {
        input: &'a [u8],
        position: usize,
        fragment: usize,
    }

    impl<'a> FragmentedReader<'a> {
        fn new(input: &'a [u8], fragment: usize) -> Self {
            Self {
                input,
                position: 0,
                fragment,
            }
        }
    }

    impl std::io::Read for FragmentedReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.position == self.input.len() {
                return Ok(0);
            }
            let length = self
                .fragment
                .min(output.len())
                .min(self.input.len() - self.position);
            output[..length].copy_from_slice(&self.input[self.position..self.position + length]);
            self.position += length;
            Ok(length)
        }
    }
}
