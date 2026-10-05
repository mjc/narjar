use std::{io, io::Read, io::Seek, io::SeekFrom, io::Write};

use sha2::{Digest, Sha256};

use crate::object::{NarHash, NarIdentity, NarSize, Sha256Digest};

pub(crate) const MANIFEST_MAGIC: &[u8; 8] = b"NARJCHNK";
pub(crate) const MANIFEST_VERSION: u8 = 1;
pub(crate) const MANIFEST_HEADER_BYTES: usize = 60;
pub(crate) const MANIFEST_RECORD_BYTES: usize = 40;
pub(crate) const MANIFEST_CHECKSUM_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ChunkContent {}

pub(crate) type ChunkHash = Sha256Digest<ChunkContent>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChunkProfile {
    MinCdcHash4V2,
}

impl ChunkProfile {
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::MinCdcHash4V2 => 2,
        }
    }
    pub(crate) const fn min_size(self) -> u64 {
        match self {
            Self::MinCdcHash4V2 => 256 * 1024,
        }
    }
    pub(crate) const fn max_size(self) -> u64 {
        match self {
            Self::MinCdcHash4V2 => 1024 * 1024,
        }
    }

    fn from_id(id: u8) -> Result<Self, ManifestError> {
        match id {
            2 => Ok(Self::MinCdcHash4V2),
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
    pub(crate) const fn new(end: u64, hash: ChunkHash) -> Self {
        Self { end, hash }
    }
    pub(crate) const fn end(self) -> u64 {
        self.end
    }
    pub(crate) const fn hash(self) -> ChunkHash {
        self.hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChunkManifest {
    identity: NarIdentity,
    profile: ChunkProfile,
    chunk_count: u64,
}

impl ChunkManifest {
    pub(crate) const fn new(
        identity: NarIdentity,
        profile: ChunkProfile,
        chunk_count: u64,
    ) -> Self {
        Self {
            identity,
            profile,
            chunk_count,
        }
    }
    pub(crate) const fn identity(self) -> NarIdentity {
        self.identity
    }
    pub(crate) const fn profile(self) -> ChunkProfile {
        self.profile
    }
    pub(crate) const fn chunk_count(self) -> u64 {
        self.chunk_count
    }
}

pub(crate) struct ManifestReader<R> {
    reader: R,
    manifest: ChunkManifest,
    records_remaining: u64,
    previous_end: u64,
    previous_length: Option<u64>,
    content_hasher: Sha256,
}

impl<R: Read + Seek> ManifestReader<R> {
    pub(crate) fn new(mut reader: R, max_bytes: u64) -> Result<Self, ManifestError> {
        let file_length = reader.seek(SeekFrom::End(0))?;
        if file_length > max_bytes {
            return Err(ManifestError::LengthOverflow);
        }
        reader.seek(SeekFrom::Start(0))?;

        let mut header = [0_u8; MANIFEST_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        let (manifest, content_bytes) = parse_header(&header)?;
        let expected_length = content_bytes
            .checked_add(MANIFEST_CHECKSUM_BYTES)
            .ok_or(ManifestError::LengthOverflow)?;
        let expected_length =
            u64::try_from(expected_length).map_err(|_| ManifestError::LengthOverflow)?;
        if file_length != expected_length {
            return Err(if file_length < expected_length {
                ManifestError::Truncated
            } else {
                ManifestError::TrailingBytes
            });
        }

        Ok(Self {
            reader,
            manifest,
            records_remaining: manifest.chunk_count(),
            previous_end: 0,
            previous_length: None,
            content_hasher: Sha256::new_with_prefix(header),
        })
    }

    pub(crate) const fn manifest(&self) -> ChunkManifest {
        self.manifest
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<ChunkDescriptor>, ManifestError> {
        if self.records_remaining == 0 {
            return Ok(None);
        }
        let mut bytes = [0_u8; MANIFEST_RECORD_BYTES];
        self.reader.read_exact(&mut bytes)?;
        self.content_hasher.update(bytes);
        let descriptor = parse_record(&bytes)?;
        self.validate_descriptor(descriptor)?;
        self.records_remaining -= 1;
        Ok(Some(descriptor))
    }

    pub(crate) fn finish_remaining(self) -> Result<(), ManifestError> {
        let mut reader = self;
        let records_remaining = reader.records_remaining;
        (0..records_remaining).try_for_each(|_| reader.next_record().map(|_| ()))?;
        reader.finish()
    }

    fn finish(self) -> Result<(), ManifestError> {
        let Self {
            mut reader,
            manifest,
            records_remaining,
            previous_end,
            content_hasher,
            ..
        } = self;
        if records_remaining != 0 {
            return Err(ManifestError::InvalidHeader);
        }

        if previous_end != manifest.identity().size().get() {
            return Err(ManifestError::FinalSizeMismatch {
                expected: manifest.identity().size().get(),
                actual: previous_end,
            });
        }

        let mut expected_checksum = [0_u8; MANIFEST_CHECKSUM_BYTES];
        reader.read_exact(&mut expected_checksum)?;
        (content_hasher.finalize().as_slice() == expected_checksum)
            .then_some(())
            .ok_or(ManifestError::ChecksumMismatch)
    }

    fn validate_descriptor(&mut self, descriptor: ChunkDescriptor) -> Result<(), ManifestError> {
        let length = descriptor
            .end()
            .checked_sub(self.previous_end)
            .ok_or(ManifestError::NonMonotonicEnds)?;
        if length == 0
            || length > self.manifest.profile().max_size()
            || descriptor.end() > self.manifest.identity().size().get()
        {
            return Err(ManifestError::InvalidChunkLength);
        }
        if self
            .previous_length
            .is_some_and(|previous| previous < self.manifest.profile().min_size())
        {
            return Err(ManifestError::InvalidChunkLength);
        }
        self.previous_end = descriptor.end();
        self.previous_length = Some(length);
        Ok(())
    }
}

fn parse_header(bytes: &[u8]) -> Result<(ChunkManifest, usize), ManifestError> {
    if bytes.len() < MANIFEST_HEADER_BYTES {
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
    let hash = NarHash::from_digest(bytes[12..44].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
    let count = u64::from_le_bytes(bytes[52..60].try_into().unwrap());
    let records = usize::try_from(count)
        .map_err(|_| ManifestError::LengthOverflow)?
        .checked_mul(MANIFEST_RECORD_BYTES)
        .ok_or(ManifestError::LengthOverflow)?;
    let content_bytes = MANIFEST_HEADER_BYTES
        .checked_add(records)
        .ok_or(ManifestError::LengthOverflow)?;
    Ok((
        ChunkManifest::new(NarIdentity::new(hash, NarSize::new(size)), profile, count),
        content_bytes,
    ))
}

pub(crate) fn parse_record(bytes: &[u8]) -> Result<ChunkDescriptor, ManifestError> {
    if bytes.len() != MANIFEST_RECORD_BYTES {
        return Err(ManifestError::Truncated);
    }
    Ok(ChunkDescriptor::new(
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        ChunkHash::from_digest(bytes[8..].try_into().unwrap()),
    ))
}

pub(crate) fn write_manifest_header<W: Write>(
    writer: &mut W,
    manifest: ChunkManifest,
) -> Result<(), ManifestError> {
    writer.write_all(MANIFEST_MAGIC)?;
    writer.write_all(&[MANIFEST_VERSION, manifest.profile.id(), 0, 0])?;
    writer.write_all(&manifest.identity.hash().bytes())?;
    writer.write_all(&manifest.identity.size().get().to_le_bytes())?;
    writer.write_all(&manifest.chunk_count.to_le_bytes())?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManifestError {
    #[error("chunk manifest checksum mismatch")]
    ChecksumMismatch,
    #[error("chunk manifest ends at {actual} bytes, expected {expected}")]
    FinalSizeMismatch { expected: u64, actual: u64 },
    #[error("invalid chunk length")]
    InvalidChunkLength,
    #[error("invalid chunk manifest header")]
    InvalidHeader,
    #[error("invalid chunk manifest magic")]
    InvalidMagic,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("chunk manifest length overflow")]
    LengthOverflow,
    #[error("chunk manifest ends are not increasing")]
    NonMonotonicEnds,
    #[error("trailing bytes after chunk manifest")]
    TrailingBytes,
    #[error("truncated chunk manifest")]
    Truncated,
    #[error("unsupported chunk profile {0}")]
    UnsupportedProfile(u8),
    #[error("unsupported chunk manifest version {0}")]
    UnsupportedVersion(u8),
}

impl PartialEq for ManifestError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => left.kind() == right.kind(),
            (
                Self::FinalSizeMismatch {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::FinalSizeMismatch {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (Self::UnsupportedProfile(left), Self::UnsupportedProfile(right)) => left == right,
            (Self::UnsupportedVersion(left), Self::UnsupportedVersion(right)) => left == right,
            (Self::ChecksumMismatch, Self::ChecksumMismatch)
            | (Self::InvalidChunkLength, Self::InvalidChunkLength)
            | (Self::InvalidHeader, Self::InvalidHeader)
            | (Self::InvalidMagic, Self::InvalidMagic)
            | (Self::LengthOverflow, Self::LengthOverflow)
            | (Self::NonMonotonicEnds, Self::NonMonotonicEnds)
            | (Self::TrailingBytes, Self::TrailingBytes)
            | (Self::Truncated, Self::Truncated) => true,
            _ => false,
        }
    }
}

impl Eq for ManifestError {}

#[cfg(test)]
mod tests {
    use super::{
        ChunkDescriptor, ChunkHash, ChunkManifest, ChunkProfile, MANIFEST_CHECKSUM_BYTES,
        MANIFEST_HEADER_BYTES, MANIFEST_RECORD_BYTES, ManifestError, ManifestReader,
        write_manifest_header,
    };
    use crate::object::{NarHash, NarIdentity, NarSize};
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    const HASH: NarHash = NarHash::from_digest([7; 32]);
    fn identity(size: u64) -> NarIdentity {
        NarIdentity::new(HASH, NarSize::new(size))
    }

    fn encoded_manifest(manifest: ChunkManifest, records: &[ChunkHash]) -> Vec<u8> {
        let mut content = Vec::new();
        write_manifest_header(&mut content, manifest).unwrap();
        let mut end = 0_u64;
        records.iter().enumerate().for_each(|(index, hash)| {
            end += if index + 1 == records.len() {
                manifest.identity().size().get() - end
            } else {
                manifest.profile().min_size()
            };
            content.extend_from_slice(&end.to_le_bytes());
            content.extend_from_slice(&hash.bytes());
        });
        let checksum = Sha256::digest(&content);
        content.extend_from_slice(&checksum);
        content
    }

    fn read_manifest(bytes: &[u8]) -> Result<ChunkManifest, ManifestError> {
        let reader = ManifestReader::new(Cursor::new(bytes), u64::MAX)?;
        let manifest = reader.manifest();
        reader.finish_remaining()?;
        Ok(manifest)
    }

    #[test]
    fn production_chunk_profile_is_versioned_and_bounded() {
        assert_eq!(ChunkProfile::MinCdcHash4V2.id(), 2);
        assert_eq!(ChunkProfile::MinCdcHash4V2.min_size(), 256 * 1024);
        assert_eq!(ChunkProfile::MinCdcHash4V2.max_size(), 1024 * 1024);
        assert_eq!(
            ChunkProfile::from_id(1),
            Err(ManifestError::UnsupportedProfile(1))
        );
        let manifest = ChunkManifest::new(identity(0), ChunkProfile::MinCdcHash4V2, 0);
        let mut bytes = encoded_manifest(manifest, &[]);
        bytes[9] = 1;
        assert_eq!(
            read_manifest(&bytes),
            Err(ManifestError::UnsupportedProfile(1))
        );
        bytes[8] = 2;
        assert_eq!(
            read_manifest(&bytes),
            Err(ManifestError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn manifest_round_trips_without_retaining_records() {
        let hash = ChunkHash::from_digest([9; 32]);
        let profile = ChunkProfile::MinCdcHash4V2;
        let first_end = profile.min_size();
        let manifest = ChunkManifest::new(identity(first_end + 8), profile, 2);
        let encoded = encoded_manifest(manifest, &[hash, hash]);
        let mut reader = ManifestReader::new(Cursor::new(encoded), u64::MAX).unwrap();
        assert_eq!(reader.manifest(), manifest);
        assert_eq!(reader.manifest().chunk_count(), 2);
        assert_eq!(
            reader.next_record().unwrap(),
            Some(ChunkDescriptor::new(first_end, hash))
        );
        assert_eq!(
            reader.next_record().unwrap(),
            Some(ChunkDescriptor::new(first_end + 8, hash))
        );
        assert_eq!(reader.next_record().unwrap(), None);
        reader.finish_remaining().unwrap();
    }

    #[test]
    fn manifest_rejects_bad_checksum_and_trailing_bytes() {
        let hash = ChunkHash::from_digest([9; 32]);
        let manifest = ChunkManifest::new(identity(8), ChunkProfile::MinCdcHash4V2, 1);
        let encoded = encoded_manifest(manifest, &[hash]);
        let mut corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assert_eq!(
            read_manifest(&corrupt),
            Err(ManifestError::ChecksumMismatch)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(read_manifest(&trailing), Err(ManifestError::TrailingBytes));
    }

    #[test]
    fn manifest_rejects_truncated_header_records_and_checksum() {
        let hash = ChunkHash::from_digest([9; 32]);
        let manifest = ChunkManifest::new(identity(8), ChunkProfile::MinCdcHash4V2, 1);
        let encoded = encoded_manifest(manifest, &[hash]);
        for length in 0..MANIFEST_HEADER_BYTES {
            assert!(
                matches!(read_manifest(&encoded[..length]), Err(ManifestError::Io(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
        for length in MANIFEST_HEADER_BYTES..encoded.len() {
            assert_eq!(
                read_manifest(&encoded[..length]),
                Err(ManifestError::Truncated)
            );
        }
    }

    #[test]
    fn manifest_rejects_invalid_record_boundaries() {
        let hash = ChunkHash::from_digest([9; 32]);
        let profile = ChunkProfile::MinCdcHash4V2;
        let minimum = profile.min_size();
        let size = minimum * 2 + 8;
        let manifest = ChunkManifest::new(identity(size), profile, 3);
        let cases = [
            (0, 0, ManifestError::InvalidChunkLength),
            (0, profile.max_size() + 1, ManifestError::InvalidChunkLength),
            (0, minimum - 1, ManifestError::InvalidChunkLength),
            (1, minimum - 1, ManifestError::NonMonotonicEnds),
            (2, size + 1, ManifestError::InvalidChunkLength),
            (
                2,
                size - 1,
                ManifestError::FinalSizeMismatch {
                    expected: size,
                    actual: size - 1,
                },
            ),
        ];
        for (index, end, expected) in cases {
            let mut encoded = encoded_manifest(manifest, &[hash; 3]);
            let offset = MANIFEST_HEADER_BYTES + index * MANIFEST_RECORD_BYTES;
            encoded[offset..offset + 8].copy_from_slice(&end.to_le_bytes());
            let checksum_offset = encoded.len() - MANIFEST_CHECKSUM_BYTES;
            let checksum = Sha256::digest(&encoded[..checksum_offset]);
            encoded[checksum_offset..].copy_from_slice(&checksum);
            assert_eq!(read_manifest(&encoded), Err(expected));
        }
    }

    #[test]
    fn manifest_reader_enforces_the_byte_limit_and_rejects_record_count_overflow() {
        let manifest = ChunkManifest::new(identity(0), ChunkProfile::MinCdcHash4V2, 0);
        let mut encoded = encoded_manifest(manifest, &[]);
        assert!(matches!(
            ManifestReader::new(Cursor::new(&encoded), encoded.len() as u64 - 1),
            Err(ManifestError::LengthOverflow)
        ));
        encoded[52..60].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(read_manifest(&encoded), Err(ManifestError::LengthOverflow));
    }

    #[test]
    fn manifest_reader_is_independent_of_source_read_boundaries() {
        let hash = ChunkHash::from_digest([9; 32]);
        let manifest = ChunkManifest::new(
            identity(ChunkProfile::MinCdcHash4V2.min_size() + 8),
            ChunkProfile::MinCdcHash4V2,
            2,
        );
        let encoded = encoded_manifest(manifest, &[hash; 2]);
        let mut reader = ManifestReader::new(
            FragmentedReader {
                reader: Cursor::new(&encoded),
                fragment: 17,
            },
            u64::MAX,
        )
        .unwrap();
        assert_eq!(reader.manifest(), manifest);
        assert_eq!(
            reader.next_record().unwrap(),
            Some(ChunkDescriptor::new(manifest.profile().min_size(), hash))
        );
        reader.finish_remaining().unwrap();
    }

    struct FragmentedReader<R> {
        reader: R,
        fragment: usize,
    }
    impl<R: std::io::Read> std::io::Read for FragmentedReader<R> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = self.fragment.min(output.len());
            self.reader.read(&mut output[..length])
        }
    }
    impl<R: std::io::Seek> std::io::Seek for FragmentedReader<R> {
        fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
            self.reader.seek(position)
        }
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn a1_error_messages_and_leaf_sources() {
        let cases: &[(&dyn std::error::Error, &str)] = &[
            (
                &ManifestError::ChecksumMismatch,
                "chunk manifest checksum mismatch",
            ),
            (
                &ManifestError::FinalSizeMismatch {
                    expected: 8,
                    actual: 9,
                },
                "chunk manifest ends at 9 bytes, expected 8",
            ),
            (&ManifestError::InvalidChunkLength, "invalid chunk length"),
            (
                &ManifestError::InvalidHeader,
                "invalid chunk manifest header",
            ),
            (&ManifestError::InvalidMagic, "invalid chunk manifest magic"),
            (
                &ManifestError::LengthOverflow,
                "chunk manifest length overflow",
            ),
            (
                &ManifestError::NonMonotonicEnds,
                "chunk manifest ends are not increasing",
            ),
            (
                &ManifestError::TrailingBytes,
                "trailing bytes after chunk manifest",
            ),
            (&ManifestError::Truncated, "truncated chunk manifest"),
            (
                &ManifestError::UnsupportedProfile(17),
                "unsupported chunk profile 17",
            ),
            (
                &ManifestError::UnsupportedVersion(23),
                "unsupported chunk manifest version 23",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
            assert!(error.source().is_none(), "{message}");
        }
    }

    #[test]
    fn a1_manifest_equality_compares_io_kinds_and_variant_data() {
        let first = ManifestError::from(io::Error::new(io::ErrorKind::NotFound, "first"));
        let second = ManifestError::from(io::Error::new(io::ErrorKind::NotFound, "second"));
        assert_eq!(first, second);
        assert_ne!(first, ManifestError::from(io::Error::other("first")));
        assert_ne!(
            ManifestError::UnsupportedVersion(1),
            ManifestError::UnsupportedVersion(2)
        );
        assert_ne!(
            ManifestError::FinalSizeMismatch {
                expected: 8,
                actual: 9
            },
            ManifestError::FinalSizeMismatch {
                expected: 9,
                actual: 8
            }
        );
    }
}
