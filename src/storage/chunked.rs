use std::{fmt, io, io::Read, io::Seek, io::SeekFrom, io::Write};

use mincdc::{MinCdcHash4, ReadChunker};
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

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let (manifest, content_bytes) = parse_header(bytes)?;
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
        verify_checksum(&bytes[..content_bytes], &bytes[content_bytes..])?;
        let mut builder = ManifestBuilder::new(manifest.identity, manifest.profile, io::sink());
        let (records, remainder) =
            bytes[MANIFEST_HEADER_BYTES..content_bytes].as_chunks::<MANIFEST_RECORD_BYTES>();
        debug_assert!(remainder.is_empty());
        records
            .iter()
            .try_for_each(|record| builder.append(parse_record(record)?))?;
        let (_, decoded) = builder.finish()?;
        (decoded == manifest)
            .then_some(decoded)
            .ok_or(ManifestError::InvalidHeader)
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

pub(crate) struct ManifestBuilder<W> {
    writer: W,
    identity: NarIdentity,
    profile: ChunkProfile,
    previous_end: u64,
    previous_length: Option<u64>,
    chunk_count: u64,
}

impl<W: Write> ManifestBuilder<W> {
    pub(crate) fn new(identity: NarIdentity, profile: ChunkProfile, writer: W) -> Self {
        Self {
            writer,
            identity,
            profile,
            previous_end: 0,
            previous_length: None,
            chunk_count: 0,
        }
    }

    pub(crate) fn append(&mut self, descriptor: ChunkDescriptor) -> Result<(), ManifestError> {
        let length = descriptor
            .end
            .checked_sub(self.previous_end)
            .ok_or(ManifestError::NonMonotonicEnds)?;
        if length == 0
            || length > self.profile.max_size()
            || descriptor.end > self.identity.size().get()
        {
            return Err(ManifestError::InvalidChunkLength);
        }
        if self
            .previous_length
            .is_some_and(|previous| previous < self.profile.min_size())
        {
            return Err(ManifestError::InvalidChunkLength);
        }
        self.writer.write_all(&descriptor.end.to_le_bytes())?;
        self.writer.write_all(&descriptor.hash.bytes())?;
        self.previous_end = descriptor.end;
        self.previous_length = Some(length);
        self.chunk_count = self
            .chunk_count
            .checked_add(1)
            .ok_or(ManifestError::LengthOverflow)?;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(W, ChunkManifest), ManifestError> {
        if self.previous_end != self.identity.size().get() {
            return Err(ManifestError::FinalSizeMismatch {
                expected: self.identity.size().get(),
                actual: self.previous_end,
            });
        }
        Ok((
            self.writer,
            ChunkManifest::new(self.identity, self.profile, self.chunk_count),
        ))
    }
}

pub(crate) fn chunk_stream<R, F>(
    source: R,
    profile: ChunkProfile,
    mut on_chunk: F,
) -> io::Result<u64>
where
    R: Read,
    F: FnMut(u64, ChunkHash, &[u8]) -> io::Result<()>,
{
    let mut chunker = ReadChunker::new(
        source,
        profile.min_size() as usize,
        profile.max_size() as usize,
        MinCdcHash4::new(),
    );
    let mut end = 0_u64;
    while let Some(chunk) = chunker.next()? {
        let bytes: &[u8] = &chunk;
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk is too large"))?;
        end = end
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR is too large"))?;
        on_chunk(
            end,
            ChunkHash::from_digest(Sha256::digest(bytes).into()),
            bytes,
        )?;
    }
    Ok(end)
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

fn verify_checksum(content: &[u8], checksum: &[u8]) -> Result<(), ManifestError> {
    (checksum == Sha256::digest(content).as_slice())
        .then_some(())
        .ok_or(ManifestError::ChecksumMismatch)
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

#[derive(Debug)]
pub(crate) enum ManifestError {
    ChecksumMismatch,
    FinalSizeMismatch { expected: u64, actual: u64 },
    InvalidChunkLength,
    InvalidHeader,
    InvalidMagic,
    Io(io::Error),
    LengthOverflow,
    NonMonotonicEnds,
    TrailingBytes,
    Truncated,
    UnsupportedProfile(u8),
    UnsupportedVersion(u8),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChecksumMismatch => f.write_str("chunk manifest checksum mismatch"),
            Self::FinalSizeMismatch { expected, actual } => write!(
                f,
                "chunk manifest ends at {actual} bytes, expected {expected}"
            ),
            Self::InvalidChunkLength => f.write_str("invalid chunk length"),
            Self::InvalidHeader => f.write_str("invalid chunk manifest header"),
            Self::InvalidMagic => f.write_str("invalid chunk manifest magic"),
            Self::Io(error) => error.fmt(f),
            Self::LengthOverflow => f.write_str("chunk manifest length overflow"),
            Self::NonMonotonicEnds => f.write_str("chunk manifest ends are not increasing"),
            Self::TrailingBytes => f.write_str("trailing bytes after chunk manifest"),
            Self::Truncated => f.write_str("truncated chunk manifest"),
            Self::UnsupportedProfile(id) => write!(f, "unsupported chunk profile {id}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported chunk manifest version {version}")
            }
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
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
impl From<io::Error> for ManifestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChunkHash, ChunkManifest, ChunkProfile, ManifestBuilder, ManifestError, chunk_stream,
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

    #[test]
    fn production_chunk_profile_is_versioned_and_bounded() {
        assert_eq!(ChunkProfile::MinCdcHash4V2.id(), 2);
        assert_eq!(ChunkProfile::MinCdcHash4V2.min_size(), 256 * 1024);
        assert_eq!(ChunkProfile::MinCdcHash4V2.max_size(), 1024 * 1024);
        assert_eq!(
            ChunkProfile::from_id(1),
            Err(ManifestError::UnsupportedProfile(1))
        );
    }

    #[test]
    fn manifest_round_trips_without_retaining_records() {
        let hash = ChunkHash::from_digest([9; 32]);
        let profile = ChunkProfile::MinCdcHash4V2;
        let first_end = profile.min_size();
        let mut records = Vec::new();
        let mut builder = ManifestBuilder::new(identity(first_end + 8), profile, &mut records);
        builder
            .append(super::ChunkDescriptor::new(first_end, hash))
            .unwrap();
        builder
            .append(super::ChunkDescriptor::new(first_end + 8, hash))
            .unwrap();
        let (_, manifest) = builder.finish().unwrap();
        let decoded = ChunkManifest::decode(&encoded_manifest(manifest, &[hash, hash])).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.chunk_count(), 2);
    }

    #[test]
    fn manifest_rejects_bad_checksum_and_trailing_bytes() {
        let hash = ChunkHash::from_digest([9; 32]);
        let manifest = ChunkManifest::new(identity(8), ChunkProfile::MinCdcHash4V2, 1);
        let encoded = encoded_manifest(manifest, &[hash]);
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
            ChunkProfile::MinCdcHash4V2,
            |end, hash, _| {
                first.push((end, hash));
                Ok(())
            },
        )
        .unwrap();
        chunk_stream(
            FragmentedReader::new(&input, 17),
            ChunkProfile::MinCdcHash4V2,
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
