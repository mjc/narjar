use std::{
    io::{self, Read},
    path::Path,
};

use rustix::fd::AsFd;
use serde::Deserialize;

use crate::filesystem::open_regular_at;

#[derive(Debug)]
pub enum BoundedRegularFile<T> {
    Missing,
    Invalid,
    Valid(T),
}

impl BoundedRegularFile<Vec<u8>> {
    pub fn parse<T>(self, parse: impl FnOnce(&[u8]) -> Option<T>) -> BoundedRegularFile<T> {
        match self {
            Self::Missing => BoundedRegularFile::Missing,
            Self::Invalid => BoundedRegularFile::Invalid,
            Self::Valid(bytes) => parse(&bytes)
                .map(BoundedRegularFile::Valid)
                .unwrap_or(BoundedRegularFile::Invalid),
        }
    }
}

/// Classify absence and invalid record files without swallowing source I/O errors.
pub fn read_bounded_regular_file(
    parent: impl AsFd,
    path: impl AsRef<Path>,
    max_bytes: u64,
) -> io::Result<BoundedRegularFile<Vec<u8>>> {
    let file = match open_regular_at(parent, path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BoundedRegularFile::Missing);
        }
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) =>
        {
            return Ok(BoundedRegularFile::Invalid);
        }
        Err(error) => return Err(error),
    };
    match read_bounded_bytes(file, max_bytes) {
        Ok(bytes) => Ok(BoundedRegularFile::Valid(bytes)),
        Err(BoundedReadError::TooLarge) => Ok(BoundedRegularFile::Invalid),
        Err(BoundedReadError::Io(error)) => Err(error),
    }
}

/// Read through EOF, rejecting output that exceeds the inclusive byte limit.
pub fn read_bounded_bytes(reader: impl Read, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum BoundedReadError {
    #[error("record exceeds its byte limit")]
    TooLarge,
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl From<BoundedReadError> for io::Error {
    fn from(error: BoundedReadError) -> Self {
        match error {
            BoundedReadError::TooLarge => Self::from(io::ErrorKind::InvalidData),
            BoundedReadError::Io(error) => error,
        }
    }
}

/// Decode exactly one private record, never accepting a valid prefix alone.
pub fn decode_complete<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, postcard::Error> {
    let (value, remainder) = postcard::take_from_bytes(bytes)?;
    if !remainder.is_empty() {
        return Err(postcard::Error::DeserializeBadEncoding);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_regular_reads_follow_the_opened_directory_not_its_old_path() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("record"), b"abc").unwrap();
        let directory = crate::filesystem::open_directory(&original).unwrap();
        std::fs::rename(&original, root.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("record"), b"replacement").unwrap();

        match read_bounded_regular_file(&directory, "record", 3).unwrap() {
            BoundedRegularFile::Valid(bytes) => assert_eq!(bytes, b"abc"),
            result => panic!("opened-directory record should fit exactly: {result:?}"),
        }
        assert!(matches!(
            read_bounded_regular_file(&directory, "record", 2).unwrap(),
            BoundedRegularFile::Invalid
        ));
        assert!(matches!(
            read_bounded_regular_file(&directory, "absent", 3).unwrap(),
            BoundedRegularFile::Missing
        ));
    }

    #[test]
    fn invalid_and_missing_record_files_never_reach_the_parser() {
        for record in [BoundedRegularFile::Missing, BoundedRegularFile::Invalid] {
            let result = record.parse::<()>(|_| panic!("there are no valid bytes to parse"));
            assert!(!matches!(result, BoundedRegularFile::Valid(_)));
        }
        assert!(matches!(
            BoundedRegularFile::Valid(vec![0]).parse::<()>(|_| None),
            BoundedRegularFile::Invalid
        ));
    }

    #[test]
    fn bounded_reads_accept_the_exact_limit_but_not_an_extra_byte() {
        assert_eq!(read_bounded_bytes(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(matches!(
            read_bounded_bytes(&b"abcd"[..], 3),
            Err(BoundedReadError::TooLarge)
        ));
    }

    #[test]
    fn complete_records_reject_truncation_and_trailing_bytes() {
        let mut bytes = postcard::to_allocvec(&(128_u64, 32_u64)).unwrap();
        assert_eq!(decode_complete::<(u64, u64)>(&bytes).unwrap(), (128, 32));
        assert!(decode_complete::<(u64, u64)>(&bytes[..bytes.len() - 1]).is_err());
        bytes.push(0);
        assert!(decode_complete::<(u64, u64)>(&bytes).is_err());
    }

    #[test]
    fn source_invalid_data_is_not_confused_with_limit_exhaustion() {
        struct FailedSource;
        impl Read for FailedSource {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::InvalidData, "source failure"))
            }
        }
        match read_bounded_bytes(FailedSource, 10) {
            Err(BoundedReadError::Io(error)) => assert_eq!(error.to_string(), "source failure"),
            result => panic!("source error lost: {result:?}"),
        }
    }
}
