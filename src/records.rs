use std::io::{self, Read};

use serde::Deserialize;

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
