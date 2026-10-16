use std::io::{self, Read, Write};

use narjar::__private::records::decode_complete;
use serde::{Serialize, de::DeserializeOwned};

pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024;
const HEADER_BYTES: usize = 8;
const MAGIC: &[u8; 4] = b"NGC2";

pub(super) fn read_frame<T: DeserializeOwned>(mut reader: impl Read) -> io::Result<T> {
    let mut header = [0; HEADER_BYTES];
    reader.read_exact(&mut header)?;
    if &header[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported control protocol",
        ));
    }
    let [_, _, _, _, a, b, c, d] = header;
    let length = u32::from_be_bytes([a, b, c, d]) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control frame length",
        ));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    decode_complete(&body).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(super) fn write_frame(mut writer: impl Write, value: &impl Serialize) -> io::Result<()> {
    let body = postcard::to_allocvec(value).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control frame too large",
        ));
    }
    writer.write_all(MAGIC)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_versioned_frame_round_trips_without_accepting_trailing_record_bytes() {
        let value = (42_u64, "a bounded local request".to_owned());
        let mut frame = Vec::new();
        write_frame(&mut frame, &value).unwrap();
        assert_eq!(read_frame::<(u64, String)>(&frame[..]).unwrap(), value);
        let length = u32::from_be_bytes(frame[4..8].try_into().unwrap());
        frame[4..8].copy_from_slice(&(length + 1).to_be_bytes());
        frame.push(0);
        assert_eq!(
            read_frame::<(u64, String)>(&frame[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unsupported_versions_and_oversized_headers_are_rejected_before_reading_a_body() {
        for header in [
            *b"NGC1\0\0\0\x01",
            [b'N', b'G', b'C', b'2', 255, 255, 255, 255],
        ] {
            assert_eq!(
                read_frame::<u64>(&header[..]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn truncated_frames_do_not_manufacture_a_request() {
        let mut frame = Vec::new();
        write_frame(&mut frame, &42_u64).unwrap();
        for length in 0..frame.len() {
            assert_eq!(
                read_frame::<u64>(&frame[..length]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}
