use std::io::{self, Read, Write};

use crate::cache::records::decode_complete;
use serde::{Serialize, de::DeserializeOwned};

pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024;
const HEADER_BYTES: usize = 8;
const MAGIC: &[u8; 4] = b"NGC3";

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
    let mut frame = vec![0; HEADER_BYTES + MAX_FRAME_BYTES];
    let length = postcard::to_slice(value, &mut frame[HEADER_BYTES..])
        .map_err(|error| match error {
            postcard::Error::SerializeBufferFull => {
                io::Error::new(io::ErrorKind::InvalidInput, "control frame too large")
            }
            error => io::Error::other(error),
        })?
        .len();
    let wire_length = u32::try_from(length).map_err(io::Error::other)?;
    frame[..4].copy_from_slice(MAGIC);
    frame[4..HEADER_BYTES].copy_from_slice(&wire_length.to_be_bytes());
    writer.write_all(&frame[..HEADER_BYTES + length])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FrameWriter {
        calls: usize,
        bytes: Vec<u8>,
    }

    impl Write for FrameWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("frame encoding must use the transport's write_all budget")
        }

        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.calls += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_complete_frame_uses_one_transport_write_budget() {
        let mut writer = FrameWriter::default();
        let value = (42_u64, "one frame");
        write_frame(&mut writer, &value).unwrap();
        assert_eq!(writer.calls, 1);
        assert_eq!(
            read_frame::<(u64, String)>(&writer.bytes[..]).unwrap(),
            (42, "one frame".to_owned())
        );
    }

    #[test]
    fn oversized_frames_do_not_start_a_transport_write() {
        let mut writer = FrameWriter::default();
        let error = write_frame(&mut writer, &vec![0_u8; MAX_FRAME_BYTES]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(writer.calls, 0);
        assert!(writer.bytes.is_empty());
    }

    #[test]
    fn a_maximum_sized_frame_fits_the_bounded_encoding_buffer() {
        let mut writer = FrameWriter::default();
        let value = vec![0_u8; MAX_FRAME_BYTES - 2];
        write_frame(&mut writer, &value).unwrap();
        assert_eq!(writer.calls, 1);
        assert_eq!(writer.bytes.len(), HEADER_BYTES + MAX_FRAME_BYTES);
        assert_eq!(read_frame::<Vec<u8>>(&writer.bytes[..]).unwrap(), value);
    }

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
            [b'N', b'G', b'C', b'3', 255, 255, 255, 255],
        ] {
            assert_eq!(
                read_frame::<u64>(&header[..]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn previous_request_and_report_schemas_are_rejected_without_reading_their_bodies() {
        fn reject<T: DeserializeOwned>(body: &[u8]) {
            let mut frame = b"NGC2".to_vec();
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(body);
            let mut reader = io::Cursor::new(frame);
            let error = read_frame::<T>(&mut reader)
                .err()
                .expect("old schema must fail");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "unsupported control protocol");
            assert_eq!(reader.position(), HEADER_BYTES as u64);
        }
        // NGC2 options: no maximum, target 0, no age, zero minimum age,
        // empty protected roots, Apply, Flat; before retention fields existed.
        reject::<crate::cache::storage::gc::GcOptions>(&[0, 1, 0, 0, 0, 0, 0, 1, 0]);
        // Completed(Logical, dry_run=true, zero counters, target_met=true).
        let mut report = [0; 26];
        report[2] = 1;
        report[5] = 1;
        reject::<super::super::Reply>(&report);
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
