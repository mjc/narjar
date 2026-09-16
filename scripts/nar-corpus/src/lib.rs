use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::rc::Rc;
use std::{cell::Cell, ffi::OsString};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DigestSummary {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug)]
pub struct InputListArguments {
    pub input_list: OsString,
    pub output_path: Option<OsString>,
}

pub fn parse_input_list_arguments(
    args: impl Iterator<Item = OsString>,
) -> io::Result<Option<InputListArguments>> {
    let args = args.collect::<Vec<_>>();
    if args.iter().any(|argument| argument == "--help") {
        return Ok(None);
    }
    let (input_list, output_path) =
        args.chunks(2)
            .try_fold((None, None), |(input_list, output_path), pair| {
                let [argument, value] = pair else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "option requires a value",
                    ));
                };
                match argument.to_str() {
                    Some("--input-list") => Ok((Some(value.clone()), output_path)),
                    Some("--output") => Ok((input_list, Some(value.clone()))),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown argument",
                    )),
                }
            })?;
    Ok(Some(InputListArguments {
        input_list: input_list.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "--input-list is required")
        })?,
        output_path,
    }))
}

pub fn usable_input_path(path: String) -> io::Result<Option<String>> {
    if path.is_empty() {
        return Ok(None);
    }
    if path.contains(['\t', '\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input path contains a tab or newline",
        ));
    }
    Ok(Some(path))
}

#[derive(Clone, Debug)]
pub struct BytePosition(Rc<Cell<u64>>);

impl BytePosition {
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.get()
    }
}

pub struct HashingReader<R> {
    inner: R,
    position: BytePosition,
    digest: Sha256,
    bytes: u64,
}

impl<R> HashingReader<R> {
    pub fn new(inner: R) -> (Self, BytePosition) {
        let position = BytePosition(Rc::new(Cell::new(0)));
        (
            Self {
                inner,
                position: position.clone(),
                digest: Sha256::new(),
                bytes: 0,
            },
            position,
        )
    }

    pub fn finish(self) -> (R, DigestSummary) {
        (
            self.inner,
            DigestSummary {
                bytes: self.bytes,
                sha256: finalize_digest(self.digest),
            },
        )
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.position.0.set(self.position.get() + read as u64);
        self.digest.update(&buffer[..read]);
        self.bytes += read as u64;
        Ok(read)
    }
}

pub struct HashingWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    pub fn finish(self) -> (W, DigestSummary) {
        (
            self.inner,
            DigestSummary {
                bytes: self.bytes,
                sha256: finalize_digest(self.digest),
            },
        )
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.digest.update(&buffer[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn finalize_digest(digest: Sha256) -> [u8; 32] {
    digest.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use super::*;

    struct ChunkedReader {
        input: Cursor<Vec<u8>>,
        chunk_size: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.chunk_size);
            self.input.read(&mut buffer[..length])
        }
    }

    struct PartialWriter {
        output: Vec<u8>,
        max_write: usize,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.max_write);
            self.output.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reader_hashes_the_bytes_it_delivers_and_exposes_a_live_position() {
        // A streaming decoder borrows the reader while it visits a file. The
        // separate position handle lets a visitor record the payload offset
        // without trying to borrow the reader a second time.
        let source = b"archive bytes".to_vec();
        let (mut reader, position) = HashingReader::new(ChunkedReader {
            input: Cursor::new(source.clone()),
            chunk_size: 3,
        });
        let mut received = Vec::new();
        io::copy(&mut reader, &mut received).expect("chunked reader is readable");

        let (_, summary) = reader.finish();
        assert_eq!(received, source);
        assert_eq!(position.get(), source.len() as u64);
        assert_eq!(summary.bytes, source.len() as u64);
        assert_eq!(
            hex(&summary.sha256),
            "cc9c340301ad4ba5e54aa24b442ff938d1ed84f7f32c4c5a73773c58af37bd1b"
        );
    }

    #[test]
    fn writer_hashes_only_bytes_accepted_by_a_partial_writer() {
        // `Write::write` may legally accept fewer bytes than requested. The
        // accounting must follow the returned count, or a short write would
        // corrupt every later size and digest assertion.
        let mut writer = HashingWriter::new(PartialWriter {
            output: Vec::new(),
            max_write: 2,
        });
        let written = writer.write(b"abcdef").expect("partial writer succeeds");
        let (writer, summary) = writer.finish();

        assert_eq!(written, 2);
        assert_eq!(writer.output, b"ab");
        assert_eq!(summary.bytes, 2);
        assert_eq!(
            hex(&summary.sha256),
            "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        );
    }

    #[test]
    fn hex_is_lowercase_and_preserves_leading_zeroes() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn input_list_arguments_accept_options_in_either_order() {
        let arguments = parse_input_list_arguments(
            ["--output", "report.tsv", "--input-list", "paths.txt"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("valid arguments parse")
        .expect("this is not the help form");

        assert_eq!(arguments.input_list, OsString::from("paths.txt"));
        assert_eq!(arguments.output_path, Some(OsString::from("report.tsv")));
    }

    #[test]
    fn input_list_arguments_require_the_input_list() {
        let error =
            parse_input_list_arguments(["--output", "report.tsv"].into_iter().map(OsString::from))
                .expect_err("missing input list is invalid");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "--input-list is required");
    }

    #[test]
    fn usable_input_path_skips_blank_lines_and_rejects_tsv_breakage() {
        assert_eq!(usable_input_path(String::new()).unwrap(), None);
        assert_eq!(
            usable_input_path("path\r".to_owned()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            usable_input_path("path.nar".to_owned()).unwrap(),
            Some("path.nar".to_owned())
        );
    }
}
