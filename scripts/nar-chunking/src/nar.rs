use std::io::{self, Read};

const FILE_BUFFER_SIZE: usize = 64 * 1024;
const MAX_NAR_STRING_BYTES: u64 = 1024 * 1024;
const MAX_NAR_DEPTH: usize = 256;

pub(super) enum NarEvent<'a> {
    BeginFile { size: u64 },
    FileBytes(&'a [u8]),
    EndFile,
}

pub(super) struct NarScanner<R> {
    reader: R,
    bytes_read: u64,
    file_buffer: [u8; FILE_BUFFER_SIZE],
}

impl<R: Read> NarScanner<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            bytes_read: 0,
            file_buffer: [0; FILE_BUFFER_SIZE],
        }
    }

    pub(super) fn scan(mut self, on_file_event: &mut impl FnMut(NarEvent<'_>)) -> io::Result<u64> {
        self.expect(b"nix-archive-1")?;
        self.decode_node(0, on_file_event)?;
        self.require_end_of_input()?;
        Ok(self.bytes_read)
    }

    fn decode_node(
        &mut self,
        depth: usize,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
    ) -> io::Result<()> {
        if depth > MAX_NAR_DEPTH {
            return Err(invalid_nar("directory nesting exceeds the research limit"));
        }
        self.expect(b"(")?;
        self.expect(b"type")?;
        match self.read_string()?.as_slice() {
            b"directory" => self.decode_directory(on_file_event, depth),
            b"regular" => self.decode_regular_file(on_file_event),
            b"symlink" => self.decode_symlink(),
            _ => Err(invalid_nar("unknown node type")),
        }
    }

    fn decode_directory(
        &mut self,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
        depth: usize,
    ) -> io::Result<()> {
        let mut previous_name = None;
        std::iter::from_fn(|| {
            self.decode_directory_entry(&mut previous_name, on_file_event, depth)
                .transpose()
        })
        .try_for_each(|entry| entry)?;
        Ok(())
    }

    fn decode_directory_entry(
        &mut self,
        previous_name: &mut Option<Vec<u8>>,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
        depth: usize,
    ) -> io::Result<Option<()>> {
        let entry_kind = self.read_string()?;
        if entry_kind == b")" {
            return Ok(None);
        }
        if entry_kind != b"entry" {
            return Err(invalid_nar("directory entry expected"));
        }
        self.expect(b"(")?;
        self.expect(b"name")?;
        self.remember_ordered_entry_name(previous_name)?;
        self.expect(b"node")?;
        self.decode_node(depth + 1, on_file_event)?;
        self.expect(b")")?;
        Ok(Some(()))
    }

    fn remember_ordered_entry_name(
        &mut self,
        previous_name: &mut Option<Vec<u8>>,
    ) -> io::Result<()> {
        let name = self.read_string()?;
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(invalid_nar("directory entry name is invalid"));
        }
        if previous_name
            .as_ref()
            .is_some_and(|previous| previous >= &name)
        {
            return Err(invalid_nar("directory entries are not strictly ordered"));
        }
        *previous_name = Some(name);
        Ok(())
    }

    fn decode_regular_file(
        &mut self,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
    ) -> io::Result<()> {
        self.read_regular_file_contents_field()?;
        let size = self.read_u64()?;
        on_file_event(NarEvent::BeginFile { size });
        self.stream_regular_file_contents(size, on_file_event)?;
        on_file_event(NarEvent::EndFile);
        self.expect(b")")
    }

    fn read_regular_file_contents_field(&mut self) -> io::Result<()> {
        match self.read_string()?.as_slice() {
            b"contents" => Ok(()),
            b"executable" => {
                if !self.read_string()?.is_empty() {
                    return Err(invalid_nar("executable marker must be empty"));
                }
                self.expect(b"contents")
            }
            _ => Err(invalid_nar("regular contents expected")),
        }
    }

    fn stream_regular_file_contents(
        &mut self,
        size: u64,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
    ) -> io::Result<()> {
        (0..size).step_by(FILE_BUFFER_SIZE).try_for_each(|offset| {
            let length = (size - offset).min(FILE_BUFFER_SIZE as u64) as usize;
            self.read_regular_file_chunk(length, on_file_event)
        })?;
        self.read_padding(size)
    }

    fn read_regular_file_chunk(
        &mut self,
        length: usize,
        on_file_event: &mut impl FnMut(NarEvent<'_>),
    ) -> io::Result<()> {
        let Self {
            reader,
            bytes_read,
            file_buffer,
        } = self;
        reader.read_exact(&mut file_buffer[..length])?;
        *bytes_read = bytes_read
            .checked_add(length as u64)
            .ok_or_else(|| invalid_nar("NAR byte count overflow"))?;
        on_file_event(NarEvent::FileBytes(&self.file_buffer[..length]));
        Ok(())
    }

    fn decode_symlink(&mut self) -> io::Result<()> {
        self.expect(b"target")?;
        let target = self.read_string()?;
        if target.contains(&0) {
            return Err(invalid_nar("symlink target contains NUL"));
        }
        self.expect(b")")
    }

    fn expect(&mut self, expected: &[u8]) -> io::Result<()> {
        let actual = self.read_string()?;
        if actual == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected NAR token {:?}, got {:?}",
                    String::from_utf8_lossy(expected),
                    String::from_utf8_lossy(&actual)
                ),
            ))
        }
    }

    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let length = self.read_u64()?;
        if length > MAX_NAR_STRING_BYTES {
            return Err(invalid_nar("NAR string exceeds the research limit"));
        }
        let mut value = Vec::new();
        let length = usize::try_from(length)
            .map_err(|_| invalid_nar("NAR string length does not fit in memory"))?;
        value
            .try_reserve_exact(length)
            .map_err(|_| invalid_nar("NAR string allocation failed"))?;
        value.resize(length, 0);
        self.read_raw(&mut value)?;
        self.read_padding(length as u64)?;
        Ok(value)
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_raw(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_padding(&mut self, length: u64) -> io::Result<()> {
        let padding_length = ((8 - length % 8) % 8) as usize;
        let mut padding = [0; 7];
        self.read_raw(&mut padding[..padding_length])?;
        if padding[..padding_length].iter().any(|byte| *byte != 0) {
            return Err(invalid_nar("non-zero NAR padding"));
        }
        Ok(())
    }

    fn read_raw(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.reader.read_exact(bytes)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid_nar("NAR byte count overflow"))?;
        Ok(())
    }

    fn require_end_of_input(&mut self) -> io::Result<()> {
        let mut trailing_byte = [0];
        if self.reader.read(&mut trailing_byte)? == 0 {
            Ok(())
        } else {
            Err(invalid_nar("trailing bytes after the root node"))
        }
    }
}

fn invalid_nar(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{NarEvent, NarScanner};
    use std::io;

    fn append_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u64).to_le_bytes());
        output.extend_from_slice(value);
        output.resize(output.len() + (8 - value.len() % 8) % 8, 0);
    }

    fn regular_nar(contents: &[u8]) -> Vec<u8> {
        let mut nar = Vec::new();
        append_string(&mut nar, b"nix-archive-1");
        append_regular_node(&mut nar, contents);
        nar
    }

    fn append_regular_node(nar: &mut Vec<u8>, contents: &[u8]) {
        append_string(nar, b"(");
        append_string(nar, b"type");
        append_string(nar, b"regular");
        append_string(nar, b"contents");
        append_string(nar, contents);
        append_string(nar, b")");
    }

    fn append_entry_header(nar: &mut Vec<u8>, name: &[u8]) {
        append_string(nar, b"entry");
        append_string(nar, b"(");
        append_string(nar, b"name");
        append_string(nar, name);
        append_string(nar, b"node");
    }

    fn mixed_node_nar() -> Vec<u8> {
        let mut nar = Vec::new();
        append_string(&mut nar, b"nix-archive-1");
        append_string(&mut nar, b"(");
        append_string(&mut nar, b"type");
        append_string(&mut nar, b"directory");

        append_entry_header(&mut nar, b"a-file");
        append_regular_node(&mut nar, b"first");
        append_string(&mut nar, b")");

        append_entry_header(&mut nar, b"b-dir");
        append_string(&mut nar, b"(");
        append_string(&mut nar, b"type");
        append_string(&mut nar, b"directory");
        append_entry_header(&mut nar, b"nested-file");
        append_regular_node(&mut nar, b"second");
        append_string(&mut nar, b")");
        append_string(&mut nar, b")");
        append_string(&mut nar, b")");

        append_entry_header(&mut nar, b"c-link");
        append_string(&mut nar, b"(");
        append_string(&mut nar, b"type");
        append_string(&mut nar, b"symlink");
        append_string(&mut nar, b"target");
        append_string(&mut nar, b"a-file");
        append_string(&mut nar, b")");
        append_string(&mut nar, b")");

        append_string(&mut nar, b")");
        nar
    }

    fn empty_directory_nar() -> Vec<u8> {
        let mut nar = Vec::new();
        append_string(&mut nar, b"nix-archive-1");
        append_string(&mut nar, b"(");
        append_string(&mut nar, b"type");
        append_string(&mut nar, b"directory");
        append_string(&mut nar, b")");
        nar
    }

    #[test]
    fn regular_file_events_preserve_contents_and_complete_nar_size() {
        let contents = vec![0x5a; 2 * 64 * 1024 + 7];
        let nar = regular_nar(&contents);
        let mut observed = Vec::new();
        let size = NarScanner::new(nar.as_slice())
            .scan(&mut |event| match event {
                NarEvent::BeginFile { size } => assert_eq!(size, contents.len() as u64),
                NarEvent::FileBytes(bytes) => observed.extend_from_slice(bytes),
                NarEvent::EndFile => {}
            })
            .expect("valid NAR should scan");

        assert_eq!(observed, contents);
        assert_eq!(size, nar.len() as u64);
    }

    #[test]
    fn scanner_rejects_truncated_and_trailing_input() {
        let nar = regular_nar(b"payload");
        assert_eq!(
            NarScanner::new(&nar[..nar.len() - 1])
                .scan(&mut |_| {})
                .expect_err("truncated NAR should fail")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut trailing = nar;
        trailing.push(0);
        assert_eq!(
            NarScanner::new(trailing.as_slice())
                .scan(&mut |_| {})
                .expect_err("trailing bytes should fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn scanner_rejects_nonzero_padding() {
        let mut nar = regular_nar(b"x");
        let padding_byte = nar.len() - 1;
        nar[padding_byte] = 1;

        let error = NarScanner::new(nar.as_slice())
            .scan(&mut |_| {})
            .expect_err("nonzero padding should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("non-zero NAR padding"));
    }

    #[test]
    fn scanner_finds_regular_contents_inside_directories_and_ignores_symlinks() {
        let nar = mixed_node_nar();
        let mut contents = Vec::new();
        let mut files = 0;
        let size = NarScanner::new(nar.as_slice())
            .scan(&mut |event| match event {
                NarEvent::BeginFile { .. } => files += 1,
                NarEvent::FileBytes(bytes) => contents.extend_from_slice(bytes),
                NarEvent::EndFile => {}
            })
            .expect("valid nested NAR should scan");

        assert_eq!(files, 2);
        assert_eq!(contents, b"firstsecond");
        assert_eq!(size, nar.len() as u64);
    }

    #[test]
    fn scanner_rejects_dot_and_dot_dot_directory_names() {
        [b".".as_slice(), b".."].into_iter().for_each(|name| {
            let mut nar = Vec::new();
            append_string(&mut nar, b"nix-archive-1");
            append_string(&mut nar, b"(");
            append_string(&mut nar, b"type");
            append_string(&mut nar, b"directory");
            append_entry_header(&mut nar, name);
            append_regular_node(&mut nar, b"");
            append_string(&mut nar, b")");
            append_string(&mut nar, b")");

            assert_eq!(
                NarScanner::new(nar.as_slice())
                    .scan(&mut |_| {})
                    .expect_err("dot path components must be rejected")
                    .kind(),
                io::ErrorKind::InvalidData
            );
        });
    }

    #[test]
    fn scanner_accepts_empty_directories_and_rejects_extra_closers() {
        let nar = empty_directory_nar();
        assert_eq!(
            NarScanner::new(nar.as_slice())
                .scan(&mut |_| {})
                .expect("an empty directory has one closing token"),
            nar.len() as u64
        );

        let mut extra_closer = nar;
        append_string(&mut extra_closer, b")");
        let error = NarScanner::new(extra_closer.as_slice())
            .scan(&mut |_| {})
            .expect_err("an extra directory closer is trailing input");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn scanner_rejects_nonzero_regular_file_content_padding() {
        let mut nar = Vec::new();
        append_string(&mut nar, b"nix-archive-1");
        append_string(&mut nar, b"(");
        append_string(&mut nar, b"type");
        append_string(&mut nar, b"regular");
        append_string(&mut nar, b"contents");
        let content_padding_byte = nar.len() + 8 + 1;
        append_string(&mut nar, b"x");
        append_string(&mut nar, b")");
        nar[content_padding_byte] = 1;

        let error = NarScanner::new(nar.as_slice())
            .scan(&mut |_| {})
            .expect_err("nonzero regular-file padding should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("non-zero NAR padding"));
    }
}
