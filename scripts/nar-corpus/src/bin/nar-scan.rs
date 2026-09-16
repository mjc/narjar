use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar_corpus::{
    BytePosition, DigestSummary, HashingReader, HashingWriter, hex, parse_input_list_arguments,
    usable_input_path,
};
use nix_archive::nar::{Error, Event, FileContents, decode_events_reader};

struct Scanner<'a, W> {
    path: &'a str,
    output: &'a mut W,
    root: Option<&'static str>,
    entries: u64,
    files: u64,
    symlinks: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct ScanSummary {
    root: &'static str,
    entries: u64,
    files: u64,
    symlinks: u64,
}

impl<W: Write> Scanner<'_, W> {
    fn visit<R: io::Read + ?Sized>(
        &mut self,
        event: Event<'_, FileContents<'_, R>>,
        offset: u64,
    ) -> Result<(), Error> {
        match event {
            Event::DirectoryStart { name } => self.record_node(name, "directory"),
            Event::DirectoryEnd { .. } => {}
            Event::Regular {
                name,
                executable,
                contents,
            } => {
                self.hash_regular_file_contents_and_write_record(
                    name, executable, contents, offset,
                )?;
            }
            Event::Symlink { name, target } => {
                self.hash_symlink_target_and_write_record(name, target)?;
            }
        }
        Ok(())
    }

    fn hash_regular_file_contents_and_write_record<R: io::Read + ?Sized>(
        &mut self,
        name: Option<&[u8]>,
        executable: bool,
        mut contents: FileContents<'_, R>,
        offset: u64,
    ) -> Result<(), Error> {
        self.record_node(name, "regular");
        let size = contents.size();
        let mut digest = HashingWriter::new(io::sink());
        let copied = contents.copy_to(&mut digest)?;
        if copied != size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short NAR file").into());
        }
        let (_, summary) = digest.finish();
        self.write_regular_file_record(size, executable, offset, summary)?;
        self.files += 1;
        Ok(())
    }

    fn write_regular_file_record(
        &mut self,
        size: u64,
        executable: bool,
        offset: u64,
        summary: DigestSummary,
    ) -> io::Result<()> {
        writeln!(
            self.output,
            "O\t{}\tfile\t{}\t{}\t{}\t{}\t",
            self.path,
            size,
            hex(&summary.sha256),
            offset,
            u8::from(executable),
        )
    }

    fn hash_symlink_target_and_write_record(
        &mut self,
        name: Option<&[u8]>,
        target: &[u8],
    ) -> io::Result<()> {
        self.record_node(name, "symlink");
        let mut digest = HashingWriter::new(io::sink());
        digest.write_all(target)?;
        let (_, summary) = digest.finish();
        writeln!(
            self.output,
            "O\t{}\tsymlink\t{}\t{}\t-\t0\t{}",
            self.path,
            target.len(),
            hex(&summary.sha256),
            hex(target),
        )?;
        self.symlinks += 1;
        Ok(())
    }

    fn record_node(&mut self, name: Option<&[u8]>, root: &'static str) {
        if name.is_some() {
            self.entries += 1;
        } else {
            self.root = Some(root);
        }
    }

    fn summary(&self) -> io::Result<ScanSummary> {
        Ok(ScanSummary {
            root: self
                .root
                .ok_or_else(|| io::Error::other("NAR had no root node"))?,
            entries: self.entries,
            files: self.files,
            symlinks: self.symlinks,
        })
    }
}

fn main() -> io::Result<()> {
    let Some(arguments) = parse_input_list_arguments(std::env::args_os().skip(1))? else {
        return Ok(());
    };
    let list = File::open(arguments.input_list)?;
    let mut output: Box<dyn Write> = match arguments.output_path {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::BufWriter::new(io::stdout().lock())),
    };
    writeln!(output, "# narjar-nar-scan-v1")?;

    BufReader::new(list)
        .lines()
        .map(|line| line.and_then(usable_input_path))
        .try_for_each(|path| path?.map_or(Ok(()), |path| scan_one(&path, &mut output)))?;
    output.flush()
}

fn scan_one<W: Write>(path: &str, output: &mut W) -> io::Result<()> {
    let file = File::open(Path::new(path))?;
    let (mut input, position) = HashingReader::new(BufReader::with_capacity(1024 * 1024, file));
    let summary = scan_reader(&mut input, &position, path, output)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (_, digest) = input.finish();
    writeln!(
        output,
        "N\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        path,
        digest.bytes,
        hex(&digest.sha256),
        summary.root,
        summary.entries,
        summary.files,
        summary.symlinks,
    )
}

fn scan_reader<R: io::Read, W: Write>(
    input: &mut HashingReader<R>,
    position: &BytePosition,
    path: &str,
    output: &mut W,
) -> Result<ScanSummary, Error> {
    let mut scanner = Scanner {
        path,
        output,
        root: None,
        entries: 0,
        files: 0,
        symlinks: 0,
    };
    decode_events_reader(input, |event| scanner.visit(event, position.get()))?;
    scanner.summary().map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use nix_archive::nar::{NamedNode, Node, encode_tree};

    use super::*;

    #[test]
    fn scanner_streams_file_and_symlink_records_with_payload_metadata() {
        // The scanner's useful output is deliberately narrower than a full
        // tree decode: file bytes become a digest plus their source offset,
        // while symlinks retain their raw target bytes. This fixture exercises
        // both record shapes in one root directory.
        let children = [
            NamedNode {
                name: b"file",
                node: Node::Regular {
                    executable: false,
                    contents: b"hello",
                },
            },
            NamedNode {
                name: b"link",
                node: Node::Symlink { target: b"target" },
            },
        ];
        let mut nar = Vec::new();
        encode_tree(&mut nar, &Node::Directory(&children)).expect("fixture encoding succeeds");

        let (mut input, position) = HashingReader::new(Cursor::new(nar));
        let mut output = Vec::new();
        let summary = scan_reader(&mut input, &position, "sample.nar", &mut output)
            .expect("canonical fixture scans");

        assert_eq!(
            summary,
            ScanSummary {
                root: "directory",
                entries: 2,
                files: 1,
                symlinks: 1,
            }
        );
        let output = String::from_utf8(output).expect("scanner output is UTF-8 TSV");
        let file = output
            .lines()
            .find(|line| line.contains("\tfile\t"))
            .expect("regular-file record is present")
            .split('\t')
            .collect::<Vec<_>>();
        assert_eq!(file[1], "sample.nar");
        assert_eq!(file[2], "file");
        assert_eq!(file[3], "5");
        assert!(file[4].starts_with("2cf24dba"), "{file:?}");
        assert!(file[5].parse::<u64>().expect("file offset is numeric") > 0);
        assert!(output.contains("\tsymlink\t6\t34a04005"));
        let (_, digest) = input.finish();
        assert_eq!(position.get(), digest.bytes);
    }
}
