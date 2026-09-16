use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar_corpus::{HashingReader, HashingWriter, hex};
use nix_archive::nar::{Event, FileContents, decode_events_reader};

struct Scanner<'a, W> {
    path: &'a str,
    output: &'a mut W,
    root: Option<&'static str>,
    entries: u64,
    files: u64,
    symlinks: u64,
}

impl<W: Write> Scanner<'_, W> {
    fn visit<R: io::Read + ?Sized>(
        &mut self,
        event: Event<'_, FileContents<'_, R>>,
        offset: u64,
    ) -> Result<(), nix_archive::nar::Error> {
        match event {
            Event::DirectoryStart { name } => self.record_node(name, "directory"),
            Event::DirectoryEnd { .. } => {}
            Event::Regular {
                name,
                executable,
                mut contents,
            } => {
                self.record_node(name, "regular");
                let size = contents.size();
                let mut digest = HashingWriter::new(io::sink());
                let copied = contents.copy_to(&mut digest)?;
                if copied != size {
                    return Err(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "short NAR file").into(),
                    );
                }
                let (_, _, digest) = digest.finish();
                writeln!(
                    self.output,
                    "O\t{}\tfile\t{}\t{}\t{}\t{}\t",
                    self.path,
                    size,
                    hex(&digest),
                    offset,
                    u8::from(executable),
                )?;
                self.files += 1;
            }
            Event::Symlink { name, target } => {
                self.record_node(name, "symlink");
                let mut digest = HashingWriter::new(io::sink());
                digest.write_all(target)?;
                let (_, _, digest) = digest.finish();
                writeln!(
                    self.output,
                    "O\t{}\tsymlink\t{}\t{}\t-\t0\t{}",
                    self.path,
                    target.len(),
                    hex(&digest),
                    hex(target),
                )?;
                self.symlinks += 1;
            }
        }
        Ok(())
    }

    fn record_node(&mut self, name: Option<&[u8]>, root: &'static str) {
        if name.is_some() {
            self.entries += 1;
        } else {
            self.root = Some(root);
        }
    }
}

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mut input_list = None;
    let mut output_path = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--input-list") => input_list = args.next(),
            Some("--output") => output_path = args.next(),
            Some("--help") => {
                println!("usage: nar-scan --input-list PATH [--output PATH]");
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown argument",
                ));
            }
        }
    }
    let input_list = input_list
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--input-list is required"))?;
    let list = File::open(input_list)?;
    let mut output: Box<dyn Write> = match output_path {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::BufWriter::new(io::stdout().lock())),
    };
    writeln!(output, "# narjar-nar-scan-v1")?;

    for line in BufReader::new(list).lines() {
        let path = line?;
        if path.is_empty() {
            continue;
        }
        if path.contains(['\t', '\n', '\r']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input path contains a tab or newline",
            ));
        }
        scan_one(&path, &mut output)?;
    }
    output.flush()
}

fn scan_one<W: Write>(path: &str, output: &mut W) -> io::Result<()> {
    let file = File::open(Path::new(path))?;
    let (mut input, position) = HashingReader::new(BufReader::with_capacity(1024 * 1024, file));
    let mut scanner = Scanner {
        path,
        output,
        root: None,
        entries: 0,
        files: 0,
        symlinks: 0,
    };
    decode_events_reader(&mut input, |event| scanner.visit(event, position.get()))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (_, raw_size, raw_sha256) = input.finish();
    writeln!(
        scanner.output,
        "N\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        path,
        raw_size,
        hex(&raw_sha256),
        scanner.root.unwrap_or("unknown"),
        scanner.entries,
        scanner.files,
        scanner.symlinks,
    )
}
