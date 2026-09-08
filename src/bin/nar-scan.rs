use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar::nar::{Decoder, Event, EventSink, RootKind};
use sha2::{Digest, Sha256};

struct Scanner<'a, W> {
    path: &'a str,
    output: &'a mut W,
    file: Option<FileObject>,
}

struct FileObject {
    executable: bool,
    size: u64,
    offset: u64,
    digest: Sha256,
}

impl<W: Write> EventSink for Scanner<'_, W> {
    fn event(&mut self, event: Event<'_>) -> io::Result<()> {
        match event {
            Event::BeginFile {
                executable,
                size,
                offset,
            } => {
                self.file = Some(FileObject {
                    executable,
                    size,
                    offset,
                    digest: Sha256::new(),
                });
            }
            Event::FileChunk(chunk) => {
                let file = self
                    .file
                    .as_mut()
                    .ok_or_else(|| io::Error::other("file chunk without file"))?;
                file.digest.update(chunk);
            }
            Event::EndFile => {
                let file = self
                    .file
                    .take()
                    .ok_or_else(|| io::Error::other("file end without file"))?;
                writeln!(
                    self.output,
                    "O\t{}\tfile\t{}\t{}\t{}\t{}\t",
                    self.path,
                    file.size,
                    hex(file.digest.finalize().as_slice()),
                    file.offset,
                    u8::from(file.executable),
                )?;
            }
            Event::Symlink { target } => {
                let mut digest = Sha256::new();
                digest.update(&target);
                writeln!(
                    self.output,
                    "O\t{}\tsymlink\t{}\t{}\t-\t0\t{}",
                    self.path,
                    target.len(),
                    hex(digest.finalize().as_slice()),
                    hex(&target),
                )?;
            }
            _ => {}
        }
        Ok(())
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
    let mut decoder = Decoder::new(BufReader::with_capacity(1024 * 1024, file));
    let mut scanner = Scanner {
        path,
        output,
        file: None,
    };
    let summary = decoder
        .decode(&mut scanner)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let root = match summary.root {
        RootKind::Directory => "directory",
        RootKind::Regular => "regular",
        RootKind::Symlink => "symlink",
    };
    writeln!(
        scanner.output,
        "N\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        path,
        summary.raw_size,
        hex(&summary.raw_sha256),
        root,
        summary.entries,
        summary.files,
        summary.symlinks,
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
