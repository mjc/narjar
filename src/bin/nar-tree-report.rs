use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar::nar::{Decoder, Event, EventSink};
use sha2::{Digest, Sha256};

const SEMANTIC_PREFIX: &[u8] = b"narjar-semantic\0\x01";

#[derive(Clone, Copy, Debug)]
struct TreeRecord {
    occurrences: u64,
    logical_bytes: u64,
}

#[derive(Debug)]
struct TreeEntry {
    name: Vec<u8>,
    kind: u8,
    oid: [u8; 32],
}

#[derive(Debug)]
struct DirectoryFrame {
    name: Option<Vec<u8>>,
    entries: Vec<TreeEntry>,
}

struct FileState {
    executable: bool,
    digest: Sha256,
}

#[derive(Default)]
struct ScannerStats {
    tree_count: u64,
    tree_bytes: u64,
    max_depth: usize,
    max_fanout: usize,
    local_trees: BTreeSet<[u8; 32]>,
}

struct Scanner<'a> {
    global_trees: &'a mut BTreeMap<[u8; 32], TreeRecord>,
    directories: Vec<DirectoryFrame>,
    pending_name: Option<Vec<u8>>,
    file: Option<FileState>,
    stats: ScannerStats,
}

impl Scanner<'_> {
    fn new(global_trees: &mut BTreeMap<[u8; 32], TreeRecord>) -> Scanner<'_> {
        Scanner {
            global_trees,
            directories: Vec::new(),
            pending_name: None,
            file: None,
            stats: ScannerStats::default(),
        }
    }

    fn add_node(&mut self, kind: u8, oid: [u8; 32]) -> io::Result<()> {
        let name = self
            .pending_name
            .take()
            .ok_or_else(|| io::Error::other("semantic node without directory entry"))?;
        let directory = self
            .directories
            .last_mut()
            .ok_or_else(|| io::Error::other("nested node without directory"))?;
        directory.entries.push(TreeEntry { name, kind, oid });
        Ok(())
    }

    fn add_root(&mut self, kind: u8, oid: [u8; 32]) -> io::Result<()> {
        if !self.directories.is_empty() || self.pending_name.is_some() {
            return Err(io::Error::other("root node completed inside a directory"));
        }
        if self.file.is_some() {
            return Err(io::Error::other("root node completed inside a file"));
        }
        let _ = (kind, oid);
        Ok(())
    }

    fn add_completed_node(&mut self, kind: u8, oid: [u8; 32]) -> io::Result<()> {
        if self.directories.is_empty() {
            self.add_root(kind, oid)
        } else {
            self.add_node(kind, oid)
        }
    }

    fn finish_directory(&mut self) -> io::Result<()> {
        let directory = self
            .directories
            .pop()
            .ok_or_else(|| io::Error::other("directory end without directory"))?;
        self.stats.max_fanout = self.stats.max_fanout.max(directory.entries.len());
        let logical_bytes = tree_preimage_len(&directory.entries)?;
        let oid = tree_oid(&directory.entries);
        self.stats.tree_count = self
            .stats
            .tree_count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("tree count overflow"))?;
        self.stats.tree_bytes = self
            .stats
            .tree_bytes
            .checked_add(logical_bytes)
            .ok_or_else(|| io::Error::other("tree byte count overflow"))?;
        self.stats.local_trees.insert(oid);
        let record = self.global_trees.entry(oid).or_insert(TreeRecord {
            occurrences: 0,
            logical_bytes,
        });
        record.occurrences = record
            .occurrences
            .checked_add(1)
            .ok_or_else(|| io::Error::other("tree occurrence overflow"))?;
        if record.logical_bytes != logical_bytes {
            return Err(io::Error::other(
                "tree OID has inconsistent preimage length",
            ));
        }

        if self.directories.is_empty() {
            self.add_root(4, oid)
        } else {
            self.pending_name = directory.name;
            self.add_node(4, oid)
        }
    }

    fn report(self, path: &str, summary: &narjar::nar::DecodeSummary) -> String {
        let repeated = self.stats.tree_count - self.stats.local_trees.len() as u64;
        format!(
            "N\t{path}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            summary.entries,
            self.stats.tree_count,
            self.stats.local_trees.len(),
            repeated,
            self.stats.tree_bytes,
            self.stats.max_depth,
            self.stats.max_fanout,
        )
    }
}

impl EventSink for Scanner<'_> {
    fn event(&mut self, event: Event<'_>) -> io::Result<()> {
        match event {
            Event::BeginDirectory { depth } => {
                self.stats.max_depth = self.stats.max_depth.max(depth);
                self.directories.push(DirectoryFrame {
                    name: self.pending_name.take(),
                    entries: Vec::new(),
                });
            }
            Event::Entry { name } => self.pending_name = Some(name),
            Event::BeginFile {
                executable, size, ..
            } => {
                let kind = if executable { 2 } else { 1 };
                let mut digest = Sha256::new();
                digest.update(SEMANTIC_PREFIX);
                digest.update([kind]);
                digest.update(size.to_le_bytes());
                self.file = Some(FileState { executable, digest });
            }
            Event::FileChunk(chunk) => self
                .file
                .as_mut()
                .ok_or_else(|| io::Error::other("file chunk without file"))?
                .digest
                .update(chunk),
            Event::EndFile => {
                let file = self
                    .file
                    .take()
                    .ok_or_else(|| io::Error::other("file end without file"))?;
                let kind = if file.executable { 2 } else { 1 };
                let mut oid = [0_u8; 32];
                oid.copy_from_slice(file.digest.finalize().as_slice());
                self.add_completed_node(kind, oid)?;
            }
            Event::Symlink { target } => {
                let mut digest = Sha256::new();
                digest.update(SEMANTIC_PREFIX);
                digest.update([3]);
                digest.update((target.len() as u64).to_le_bytes());
                digest.update(target);
                let mut oid = [0_u8; 32];
                oid.copy_from_slice(digest.finalize().as_slice());
                self.add_completed_node(3, oid)?;
            }
            Event::EndDirectory => self.finish_directory()?,
        }
        Ok(())
    }
}

fn tree_preimage_len(entries: &[TreeEntry]) -> io::Result<u64> {
    let mut size = (SEMANTIC_PREFIX.len() + 1 + 8) as u64;
    for entry in entries {
        size = size
            .checked_add(8)
            .and_then(|size| size.checked_add(entry.name.len() as u64))
            .and_then(|size| size.checked_add(1 + 32))
            .ok_or_else(|| io::Error::other("tree preimage length overflow"))?;
    }
    Ok(size)
}

fn tree_oid(entries: &[TreeEntry]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SEMANTIC_PREFIX);
    digest.update([4]);
    digest.update((entries.len() as u64).to_le_bytes());
    for entry in entries {
        digest.update((entry.name.len() as u64).to_le_bytes());
        digest.update(&entry.name);
        digest.update([entry.kind]);
        digest.update(entry.oid);
    }
    let mut oid = [0_u8; 32];
    oid.copy_from_slice(digest.finalize().as_slice());
    oid
}

fn scan_one(
    path: &str,
    global_trees: &mut BTreeMap<[u8; 32], TreeRecord>,
) -> io::Result<(String, narjar::nar::DecodeSummary)> {
    let file = File::open(Path::new(path))?;
    let mut decoder = Decoder::new(BufReader::with_capacity(1024 * 1024, file));
    let mut scanner = Scanner::new(global_trees);
    let summary = decoder
        .decode(&mut scanner)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok((scanner.report(path, &summary), summary))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
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
                println!("usage: nar-tree-report --input-list PATH [--output PATH]");
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
    writeln!(output, "# narjar-nar-tree-report-v1")?;
    let mut global_trees = BTreeMap::new();
    let mut total_tree_occurrences = 0_u64;
    let mut total_tree_bytes = 0_u64;

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
        let (report, summary) = scan_one(&path, &mut global_trees)?;
        let fields = report.trim_end().split('\t').collect::<Vec<_>>();
        total_tree_occurrences += fields[3]
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid tree count"))?;
        total_tree_bytes += fields[6]
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid tree byte count"))?;
        output.write_all(report.as_bytes())?;
        let _ = summary;
    }

    let unique_tree_bytes = global_trees
        .values()
        .try_fold(0_u64, |total, record| {
            total.checked_add(record.logical_bytes)
        })
        .ok_or_else(|| io::Error::other("unique tree byte count overflow"))?;
    let repeated = total_tree_occurrences - global_trees.len() as u64;
    writeln!(
        output,
        "G\t{total_tree_occurrences}\t{}\t{repeated}\t{total_tree_bytes}\t{unique_tree_bytes}",
        global_trees.len()
    )?;
    for (oid, record) in global_trees {
        writeln!(
            output,
            "T\t{}\t{}\t{}",
            hex(&oid),
            record.occurrences,
            record.logical_bytes
        )?;
    }
    output.flush()
}
