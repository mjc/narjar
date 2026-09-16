use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar_corpus::{HashingReader, HashingWriter, hex};
use nix_archive::nar::{Event, FileContents, decode_events_reader};
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

#[derive(Default)]
struct ScannerStats {
    entries: u64,
    tree_count: u64,
    tree_bytes: u64,
    max_depth: usize,
    max_fanout: usize,
    local_trees: BTreeSet<[u8; 32]>,
}

struct Scanner<'a> {
    global_trees: &'a mut BTreeMap<[u8; 32], TreeRecord>,
    directories: Vec<DirectoryFrame>,
    stats: ScannerStats,
}

impl Scanner<'_> {
    fn new(global_trees: &mut BTreeMap<[u8; 32], TreeRecord>) -> Scanner<'_> {
        Scanner {
            global_trees,
            directories: Vec::new(),
            stats: ScannerStats::default(),
        }
    }

    fn visit<R: io::Read + ?Sized>(
        &mut self,
        event: Event<'_, FileContents<'_, R>>,
    ) -> Result<(), nix_archive::nar::Error> {
        match event {
            Event::DirectoryStart { name } => {
                self.stats.entries += u64::from(name.is_some());
                self.stats.max_depth = self.stats.max_depth.max(self.directories.len());
                self.directories.push(DirectoryFrame {
                    name: name.map(ToOwned::to_owned),
                    entries: Vec::new(),
                });
            }
            Event::DirectoryEnd { .. } => self.finish_directory()?,
            Event::Regular {
                name,
                executable,
                mut contents,
            } => {
                self.stats.entries += u64::from(name.is_some());
                let kind = if executable { 2 } else { 1 };
                let mut digest = HashingWriter::new(io::sink());
                digest.write_all(SEMANTIC_PREFIX)?;
                digest.write_all(&[kind])?;
                digest.write_all(&contents.size().to_le_bytes())?;
                contents.copy_to(&mut digest)?;
                let (_, _, digest) = digest.finish();
                self.add_completed_node(name, kind, digest)?;
            }
            Event::Symlink { name, target } => {
                self.stats.entries += u64::from(name.is_some());
                let mut digest = Sha256::new();
                digest.update(SEMANTIC_PREFIX);
                digest.update([3]);
                digest.update((target.len() as u64).to_le_bytes());
                digest.update(target);
                let mut oid = [0_u8; 32];
                oid.copy_from_slice(&digest.finalize());
                self.add_completed_node(name, 3, oid)?;
            }
        }
        Ok(())
    }

    fn add_completed_node(
        &mut self,
        name: Option<&[u8]>,
        kind: u8,
        oid: [u8; 32],
    ) -> io::Result<()> {
        match self.directories.last_mut() {
            Some(directory) => directory.entries.push(TreeEntry {
                name: name
                    .ok_or_else(|| io::Error::other("unnamed node inside directory"))?
                    .to_owned(),
                kind,
                oid,
            }),
            None if name.is_none() => {}
            None => return Err(io::Error::other("named root node")),
        }
        Ok(())
    }

    fn finish_directory(&mut self) -> io::Result<()> {
        let directory = self
            .directories
            .pop()
            .ok_or_else(|| io::Error::other("directory end without directory"))?;
        self.stats.max_fanout = self.stats.max_fanout.max(directory.entries.len());
        let logical_bytes = tree_preimage_len(&directory.entries)?;
        let oid = tree_oid(&directory.entries);
        self.stats.tree_count += 1;
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
        record.occurrences += 1;
        if record.logical_bytes != logical_bytes {
            return Err(io::Error::other(
                "tree OID has inconsistent preimage length",
            ));
        }
        self.add_completed_node(directory.name.as_deref(), 4, oid)
    }

    fn report(self, path: &str) -> String {
        let repeated = self.stats.tree_count - self.stats.local_trees.len() as u64;
        format!(
            "N\t{path}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.stats.entries,
            self.stats.tree_count,
            self.stats.local_trees.len(),
            repeated,
            self.stats.tree_bytes,
            self.stats.max_depth,
            self.stats.max_fanout,
        )
    }
}

fn tree_preimage_len(entries: &[TreeEntry]) -> io::Result<u64> {
    entries
        .iter()
        .try_fold((SEMANTIC_PREFIX.len() + 1 + 8) as u64, |size, entry| {
            size.checked_add(8)
                .and_then(|size| size.checked_add(entry.name.len() as u64))
                .and_then(|size| size.checked_add(1 + 32))
                .ok_or_else(|| io::Error::other("tree preimage length overflow"))
        })
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
    oid.copy_from_slice(&digest.finalize());
    oid
}

fn scan_one(path: &str, global_trees: &mut BTreeMap<[u8; 32], TreeRecord>) -> io::Result<String> {
    let file = File::open(Path::new(path))?;
    let (mut input, _) = HashingReader::new(BufReader::with_capacity(1024 * 1024, file));
    let mut scanner = Scanner::new(global_trees);
    decode_events_reader(&mut input, |event| scanner.visit(event))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(scanner.report(path))
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
        let report = scan_one(&path, &mut global_trees)?;
        let fields = report.trim_end().split('\t').collect::<Vec<_>>();
        total_tree_occurrences += fields[3]
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid tree count"))?;
        total_tree_bytes += fields[6]
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid tree byte count"))?;
        output.write_all(report.as_bytes())?;
    }

    let unique_tree_bytes = global_trees.values().try_fold(0_u64, |total, record| {
        total
            .checked_add(record.logical_bytes)
            .ok_or_else(|| io::Error::other("unique tree byte count overflow"))
    })?;
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
