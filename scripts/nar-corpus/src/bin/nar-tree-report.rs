use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use narjar_corpus::{
    HashingReader, HashingWriter, hex, parse_input_list_arguments, usable_input_path,
};
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

struct ScanReport {
    line: String,
    tree_count: u64,
    tree_bytes: u64,
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
                self.count_named_entry(name);
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
                contents,
            } => self.hash_regular_node_and_append_entry(name, executable, contents)?,
            Event::Symlink { name, target } => {
                self.hash_symlink_target_and_append_entry(name, target)?
            }
        }
        Ok(())
    }

    fn hash_regular_node_and_append_entry<R: io::Read + ?Sized>(
        &mut self,
        name: Option<&[u8]>,
        executable: bool,
        mut contents: FileContents<'_, R>,
    ) -> Result<(), nix_archive::nar::Error> {
        self.count_named_entry(name);
        let kind = if executable { 2 } else { 1 };
        let mut digest = HashingWriter::new(io::sink());
        digest.write_all(SEMANTIC_PREFIX)?;
        digest.write_all(&[kind])?;
        digest.write_all(&contents.size().to_le_bytes())?;
        contents.copy_to(&mut digest)?;
        let (_, summary) = digest.finish();
        let mut oid = [0_u8; 32];
        oid.copy_from_slice(&summary.sha256);
        self.append_completed_entry(name, kind, oid)
            .map_err(Into::into)
    }

    fn hash_symlink_target_and_append_entry(
        &mut self,
        name: Option<&[u8]>,
        target: &[u8],
    ) -> Result<(), nix_archive::nar::Error> {
        self.count_named_entry(name);
        let mut digest = Sha256::new();
        digest.update(SEMANTIC_PREFIX);
        digest.update([3]);
        digest.update((target.len() as u64).to_le_bytes());
        digest.update(target);
        let mut oid = [0_u8; 32];
        oid.copy_from_slice(&digest.finalize());
        self.append_completed_entry(name, 3, oid)
            .map_err(Into::into)
    }

    fn count_named_entry(&mut self, name: Option<&[u8]>) {
        self.stats.entries += u64::from(name.is_some());
    }

    fn append_completed_entry(
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
        self.append_completed_entry(directory.name.as_deref(), 4, oid)
    }

    fn build_scan_report(self, path: &str) -> ScanReport {
        let repeated = self.stats.tree_count - self.stats.local_trees.len() as u64;
        ScanReport {
            line: format!(
                "N\t{path}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                self.stats.entries,
                self.stats.tree_count,
                self.stats.local_trees.len(),
                repeated,
                self.stats.tree_bytes,
                self.stats.max_depth,
                self.stats.max_fanout,
            ),
            tree_count: self.stats.tree_count,
            tree_bytes: self.stats.tree_bytes,
        }
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

fn scan_one(
    path: &str,
    global_trees: &mut BTreeMap<[u8; 32], TreeRecord>,
) -> io::Result<ScanReport> {
    let file = File::open(Path::new(path))?;
    let (mut input, _) = HashingReader::new(BufReader::with_capacity(1024 * 1024, file));
    scan_reader(&mut input, path, global_trees)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn scan_reader<R: io::Read>(
    input: &mut HashingReader<R>,
    path: &str,
    global_trees: &mut BTreeMap<[u8; 32], TreeRecord>,
) -> Result<ScanReport, nix_archive::nar::Error> {
    let mut scanner = Scanner::new(global_trees);
    decode_events_reader(input, |event| scanner.visit(event))?;
    Ok(scanner.build_scan_report(path))
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
    writeln!(output, "# narjar-nar-tree-report-v1")?;
    let mut global_trees = BTreeMap::new();
    let mut total_tree_occurrences = 0_u64;
    let mut total_tree_bytes = 0_u64;

    BufReader::new(list)
        .lines()
        .map(|line| line.and_then(usable_input_path))
        .try_for_each(|path| {
            path?.map_or(Ok(()), |path| {
                let report = scan_one(&path, &mut global_trees)?;
                total_tree_occurrences += report.tree_count;
                total_tree_bytes += report.tree_bytes;
                output.write_all(report.line.as_bytes())
            })
        })?;

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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use nix_archive::nar::{NamedNode, Node, encode_tree};

    use super::*;

    #[test]
    fn tree_report_counts_identical_subtrees_once_for_unique_bytes() {
        // `a/child` and `b/child` are different paths but identical semantic
        // subtrees. The report must count three tree occurrences (a, b, root),
        // while charging only two unique tree preimages.
        let child_entries = [NamedNode {
            name: b"child",
            node: Node::Regular {
                executable: false,
                contents: b"x",
            },
        }];
        let child = Node::Directory(&child_entries);
        let root = [
            NamedNode {
                name: b"a",
                node: child,
            },
            NamedNode {
                name: b"b",
                node: child,
            },
        ];
        let mut nar = Vec::new();
        encode_tree(&mut nar, &Node::Directory(&root)).expect("fixture encoding succeeds");

        let (mut input, _) = HashingReader::new(Cursor::new(nar));
        let mut trees = BTreeMap::new();
        let report =
            scan_reader(&mut input, "sample.nar", &mut trees).expect("canonical fixture scans");

        let fields = report.line.trim_end().split('\t').collect::<Vec<_>>();
        assert_eq!(fields[0], "N");
        assert_eq!(fields[2], "4", "four named entries are visited");
        assert_eq!(fields[3], "3", "three directory tree occurrences");
        assert_eq!(fields[4], "2", "the two identical child trees share bytes");
        assert_eq!(fields[5], "1", "one occurrence is repeated");
        assert_eq!(trees.len(), 2);
    }
}
