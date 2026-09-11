use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Kind {
    File,
    Symlink,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Clone, Debug)]
struct Object {
    path: PathBuf,
    kind: Kind,
    size: u64,
    digest: String,
    offset: Option<u64>,
    executable: bool,
    payload_hex: String,
    identity: Option<usize>,
    collision: bool,
}

#[derive(Debug)]
struct Nar {
    path: PathBuf,
    raw_size: u64,
    raw_sha256: String,
    root: String,
    entries: u64,
    files: u64,
    symlinks: u64,
    identity: Option<usize>,
    collision: bool,
}

#[derive(Debug)]
struct Scan {
    nars: Vec<Nar>,
    objects: Vec<Object>,
}

#[cfg(test)]
#[derive(Debug)]
struct Aggregate {
    occurrences: u64,
    unique_objects: u64,
    total_payload_bytes: u64,
    unique_payload_bytes: u64,
    collision_count: u64,
}

#[cfg(test)]
impl Aggregate {
    fn duplicate_payload_bytes(&self) -> u64 {
        self.total_payload_bytes - self.unique_payload_bytes
    }
}

#[derive(Debug)]
enum Error {
    InvalidRow { line: usize, message: String },
    Io(io::Error),
    InvalidArgument(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRow { line, message } => {
                write!(formatter, "invalid scanner row at {line}: {message}")
            }
            Self::Io(error) => error.fmt(formatter),
            Self::InvalidArgument(message) => formatter.write_str(message),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
fn size_bucket(size: u64) -> &'static str {
    if size < 1024 {
        "<1KiB"
    } else if size < 1024 * 1024 {
        "1KiB-1MiB"
    } else if size < 16 * 1024 * 1024 {
        "1MiB-16MiB"
    } else if size < 1024 * 1024 * 1024 {
        "16MiB-1GiB"
    } else {
        ">=1GiB"
    }
}

fn parse_scan(path: &Path) -> Result<Scan, Error> {
    let input = File::open(path)?;
    let mut scan = Scan {
        nars: Vec::new(),
        objects: Vec::new(),
    };
    for (line_index, line) in BufReader::new(input).lines().enumerate() {
        let line_number = line_index + 1;
        let line = line?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["N", path, raw_size, raw_sha256, root, entries, files, symlinks] => {
                scan.nars.push(Nar {
                    path: PathBuf::from(path),
                    raw_size: parse_u64(raw_size, line_number, "raw size")?,
                    raw_sha256: (*raw_sha256).to_owned(),
                    root: (*root).to_owned(),
                    entries: parse_u64(entries, line_number, "entry count")?,
                    files: parse_u64(files, line_number, "file count")?,
                    symlinks: parse_u64(symlinks, line_number, "symlink count")?,
                    identity: None,
                    collision: false,
                });
            }
            [
                "O",
                path,
                kind,
                size,
                digest,
                offset,
                executable,
                payload_hex,
            ] => {
                let kind = match *kind {
                    "file" => Kind::File,
                    "symlink" => Kind::Symlink,
                    _ => {
                        return Err(Error::InvalidRow {
                            line: line_number,
                            message: "unknown object kind".to_owned(),
                        });
                    }
                };
                scan.objects.push(Object {
                    path: PathBuf::from(path),
                    kind,
                    size: parse_u64(size, line_number, "object size")?,
                    digest: (*digest).to_owned(),
                    offset: if *offset == "-" {
                        None
                    } else {
                        Some(parse_u64(offset, line_number, "object offset")?)
                    },
                    executable: parse_u64(executable, line_number, "executable flag")? != 0,
                    payload_hex: (*payload_hex).to_owned(),
                    identity: None,
                    collision: false,
                });
            }
            _ => {
                return Err(Error::InvalidRow {
                    line: line_number,
                    message: "expected an N or O row with eight fields".to_owned(),
                });
            }
        }
    }
    Ok(scan)
}

fn parse_u64(value: &str, line: usize, name: &str) -> Result<u64, Error> {
    value.parse().map_err(|_| Error::InvalidRow {
        line,
        message: format!("invalid {name}"),
    })
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ObjectKey {
    kind: Kind,
    size: u64,
    digest: String,
}

fn verify_objects(objects: &mut [Object]) -> Result<(), Error> {
    let mut representatives: HashMap<ObjectKey, Vec<(usize, usize)>> = HashMap::new();
    let mut verified: HashMap<ObjectKey, usize> = HashMap::new();
    let mut next_identity = 0;
    for index in 0..objects.len() {
        let key = ObjectKey {
            kind: objects[index].kind,
            size: objects[index].size,
            digest: objects[index].digest.clone(),
        };
        if let Some(identity) = verified.get(&key) {
            objects[index].identity = Some(*identity);
            continue;
        }
        let mut matched = None;
        if let Some(candidates) = representatives.get(&key) {
            for (identity, candidate) in candidates {
                if compare_objects(&objects[*candidate], &objects[index])? {
                    matched = Some(*identity);
                    break;
                }
            }
        }
        if let Some(identity) = matched {
            objects[index].identity = Some(identity);
            if representatives[&key].len() == 1 {
                verified.insert(key, identity);
            }
        } else {
            let identity = next_identity;
            next_identity += 1;
            objects[index].identity = Some(identity);
            objects[index].collision = representatives.contains_key(&key);
            representatives.entry(key).or_default().push((identity, index));
        }
    }
    Ok(())
}

fn verify_nars(nars: &mut [Nar]) -> Result<(), Error> {
    let mut representatives: HashMap<(u64, String), Vec<(usize, usize)>> = HashMap::new();
    let mut verified: HashMap<(u64, String), usize> = HashMap::new();
    let mut next_identity = 0;
    for index in 0..nars.len() {
        let key = (nars[index].raw_size, nars[index].raw_sha256.clone());
        if let Some(identity) = verified.get(&key) {
            nars[index].identity = Some(*identity);
            continue;
        }
        let mut matched = None;
        if let Some(candidates) = representatives.get(&key) {
            for (identity, candidate) in candidates {
                if compare_nars(&nars[*candidate], &nars[index])? {
                    matched = Some(*identity);
                    break;
                }
            }
        }
        if let Some(identity) = matched {
            nars[index].identity = Some(identity);
            if representatives[&key].len() == 1 {
                verified.insert(key, identity);
            }
        } else {
            let identity = next_identity;
            next_identity += 1;
            nars[index].identity = Some(identity);
            nars[index].collision = representatives.contains_key(&key);
            representatives.entry(key).or_default().push((identity, index));
        }
    }
    Ok(())
}

fn compare_nars(left: &Nar, right: &Nar) -> Result<bool, Error> {
    if left.raw_size != right.raw_size {
        return Ok(false);
    }
    let mut left_file = File::open(&left.path)?;
    let mut right_file = File::open(&right.path)?;
    let mut left_buffer = vec![0_u8; 1024 * 1024];
    let mut right_buffer = vec![0_u8; 1024 * 1024];
    let mut remaining = left.raw_size;
    while remaining != 0 {
        let length = remaining.min(left_buffer.len() as u64) as usize;
        left_file.read_exact(&mut left_buffer[..length])?;
        right_file.read_exact(&mut right_buffer[..length])?;
        if left_buffer[..length] != right_buffer[..length] {
            return Ok(false);
        }
        remaining -= length as u64;
    }
    Ok(true)
}

fn compare_objects(left: &Object, right: &Object) -> Result<bool, Error> {
    if left.size != right.size {
        return Ok(false);
    }
    if left.kind != Kind::File || right.kind != Kind::File {
        return Ok(left.payload_hex == right.payload_hex);
    }
    let (Some(left_offset), Some(right_offset)) = (left.offset, right.offset) else {
        return Ok(false);
    };
    let mut left_file = File::open(&left.path)?;
    let mut right_file = File::open(&right.path)?;
    left_file.seek(SeekFrom::Start(left_offset))?;
    right_file.seek(SeekFrom::Start(right_offset))?;
    let mut left_buffer = vec![0_u8; 1024 * 1024];
    let mut right_buffer = vec![0_u8; 1024 * 1024];
    let mut remaining = left.size;
    while remaining != 0 {
        let length = remaining.min(left_buffer.len() as u64) as usize;
        left_file.read_exact(&mut left_buffer[..length])?;
        right_file.read_exact(&mut right_buffer[..length])?;
        if left_buffer[..length] != right_buffer[..length] {
            return Ok(false);
        }
        remaining -= length as u64;
    }
    Ok(true)
}

#[cfg(test)]
fn aggregate_objects(objects: &[Object], minimum_size: u64) -> Result<Aggregate, Error> {
    let mut objects = objects.to_vec();
    verify_objects(&mut objects)?;
    let mut seen: HashMap<(Kind, u64, usize), usize> = HashMap::new();
    let mut total_payload_bytes = 0;
    let mut unique_payload_bytes = 0;
    let mut unique_objects = 0;
    let mut collision_count = 0;
    let mut occurrences = 0;
    for object in objects {
        if object.size < minimum_size {
            continue;
        }
        occurrences += 1;
        total_payload_bytes += object.size;
        let identity = object.identity.unwrap_or(usize::MAX);
        let key = (object.kind, object.size, identity);
        if seen.insert(key, 1).is_none() {
            unique_objects += 1;
            unique_payload_bytes += object.size;
            collision_count += u64::from(object.collision);
        }
    }
    Ok(Aggregate {
        occurrences,
        unique_objects,
        total_payload_bytes,
        unique_payload_bytes,
        collision_count,
    })
}

fn parse_arguments() -> Result<(PathBuf, PathBuf), Error> {
    let mut scan = None;
    let mut output = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--scan") => scan = args.next().map(PathBuf::from),
            Some("--output") => output = args.next().map(PathBuf::from),
            Some("--help") => {
                println!("usage: nar-report --scan PATH --output PATH");
                std::process::exit(0);
            }
            Some(value) => return Err(Error::InvalidArgument(format!("unknown argument: {value}"))),
            None => return Err(Error::InvalidArgument("argument is not UTF-8".to_owned())),
        }
    }
    let scan = scan.ok_or_else(|| Error::InvalidArgument("--scan is required".to_owned()))?;
    let output = output.ok_or_else(|| Error::InvalidArgument("--output is required".to_owned()))?;
    Ok((scan, output))
}

fn write_enriched(scan: &Scan, output: &Path) -> Result<(), Error> {
    let mut objects = scan.objects.clone();
    let mut nars = scan.nars.iter().map(|nar| Nar {
        path: nar.path.clone(),
        raw_size: nar.raw_size,
        raw_sha256: nar.raw_sha256.clone(),
        root: nar.root.clone(),
        entries: nar.entries,
        files: nar.files,
        symlinks: nar.symlinks,
        identity: None,
        collision: false,
    }).collect::<Vec<_>>();
    verify_objects(&mut objects)?;
    verify_nars(&mut nars)?;
    let mut file = io::BufWriter::new(File::create(output)?);
    for object in objects {
        writeln!(
            file,
            "O\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            object.path.display(),
            object.kind.as_str(),
            object.size,
            object.digest,
            object.offset.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            u8::from(object.executable),
            object.payload_hex,
            object.identity.unwrap_or(usize::MAX),
            u8::from(object.collision),
        )?;
    }
    for nar in &nars {
        writeln!(
            file,
            "N\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            nar.path.display(), nar.raw_size, nar.raw_sha256, nar.root, nar.entries, nar.files, nar.symlinks,
            nar.identity.unwrap_or(usize::MAX), u8::from(nar.collision)
        )?;
    }
    file.flush()?;
    Ok(())
}

fn main() {
    let result = parse_arguments().and_then(|(scan, output)| {
        let scan = parse_scan(&scan)?;
        write_enriched(&scan, &output)
    });
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("narjar-nar-report-{name}-{}", std::process::id()));
        fs::write(&path, bytes).expect("write fixture");
        path
    }

    #[test]
    fn size_buckets_are_stable() {
        assert_eq!(size_bucket(1023), "<1KiB");
        assert_eq!(size_bucket(1024), "1KiB-1MiB");
        assert_eq!(size_bucket(1024 * 1024), "1MiB-16MiB");
        assert_eq!(size_bucket(16 * 1024 * 1024), "16MiB-1GiB");
        assert_eq!(size_bucket(1024 * 1024 * 1024), ">=1GiB");
    }

    #[test]
    fn repeated_file_bytes_are_verified_and_counted_once() {
        let first = fixture("first", b"prefixsamepayloadsuffix");
        let second = fixture("second", b"other--samepayloadsuffix");
        let objects = vec![
            Object {
                path: first.clone(),
                kind: Kind::File,
                size: 12,
                digest: "same".to_owned(),
                offset: Some(6),
                executable: false,
                payload_hex: String::new(),
                identity: None,
                collision: false,
            },
            Object {
                path: second.clone(),
                kind: Kind::File,
                size: 12,
                digest: "same".to_owned(),
                offset: Some(7),
                executable: false,
                payload_hex: String::new(),
                identity: None,
                collision: false,
            },
        ];
        let report = aggregate_objects(&objects, 0).expect("aggregate");
        assert_eq!(report.occurrences, 2);
        assert_eq!(report.unique_objects, 1);
        assert_eq!(report.unique_payload_bytes, 12);
        assert_eq!(report.duplicate_payload_bytes(), 12);
        assert_eq!(report.collision_count, 0);
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
    }

    #[test]
    fn same_digest_with_different_bytes_is_not_deduplicated() {
        let first = fixture("collision-first", b"first");
        let second = fixture("collision-second", b"other");
        let objects = vec![
            Object {
                path: first.clone(),
                kind: Kind::File,
                size: 5,
                digest: "forced-collision".to_owned(),
                offset: Some(0),
                executable: false,
                payload_hex: String::new(),
                identity: None,
                collision: false,
            },
            Object {
                path: second.clone(),
                kind: Kind::File,
                size: 5,
                digest: "forced-collision".to_owned(),
                offset: Some(0),
                executable: false,
                payload_hex: String::new(),
                identity: None,
                collision: false,
            },
        ];
        let report = aggregate_objects(&objects, 0).expect("aggregate");
        assert_eq!(report.occurrences, 2);
        assert_eq!(report.unique_objects, 2);
        assert_eq!(report.unique_payload_bytes, 10);
        assert_eq!(report.duplicate_payload_bytes(), 0);
        assert_eq!(report.collision_count, 1);
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
    }
}
