use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{Storage, StorageError, StoreHash, publication_record::PublicationRecord};
use crate::cache::{
    filesystem::{FilePrivacy, PreparedFile, open_regular, open_regular_at, validate_private_file},
    object::NarFileName,
    token_file::valid_label,
};

pub(crate) const LOG_FILE: &str = ".narjar-fetch-failures";
/// A client cannot grow the private failure log past this size.
pub(crate) const MAX_LOG_BYTES: u64 = 1024 * 1024;
const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FetchFailureKind {
    MissingNarinfo,
    MissingNar,
    FailedNarinfo,
    FailedNar,
}

impl FetchFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingNarinfo => "narinfo-miss",
            Self::MissingNar => "nar-miss",
            Self::FailedNarinfo => "narinfo-failure",
            Self::FailedNar => "nar-failure",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "narinfo-miss" => Some(Self::MissingNarinfo),
            "nar-miss" => Some(Self::MissingNar),
            "narinfo-failure" => Some(Self::FailedNarinfo),
            "nar-failure" => Some(Self::FailedNar),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FetchTarget<'a> {
    NarInfo(&'a StoreHash),
    Nar(NarFileName),
}

struct LoggedPublication {
    store: StoreHash,
    record: PublicationRecord,
}

struct FailureLine {
    requested_at: SystemTime,
    reader: Option<String>,
    store: StoreHash,
    store_path: String,
    kind: FetchFailureKind,
    published_at: SystemTime,
    writer: Option<String>,
}

impl Storage {
    pub(crate) fn record_recent_fetch_failure(
        &self,
        kind: FetchFailureKind,
        target: FetchTarget<'_>,
        reader: Option<&str>,
        now: SystemTime,
    ) -> Result<(), StorageError> {
        self.record_recent_fetch_failure_within(kind, target, reader, now, MAX_LOG_BYTES)
    }

    pub(super) fn record_recent_fetch_failure_within(
        &self,
        kind: FetchFailureKind,
        target: FetchTarget<'_>,
        reader: Option<&str>,
        now: SystemTime,
        max_bytes: u64,
    ) -> Result<(), StorageError> {
        let Some(publication) = self.logged_publication(target, now)? else {
            return Ok(());
        };
        if older_than_retention(publication.record.published_at, now) {
            return Ok(());
        }
        let reader = match reader {
            Some(label) if valid_label(label) => Some(label.to_owned()),
            Some(_) => {
                return Err(invalid("fetch failure reader label is invalid").into());
            }
            None => None,
        };
        let line = FailureLine {
            requested_at: now,
            reader,
            store: publication.store,
            store_path: publication.record.store_path,
            kind,
            published_at: publication.record.published_at,
            writer: publication.record.writer,
        };
        let _log = self
            .fetch_failure_log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rewrite_log(&self.root_directory()?, line, now, max_bytes)?;
        Ok(())
    }

    fn logged_publication(
        &self,
        target: FetchTarget<'_>,
        now: SystemTime,
    ) -> Result<Option<LoggedPublication>, StorageError> {
        match target {
            FetchTarget::NarInfo(store) => {
                let Some(record) = self.publication_record(store, now)? else {
                    return Ok(None);
                };
                Ok(Some(LoggedPublication {
                    store: *store,
                    record,
                }))
            }
            FetchTarget::Nar(name) => Ok(self
                .published_store_for_nar(name, now)?
                .map(|(store, record)| LoggedPublication { store, record })),
        }
    }
}

pub(crate) fn read_recent_fetch_failures(
    data_dir: &Path,
    now: SystemTime,
) -> io::Result<Vec<String>> {
    let file = match open_regular(&data_dir.join(LOG_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut lines = retained_lines(&file, now)?;
    lines.reverse();
    lines.sort_by_key(|line| std::cmp::Reverse(line.requested_at));
    lines.into_iter().map(|line| encode_line(&line)).collect()
}

fn rewrite_log(root: &File, line: FailureLine, now: SystemTime, max_bytes: u64) -> io::Result<()> {
    let mut lines = match open_regular_at(root, LOG_FILE) {
        Ok(file) => read_log_lines(&file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    lines.retain(|existing| !older_than_retention(existing.requested_at, now));
    lines.push(line);
    let lines = within_bound(lines, max_bytes)?;
    let mut bytes = Vec::new();
    for line in &lines {
        writeln!(bytes, "{}", encode_line(line)?)?;
    }
    let temporary = PreparedFile::write(root, FilePrivacy::Private, |file| file.write_all(&bytes))?;
    temporary.replace(OsStr::new(LOG_FILE))?;
    Ok(())
}

fn retained_lines(file: &File, now: SystemTime) -> io::Result<Vec<FailureLine>> {
    let mut lines = read_log_lines(file)?;
    lines.retain(|line| !older_than_retention(line.requested_at, now));
    Ok(lines)
}

fn read_log_lines(file: &File) -> io::Result<Vec<FailureLine>> {
    validate_private_file(file)?;
    if file.metadata()?.len() > MAX_LOG_BYTES {
        return Err(invalid("fetch failure log exceeds its size limit"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(invalid("fetch failure log exceeds its size limit"));
    }
    parse_log(&bytes)
}

fn within_bound(mut lines: Vec<FailureLine>, max_bytes: u64) -> io::Result<Vec<FailureLine>> {
    while encoded_size(&lines)? > max_bytes {
        if lines.is_empty() {
            break;
        }
        lines.remove(0);
    }
    Ok(lines)
}

fn encoded_size(lines: &[FailureLine]) -> io::Result<u64> {
    let mut total = 0u64;
    for line in lines {
        let line_bytes = encode_line(line)?.len() as u64 + 1;
        total = total.saturating_add(line_bytes);
    }
    Ok(total)
}

fn encode_line(line: &FailureLine) -> io::Result<String> {
    Ok(format!(
        "v1\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        unix_seconds(line.requested_at)?,
        line.reader.as_deref().unwrap_or(""),
        line.store.as_str(),
        line.store_path,
        line.kind.as_str(),
        unix_seconds(line.published_at)?,
        line.writer.as_deref().unwrap_or(""),
    ))
}

fn parse_log(bytes: &[u8]) -> io::Result<Vec<FailureLine>> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("fetch failure log is not text"))?;
    text.lines().map(parse_line).collect()
}

fn parse_line(line: &str) -> io::Result<FailureLine> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [
        version,
        requested,
        reader,
        store,
        store_path,
        kind,
        published,
        writer,
    ] = fields.as_slice()
    else {
        return Err(invalid("fetch failure log line is invalid"));
    };
    if *version != "v1" {
        return Err(invalid("fetch failure log version is unsupported"));
    }
    let store =
        StoreHash::parse(store).map_err(|_| invalid("fetch failure log store hash is invalid"))?;
    if !single_line(store_path) {
        return Err(invalid("fetch failure log store path is invalid"));
    }
    let kind = FetchFailureKind::parse(kind)
        .ok_or_else(|| invalid("fetch failure log kind is invalid"))?;
    Ok(FailureLine {
        requested_at: system_time(requested)?,
        reader: optional_label(reader)?,
        store,
        store_path: (*store_path).to_owned(),
        kind,
        published_at: system_time(published)?,
        writer: optional_label(writer)?,
    })
}

fn optional_label(value: &str) -> io::Result<Option<String>> {
    match value {
        "" => Ok(None),
        label if valid_label(label) => Ok(Some(label.to_owned())),
        _ => Err(invalid("fetch failure log token label is invalid")),
    }
}

fn single_line(value: &str) -> bool {
    !value.is_empty() && !value.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn older_than_retention(time: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(time) {
        Ok(age) => age > RETENTION,
        Err(_) => false,
    }
}

fn unix_seconds(time: SystemTime) -> io::Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid("fetch failure time predates the Unix epoch"))
}

fn system_time(seconds: &str) -> io::Result<SystemTime> {
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_| invalid("fetch failure time is invalid"))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| invalid("fetch failure time is too large"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
