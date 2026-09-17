use std::{collections::HashSet, ffi::OsStr, fs::File, io};

use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, ValidatedNarInfo, read_narinfo_file},
    storage::{
        Directory, FileHash, StoreHash, for_each_dir_name,
        inspection::{NarinfoCandidate, NarinfoName, PayloadEntry, ReferencedPayload},
        open_directory_at, read_dir_names,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryClass {
    ValidPair,
    OrphanNar,
    MissingNar,
    MalformedNarInfo,
    HashOrSizeMismatch,
    UntrustedSignature,
    InvalidFilename,
}

impl InventoryClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidPair => "valid_pair",
            Self::OrphanNar => "orphan_nar",
            Self::MissingNar => "missing_nar",
            Self::MalformedNarInfo => "malformed_narinfo",
            Self::HashOrSizeMismatch => "hash_or_size_mismatch",
            Self::UntrustedSignature => "untrusted_signature",
            Self::InvalidFilename => "invalid_filename",
        }
    }

    pub const fn action(self) -> &'static str {
        match self {
            Self::ValidPair => "none",
            Self::OrphanNar => "review before deleting",
            Self::MissingNar => "reupload NAR or quarantine narinfo",
            Self::MalformedNarInfo => "quarantine narinfo",
            Self::HashOrSizeMismatch => "quarantine and reupload",
            Self::UntrustedSignature => "restore trust or quarantine narinfo",
            Self::InvalidFilename => "quarantine manually",
        }
    }

    pub const fn invalid_published_pair(self) -> bool {
        match self {
            Self::MissingNar
            | Self::MalformedNarInfo
            | Self::HashOrSizeMismatch
            | Self::UntrustedSignature => true,
            Self::ValidPair | Self::OrphanNar | Self::InvalidFilename => false,
        }
    }

    pub const fn blocks_serve(self) -> bool {
        match self {
            Self::MalformedNarInfo | Self::UntrustedSignature => true,
            Self::ValidPair
            | Self::OrphanNar
            | Self::MissingNar
            | Self::HashOrSizeMismatch
            | Self::InvalidFilename => false,
        }
    }
}

impl std::fmt::Display for InventoryClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InventoryEntry {
    class: InventoryClass,
    identifier: String,
}

impl InventoryEntry {
    pub fn class(&self) -> InventoryClass {
        self.class
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    fn new(class: InventoryClass, identifier: impl Into<String>) -> Self {
        Self {
            class,
            identifier: identifier.into(),
        }
    }
}

#[derive(Debug)]
pub struct Inventory {
    entries: Vec<InventoryEntry>,
}

#[derive(Clone, Copy, Debug)]
pub enum VerificationMode {
    /// Inspect trusted metadata and the referenced payload's existence and size.
    Availability,
    /// Also verify encoded and decoded content identities.
    Content,
}

#[derive(Default)]
struct MetadataScan {
    entries: Vec<InventoryEntry>,
    references: HashSet<FileHash>,
}

enum MetadataAssessment {
    Rejected(InventoryEntry),
    Referenced {
        entry: InventoryEntry,
        payload: FileHash,
        raw_nar: FileHash,
    },
}

impl VerificationMode {
    fn inspect_referenced_payload(self, payload: ReferencedPayload) -> io::Result<InventoryClass> {
        let matches = match self {
            Self::Availability => payload.has_expected_size()?,
            Self::Content => payload.verify_content()?,
        };
        Ok(match matches {
            true => InventoryClass::ValidPair,
            false => InventoryClass::HashOrSizeMismatch,
        })
    }
}

fn inspect_trusted_narinfo(
    payloads: &File,
    store: &StoreHash,
    metadata: ValidatedNarInfo,
    verification: VerificationMode,
) -> io::Result<MetadataAssessment> {
    let payload = metadata.payload_name().file_hash();
    let raw_nar = FileHash::from_nar_hash(metadata.decoded_identity().hash());
    let class = match ReferencedPayload::open(payloads, metadata.payload())? {
        None => InventoryClass::MissingNar,
        Some(payload) => verification.inspect_referenced_payload(payload)?,
    };
    // Trust establishes the reference even when its payload is missing or corrupt.
    Ok(MetadataAssessment::Referenced {
        entry: InventoryEntry::new(class, store.as_str()),
        payload,
        raw_nar,
    })
}

fn validate_narinfo_candidate(
    root: &File,
    candidate: &NarinfoCandidate<'_>,
    trusted: &TrustedPublicKeys,
) -> io::Result<Result<ValidatedNarInfo, PublishedNarInfoError>> {
    match candidate.open(root)? {
        None => Ok(Err(PublishedNarInfoError::Malformed)),
        Some(file) => Ok(trusted.inspect(candidate.store(), read_narinfo_file(file)?)),
    }
}

fn inspect_narinfo_entry(
    name: NarinfoName<'_>,
    root: &File,
    payloads: &File,
    trusted: &TrustedPublicKeys,
    verification: VerificationMode,
) -> io::Result<MetadataAssessment> {
    match name {
        NarinfoName::Invalid(name) => Ok(MetadataAssessment::Rejected(InventoryEntry::new(
            InventoryClass::InvalidFilename,
            name,
        ))),
        NarinfoName::Candidate(candidate) => {
            match validate_narinfo_candidate(root, &candidate, trusted)? {
                Ok(metadata) => {
                    inspect_trusted_narinfo(payloads, candidate.store(), metadata, verification)
                }
                Err(error) => Ok(MetadataAssessment::Rejected(InventoryEntry::new(
                    match error {
                        PublishedNarInfoError::Malformed => InventoryClass::MalformedNarInfo,
                        PublishedNarInfoError::UntrustedSignature => {
                            InventoryClass::UntrustedSignature
                        }
                    },
                    candidate.store().as_str(),
                ))),
            }
        }
    }
}

impl MetadataScan {
    fn record(&mut self, assessment: MetadataAssessment) {
        match assessment {
            MetadataAssessment::Rejected(entry) => self.entries.push(entry),
            MetadataAssessment::Referenced {
                entry,
                payload,
                raw_nar,
            } => {
                self.references.insert(payload);
                self.references.insert(raw_nar);
                self.entries.push(entry);
            }
        }
    }
}

fn inspect_narinfo_entries(
    root: &File,
    payloads: &File,
    trusted: &TrustedPublicKeys,
    verification: VerificationMode,
) -> io::Result<MetadataScan> {
    let mut scan = MetadataScan::default();
    read_dir_names(root)?
        .iter()
        .filter_map(|name| NarinfoName::classify(name))
        .try_for_each(|name| {
            scan.record(inspect_narinfo_entry(
                name,
                root,
                payloads,
                trusted,
                verification,
            )?);
            Ok::<(), io::Error>(())
        })?;
    Ok(scan)
}

fn classify_unreferenced_payload(
    payload: PayloadEntry<'_>,
    references: &HashSet<FileHash>,
) -> Option<InventoryEntry> {
    match payload {
        PayloadEntry::Invalid(name) => {
            Some(InventoryEntry::new(InventoryClass::InvalidFilename, name))
        }
        PayloadEntry::Identified(payload) => match references.contains(&payload.file_hash()) {
            true => None,
            false => Some(InventoryEntry::new(
                InventoryClass::OrphanNar,
                payload.file_hash().to_string(),
            )),
        },
    }
}

fn inspect_unreferenced_payloads(
    directory: &File,
    references: &HashSet<FileHash>,
) -> io::Result<Vec<InventoryEntry>> {
    let mut entries = Vec::new();
    read_dir_names(directory)?.iter().try_for_each(|name| {
        entries.extend(
            PayloadEntry::identify(directory, name)?
                .and_then(|payload| classify_unreferenced_payload(payload, references)),
        );
        Ok::<(), io::Error>(())
    })?;
    Ok(entries)
}

impl Inventory {
    pub fn can_serve_streaming(root: &Directory, trusted: &TrustedPublicKeys) -> io::Result<bool> {
        let root = root.file();
        let mut can_serve = true;
        for_each_dir_name(root, |name| {
            can_serve = match NarinfoName::classify(name) {
                None | Some(NarinfoName::Invalid(_)) => true,
                Some(NarinfoName::Candidate(candidate)) => {
                    validate_narinfo_candidate(root, &candidate, trusted)?.is_ok()
                }
            };
            Ok(can_serve)
        })?;
        Ok(can_serve)
    }

    pub fn can_recover(root: &Directory, trusted: &TrustedPublicKeys) -> io::Result<bool> {
        Ok(!Self::scan(root, trusted, VerificationMode::Availability)?
            .entries
            .iter()
            .any(|entry| entry.class.invalid_published_pair()))
    }

    pub fn scan(
        root: &Directory,
        trusted: &TrustedPublicKeys,
        verification: VerificationMode,
    ) -> io::Result<Self> {
        let root = root.file();
        let nar_directory = open_directory_at(root, OsStr::new("nar"))?;
        let MetadataScan {
            mut entries,
            references,
        } = inspect_narinfo_entries(root, &nar_directory, trusted, verification)?;
        entries.extend(inspect_unreferenced_payloads(&nar_directory, &references)?);
        entries.sort();
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    pub fn can_serve(&self) -> bool {
        !self.entries.iter().any(|entry| entry.class.blocks_serve())
    }
}
