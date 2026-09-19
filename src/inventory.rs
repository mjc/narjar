use std::{collections::HashSet, ffi::OsStr, fs::File, io, io::Read};

use sha2::{Digest, Sha256};

use crate::{
    narinfo::{PublishedNarInfoError, TrustedPublicKeys, ValidatedNarInfo, read_narinfo_file},
    object::NarRepresentation,
    storage::{
        Directory, FileHash, NarFileName, NarHash, Storage, StoreHash, for_each_dir_name,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy)]
enum PayloadSource<'a> {
    Directory(&'a File),
    Storage(&'a Storage),
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

fn inspect_directory_payload(
    payloads: &File,
    payload: NarRepresentation,
    verification: VerificationMode,
) -> io::Result<InventoryClass> {
    match ReferencedPayload::open(payloads, payload)? {
        None => Ok(InventoryClass::MissingNar),
        Some(payload) => verification.inspect_referenced_payload(payload),
    }
}

fn inspect_storage_payload(
    storage: &Storage,
    payload: NarRepresentation,
    verification: VerificationMode,
) -> io::Result<InventoryClass> {
    if let NarRepresentation::Raw(identity) = payload {
        return inspect_storage_canonical_nar(storage, identity, verification);
    }
    inspect_directory_payload(
        &storage.nar_directory().map_err(storage_error_to_io)?,
        payload,
        verification,
    )
}

fn inspect_payload(
    source: PayloadSource<'_>,
    payload: NarRepresentation,
    verification: VerificationMode,
) -> io::Result<InventoryClass> {
    match source {
        PayloadSource::Directory(payloads) => {
            inspect_directory_payload(payloads, payload, verification)
        }
        PayloadSource::Storage(storage) => inspect_storage_payload(storage, payload, verification),
    }
}

fn inspect_storage_canonical_nar(
    storage: &Storage,
    identity: crate::object::NarIdentity,
    verification: VerificationMode,
) -> io::Result<InventoryClass> {
    let name = NarFileName::raw(identity.hash());
    let size = match storage.nar_size(name) {
        Ok(Some(size)) => size,
        Ok(None) => return Ok(InventoryClass::MissingNar),
        Err(error) => {
            if let Some(class) = classify_storage_failure(&error) {
                return Ok(class);
            }
            return Err(storage_error_to_io(error));
        }
    };
    if size != identity.size().get() {
        return Ok(InventoryClass::HashOrSizeMismatch);
    }
    let mut opened = match storage.open_nar_range(name, 0..size) {
        Ok(Some(opened)) => opened,
        Ok(None) => return Ok(InventoryClass::MissingNar),
        Err(error) => {
            if let Some(class) = classify_storage_failure(&error) {
                return Ok(class);
            }
            return Err(storage_error_to_io(error));
        }
    };

    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match opened.body.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                if let Some(class) = classify_io_failure(&error) {
                    return Ok(class);
                }
                return Err(error);
            }
        };
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NAR size overflow"))?;
        if verification == VerificationMode::Content {
            hasher.update(&buffer[..read]);
        }
    }
    if bytes != identity.size().get() {
        return Ok(InventoryClass::HashOrSizeMismatch);
    }
    if verification == VerificationMode::Content
        && NarHash::from_digest(hasher.finalize().into()) != identity.hash()
    {
        return Ok(InventoryClass::HashOrSizeMismatch);
    }
    Ok(InventoryClass::ValidPair)
}

fn storage_error_to_io(error: crate::storage::StorageError) -> io::Error {
    match error {
        crate::storage::StorageError::Io(error) => error,
        crate::storage::StorageError::MissingNar => io::Error::from(io::ErrorKind::NotFound),
        error => io::Error::new(io::ErrorKind::InvalidData, error.to_string()),
    }
}

fn classify_storage_failure(error: &crate::storage::StorageError) -> Option<InventoryClass> {
    match error {
        crate::storage::StorageError::MissingNar => Some(InventoryClass::MissingNar),
        crate::storage::StorageError::NarMismatch => Some(InventoryClass::HashOrSizeMismatch),
        crate::storage::StorageError::Io(error) => classify_io_failure(error),
        crate::storage::StorageError::Conflict
        | crate::storage::StorageError::InsufficientSpace
        | crate::storage::StorageError::InsufficientInodes
        | crate::storage::StorageError::Locked
        | crate::storage::StorageError::UploadTooLarge => None,
    }
}

fn classify_io_failure(error: &io::Error) -> Option<InventoryClass> {
    match error.kind() {
        io::ErrorKind::NotFound => Some(InventoryClass::MissingNar),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            Some(InventoryClass::HashOrSizeMismatch)
        }
        _ => None,
    }
}

fn combine_payload_classes(
    advertised: InventoryClass,
    canonical: InventoryClass,
) -> InventoryClass {
    match (advertised, canonical) {
        (InventoryClass::MissingNar, _) | (_, InventoryClass::MissingNar) => {
            InventoryClass::MissingNar
        }
        (InventoryClass::HashOrSizeMismatch, _) | (_, InventoryClass::HashOrSizeMismatch) => {
            InventoryClass::HashOrSizeMismatch
        }
        _ => InventoryClass::ValidPair,
    }
}

fn inspect_trusted_narinfo(
    source: PayloadSource<'_>,
    store: &StoreHash,
    metadata: ValidatedNarInfo,
    verification: VerificationMode,
) -> io::Result<MetadataAssessment> {
    let representation = metadata.payload();
    let payload = representation.file_name().file_hash();
    let raw_nar = FileHash::from_nar_hash(representation.identity().hash());
    let advertised_class = inspect_payload(source, metadata.payload(), verification)?;
    let class = match representation {
        NarRepresentation::Raw(_) => advertised_class,
        NarRepresentation::Compressed(_) => combine_payload_classes(
            advertised_class,
            inspect_payload(
                source,
                NarRepresentation::Raw(representation.identity()),
                verification,
            )?,
        ),
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
    source: PayloadSource<'_>,
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
                    inspect_trusted_narinfo(source, candidate.store(), metadata, verification)
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
    source: PayloadSource<'_>,
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
                source,
                trusted,
                verification,
            )?);
            Ok::<(), io::Error>(())
        })?;
    Ok(scan)
}

fn inspect_unreferenced_manifests(
    storage: &Storage,
    references: &HashSet<FileHash>,
) -> io::Result<Vec<InventoryEntry>> {
    let root = storage.root_directory().map_err(storage_error_to_io)?;
    let manifests = open_directory_at(&root, OsStr::new(crate::storage::MANIFEST_DIRECTORY))?;
    let mut entries = Vec::new();
    read_dir_names(&manifests)?.iter().try_for_each(|name| {
        let Some(text) = name.to_str() else {
            return Ok::<(), io::Error>(());
        };
        let Some(hash_text) = text.strip_suffix(".manifest") else {
            return Ok(());
        };
        let Ok(hash) = NarHash::parse(hash_text) else {
            return Ok(());
        };
        if references.contains(&FileHash::from_nar_hash(hash)) {
            return Ok(());
        }
        if !crate::storage::entry_is_regular_at(&manifests, name)? {
            return Ok(());
        }
        entries.push(InventoryEntry::new(
            InventoryClass::OrphanNar,
            hash_text.to_owned(),
        ));
        Ok(())
    })?;
    Ok(entries)
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

    pub fn can_recover(storage: &Storage, trusted: &TrustedPublicKeys) -> io::Result<bool> {
        Ok(
            !Self::scan_storage(storage, trusted, VerificationMode::Availability)?
                .entries
                .iter()
                .any(|entry| entry.class.invalid_published_pair()),
        )
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
        } = inspect_narinfo_entries(
            root,
            PayloadSource::Directory(&nar_directory),
            trusted,
            verification,
        )?;
        entries.extend(inspect_unreferenced_payloads(&nar_directory, &references)?);
        entries.sort();
        Ok(Self { entries })
    }

    pub fn scan_storage(
        storage: &Storage,
        trusted: &TrustedPublicKeys,
        verification: VerificationMode,
    ) -> io::Result<Self> {
        let root = storage.root_directory().map_err(storage_error_to_io)?;
        let nar_directory = storage.nar_directory().map_err(storage_error_to_io)?;
        let MetadataScan {
            mut entries,
            references,
        } = inspect_narinfo_entries(
            &root,
            PayloadSource::Storage(storage),
            trusted,
            verification,
        )?;
        entries.extend(inspect_unreferenced_payloads(&nar_directory, &references)?);
        if storage.backend() == crate::storage::StorageBackend::Chunked {
            entries.extend(inspect_unreferenced_manifests(storage, &references)?);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{NarUploadPolicy, PublishOutcome, StorageBackend};
    use sha2::{Digest, Sha256};
    use std::{io::Cursor, path::Path};
    use tempfile::tempdir;

    #[test]
    fn chunked_storage_inventory_checks_the_manifest_backed_nar() {
        let directory = tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let storage = Storage::initialize(&root, StorageBackend::Chunked).unwrap();
        let raw = vec![b'i'; 100_000];
        let hash = NarHash::from_digest(Sha256::digest(&raw).into());
        let name = NarFileName::raw(hash);
        assert_eq!(
            storage
                .publish_nar(
                    name,
                    Cursor::new(&raw),
                    raw.len() as u64,
                    NarUploadPolicy::new(raw.len() as u64, 0),
                )
                .unwrap(),
            PublishOutcome::Created
        );

        assert_eq!(
            inspect_storage_canonical_nar(
                &storage,
                crate::object::NarIdentity::new(hash, (raw.len() as u64).into()),
                VerificationMode::Availability,
            )
            .unwrap(),
            InventoryClass::ValidPair
        );
        assert_eq!(
            inspect_storage_canonical_nar(
                &storage,
                crate::object::NarIdentity::new(hash, (raw.len() as u64).into()),
                VerificationMode::Content,
            )
            .unwrap(),
            InventoryClass::ValidPair
        );

        let inventory = Inventory::scan_storage(
            &storage,
            &TrustedPublicKeys::default(),
            VerificationMode::Availability,
        )
        .unwrap();
        assert!(inventory.entries().iter().any(|entry| {
            entry.class() == InventoryClass::OrphanNar && entry.identifier() == hash.to_string()
        }));

        let manifest = Path::new(directory.path())
            .join(crate::storage::MANIFEST_DIRECTORY)
            .join(format!("{hash}.manifest"));
        std::fs::remove_file(manifest).unwrap();
        assert_eq!(
            inspect_storage_canonical_nar(
                &storage,
                crate::object::NarIdentity::new(hash, (raw.len() as u64).into()),
                VerificationMode::Availability,
            )
            .unwrap(),
            InventoryClass::MissingNar
        );
    }
}
