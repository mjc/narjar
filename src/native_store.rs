use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    num::{NonZeroU64, NonZeroUsize},
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use narjar::__private::narinfo::TrustedPublicKeys;
use sqlite::{Connection, ConnectionThreadSafe, OpenFlags, State};

#[expect(
    dead_code,
    reason = "NARJ-142 connects lease capabilities to native-store serving"
)]
pub(crate) mod lease;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "NARJ-141 connects native metadata projection to HTTP"
    )
)]
pub(crate) mod metadata;

const REQUIRED_TABLE_COLUMNS: &[(&str, &[&str])] = &[
    (
        "ValidPaths",
        &[
            "id",
            "path",
            "hash",
            "registrationTime",
            "deriver",
            "narSize",
            "sigs",
            "ca",
        ],
    ),
    ("Refs", &["referrer", "reference"]),
    ("SchemaMigrations", &["migration"]),
];

const SUPPORTED_NIX_SCHEMA_VERSION: u32 = 10;
const SUPPORTED_NIX_MIGRATIONS: &[&str] = &[
    "20220326-ca-derivations",
    "20251017-ca-derivations",
    "20260309-drop-redundant-indexreferrer",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeStoreIssue {
    StorePath,
    StateDirectory,
    RootsDirectory,
    LeaseState,
    RootsLocation,
    Database,
    SchemaVersion,
    SchemaStructure,
    SchemaMigration,
    SignatureTrust,
}

#[derive(Debug)]
pub(crate) struct NativeStoreValidationError {
    issue: NativeStoreIssue,
    detail: String,
}

impl NativeStoreValidationError {
    fn new(issue: NativeStoreIssue, detail: impl Into<String>) -> Self {
        Self {
            issue,
            detail: detail.into(),
        }
    }

    pub(crate) fn doctor_detail(&self) -> &'static str {
        match self.issue {
            NativeStoreIssue::StorePath => "Nix store path is unavailable or unsafe",
            NativeStoreIssue::StateDirectory => "Nix state directory is unavailable or unsafe",
            NativeStoreIssue::RootsDirectory => "Narjar roots directory is unavailable or unsafe",
            NativeStoreIssue::LeaseState => {
                "Narjar native-store lease state is invalid or unavailable"
            }
            NativeStoreIssue::RootsLocation => {
                "Narjar roots directory overlaps a protected directory"
            }
            NativeStoreIssue::Database => "Nix metadata database is unavailable or unsafe",
            NativeStoreIssue::SchemaVersion => "Nix metadata schema version is unsupported",
            NativeStoreIssue::SchemaStructure => "Nix metadata schema is incomplete or unsupported",
            NativeStoreIssue::SchemaMigration => "Nix metadata contains an unsupported migration",
            NativeStoreIssue::SignatureTrust => {
                "native-store signature trust policy is unavailable"
            }
        }
    }
}

fn classify_validation<T>(
    result: Result<T, String>,
    issue: NativeStoreIssue,
) -> Result<T, NativeStoreValidationError> {
    result.map_err(|detail| NativeStoreValidationError::new(issue, detail))
}

impl std::fmt::Display for NativeStoreValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for NativeStoreValidationError {}

#[derive(Debug)]
pub(crate) struct NativeStoreSettings {
    store_dir: PathBuf,
    state_dir: PathBuf,
    roots_dir: PathBuf,
    min_lease_seconds: NonZeroU64,
}

const MAX_ACTIVE_NATIVE_LEASES: NonZeroUsize =
    NonZeroUsize::new(100_000).expect("native lease capacity is nonzero");

impl NativeStoreSettings {
    pub(crate) fn new(
        store_dir: PathBuf,
        state_dir: PathBuf,
        roots_dir: PathBuf,
        min_lease_seconds: NonZeroU64,
    ) -> Self {
        Self {
            store_dir,
            state_dir,
            roots_dir,
            min_lease_seconds,
        }
    }

    pub(crate) fn validate(
        &self,
        narjar_data_dir: &Path,
        trusted_keys: &TrustedPublicKeys,
    ) -> Result<ValidatedNativeStore, NativeStoreValidationError> {
        let store_directory = classify_validation(
            open_readable_directory(&self.store_dir, "Nix store"),
            NativeStoreIssue::StorePath,
        )?;
        let state_directory = classify_validation(
            open_readable_directory(&self.state_dir, "Nix state directory"),
            NativeStoreIssue::StateDirectory,
        )?;
        let roots_directory = classify_validation(
            open_owned_roots_directory(&self.roots_dir),
            NativeStoreIssue::RootsDirectory,
        )?;
        let store_path = classify_validation(
            canonical_directory_path(&self.store_dir, &store_directory, "Nix store"),
            NativeStoreIssue::StorePath,
        )?;
        let state_path = classify_validation(
            canonical_directory_path(&self.state_dir, &state_directory, "Nix state directory"),
            NativeStoreIssue::StateDirectory,
        )?;
        let roots_path = classify_validation(
            canonical_directory_path(&self.roots_dir, &roots_directory, "Narjar roots"),
            NativeStoreIssue::RootsDirectory,
        )?;
        let roots_location =
            validate_gc_discoverable_roots(&roots_path, &state_path, narjar_data_dir, &store_path);
        classify_validation(roots_location, NativeStoreIssue::RootsLocation)?;
        classify_validation(
            validate_nix_database_path(&state_path),
            NativeStoreIssue::Database,
        )?;
        let metadata_database = open_supported_metadata_database(&state_path)?;
        let path_lookup_database = Arc::new(open_native_path_lookup_database(&state_path)?);
        classify_validation(
            require_trusted_signature_key(trusted_keys),
            NativeStoreIssue::SignatureTrust,
        )?;
        let lease_manager = lease::NativeStoreLeaseManager::open(
            store_path,
            state_path,
            roots_path,
            self.min_lease_seconds,
            MAX_ACTIVE_NATIVE_LEASES,
            path_lookup_database,
        )
        .map_err(|error| {
            NativeStoreValidationError::new(NativeStoreIssue::LeaseState, error.to_string())
        })?;

        Ok(ValidatedNativeStore {
            _store_directory: store_directory,
            _state_directory: state_directory,
            _roots_directory: roots_directory,
            _metadata_database: metadata_database,
            lease_manager,
        })
    }
}

fn canonical_directory_path(
    path: &Path,
    opened_directory: &File,
    name: &str,
) -> Result<PathBuf, String> {
    let canonical_path = path
        .canonicalize()
        .map_err(|error| format!("resolving {name} path: {error}"))?;
    let path_directory = open_directory_without_following_final_symlink(&canonical_path)
        .map_err(|error| format!("reopening resolved {name} path: {error}"))?;
    match descriptor_identity(opened_directory)? == descriptor_identity(&path_directory)? {
        true => validate_directory_ancestors(&canonical_path).map(|()| canonical_path),
        false => Err(format!("{name} path changed during validation")),
    }
}

fn validate_directory_ancestors(path: &Path) -> Result<(), String> {
    path.ancestors().try_for_each(|ancestor| {
        let metadata = fs::metadata(ancestor)
            .map_err(|error| format!("inspecting native-store path ancestor: {error}"))?;
        validate_ancestor_owner_and_mode(metadata.uid(), metadata.mode(), effective_user_id())
    })
}

fn validate_ancestor_owner_and_mode(
    owner_uid: u32,
    mode: u32,
    service_uid: u32,
) -> Result<(), String> {
    match owner_uid == 0 || owner_uid == service_uid {
        true => {}
        false => return Err("native-store path has an ancestor with untrusted ownership".into()),
    }
    match mode & 0o022 == 0 || mode & 0o1000 != 0 {
        true => Ok(()),
        false => Err("native-store path has an ancestor that other users can replace".into()),
    }
}

pub(crate) struct ValidatedNativeStore {
    _store_directory: File,
    _state_directory: File,
    _roots_directory: File,
    _metadata_database: ConnectionThreadSafe,
    #[expect(
        dead_code,
        reason = "NARJ-142 consumes this manager before returning native narinfo"
    )]
    lease_manager: lease::NativeStoreLeaseManager,
}

impl ValidatedNativeStore {
    #[expect(
        dead_code,
        reason = "NARJ-142 acquires leases before advertising native paths"
    )]
    pub(crate) fn leases(&self) -> &lease::NativeStoreLeaseManager {
        &self.lease_manager
    }
}

pub(crate) fn open_supported_metadata_database(
    state_dir: &Path,
) -> Result<ConnectionThreadSafe, NativeStoreValidationError> {
    let database = open_native_path_lookup_database(state_dir)?;
    database.execute("BEGIN").map_err(|error| {
        NativeStoreValidationError::new(
            NativeStoreIssue::Database,
            format!("starting the Nix store database snapshot: {error}"),
        )
    })?;
    let schema_version = classify_validation(
        read_nix_schema_version(state_dir),
        NativeStoreIssue::SchemaVersion,
    )?;
    classify_validation(
        validate_supported_schema(&database),
        NativeStoreIssue::SchemaStructure,
    )?;
    classify_validation(
        validate_supported_migrations(&database),
        NativeStoreIssue::SchemaMigration,
    )?;
    let confirmed_schema_version = classify_validation(
        read_nix_schema_version(state_dir),
        NativeStoreIssue::SchemaVersion,
    )?;
    match confirmed_schema_version == schema_version {
        true => Ok(database),
        false => Err(NativeStoreValidationError::new(
            NativeStoreIssue::SchemaVersion,
            "Nix store schema version changed during validation",
        )),
    }
}

fn open_native_path_lookup_database(
    state_dir: &Path,
) -> Result<ConnectionThreadSafe, NativeStoreValidationError> {
    let database_path = state_dir.join("db/db.sqlite");
    let checked_file = classify_validation(
        open_read_only_regular_file(&database_path, "Nix store database"),
        NativeStoreIssue::Database,
    )?;
    let checked_identity = classify_validation(
        descriptor_identity(&checked_file),
        NativeStoreIssue::Database,
    )?;
    let database =
        Connection::open_thread_safe_with_flags(&database_path, OpenFlags::new().with_read_only())
            .map_err(|error| {
                NativeStoreValidationError::new(
                    NativeStoreIssue::Database,
                    format!("opening the Nix store database: {error}"),
                )
            })?;
    classify_validation(
        require_database_path_matches_open_file(&database_path, checked_identity),
        NativeStoreIssue::Database,
    )?;
    database
        .execute("PRAGMA busy_timeout = 30000")
        .map_err(|error| {
            NativeStoreValidationError::new(
                NativeStoreIssue::Database,
                format!("configuring the Nix store database wait: {error}"),
            )
        })?;
    Ok(database)
}

fn open_readable_directory(path: &Path, description: &str) -> Result<File, String> {
    require_absolute_path(path, description)?;
    let directory = open_directory_without_following_final_symlink(path)
        .map_err(|error| format!("opening {description} {}: {error}", path.display()))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("inspecting {description} {}: {error}", path.display()))?;
    match metadata.is_dir() {
        true => {
            require_read_and_search_access(path, &metadata, description)?;
            Ok(directory)
        }
        false => Err(format!(
            "{description} is not a directory: {}",
            path.display()
        )),
    }
}

fn require_read_and_search_access(
    path: &Path,
    metadata: &fs::Metadata,
    description: &str,
) -> Result<(), String> {
    if metadata.uid() == effective_user_id() {
        return match metadata.mode() & 0o500 == 0o500 {
            true => Ok(()),
            false => Err(format!(
                "{description} is not readable and searchable by the service user"
            )),
        };
    }

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{description} path contains a NUL byte"))?;
    // SAFETY: c_path is NUL-terminated and faccessat does not retain its pointer.
    let result = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::R_OK | libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    match result {
        0 => Ok(()),
        _ => Err(format!(
            "{description} is not readable and searchable by the service user: {}",
            std::io::Error::last_os_error()
        )),
    }
}

fn open_owned_roots_directory(path: &Path) -> Result<File, String> {
    require_absolute_path(path, "Narjar roots directory")?;
    let directory = open_directory_without_following_final_symlink(path)
        .map_err(|error| format!("opening Narjar roots directory {}: {error}", path.display()))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("inspecting Narjar roots directory: {error}"))?;
    let filesystem_writeability = filesystem_writeability(&directory)?;
    require_writable_roots_filesystem(filesystem_writeability)?;
    match (
        metadata.is_dir(),
        metadata.uid() == effective_user_id(),
        metadata.mode() & 0o700 == 0o700 && metadata.mode() & 0o077 == 0,
    ) {
        (true, true, true) => Ok(directory),
        (false, _, _) => Err(format!(
            "Narjar roots path is not a directory: {}",
            path.display()
        )),
        (true, false, _) => Err(format!(
            "Narjar roots directory is not owned by the service user: {}",
            path.display()
        )),
        (true, true, false) => Err(format!(
            "Narjar roots directory must be mode 0700: {}",
            path.display()
        )),
    }
}

fn require_writable_roots_filesystem(writeability: FilesystemWriteability) -> Result<(), String> {
    match writeability {
        FilesystemWriteability::Writable => Ok(()),
        FilesystemWriteability::ReadOnly => Err("Narjar roots filesystem is read-only".to_owned()),
    }
}

fn open_read_only_regular_file(path: &Path, description: &str) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => format!("{description} must not be a symlink"),
            _ => format!("opening {description} {}: {error}", path.display()),
        })?;
    match file
        .metadata()
        .map_err(|error| format!("inspecting {description}: {error}"))?
        .is_file()
    {
        true => Ok(file),
        false => Err(format!("{description} is not a regular file")),
    }
}

fn descriptor_identity(file: &File) -> Result<(u64, u64), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspecting opened filesystem object: {error}"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn require_database_path_matches_open_file(
    database_path: &Path,
    checked_identity: (u64, u64),
) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(database_path)
        .map_err(|error| format!("rechecking Nix store database path: {error}"))?;
    match (
        path_metadata.file_type().is_symlink(),
        (path_metadata.dev(), path_metadata.ino()) == checked_identity,
    ) {
        (false, true) => Ok(()),
        (true, _) => Err("Nix store database must not be a symlink".to_owned()),
        (false, false) => Err("Nix store database changed while opening it".to_owned()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilesystemWriteability {
    Writable,
    ReadOnly,
}

fn filesystem_writeability(directory: &File) -> Result<FilesystemWriteability, String> {
    // SAFETY: fstatvfs only writes to the initialized output struct and reads the live fd.
    let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
    // SAFETY: directory owns a valid descriptor; stats points to writable storage.
    let result = unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stats) };
    match result {
        0 => Ok(filesystem_writeability_from_flags(stats.f_flag)),
        _ => Err(format!(
            "checking Narjar roots filesystem: {}",
            std::io::Error::last_os_error()
        )),
    }
}

fn filesystem_writeability_from_flags(flags: libc::c_ulong) -> FilesystemWriteability {
    match flags & libc::ST_RDONLY != 0 {
        true => FilesystemWriteability::ReadOnly,
        false => FilesystemWriteability::Writable,
    }
}

fn open_directory_without_following_final_symlink(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn require_absolute_path(path: &Path, description: &str) -> Result<(), String> {
    match path.is_absolute() {
        true => Ok(()),
        false => Err(format!(
            "{description} path must be absolute: {}",
            path.display()
        )),
    }
}

fn reject_roots_inside_narjar_data(roots_dir: &Path, narjar_data_dir: &Path) -> Result<(), String> {
    let narjar_data_dir = narjar_data_dir
        .canonicalize()
        .map_err(|error| format!("resolving Narjar data directory: {error}"))?;
    match roots_dir.starts_with(&narjar_data_dir) {
        true => Err("Narjar roots directory must be outside the Narjar data directory".to_owned()),
        false => Ok(()),
    }
}

fn reject_roots_inside_nix_store(roots_dir: &Path, store_dir: &Path) -> Result<(), String> {
    match roots_dir.starts_with(store_dir) {
        true => Err("Narjar roots directory must be outside the Nix store".to_owned()),
        false => Ok(()),
    }
}

fn validate_gc_discoverable_roots(
    roots_dir: &Path,
    state_dir: &Path,
    narjar_data_dir: &Path,
    store_dir: &Path,
) -> Result<(), String> {
    reject_roots_inside_narjar_data(roots_dir, narjar_data_dir)
        .and_then(|()| reject_roots_inside_nix_store(roots_dir, store_dir))?;
    let nix_roots = state_dir.join("gcroots");
    match roots_dir != nix_roots && roots_dir.starts_with(&nix_roots) {
        true => {}
        false => {
            return Err(format!(
                "Narjar roots directory must be a child of Nix GC roots at {}",
                nix_roots.display()
            ));
        }
    }
    Ok(())
}

fn validate_nix_database_path(state_dir: &Path) -> Result<(), String> {
    let database_directory_path = state_dir.join("db");
    let database_directory =
        open_readable_directory(&database_directory_path, "Nix database directory")?;
    let directory_metadata = database_directory
        .metadata()
        .map_err(|error| format!("inspecting Nix database directory: {error}"))?;
    match directory_metadata.uid() == 0 || directory_metadata.uid() == effective_user_id() {
        true => {}
        false => return Err("Nix database directory has untrusted ownership".into()),
    }
    match directory_metadata.mode() & 0o022 == 0 {
        true => {}
        false => return Err("Nix database directory must not be group- or world-writable".into()),
    }
    open_read_only_regular_file(
        &database_directory_path.join("db.sqlite"),
        "Nix store database",
    )
    .map(|_| ())
}

fn read_nix_schema_version(state_dir: &Path) -> Result<u32, String> {
    let schema_path = state_dir.join("db/schema");
    let mut schema_file = open_read_only_regular_file(&schema_path, "Nix schema version file")?;
    let mut schema = String::new();
    let bytes_read = schema_file
        .by_ref()
        .take(64)
        .read_to_string(&mut schema)
        .map_err(|error| format!("reading Nix store schema version: {error}"))?;
    match bytes_read < 64 {
        true => {}
        false => return Err("Nix store schema version file is too large".to_owned()),
    }
    let version = schema
        .trim()
        .parse::<u32>()
        .map_err(|error| format!("parsing Nix store schema version: {error}"))?;
    match version == SUPPORTED_NIX_SCHEMA_VERSION {
        true => Ok(version),
        false => Err(format!(
            "unsupported Nix store schema version {version}; supported version is {SUPPORTED_NIX_SCHEMA_VERSION}"
        )),
    }
}

fn validate_supported_migrations(database: &Connection) -> Result<(), String> {
    let mut statement = database
        .prepare("SELECT migration FROM SchemaMigrations")
        .map_err(|error| format!("reading Nix store schema migrations: {error}"))?;
    std::iter::from_fn(|| match statement.next() {
        Ok(State::Row) => Some(
            statement
                .read::<String, _>("migration")
                .map_err(|error| format!("reading Nix store schema migrations: {error}")),
        ),
        Ok(State::Done) => None,
        Err(error) => Some(Err(format!("reading Nix store schema migrations: {error}"))),
    })
    .try_for_each(|migration| {
        let migration = migration?;
        if SUPPORTED_NIX_MIGRATIONS.contains(&migration.as_str()) {
            Ok(())
        } else {
            Err(format!(
                "unsupported Nix store schema migration: {migration}"
            ))
        }
    })
}

fn require_trusted_signature_key(trusted_keys: &TrustedPublicKeys) -> Result<(), String> {
    match trusted_keys.is_empty() {
        true => Err("native-store source requires at least one trusted public key".to_owned()),
        false => Ok(()),
    }
}

fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and reads the process effective uid.
    unsafe { libc::geteuid() }
}

fn validate_supported_schema(database: &Connection) -> Result<(), String> {
    REQUIRED_TABLE_COLUMNS
        .iter()
        .try_for_each(|(table, required_columns)| {
            let present_columns = table_columns(database, table)?;
            match required_columns
                .iter()
                .all(|column| present_columns.contains(*column))
            {
                true => Ok(()),
                false => Err(format!(
                    "unsupported or incomplete Nix store database schema: {table}"
                )),
            }
        })
}

fn table_columns(
    database: &Connection,
    table: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut statement = database
        .prepare(format!("PRAGMA table_info({table})"))
        .map_err(|error| format!("reading Nix store schema for {table}: {error}"))?;
    std::iter::from_fn(|| match statement.next() {
        Ok(State::Row) => Some(
            statement
                .read::<String, _>("name")
                .map_err(|error| format!("reading Nix store schema for {table}: {error}")),
        ),
        Ok(State::Done) => None,
        Err(error) => Some(Err(format!(
            "reading Nix store schema for {table}: {error}"
        ))),
    })
    .try_fold(std::collections::BTreeSet::new(), |mut columns, column| {
        columns.insert(column?);
        Ok(columns)
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
    };

    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;
    use narjar::__private::{narinfo::TrustedPublicKeys, storage::StoreHash};
    use narjar::object::{NarHash, NarIdentity, NarRepresentation, NarSize};
    use sqlite::Connection;
    use tempfile::TempDir;

    use super::{
        NativeStoreIssue, NativeStoreSettings, open_supported_metadata_database,
        validate_supported_schema,
    };

    struct NativeStoreFixture {
        _root: TempDir,
        settings: NativeStoreSettings,
        narjar_data_dir: PathBuf,
    }

    impl NativeStoreFixture {
        fn new(valid_schema: bool) -> Self {
            let root = tempfile::tempdir().expect("fixture root should be created");
            let store_dir = root.path().join("store");
            let state_dir = root.path().join("state");
            let database_dir = state_dir.join("db");
            let roots_dir = state_dir.join("gcroots/auto/narjar");
            let narjar_data_dir = root.path().join("narjar-data");
            for directory in [&store_dir, &database_dir, &roots_dir, &narjar_data_dir] {
                fs::create_dir_all(directory).expect("fixture directory should be created");
            }
            File::create(state_dir.join("gc.lock")).expect("Nix GC lock should be created");
            fs::set_permissions(&roots_dir, fs::Permissions::from_mode(0o700))
                .expect("roots directory should be private");
            create_database(&database_dir.join("db.sqlite"), valid_schema);
            fs::write(database_dir.join("schema"), "10\n")
                .expect("supported schema version should be recorded");

            Self {
                _root: root,
                settings: NativeStoreSettings::new(
                    store_dir,
                    state_dir,
                    roots_dir,
                    std::num::NonZeroU64::new(60).expect("nonzero lease"),
                ),
                narjar_data_dir,
            }
        }
    }

    fn create_database(path: &std::path::Path, valid_schema: bool) {
        let database = Connection::open(path).expect("create fixture database");
        if valid_schema {
            database
                .execute(
                    "CREATE TABLE ValidPaths (
                        id INTEGER PRIMARY KEY,
                        path TEXT,
                        hash TEXT,
                        registrationTime INTEGER,
                        deriver TEXT,
                        narSize INTEGER,
                        sigs TEXT,
                        ca TEXT
                    );
                    CREATE TABLE Refs (referrer INTEGER, reference INTEGER);
                    CREATE TABLE SchemaMigrations (migration TEXT);",
                )
                .expect("create supported Nix metadata schema");
            database
                .execute(
                    "INSERT INTO SchemaMigrations (migration) VALUES \
                     ('20260309-drop-redundant-indexreferrer')",
                )
                .expect("record a supported Nix schema migration");
        } else {
            database
                .execute("CREATE TABLE ValidPaths (id INTEGER PRIMARY KEY)")
                .expect("create incomplete Nix metadata schema");
        }
    }

    fn trusted_keys() -> TrustedPublicKeys {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        TrustedPublicKeys::parse(&format!(
            "narjar-test:{}",
            BASE64.encode(signing_key.verifying_key().as_bytes())
        ))
        .expect("fixture trusted key should parse")
    }

    #[test]
    fn opens_supported_native_store_inputs_read_only() {
        let fixture = NativeStoreFixture::new(true);

        let validated = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .expect("complete native-store config should validate");

        assert!(
            validated
                ._metadata_database
                .execute("CREATE TABLE must_not_be_written (id INTEGER)")
                .is_err()
        );
    }

    #[test]
    fn reads_one_consistent_typed_path_record_and_its_references() {
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute(
                "INSERT INTO ValidPaths (id, path, hash, registrationTime, deriver, narSize, sigs, ca) VALUES
                 (1, '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, '/nix/store/11111111111111111111111111111111-builder.drv', 289656, '',
                  'fixed:sha256:0000000000000000000000000000000000000000000000000000000000000000'),
                 (2, '/nix/store/11111111111111111111111111111111-z-reference',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 1, '', NULL),
                 (3, '/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-a-reference',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 1, '', NULL);
                 INSERT INTO Refs (referrer, reference) VALUES (1, 2), (1, 3), (1, 2);",
            )
            .expect("native path and reference rows should be inserted");

        let snapshot = super::metadata::NativeMetadataSnapshot::open(&fixture.settings.state_dir)
            .expect("supported Nix metadata snapshot should open");
        let metadata = snapshot
            .validated_claims_for("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root")
            .expect("exact valid path should resolve");
        let claims = metadata.claims();

        assert_eq!(
            claims.store_path(),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root"
        );
        assert_eq!(
            claims.identity(),
            NarIdentity::new(
                NarHash::from_digest([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                NarSize::new(289_656),
            )
        );
        assert_eq!(
            claims.reference_paths().collect::<Vec<_>>(),
            [
                "/nix/store/11111111111111111111111111111111-z-reference",
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-a-reference",
            ]
        );
        let identity = claims.identity();
        let narinfo = metadata
            .into_narinfo_metadata()
            .serialize(NarRepresentation::Raw(identity))
            .expect("native metadata should project through the raw representation");
        let narinfo = std::str::from_utf8(&narinfo).expect("narinfo should be UTF-8");
        assert!(narinfo.contains("Deriver: 11111111111111111111111111111111-builder.drv\n"));
        assert!(narinfo.contains(
            "CA: fixed:sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        ));
        assert!(
            snapshot
                .validated_claims_for("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-missing")
                .is_err()
        );
    }

    #[test]
    fn read_transaction_keeps_path_claims_references_and_signatures_on_one_snapshot() {
        let fixture = NativeStoreFixture::new(true);
        let database_path = fixture.settings.state_dir.join("db/db.sqlite");
        let database = Connection::open(&database_path).expect("fixture database should open");
        database
            .execute(
                "PRAGMA journal_mode=WAL;
                 INSERT INTO ValidPaths (id, path, hash, registrationTime, deriver, narSize, sigs, ca) VALUES
                 (1, '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 289656, 'old-key:old-signature', NULL),
                 (2, '/nix/store/11111111111111111111111111111111-old-reference',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 1, '', NULL),
                 (3, '/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-new-reference',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 1, '', NULL);
                 INSERT INTO Refs (referrer, reference) VALUES (1, 2);",
            )
            .expect("initial snapshot rows should be inserted");
        drop(database);

        let snapshot = super::metadata::NativeMetadataSnapshot::open(&fixture.settings.state_dir)
            .expect("supported Nix metadata snapshot should open");
        let writer = Connection::open(&database_path).expect("WAL writer should open");
        writer
            .execute(
                "BEGIN IMMEDIATE;
                 UPDATE ValidPaths SET narSize=289657, sigs='new-key:new-signature' WHERE id=1;
                 DELETE FROM Refs WHERE referrer=1;
                 INSERT INTO Refs (referrer, reference) VALUES (1, 3);
                 COMMIT;",
            )
            .expect("writer should commit one coherent metadata update");

        let existing_snapshot = snapshot
            .validated_claims_for("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root")
            .expect("existing snapshot should still read its original path");
        assert_eq!(existing_snapshot.claims().identity().size().get(), 289_656);
        assert_eq!(
            existing_snapshot
                .claims()
                .reference_paths()
                .collect::<Vec<_>>(),
            ["/nix/store/11111111111111111111111111111111-old-reference"]
        );
        assert_eq!(
            existing_snapshot.into_narinfo_metadata().signatures(),
            ["old-key:old-signature"]
        );

        let refreshed_snapshot =
            super::metadata::NativeMetadataSnapshot::open(&fixture.settings.state_dir)
                .expect("fresh supported snapshot should open");
        let refreshed_claims = refreshed_snapshot
            .validated_claims_for("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root")
            .expect("fresh snapshot should read the committed path");
        assert_eq!(refreshed_claims.claims().identity().size().get(), 289_657);
        assert_eq!(
            refreshed_claims
                .claims()
                .reference_paths()
                .collect::<Vec<_>>(),
            ["/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-new-reference"]
        );
        assert_eq!(
            refreshed_claims.into_narinfo_metadata().signatures(),
            ["new-key:new-signature"]
        );
    }

    #[test]
    fn nix_store_fixtures_verify_signatures_and_project_raw_narinfo() {
        // Captured from Nix 2.34.8 ValidPaths rows; cache.nixos.org signatures
        // are verified offline with its published public key.
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute(
                "INSERT INTO ValidPaths (id, path, hash, registrationTime, deriver, narSize, sigs, ca) VALUES
                 (1, '/nix/store/d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8',
                  'sha256:503893073fe39f4b985ee90a4d4b94e56e0f6c46570cf00fb14d5da2cbd364ac',
                  1, '/nix/store/mpzn77a9867s84iyd1srfwrd64y5awsv-libidn2-2.3.8.drv', 368208,
                  'cache.nixos.org-1:MPH/F9lUYyvh6VR/Tr8iM/kguaHnt4U5h5Kz6dYc+6agt6qMW4V5rcXw+ykc0BVlz3yoBuwAic/KnSUNdCw8AQ==', NULL),
                 (2, '/nix/store/pkphs076yz5ajnqczzj0588n6miph269-libunistring-1.4.1',
                  'sha256:ad10dff2809a0cd2734a9574dddd8df9780a1a2a6dba7769f1eeb5e7b260c1ef',
                  1, '/nix/store/m8n3ng116gv3id8dm61kx1cqnh99rwaz-libunistring-1.4.1.drv', 2078792,
                  'cache.nixos.org-1:QKjGZh4tgGKcAKfpuKF+F9rDBgycWirDRk/f3OXKrF+JaCQB9xcw8P83u9BWN2gyyLLTfuK14MTvbYFrTdsJDQ==', NULL),
                 (3, '/nix/store/xvdf2dnj66vyyi0jjwxr17qjk0v3w8fp-nix-wallpaper-simple-dark-gray_bootloader.png',
                  'sha256:77fffdbb77e42ed9fb8a14d1462a722a77dc90f669b8795615e35d188c4f59af',
                  1, '/nix/store/qjpq7vib1plv6lj2hql80yqhn9mdc6by-nix-wallpaper-simple-dark-gray_bootloader.png.drv',
                  9176,
                  'cache.nixos.org-1:h0NTWnKoJcfR9vgT499okYa0XnuAOsA/ZVdEcNRYjrdd1y9D1ujs+uIM5ocXiAcTt/n0KnkUIbfOU+xR7EgbCQ==', NULL),
                 (4, '/nix/store/4d0ix5djms3n2jnjdc58l916cwack1rp-empty-directory',
                  'sha256:a50a5ab6d992f5598edd92105059fae9acfc192981e08bd88534c2167e92526a',
                  1, '/nix/store/5ncnx3qgzykavgkdvj3gkcdi8q6fnp8j-empty-directory.drv', 96,
                  'cache.nixos.org-1:TlGxThvFIpDeZdovNZRP3yR/kDYTaOke6wul57doLvldLGHVYzeHiXgrPZd2TrDcLsDPcOP4M8RuEdthhMK3BA==',
                  'fixed:r:sha256:0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5');
                 INSERT INTO Refs (referrer, reference) VALUES (1, 1), (1, 2);",
            )
            .expect("Nix metadata fixture rows should be inserted");
        let snapshot = super::metadata::NativeMetadataSnapshot::open(&fixture.settings.state_dir)
            .expect("supported Nix metadata snapshot should open");
        let trusted_keys = TrustedPublicKeys::parse(
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
        )
        .expect("official Nix cache public key should parse");

        let referenced = snapshot
            .validated_claims_for("/nix/store/d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8")
            .expect("referenced Nix fixture should validate");
        assert_eq!(
            referenced.claims().fingerprint(),
            "1;/nix/store/d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8;sha256:1b34sg5s4padn47z032p8rn0yvp5ji5ls2p9bsc4p7z37w3r6f2h;368208;/nix/store/d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8,/nix/store/pkphs076yz5ajnqczzj0588n6miph269-libunistring-1.4.1"
        );
        assert_eq!(
            referenced.claims().reference_paths().collect::<Vec<_>>(),
            [
                "/nix/store/d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8",
                "/nix/store/pkphs076yz5ajnqczzj0588n6miph269-libunistring-1.4.1",
            ]
        );
        verify_nix_raw_projection(
            referenced.into_narinfo_metadata(),
            &trusted_keys,
            "d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8",
            "1b34sg5s4padn47z032p8rn0yvp5ji5ls2p9bsc4p7z37w3r6f2h",
            368_208,
            "d0d9wqmw5saaynfvmszsda3dmh5q82z8-libidn2-2.3.8 pkphs076yz5ajnqczzj0588n6miph269-libunistring-1.4.1",
        );

        let unreferenced = snapshot
            .validated_claims_for(
                "/nix/store/xvdf2dnj66vyyi0jjwxr17qjk0v3w8fp-nix-wallpaper-simple-dark-gray_bootloader.png",
            )
            .expect("unreferenced Nix fixture should validate");
        assert!(unreferenced.claims().reference_paths().next().is_none());
        assert_eq!(
            unreferenced.claims().fingerprint(),
            "1;/nix/store/xvdf2dnj66vyyi0jjwxr17qjk0v3w8fp-nix-wallpaper-simple-dark-gray_bootloader.png;sha256:1bsr9y61hpg32mb7kf39ys8dqxraf8m4dl8libxxjbp4fyxzvzvp;9176;"
        );
        verify_nix_raw_projection(
            unreferenced.into_narinfo_metadata(),
            &trusted_keys,
            "xvdf2dnj66vyyi0jjwxr17qjk0v3w8fp-nix-wallpaper-simple-dark-gray_bootloader.png",
            "1bsr9y61hpg32mb7kf39ys8dqxraf8m4dl8libxxjbp4fyxzvzvp",
            9_176,
            "",
        );

        let content_addressed = snapshot
            .validated_claims_for("/nix/store/4d0ix5djms3n2jnjdc58l916cwack1rp-empty-directory")
            .expect("content-addressed Nix fixture should validate");
        assert_eq!(
            content_addressed.claims().fingerprint(),
            "1;/nix/store/4d0ix5djms3n2jnjdc58l916cwack1rp-empty-directory;sha256:0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5;96;"
        );
        let content_addressed_raw = content_addressed
            .sign_for_trusted_cache(&trusted_keys, None)
            .expect("Nix signature should be reusable for its exact fingerprint")
            .serialize_raw()
            .expect("content-addressed raw narinfo should serialize");
        let content_addressed_text =
            std::str::from_utf8(&content_addressed_raw).expect("narinfo should be UTF-8");
        assert!(
            content_addressed_text
                .contains("URL: nar/0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5.nar\n")
        );
        assert!(
            content_addressed_text.contains(
                "FileHash: sha256:0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5\n"
            )
        );
        assert!(
            content_addressed_text
                .contains("NarHash: sha256:0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5\n")
        );
        assert!(content_addressed_text.contains("Compression: none\n"));
        assert!(content_addressed_text.contains("FileSize: 96\n"));
        assert!(content_addressed_text.contains("NarSize: 96\n"));
        assert!(
            content_addressed_text.contains(
                "CA: fixed:r:sha256:0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5\n"
            )
        );
        trusted_keys
            .validate(
                &StoreHash::parse("4d0ix5djms3n2jnjdc58l916cwack1rp")
                    .expect("content-addressed route hash should parse"),
                content_addressed_raw,
            )
            .expect("content-addressed Nix signature should accept raw projection");
    }

    fn verify_nix_raw_projection(
        metadata: narjar::__private::narinfo::NarInfoMetadata,
        trusted_keys: &TrustedPublicKeys,
        route_and_store_path: &str,
        nar_hash: &str,
        nar_size: u64,
        references: &str,
    ) {
        let route = route_and_store_path
            .split_once('-')
            .expect("fixture route should have a Nix store basename")
            .0;
        let path = format!("/nix/store/{route_and_store_path}");
        let identity = metadata.claims().identity();
        let bytes = metadata
            .serialize(NarRepresentation::Raw(identity))
            .expect("raw Nix narinfo should serialize");
        let text = std::str::from_utf8(&bytes).expect("narinfo should be UTF-8");
        assert!(text.contains(&format!("StorePath: {path}\n")));
        assert!(text.contains(&format!("URL: nar/{nar_hash}.nar\n")));
        assert!(text.contains(&format!("FileHash: sha256:{nar_hash}\n")));
        assert!(text.contains(&format!("NarHash: sha256:{nar_hash}\n")));
        assert!(text.contains(&format!("FileSize: {nar_size}\n")));
        assert!(text.contains(&format!("NarSize: {nar_size}\n")));
        assert!(text.contains(&format!("References: {references}\n")));
        assert!(text.contains("Compression: none\n"));
        trusted_keys
            .validate(
                &StoreHash::parse(route).expect("fixture route hash should parse"),
                bytes,
            )
            .expect("Nix-generated signature should accept the raw projection");
    }

    #[test]
    fn rejects_a_dangling_native_store_reference() {
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute(
                "INSERT INTO ValidPaths (id, path, hash, registrationTime, deriver, narSize, sigs, ca) VALUES
                 (1, '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root',
                  'sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                  1, NULL, 289656, '', NULL);
                 INSERT INTO Refs (referrer, reference) VALUES (1, 999);",
            )
            .expect("dangling reference fixture should be inserted");

        let snapshot = super::metadata::NativeMetadataSnapshot::open(&fixture.settings.state_dir)
            .expect("supported Nix metadata snapshot should open");
        let result =
            snapshot.validated_claims_for("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-root");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_malformed_narjar_lease_state_as_its_own_validation_issue() {
        let fixture = NativeStoreFixture::new(true);
        let lease_directory = fixture
            .settings
            .roots_dir
            .join(format!(".narjar-lease-{}", "a".repeat(64)));
        fs::create_dir(&lease_directory).expect("lease directory should be created");
        fs::write(lease_directory.join("record"), b"not a lease record")
            .expect("malformed lease record should be written");

        let error = match fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
        {
            Ok(_) => panic!("malformed lease state should reject startup"),
            Err(error) => error,
        };

        assert_eq!(error.issue, NativeStoreIssue::LeaseState);
        assert_eq!(
            error.doctor_detail(),
            "Narjar native-store lease state is invalid or unavailable"
        );
    }

    #[test]
    fn rejects_an_unsupported_nix_database_schema_before_serving() {
        let fixture = NativeStoreFixture::new(false);

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unsupported Nix schema must fail startup validation");

        assert_eq!(error.issue, NativeStoreIssue::SchemaStructure);
        assert!(
            error
                .to_string()
                .contains("unsupported or incomplete Nix store database schema")
        );
    }

    #[test]
    fn rejects_an_unsupported_numeric_nix_schema_version() {
        let fixture = NativeStoreFixture::new(true);
        fs::write(fixture.settings.state_dir.join("db/schema"), "11\n")
            .expect("unsupported schema version should be recorded");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unknown Nix schema version must fail startup");

        assert_eq!(error.issue, NativeStoreIssue::SchemaVersion);
        assert!(
            error
                .to_string()
                .contains("unsupported Nix store schema version 11")
        );
    }

    #[test]
    fn rejects_unknown_nix_schema_migrations() {
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute("INSERT INTO SchemaMigrations (migration) VALUES ('future-migration')")
            .expect("unknown migration should be recorded");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unknown Nix migration must fail startup");

        assert_eq!(error.issue, NativeStoreIssue::SchemaMigration);
        assert!(
            error
                .to_string()
                .contains("unsupported Nix store schema migration: future-migration")
        );
    }

    #[test]
    fn accepts_the_historical_ca_derivations_migration_without_newer_entries() {
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute("DELETE FROM SchemaMigrations")
            .expect("newer migration should be removed");
        database
            .execute(
                "INSERT INTO SchemaMigrations (migration) \
                 VALUES ('20220326-ca-derivations')",
            )
            .expect("historical migration should be recorded");

        fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .expect("known historical Nix stores should validate");
    }

    #[test]
    fn accepts_historical_and_newer_ca_derivations_migrations_together() {
        let fixture = NativeStoreFixture::new(true);
        let database = Connection::open(fixture.settings.state_dir.join("db/db.sqlite"))
            .expect("fixture database should open");
        database
            .execute(
                "INSERT INTO SchemaMigrations (migration) \
                 VALUES ('20220326-ca-derivations')",
            )
            .expect("historical migration should be recorded");

        fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .expect("stores retaining old and new migration records should validate");
    }

    #[test]
    fn rejects_a_symlinked_native_store_directory() {
        let fixture = NativeStoreFixture::new(true);
        let target = fixture._root.path().join("store");
        let link = fixture._root.path().join("store-link");
        std::os::unix::fs::symlink(&target, &link).expect("store symlink should be created");
        let settings = NativeStoreSettings::new(
            link,
            fixture.settings.state_dir.clone(),
            fixture.settings.roots_dir.clone(),
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("symlinked store directory must be rejected");

        assert!(error.to_string().contains("opening Nix store"));
    }

    #[test]
    fn rejects_a_non_directory_native_store_path() {
        let fixture = NativeStoreFixture::new(true);
        let file = fixture._root.path().join("not-a-store-directory");
        fs::write(&file, b"not a directory").expect("wrong-type fixture should be written");
        let settings = NativeStoreSettings::new(
            file,
            fixture.settings.state_dir.clone(),
            fixture.settings.roots_dir.clone(),
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("wrong store path type must be rejected");

        assert!(error.to_string().contains("opening Nix store"));
    }

    #[test]
    fn rejects_a_native_store_without_any_read_permission_bits() {
        let fixture = NativeStoreFixture::new(true);
        fs::set_permissions(
            &fixture.settings.store_dir,
            fs::Permissions::from_mode(0o000),
        )
        .expect("store permissions should be changed");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unreadable store must be rejected");

        assert!(
            error.to_string().contains("Nix store"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn rejects_a_native_store_directory_without_search_permissions() {
        let fixture = NativeStoreFixture::new(true);
        fs::set_permissions(
            &fixture.settings.store_dir,
            fs::Permissions::from_mode(0o611),
        )
        .expect("owner should lack search permission while other classes have it");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unsearchable store must fail startup validation");

        assert!(error.to_string().contains("searchable"));
    }

    #[test]
    fn rejects_shared_writable_service_owned_ancestors() {
        let fixture = NativeStoreFixture::new(true);
        fs::set_permissions(fixture._root.path(), fs::Permissions::from_mode(0o777))
            .expect("fixture ancestor should become shared-writable");

        let error = super::validate_directory_ancestors(&fixture.settings.state_dir)
            .expect_err("shared-writable ancestors must be rejected even when service-owned");

        assert!(error.contains("other users can replace"));
    }

    #[test]
    fn rejects_untrusted_owners_even_with_sticky_or_non_writable_modes() {
        let service_uid = super::effective_user_id();
        let untrusted_uid = if service_uid == u32::MAX {
            service_uid - 1
        } else {
            service_uid + 1
        };

        for mode in [0o755, 0o1777] {
            let error = super::validate_ancestor_owner_and_mode(untrusted_uid, mode, service_uid)
                .expect_err("untrusted directory owners must be rejected");
            assert!(error.contains("untrusted ownership"));
        }
    }

    #[test]
    fn rejects_fifo_database_and_schema_without_blocking() {
        let fixture = NativeStoreFixture::new(true);
        let database_path = fixture.settings.state_dir.join("db/db.sqlite");
        fs::remove_file(&database_path).expect("database fixture should be removable");
        create_fifo(&database_path);

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("FIFO database must be rejected");
        assert!(error.to_string().contains("not a regular file"));

        fs::remove_file(&database_path).expect("FIFO database should be removable");
        create_database(&database_path, true);
        let schema_path = fixture.settings.state_dir.join("db/schema");
        fs::remove_file(&schema_path).expect("schema fixture should be removable");
        create_fifo(&schema_path);

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("FIFO schema file must be rejected");
        assert!(error.to_string().contains("not a regular file"));
    }

    fn create_fifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;

        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .expect("fixture path should not contain NUL");
        // SAFETY: path is NUL-terminated and mkfifo reads it before returning.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(result, 0, "FIFO fixture should be created");
    }

    #[test]
    fn detects_read_only_roots_filesystem_capability() {
        assert_eq!(
            super::filesystem_writeability_from_flags(libc::ST_RDONLY),
            super::FilesystemWriteability::ReadOnly
        );
        assert_eq!(
            super::filesystem_writeability_from_flags(0),
            super::FilesystemWriteability::Writable
        );
        assert_eq!(
            super::require_writable_roots_filesystem(super::FilesystemWriteability::ReadOnly),
            Err("Narjar roots filesystem is read-only".to_owned())
        );
    }

    #[test]
    fn rejects_roots_directory_with_group_or_other_permissions() {
        let fixture = NativeStoreFixture::new(true);
        fs::set_permissions(
            &fixture.settings.roots_dir,
            fs::Permissions::from_mode(0o750),
        )
        .expect("roots permissions should be changed");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("shared roots directory must be rejected");

        assert!(error.to_string().contains("must be mode 0700"));
    }

    #[test]
    fn rejects_a_symlinked_roots_directory() {
        let fixture = NativeStoreFixture::new(true);
        let target = fixture._root.path().join("roots");
        let link = fixture._root.path().join("roots-link");
        std::os::unix::fs::symlink(&target, &link).expect("roots symlink should be created");
        let settings = NativeStoreSettings::new(
            fixture.settings.store_dir.clone(),
            fixture.settings.state_dir.clone(),
            link,
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("symlinked roots directory must be rejected");

        assert!(error.to_string().contains("opening Narjar roots directory"));
    }

    #[test]
    fn rejects_a_symlinked_nix_metadata_database() {
        let fixture = NativeStoreFixture::new(true);
        let database_path = fixture.settings.state_dir.join("db/db.sqlite");
        let target = fixture._root.path().join("database-target.sqlite");
        fs::rename(&database_path, &target).expect("database fixture should be movable");
        std::os::unix::fs::symlink(&target, &database_path)
            .expect("database symlink should be created");

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("symlinked Nix database must be rejected");

        assert!(error.to_string().contains("database must not be a symlink"));
    }

    #[test]
    fn rejects_a_roots_directory_inside_narjar_data() {
        let fixture = NativeStoreFixture::new(true);
        let roots_dir = fixture.narjar_data_dir.join("native-roots");
        fs::create_dir(&roots_dir).expect("nested roots directory should be created");
        fs::set_permissions(&roots_dir, fs::Permissions::from_mode(0o700))
            .expect("nested roots should be private");
        let settings = NativeStoreSettings::new(
            fixture.settings.store_dir.clone(),
            fixture.settings.state_dir.clone(),
            roots_dir,
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("native roots must not share the Narjar data directory");

        assert!(
            error
                .to_string()
                .contains("outside the Narjar data directory")
        );
    }

    #[test]
    fn rejects_a_roots_directory_inside_the_nix_store() {
        let fixture = NativeStoreFixture::new(true);
        let roots_dir = fixture.settings.store_dir.join("roots");
        fs::create_dir(&roots_dir).expect("roots directory inside the store should be created");
        fs::set_permissions(&roots_dir, fs::Permissions::from_mode(0o700))
            .expect("nested roots should be private");
        let settings = NativeStoreSettings::new(
            fixture.settings.store_dir.clone(),
            fixture.settings.state_dir.clone(),
            roots_dir,
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("native roots must not share the Nix store");

        assert_eq!(
            error.to_string(),
            "Narjar roots directory must be outside the Nix store"
        );
    }

    #[test]
    fn rejects_roots_outside_nix_discovered_gc_roots() {
        let fixture = NativeStoreFixture::new(true);
        let roots_dir = fixture._root.path().join("narjar-roots");
        fs::create_dir(&roots_dir).expect("external roots directory should be created");
        fs::set_permissions(&roots_dir, fs::Permissions::from_mode(0o700))
            .expect("external roots should be private");
        let settings = NativeStoreSettings::new(
            fixture.settings.store_dir.clone(),
            fixture.settings.state_dir.clone(),
            roots_dir,
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("Nix-invisible root directory must be rejected");

        assert!(
            error
                .to_string()
                .contains("must be a child of Nix GC roots")
        );
    }

    #[test]
    fn rejects_relative_native_store_paths() {
        let fixture = NativeStoreFixture::new(true);
        let settings = NativeStoreSettings::new(
            PathBuf::from("relative-store"),
            fixture.settings.state_dir.clone(),
            fixture.settings.roots_dir.clone(),
            std::num::NonZeroU64::new(60).expect("nonzero lease"),
        );

        let error = settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("native paths must be absolute");

        assert!(
            error
                .to_string()
                .contains("Nix store path must be absolute")
        );
    }

    #[test]
    fn rejects_native_store_without_a_signature_trust_key() {
        let fixture = NativeStoreFixture::new(true);

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &TrustedPublicKeys::default())
            .err()
            .expect("native source needs signature policy input");

        assert_eq!(
            error.to_string(),
            "native-store source requires at least one trusted public key"
        );
    }

    #[test]
    fn rejects_incomplete_nix_metadata_schema() {
        let database = Connection::open(":memory:").expect("open schema test database");
        database
            .execute("CREATE TABLE ValidPaths (id INTEGER PRIMARY KEY)")
            .expect("create incomplete schema");

        let error = validate_supported_schema(&database)
            .expect_err("incomplete Nix schema must be rejected");

        assert!(error.contains("unsupported or incomplete Nix store database schema"));
    }

    #[test]
    fn push_and_native_serve_share_the_supported_read_only_database_gate() {
        let fixture = NativeStoreFixture::new(true);

        let database = open_supported_metadata_database(&fixture.settings.state_dir)
            .expect("native metadata database should pass the shared schema gate");

        assert!(
            database
                .execute("CREATE TABLE must_not_be_written (id INTEGER)")
                .is_err()
        );
    }
}
