use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    num::NonZeroU64,
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use narjar::__private::narinfo::TrustedPublicKeys;
use sqlite::{Connection, OpenFlags, State};

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
    "20251017-ca-derivations",
    "20260309-drop-redundant-indexreferrer",
];

#[derive(Debug)]
pub(crate) struct NativeStoreSettings {
    store_dir: PathBuf,
    state_dir: PathBuf,
    roots_dir: PathBuf,
    min_lease_seconds: NonZeroU64,
}

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
    ) -> Result<ValidatedNativeStore, String> {
        let store_directory = open_readable_directory(&self.store_dir, "Nix store")?;
        let state_directory = open_readable_directory(&self.state_dir, "Nix state directory")?;
        let roots_directory = open_owned_roots_directory(&self.roots_dir)?;
        let store_path = canonical_directory_path(&self.store_dir, &store_directory, "Nix store")?;
        let state_path =
            canonical_directory_path(&self.state_dir, &state_directory, "Nix state directory")?;
        let roots_path =
            canonical_directory_path(&self.roots_dir, &roots_directory, "Narjar roots")?;
        reject_roots_inside_narjar_data(&roots_path, narjar_data_dir)?;
        reject_roots_inside_nix_store(&roots_path, &store_path)?;
        validate_nix_database_path(&state_path)?;
        let metadata_database = open_supported_metadata_database(&state_path)?;
        require_trusted_signature_key(trusted_keys)?;

        Ok(ValidatedNativeStore {
            _store_directory: store_directory,
            _state_directory: state_directory,
            _roots_directory: roots_directory,
            _metadata_database: metadata_database,
            _min_lease_seconds: self.min_lease_seconds,
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
    _metadata_database: Connection,
    _min_lease_seconds: NonZeroU64,
}

pub(crate) fn open_supported_metadata_database(state_dir: &Path) -> Result<Connection, String> {
    let database_path = state_dir.join("db/db.sqlite");
    let checked_file = open_read_only_regular_file(&database_path, "Nix store database")?;
    let checked_identity = descriptor_identity(&checked_file)?;
    let database = Connection::open_with_flags(&database_path, OpenFlags::new().with_read_only())
        .map_err(|error| format!("opening the Nix store database: {error}"))?;
    require_database_path_matches_open_file(&database_path, checked_identity)?;
    database
        .execute("PRAGMA busy_timeout = 30000")
        .map_err(|error| format!("configuring the Nix store database wait: {error}"))?;
    database
        .execute("BEGIN")
        .map_err(|error| format!("starting the Nix store database snapshot: {error}"))?;
    let schema_version = read_nix_schema_version(state_dir)?;
    validate_supported_schema(&database)?;
    validate_supported_migrations(&database)?;
    match read_nix_schema_version(state_dir)? == schema_version {
        true => {}
        false => return Err("Nix store schema version changed during validation".to_owned()),
    }
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
    while let State::Row = statement
        .next()
        .map_err(|error| format!("reading Nix store schema migrations: {error}"))?
    {
        let migration = statement
            .read::<String, _>("migration")
            .map_err(|error| format!("reading Nix store schema migrations: {error}"))?;
        match SUPPORTED_NIX_MIGRATIONS.contains(&migration.as_str()) {
            true => {}
            false => {
                return Err(format!(
                    "unsupported Nix store schema migration: {migration}"
                ));
            }
        }
    }
    Ok(())
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
    let mut columns = std::collections::BTreeSet::new();
    while let State::Row = statement
        .next()
        .map_err(|error| format!("reading Nix store schema for {table}: {error}"))?
    {
        columns.insert(
            statement
                .read::<String, _>("name")
                .map_err(|error| format!("reading Nix store schema for {table}: {error}"))?,
        );
    }
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;
    use narjar::__private::narinfo::TrustedPublicKeys;
    use sqlite::Connection;
    use tempfile::TempDir;

    use super::{NativeStoreSettings, open_supported_metadata_database, validate_supported_schema};

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
            let roots_dir = root.path().join("roots");
            let narjar_data_dir = root.path().join("narjar-data");
            for directory in [&store_dir, &database_dir, &roots_dir, &narjar_data_dir] {
                fs::create_dir_all(directory).expect("fixture directory should be created");
            }
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
    fn rejects_an_unsupported_nix_database_schema_before_serving() {
        let fixture = NativeStoreFixture::new(false);

        let error = fixture
            .settings
            .validate(&fixture.narjar_data_dir, &trusted_keys())
            .err()
            .expect("unsupported Nix schema must fail startup validation");

        assert!(error.contains("unsupported or incomplete Nix store database schema"));
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

        assert!(error.contains("unsupported Nix store schema version 11"));
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

        assert!(error.contains("unsupported Nix store schema migration: future-migration"));
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

        assert!(error.contains("opening Nix store"));
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

        assert!(error.contains("opening Nix store"));
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
            error.contains("Nix store"),
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

        assert!(error.contains("searchable"));
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
        assert!(error.contains("not a regular file"));

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
        assert!(error.contains("not a regular file"));
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

        assert!(error.contains("must be mode 0700"));
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

        assert!(error.contains("opening Narjar roots directory"));
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

        assert!(error.contains("database must not be a symlink"));
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

        assert_eq!(
            error,
            "Narjar roots directory must be outside the Narjar data directory"
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
            error,
            "Narjar roots directory must be outside the Nix store"
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

        assert!(error.contains("Nix store path must be absolute"));
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
            error,
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
