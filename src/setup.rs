use std::{
    fs::{self, File},
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use clap::Args;
use narjar::__private::storage::StorageBackend;

use crate::{
    error::Error,
    http_url::HttpUrl,
    operator::{self, Init, generate_key_pair},
    token,
};

#[derive(Args)]
pub(crate) struct Setup {
    #[arg(long, default_value = "./narjar-data", value_parser = non_empty_path)]
    data_dir: PathBuf,
    #[arg(long, default_value = "./narjar-credentials", value_parser = non_empty_path)]
    credentials_dir: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:5000")]
    cache_url: HttpUrl,
    #[arg(long, default_value = "127.0.0.1:5000")]
    listen: SocketAddr,
    #[arg(long, default_value = "narjar", value_parser = operator::valid_key_name)]
    key_name: String,
    #[arg(long, default_value_t = 30)]
    priority: u32,
    #[arg(long, default_value = "flat")]
    storage_backend: StorageBackend,
    #[arg(long)]
    private_read: bool,
    #[arg(long, short)]
    yes: bool,
}

pub(crate) fn run(mut options: Setup) -> Result<(), Error> {
    let destinations = SetupDestinations::new(&options.data_dir, &options.credentials_dir)?;
    destinations.ensure_available()?;
    options.data_dir = destinations.data_dir;
    options.credentials_dir = destinations.credentials_dir;
    confirm_setup(&options)?;

    create_setup_directories(&options.data_dir, &options.credentials_dir)?;

    operator::init(Init {
        data_dir: options.data_dir.clone(),
        priority: options.priority,
        private_read: options.private_read,
        storage_backend: options.storage_backend,
    })?;

    let secret_key = options.credentials_dir.join("producer.sec");
    let public_key = options.credentials_dir.join("producer.pub");
    generate_key_pair(&options.key_name, &secret_key, &public_key)?;
    install_trusted_public_key(&options.data_dir, &public_key)?;

    let write_token =
        token::create_secret_token(&options.data_dir.join("auth/write.tokens"), "setup-write")?;
    operator::create_file(
        &options.credentials_dir.join("write.token"),
        write_token.as_bytes(),
        0o600,
        false,
    )?;
    let netrc = netrc_entry(options.cache_url.host(), &write_token);
    operator::create_file(
        &options.credentials_dir.join("narjar.netrc"),
        netrc.as_bytes(),
        0o600,
        false,
    )?;

    if options.private_read {
        create_private_read_token(&options)?;
    }

    print_setup_summary(&options, &secret_key, &public_key);
    Ok(())
}

struct SetupDestinations {
    data_dir: PathBuf,
    credentials_dir: PathBuf,
}

impl SetupDestinations {
    fn new(data_dir: &Path, credentials_dir: &Path) -> Result<Self, Error> {
        let data_dir = absolute_destination(data_dir)?;
        let credentials_dir = absolute_destination(credentials_dir)?;
        if data_dir == credentials_dir
            || data_dir.starts_with(&credentials_dir)
            || credentials_dir.starts_with(&data_dir)
        {
            return Err(Error::usage(
                "--data-dir and --credentials-dir must be separate, non-nested directories",
            ));
        }
        Ok(Self {
            data_dir,
            credentials_dir,
        })
    }

    fn ensure_available(&self) -> Result<(), Error> {
        [&self.data_dir, &self.credentials_dir]
            .into_iter()
            .try_for_each(|path| match fs::symlink_metadata(path) {
                Ok(_) => Err(Error::runtime(format!(
                    "setup destination already exists; refusing to overwrite: {}",
                    path.display()
                ))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(runtime(error)),
            })
    }
}

fn create_setup_directories(data_dir: &Path, credentials_dir: &Path) -> Result<(), Error> {
    create_private_directory(data_dir)?;
    if let Err(error) = create_private_directory(credentials_dir) {
        let _ = fs::remove_dir(data_dir);
        return Err(error);
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(runtime)?;
    set_directory_mode(path)
}

fn absolute_destination(path: &Path) -> Result<PathBuf, Error> {
    let name = path
        .file_name()
        .filter(|name| *name != "." && *name != "..")
        .ok_or_else(|| Error::usage("setup destinations must name directories"))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| {
        Error::usage(format!(
            "setup destination parent must exist ({}): {error}",
            parent.display()
        ))
    })?;
    Ok(parent.join(name))
}

fn confirm_setup(options: &Setup) -> Result<(), Error> {
    if options.yes || !io::stdin().is_terminal() {
        return Ok(());
    }

    println!(
        "Create Narjar data in {} and credentials in {}?",
        options.data_dir.display(),
        options.credentials_dir.display()
    );
    print!("Continue [y/N]? ");
    io::stdout().flush().map_err(runtime)?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(runtime)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        return Ok(());
    }
    Err(Error::runtime("setup cancelled"))
}

fn set_directory_mode(path: &Path) -> Result<(), Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(runtime)
}

fn install_trusted_public_key(data_dir: &Path, public_key: &Path) -> Result<(), Error> {
    let target = data_dir.join("trusted-public-keys");
    let metadata = fs::symlink_metadata(&target).map_err(runtime)?;
    if !metadata.file_type().is_file()
        || metadata.len() != 0
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Error::runtime(
            "initialized trusted-public-keys must be an empty regular 0600 file",
        ));
    }
    let key = fs::read(public_key).map_err(runtime)?;
    let mut temporary = tempfile::NamedTempFile::new_in(data_dir).map_err(runtime)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(runtime)?;
    temporary.write_all(&key).map_err(runtime)?;
    temporary.as_file().sync_all().map_err(runtime)?;
    temporary
        .persist(&target)
        .map_err(|error| runtime(error.error))?;
    File::open(data_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(runtime)
}

fn create_private_read_token(options: &Setup) -> Result<(), Error> {
    let token_value =
        token::create_secret_token(&options.data_dir.join("auth/read.tokens"), "setup-read")?;
    operator::create_file(
        &options.credentials_dir.join("read.token"),
        token_value.as_bytes(),
        0o600,
        false,
    )
}

fn netrc_entry(host: &str, token: &str) -> String {
    format!("machine {host} login narjar password {token}\n")
}

fn print_setup_summary(options: &Setup, secret_key: &Path, public_key: &Path) {
    println!("Narjar setup complete");
    println!("data directory: {}", options.data_dir.display());
    println!(
        "credentials directory: {}",
        options.credentials_dir.display()
    );
    println!("trusted public key: {}", public_key.display());
    println!(
        "private signing key: {} (keep this file private)",
        secret_key.display()
    );
    println!(
        "write credentials: {}/narjar.netrc",
        options.credentials_dir.display()
    );
    if options.private_read {
        println!(
            "read token: {}/read.token",
            options.credentials_dir.display()
        );
    }
    println!(
        "start the cache: narjar serve --data-dir {} --listen {} --storage-backend {}",
        shell_quote(&options.data_dir.to_string_lossy()),
        options.listen,
        storage_backend_name(options.storage_backend)
    );
    println!(
        "push a path: narjar push {}--to {} --netrc-file {} --signing-key-file {} <store-path>",
        if options.cache_url.is_https() {
            ""
        } else {
            "--insecure-http "
        },
        shell_quote(&options.cache_url.to_string()),
        shell_quote(
            &options
                .credentials_dir
                .join("narjar.netrc")
                .to_string_lossy()
        ),
        shell_quote(&secret_key.to_string_lossy())
    );
    if !options.cache_url.is_https() {
        println!("warning: HTTP is suitable only for trusted local networks; use HTTPS remotely");
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

const fn storage_backend_name(backend: StorageBackend) -> &'static str {
    match backend {
        StorageBackend::Flat => "flat",
        StorageBackend::Chunked => "chunked",
    }
}

fn non_empty_path(value: &str) -> Result<PathBuf, String> {
    (!value.is_empty())
        .then(|| PathBuf::from(value))
        .ok_or_else(|| "must not be empty".to_owned())
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(error.to_string())
}

#[cfg(test)]
mod tests {
    use clap::{Args as _, Command, FromArgMatches};

    use super::Setup;

    #[test]
    fn setup_defaults_match_the_documented_local_first_run() {
        let matches = Setup::augment_args(Command::new("setup"))
            .try_get_matches_from(["setup"])
            .expect("setup should have usable local defaults");
        let setup = Setup::from_arg_matches(&matches).expect("setup defaults should deserialize");

        assert_eq!(setup.data_dir, std::path::Path::new("./narjar-data"));
        assert_eq!(
            setup.credentials_dir,
            std::path::Path::new("./narjar-credentials")
        );
        assert_eq!(setup.cache_url.as_str(), "http://127.0.0.1:5000");
        assert_eq!(setup.listen, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(setup.key_name, "narjar");
        assert_eq!(setup.priority, 30);
        assert!(matches!(
            setup.storage_backend,
            narjar::__private::storage::StorageBackend::Flat
        ));
        assert!(!setup.private_read);
    }
}
