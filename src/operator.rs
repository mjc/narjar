use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use narjar::inventory::{Inventory, InventoryClass, MAX_NARINFO_BYTES, narinfo_is_valid};

use crate::error::Error;
use narjar::{
    narinfo::TrustedPublicKeys,
    storage::{Storage, StoreHash},
};

pub(crate) fn run(command: &str, args: impl Iterator<Item = String>) -> Result<(), Error> {
    match command {
        "init" => init(args),
        "key" => key(args),
        "reconcile" => report(args, false, false),
        "verify" => report(args, true, false),
        "list-orphans" => report(args, false, true),
        "delete" => delete(args),
        "stats" => stats(args),
        _ => Err(Error::usage(format!("unknown command: {command}"))),
    }
}

fn init(args: impl Iterator<Item = String>) -> Result<(), Error> {
    let options = Options::parse(args, &["--data-dir", "--priority"], &["--private-read"])?;
    let root = PathBuf::from(options.required("--data-dir")?);
    let priority: u32 = options
        .value("--priority")
        .unwrap_or("30")
        .parse()
        .map_err(|_| Error::usage("--priority must be an unsigned integer"))?;

    if root.exists() {
        let mut entries = fs::read_dir(&root).map_err(runtime)?;
        if entries.next().transpose().map_err(runtime)?.is_some() {
            return Err(Error::runtime(format!(
                "data directory is not empty: {}",
                root.display()
            )));
        }
    } else {
        fs::create_dir_all(&root).map_err(runtime)?;
    }

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(runtime)?;
    let storage = Storage::initialize(&root).map_err(runtime)?;
    for directory in ["nar", ".tmp", "realisations"] {
        fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700))
            .map_err(runtime)?;
    }
    fs::create_dir(root.join("auth")).map_err(runtime)?;
    fs::set_permissions(root.join("auth"), fs::Permissions::from_mode(0o700)).map_err(runtime)?;
    create_file(
        &root.join("nix-cache-info"),
        format!("StoreDir: /nix/store\nWantMassQuery: 0\nPriority: {priority}\n").as_bytes(),
        0o600,
    )?;
    create_file(&root.join("trusted-public-keys"), b"", 0o600)?;
    create_file(&root.join("auth/write.tokens"), b"", 0o600)?;
    if options.switch("--private-read") {
        create_file(&root.join("auth/read.tokens"), b"", 0o600)?;
    }
    drop(storage);
    Ok(())
}

fn key(mut args: impl Iterator<Item = String>) -> Result<(), Error> {
    match args.next().as_deref() {
        Some("generate") => generate_key(args),
        Some(command) => Err(Error::usage(format!("unknown key command: {command}"))),
        None => Err(Error::usage("key command is required")),
    }
}

fn generate_key(args: impl Iterator<Item = String>) -> Result<(), Error> {
    let options = Options::parse(
        args,
        &["--name", "--secret-key-file", "--public-key-file"],
        &[],
    )?;
    let name = options.required("--name")?;
    validate_name(name)?;
    let secret_path = PathBuf::from(options.required("--secret-key-file")?);
    let public_path = PathBuf::from(options.required("--public-key-file")?);

    let mut seed = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut seed))
        .map_err(runtime)?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    let mut secret = [0; 64];
    secret[..32].copy_from_slice(&seed);
    secret[32..].copy_from_slice(public.as_bytes());

    create_file(
        &secret_path,
        format!("{name}:{}\n", BASE64.encode(&secret)).as_bytes(),
        0o600,
    )?;
    if let Err(error) = create_file(
        &public_path,
        format!("{name}:{}\n", BASE64.encode(public.as_bytes())).as_bytes(),
        0o644,
    ) {
        let _ = fs::remove_file(&secret_path);
        return Err(error);
    }
    Ok(())
}

fn report(
    args: impl Iterator<Item = String>,
    verify: bool,
    only_orphans: bool,
) -> Result<(), Error> {
    let switches = if verify {
        &["--json"][..]
    } else {
        &["--verify-hashes", "--json"][..]
    };
    let options = Options::parse(args, &["--data-dir"], switches)?;
    let root = PathBuf::from(options.required("--data-dir")?);
    let trusted = TrustedPublicKeys::load(&root.join("trusted-public-keys")).map_err(runtime)?;
    let inventory = Inventory::scan(&root, &trusted, verify || options.switch("--verify-hashes"))
        .map_err(runtime)?;
    let json = options.switch("--json");

    for finding in inventory
        .entries()
        .iter()
        .filter(|finding| !only_orphans || finding.class() == InventoryClass::OrphanNar)
    {
        if json {
            println!(
                "{{\"class\":\"{}\",\"identifier\":\"{}\",\"action\":\"{}\"}}",
                finding.class(),
                json_escape(finding.identifier()),
                finding.class().action()
            );
        } else {
            println!(
                "{}\t{}\t{}",
                finding.class(),
                finding.identifier(),
                finding.class().action()
            );
        }
    }

    if verify
        && inventory
            .entries()
            .iter()
            .any(|finding| finding.class().invalid_published_pair())
    {
        return Err(Error::runtime("verification found invalid published pairs"));
    }
    Ok(())
}

fn delete(args: impl Iterator<Item = String>) -> Result<(), Error> {
    let options = Options::parse(args, &["--data-dir", "--store-hash"], &["--json"])?;
    let root = PathBuf::from(options.required("--data-dir")?);
    let route = options.required("--store-hash")?;
    let store = StoreHash::parse(route).map_err(|_| Error::usage("--store-hash is invalid"))?;
    let storage = Storage::initialize(&root).map_err(runtime)?;
    let trusted = TrustedPublicKeys::load(&root.join("trusted-public-keys")).map_err(runtime)?;
    let file = storage
        .open_narinfo(&store)
        .map_err(runtime)?
        .ok_or_else(|| Error::runtime("narinfo is not published"))?;
    let mut bytes = Vec::new();
    file.take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(runtime)?;
    if !narinfo_is_valid(&trusted, &store, bytes) {
        return Err(Error::runtime("narinfo is malformed or untrusted"));
    }
    storage.delete_narinfo(&store).map_err(runtime)?;

    if options.switch("--json") {
        println!(
            "{{\"class\":\"deleted\",\"identifier\":\"{}\",\"action\":\"narinfo removed; NAR retained\"}}",
            json_escape(route)
        );
    } else {
        println!("deleted\t{route}");
    }
    Ok(())
}

fn stats(args: impl Iterator<Item = String>) -> Result<(), Error> {
    let options = Options::parse(args, &["--url", "--netrc-file"], &["--json"])?;
    let url = options.required("--url")?;
    let authority = url
        .strip_prefix("http://")
        .and_then(|url| url.split('/').next())
        .filter(|authority| !authority.is_empty())
        .ok_or_else(|| Error::usage("--url must be an http:// URL"))?;
    let authorization = options
        .value("--netrc-file")
        .map(|path| netrc_authorization(Path::new(path), authority))
        .transpose()?;

    let mut stream = TcpStream::connect(authority).map_err(runtime)?;
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
    )
    .map_err(runtime)?;
    if let Some(authorization) = authorization {
        write!(stream, "Authorization: Basic {authorization}\r\n").map_err(runtime)?;
    }
    write!(stream, "\r\n").map_err(runtime)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(runtime)?;
    let split = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| Error::runtime("stats endpoint returned an invalid HTTP response"))?;
    let headers = String::from_utf8_lossy(&response[..split]);
    if !headers.starts_with("HTTP/1.1 200") {
        return Err(Error::runtime(format!(
            "stats endpoint failed: {}",
            headers.lines().next().unwrap_or("unknown status")
        )));
    }
    let body = String::from_utf8(response[split + 4..].to_vec())
        .map_err(|_| Error::runtime("stats endpoint returned non-UTF-8 metrics"))?;
    if options.switch("--json") {
        println!("{{\"metrics\":\"{}\"}}", json_escape(&body));
    } else {
        print!("{body}");
    }
    Ok(())
}

fn netrc_authorization(path: &Path, authority: &str) -> Result<String, Error> {
    let text = fs::read_to_string(path).map_err(runtime)?;
    netrc_authorization_from_str(&text, authority)
}

fn netrc_authorization_from_str(text: &str, authority: &str) -> Result<String, Error> {
    let host = match authority
        .strip_prefix('[')
        .and_then(|authority| authority.split_once(']'))
    {
        Some((host, _)) => host,
        None => authority
            .split_once(':')
            .map_or(authority, |(host, _)| host),
    };
    let words: Vec<_> = text.split_whitespace().collect();
    let machine = words
        .windows(2)
        .position(|pair| pair == ["machine", host])
        .ok_or_else(|| Error::runtime("netrc has no matching machine"))?;
    let remaining = &words[machine + 2..];
    let entry_end = remaining
        .iter()
        .position(|word| *word == "machine")
        .unwrap_or(remaining.len());
    let fields = &remaining[..entry_end];
    let login = fields
        .windows(2)
        .find(|pair| pair[0] == "login")
        .map(|pair| pair[1])
        .ok_or_else(|| Error::runtime("netrc entry has no login"))?;
    let password = fields
        .windows(2)
        .find(|pair| pair[0] == "password")
        .map(|pair| pair[1])
        .ok_or_else(|| Error::runtime("netrc entry has no password"))?;
    Ok(BASE64.encode(format!("{login}:{password}").as_bytes()))
}

fn create_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(runtime)?;
    file.write_all(bytes).map_err(runtime)?;
    file.sync_all().map_err(runtime)
}

fn validate_name(name: &str) -> Result<(), Error> {
    if !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(Error::usage("--name is invalid"))
    }
}

fn runtime(error: impl std::fmt::Display) -> Error {
    Error::runtime(error.to_string())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[derive(Default)]
struct Options {
    values: BTreeMap<String, String>,
    switches: BTreeSet<String>,
}

impl Options {
    fn parse(
        mut args: impl Iterator<Item = String>,
        valued: &[&str],
        switches: &[&str],
    ) -> Result<Self, Error> {
        let mut options = Self::default();
        while let Some(option) = args.next() {
            if valued.contains(&option.as_str()) {
                let value = args
                    .next()
                    .ok_or_else(|| Error::usage(format!("{option} requires a value")))?;
                if options.values.insert(option.clone(), value).is_some() {
                    return Err(Error::usage(format!("{option} may only be specified once")));
                }
            } else if switches.contains(&option.as_str()) {
                if !options.switches.insert(option.clone()) {
                    return Err(Error::usage(format!("{option} may only be specified once")));
                }
            } else {
                return Err(Error::usage(format!("unexpected argument: {option}")));
            }
        }
        Ok(options)
    }

    fn required(&self, name: &str) -> Result<&str, Error> {
        self.value(name)
            .ok_or_else(|| Error::usage(format!("{name} is required")))
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netrc_entry_does_not_borrow_password_from_next_machine() {
        let error = netrc_authorization_from_str(
            "machine cache.example login cache-user
machine other.example password other-secret
",
            "cache.example:5000",
        )
        .expect_err("the matching machine has no password");

        assert_eq!(error.to_string(), "netrc entry has no password");
    }

    #[test]
    fn netrc_matches_a_bracketed_ipv6_authority() {
        let authorization = netrc_authorization_from_str(
            "machine ::1 login cache-user password cache-secret
",
            "[::1]:5000",
        )
        .expect("IPv6 machine should match");

        assert_eq!(authorization, BASE64.encode(b"cache-user:cache-secret"));
    }
}
