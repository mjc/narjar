use std::{ffi::OsStr, fs::File, io};

use crate::cache::{
    http_server::Request,
    storage::{Directory, open_directory_at, open_regular_at},
    token_file::{Error as TokenFileError, TokenFile},
};
use data_encoding::BASE64;
use sha2::{Digest, Sha256};

const TOKEN_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permission {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadVisibility {
    Public,
    Private,
}

#[derive(Debug, Default)]
struct TokenHashes(TokenFile);

impl TokenHashes {
    fn load(directory: &File, name: &str) -> Result<Option<Self>, TokenFileError> {
        match open_regular_at(directory, OsStr::new(name)) {
            Ok(file) => TokenFile::read(file).map(Self).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn matching_label(&self, actual: &[u8; TOKEN_BYTES]) -> Option<String> {
        self.0.matching_label(actual)
    }
}

#[derive(Debug)]
enum ReadPolicy {
    Public,
    Private(TokenHashes),
}

impl ReadPolicy {
    fn load(directory: &File) -> Result<Self, TokenFileError> {
        Ok(match TokenHashes::load(directory, "read.tokens")? {
            Some(tokens) => Self::Private(tokens),
            None => Self::Public,
        })
    }

    fn is_public(&self) -> bool {
        match self {
            Self::Public => true,
            Self::Private(_) => false,
        }
    }

    fn matching_label(&self, actual: &[u8; TOKEN_BYTES]) -> Option<String> {
        match self {
            Self::Public => None,
            Self::Private(tokens) => tokens.matching_label(actual),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptedAccess {
    Unlabeled,
    Token(String),
}

#[derive(Debug)]
pub struct Authorizer {
    read: ReadPolicy,
    write: TokenHashes,
}

impl Authorizer {
    pub fn load(root: &Directory) -> Result<Self, TokenFileError> {
        let auth = open_directory_at(root.file(), OsStr::new("auth"))?;
        Ok(Self {
            read: ReadPolicy::load(&auth)?,
            write: TokenHashes::load(&auth, "write.tokens")?.unwrap_or_default(),
        })
    }

    pub fn authenticate(
        &self,
        request: &Request,
        permission: Permission,
    ) -> Option<AcceptedAccess> {
        if permission == Permission::Read && self.read.is_public() {
            return Some(AcceptedAccess::Unlabeled);
        }
        let actual = authorization_token_hash(request)?;
        let write_label = self.write.matching_label(&actual);
        let read_label = self.read.matching_label(&actual);
        let label = match permission {
            Permission::Read => write_label.or(read_label),
            Permission::Write => write_label,
        };
        label.map(AcceptedAccess::Token)
    }

    pub fn allows(&self, request: &Request, permission: Permission) -> bool {
        self.authenticate(request, permission).is_some()
    }

    pub(crate) fn read_visibility(&self) -> ReadVisibility {
        match self.read {
            ReadPolicy::Public => ReadVisibility::Public,
            ReadPolicy::Private(_) => ReadVisibility::Private,
        }
    }
}

fn authorization_token_hash(request: &Request) -> Option<[u8; TOKEN_BYTES]> {
    let mut headers = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv("Authorization"));
    let header = headers.next()?;
    let value = header.value.as_str();
    if headers.next().is_some() {
        return None;
    }

    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic")
        || encoded.is_empty()
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    let decoded = BASE64.decode(encoded.as_bytes()).ok()?;
    let separator = decoded.iter().position(|&byte| byte == b':')?;
    let token = decoded.get(separator + 1..)?;
    if token.is_empty() {
        return None;
    }
    Some(Sha256::digest(token).into())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    const WRITE_TOKEN: &str =
        "test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45\n";

    fn test_root(test: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("narjar-auth-{test}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn accepted_request_resolves_to_the_matching_token_label() {
        let root = test_root("labels");
        let auth = root.join("auth");
        fs::create_dir_all(&auth).expect("create test auth directory");
        write_private_token_file(
            &auth.join("write.tokens"),
            &format!(
                "{}{}",
                token_record("other-writer", "unused-write-secret"),
                token_record("publisher", "write-secret")
            ),
        );
        write_private_token_file(
            &auth.join("read.tokens"),
            &token_record("reader", "read-secret"),
        );
        let authorizer = Authorizer::load(&Directory::open(&root).expect("open test root"))
            .expect("load token files");

        let write = authenticate(&authorizer, "narjar", "write-secret");
        let read = authenticate(&authorizer, "someone-else", "read-secret");
        let write_used_to_read = authenticate(&authorizer, "narjar", "write-secret");
        let rejected = authenticate(&authorizer, "publisher", "wrong-secret");
        fs::remove_dir_all(root).expect("remove test data directory");

        assert_eq!(
            write,
            (
                Some(AcceptedAccess::Token("publisher".to_owned())),
                Some(AcceptedAccess::Token("publisher".to_owned()))
            )
        );
        assert_eq!(
            read,
            (Some(AcceptedAccess::Token("reader".to_owned())), None)
        );
        assert_eq!(
            write_used_to_read.0,
            Some(AcceptedAccess::Token("publisher".to_owned()))
        );
        assert_eq!(rejected, (None, None));
    }

    #[test]
    fn public_read_has_no_token_label() {
        let root = test_root("public");
        let auth = root.join("auth");
        fs::create_dir_all(&auth).expect("create test auth directory");
        write_private_token_file(
            &auth.join("write.tokens"),
            &token_record("publisher", "write-secret"),
        );
        let authorizer = Authorizer::load(&Directory::open(&root).expect("open test root"))
            .expect("load token files");

        let unlabeled = authenticate(&authorizer, "publisher", "not-the-secret");
        let named_write = authenticate(&authorizer, "other-login", "write-secret");
        fs::remove_dir_all(root).expect("remove test data directory");

        assert_eq!(unlabeled.0, Some(AcceptedAccess::Unlabeled));
        assert_eq!(unlabeled.1, None);
        assert_eq!(
            named_write,
            (
                Some(AcceptedAccess::Unlabeled),
                Some(AcceptedAccess::Token("publisher".to_owned()))
            )
        );
    }

    fn token_record(label: &str, secret: &str) -> String {
        format!(
            "{label} {}\n",
            data_encoding::HEXLOWER.encode(Sha256::digest(secret.as_bytes()).as_slice())
        )
    }

    fn write_private_token_file(path: &std::path::Path, contents: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create private token file")
            .write_all(contents.as_bytes())
            .expect("write private token file");
    }

    fn authenticate(
        authorizer: &Authorizer,
        login: &str,
        secret: &str,
    ) -> (Option<AcceptedAccess>, Option<AcceptedAccess>) {
        let encoded = BASE64.encode(format!("{login}:{secret}").as_bytes());
        let request = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");
        let mut access = None;
        with_request(request.as_bytes(), |request| {
            access = Some((
                authorizer.authenticate(&request, Permission::Read),
                authorizer.authenticate(&request, Permission::Write),
            ));
        });
        access.expect("request should be parsed")
    }

    fn with_request(input: &[u8], inspect: impl FnOnce(Request)) {
        use std::{io::Write, net::TcpListener, thread};
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let input = input.to_vec();
        let writer = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream.write_all(&input).expect("write test request");
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let request = Request::read(stream).expect("parse test request");
        inspect(request);
        writer.join().expect("test writer");
    }

    #[test]
    fn rejects_group_or_world_readable_token_files() {
        let root = test_root("permissions");
        let auth = root.join("auth");
        fs::create_dir_all(&auth).expect("create test auth directory");
        let path = auth.join("write.tokens");
        fs::write(&path, WRITE_TOKEN).expect("write test token file");
        crate::cache::test_support::make_public_file(&path).expect("set insecure test permissions");

        let result = Authorizer::load(&Directory::open(&root).expect("open test root"));
        fs::remove_dir_all(root).expect("remove test data directory");

        assert!(result.is_err(), "insecure token file should be rejected");
    }
}
