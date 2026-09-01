use std::path::Path;

use data_encoding::BASE64;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use tiny_http::Request;

use crate::token_file::{Error as TokenFileError, TokenFile};

const TOKEN_BYTES: usize = 32;

#[derive(Clone, Copy, Debug)]
pub enum Permission {
    Read,
    Write,
}

#[derive(Debug, Default)]
struct TokenHashes(TokenFile);

impl TokenHashes {
    fn load(path: &Path) -> Result<Option<Self>, TokenFileError> {
        Ok(TokenFile::load(path)?.map(Self))
    }

    fn matches(&self, actual: &[u8; TOKEN_BYTES]) -> Choice {
        self.0
            .hashes()
            .fold(Choice::from(0), |accepted, candidate| {
                accepted | candidate.ct_eq(actual)
            })
    }
}

#[derive(Debug)]
enum ReadPolicy {
    Public,
    Private(TokenHashes),
}

impl ReadPolicy {
    fn load(path: &Path) -> Result<Self, TokenFileError> {
        Ok(match TokenHashes::load(path)? {
            Some(tokens) => Self::Private(tokens),
            None => Self::Public,
        })
    }

    fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    fn matches(&self, actual: &[u8; TOKEN_BYTES]) -> Choice {
        match self {
            Self::Public => Choice::from(0),
            Self::Private(tokens) => tokens.matches(actual),
        }
    }
}

#[derive(Debug)]
pub struct Authorizer {
    read: ReadPolicy,
    write: TokenHashes,
}

impl Authorizer {
    pub fn load(root: &Path) -> Result<Self, TokenFileError> {
        let auth = root.join("auth");
        Ok(Self {
            read: ReadPolicy::load(&auth.join("read.tokens"))?,
            write: TokenHashes::load(&auth.join("write.tokens"))?.unwrap_or_default(),
        })
    }

    pub fn allows(&self, request: &Request, permission: Permission) -> bool {
        if matches!(permission, Permission::Read) && self.read.is_public() {
            return true;
        }
        let Some(actual) = authorization_token_hash(request) else {
            return false;
        };

        let accepted = match permission {
            Permission::Read => self.read.matches(&actual) | self.write.matches(&actual),
            Permission::Write => self.write.matches(&actual),
        };
        bool::from(accepted)
    }
}

fn authorization_token_hash(request: &Request) -> Option<[u8; TOKEN_BYTES]> {
    let mut headers = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv("Authorization"));
    let value = headers.next()?.value.as_str();
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
        os::unix::fs::PermissionsExt,
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
    fn rejects_group_or_world_readable_token_files() {
        let root = test_root("permissions");
        let auth = root.join("auth");
        fs::create_dir_all(&auth).expect("create test auth directory");
        let path = auth.join("write.tokens");
        fs::write(&path, WRITE_TOKEN).expect("write test token file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set insecure test permissions");

        let result = Authorizer::load(&root);
        fs::remove_dir_all(root).expect("remove test data directory");

        assert!(result.is_err(), "insecure token file should be rejected");
    }
}
