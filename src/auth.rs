use std::{collections::HashSet, fmt, fs, io, path::Path};

use data_encoding::{BASE64, HEXLOWER};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use tiny_http::Request;

const TOKEN_BYTES: usize = 32;

#[derive(Clone, Copy, Debug)]
pub enum Permission {
    Read,
    Write,
}

#[derive(Debug)]
struct TokenHash([u8; TOKEN_BYTES]);

#[derive(Debug, Default)]
struct TokenHashes(Vec<TokenHash>);

impl TokenHashes {
    fn load(path: &Path) -> Result<Self, AuthError> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };

        let mut labels = HashSet::new();
        let mut tokens = Vec::new();
        for line in contents.lines().filter(|line| !line.is_empty()) {
            let mut fields = line.split_ascii_whitespace();
            let (Some(label), Some(encoded), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(AuthError::InvalidTokenFile);
            };
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || label.is_empty()
                || !labels.insert(label)
            {
                return Err(AuthError::InvalidTokenFile);
            }
            let digest: [u8; TOKEN_BYTES] = HEXLOWER
                .decode(encoded.as_bytes())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(AuthError::InvalidTokenFile)?;
            tokens.push(TokenHash(digest));
        }
        Ok(Self(tokens))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn matches(&self, actual: &[u8; TOKEN_BYTES]) -> Choice {
        self.0.iter().fold(Choice::from(0), |accepted, candidate| {
            accepted | candidate.0.ct_eq(actual)
        })
    }
}

#[derive(Debug)]
pub struct Authorizer {
    read: TokenHashes,
    write: TokenHashes,
}

impl Authorizer {
    pub fn load(root: &Path) -> Result<Self, AuthError> {
        let auth = root.join("auth");
        Ok(Self {
            read: TokenHashes::load(&auth.join("read.tokens"))?,
            write: TokenHashes::load(&auth.join("write.tokens"))?,
        })
    }

    pub fn allows(&self, request: &Request, permission: Permission) -> bool {
        if matches!(permission, Permission::Read) && self.read.is_empty() {
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

#[derive(Debug)]
pub enum AuthError {
    InvalidTokenFile,
    Io(io::Error),
}

impl From<io::Error> for AuthError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenFile => formatter.write_str("invalid token hash file"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTokenFile => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
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
