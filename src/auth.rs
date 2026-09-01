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

#[derive(Debug)]
pub struct Authorizer {
    read: Vec<TokenHash>,
    write: Vec<TokenHash>,
}

impl Authorizer {
    pub fn load(root: &Path) -> Result<Self, AuthError> {
        let auth = root.join("auth");
        Ok(Self {
            read: load_tokens(&auth.join("read.tokens"))?,
            write: load_tokens(&auth.join("write.tokens"))?,
        })
    }

    pub fn allows(&self, request: &Request, permission: Permission) -> bool {
        if matches!(permission, Permission::Read) && self.read.is_empty() {
            return true;
        }
        let Some(actual) = authorization_token_hash(request) else {
            return false;
        };

        match permission {
            Permission::Read => token_matches(self.read.iter().chain(&self.write), &actual),
            Permission::Write => token_matches(self.write.iter(), &actual),
        }
    }
}

fn token_matches<'a>(
    candidates: impl Iterator<Item = &'a TokenHash>,
    actual: &[u8; TOKEN_BYTES],
) -> bool {
    let mut accepted = Choice::from(0);
    for candidate in candidates {
        accepted |= candidate.0.ct_eq(actual);
    }
    bool::from(accepted)
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

fn load_tokens(path: &Path) -> Result<Vec<TokenHash>, AuthError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
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
    Ok(tokens)
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
