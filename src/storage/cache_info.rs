use std::io;

pub(super) const MAX_CACHE_INFO_BYTES: u64 = 1024;

pub(super) fn validate(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() as u64 > MAX_CACHE_INFO_BYTES {
        return Err(invalid("nix-cache-info exceeds configured size limit"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("nix-cache-info is not UTF-8"))?;
    let mut fields = text
        .lines()
        .map(CacheInfoField::parse)
        .collect::<io::Result<Vec<_>>>()?;
    fields.sort_unstable();
    match fields.as_slice() {
        [
            CacheInfoField::StoreDir,
            CacheInfoField::WantMassQuery,
            CacheInfoField::Priority(_),
        ] => Ok(()),
        _ => Err(invalid(
            "nix-cache-info must contain each supported field exactly once",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CacheInfoField {
    StoreDir,
    WantMassQuery,
    Priority(u32),
}

impl CacheInfoField {
    fn parse(line: &str) -> io::Result<Self> {
        match line.split_once(": ") {
            Some(("StoreDir", "/nix/store")) => Ok(Self::StoreDir),
            Some(("WantMassQuery", "0")) => Ok(Self::WantMassQuery),
            Some(("Priority", value)) => value
                .parse()
                .map(Self::Priority)
                .map_err(|_| invalid("invalid nix-cache-info priority")),
            _ => Err(invalid("unsupported or malformed nix-cache-info field")),
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
