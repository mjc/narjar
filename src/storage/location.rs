use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::{Component, Path, PathBuf},
};

use super::{
    EGRESS_RECEIPT_DIRECTORY, INGESTION_RECEIPT_DIRECTORY, NAR_DIRECTORY, TEMPORARY_DIRECTORY,
    open_directory_at,
};

/// A regular-file location inside one of the store directories that may hold
/// published content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StorePath {
    Root(OsString),
    Nar(OsString),
    IngestionReceipt(OsString),
    EgressReceipt(OsString),
}

impl StorePath {
    pub(super) fn relative_path(&self) -> PathBuf {
        let mut path = PathBuf::new();
        if let Some(directory) = self.directory() {
            path.push(directory);
        }
        path.push(self.name());
        path
    }

    pub(super) fn parse(path: &Path) -> io::Result<Self> {
        let mut components = path.components();
        let first = next_normal_component(&mut components)?
            .ok_or_else(|| invalid_location("store path is empty"))?;
        let second = next_normal_component(&mut components)?;
        if components.next().is_some() {
            return Err(invalid_location("store path has too many components"));
        }
        match (first, second) {
            (name, None) => Ok(Self::Root(name)),
            (directory, Some(name)) if directory == OsStr::new(NAR_DIRECTORY) => {
                Ok(Self::Nar(name))
            }
            (directory, Some(name)) if directory == OsStr::new(INGESTION_RECEIPT_DIRECTORY) => {
                Ok(Self::IngestionReceipt(name))
            }
            (directory, Some(name)) if directory == OsStr::new(EGRESS_RECEIPT_DIRECTORY) => {
                Ok(Self::EgressReceipt(name))
            }
            _ => Err(invalid_location("store path is outside published storage")),
        }
    }

    pub(super) fn open_parent(&self, root: &File) -> io::Result<File> {
        match self.directory() {
            None => root.try_clone(),
            Some(directory) => open_directory_at(root, OsStr::new(directory)),
        }
    }

    pub(super) fn name(&self) -> &OsStr {
        match self {
            Self::Root(name)
            | Self::Nar(name)
            | Self::IngestionReceipt(name)
            | Self::EgressReceipt(name) => name,
        }
    }

    fn directory(&self) -> Option<&'static str> {
        match self {
            Self::Root(_) => None,
            Self::Nar(_) => Some(NAR_DIRECTORY),
            Self::IngestionReceipt(_) => Some(INGESTION_RECEIPT_DIRECTORY),
            Self::EgressReceipt(_) => Some(EGRESS_RECEIPT_DIRECTORY),
        }
    }
}

/// A temporary publication file under a store-managed temporary directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TemporaryPath {
    Root(OsString),
    Nar(OsString),
}

impl TemporaryPath {
    pub(super) fn root(name: OsString) -> Self {
        Self::Root(name)
    }

    pub(super) fn nar(name: OsString) -> Self {
        Self::Nar(name)
    }

    pub(super) fn relative_path(&self) -> PathBuf {
        match self {
            Self::Root(name) => PathBuf::from(TEMPORARY_DIRECTORY).join(name),
            Self::Nar(name) => PathBuf::from(NAR_DIRECTORY)
                .join(TEMPORARY_DIRECTORY)
                .join(name),
        }
    }

    pub(super) fn parse(path: &Path) -> io::Result<Self> {
        let mut components = path.components();
        let first = next_normal_component(&mut components)?
            .ok_or_else(|| invalid_location("temporary path is empty"))?;
        let second = next_normal_component(&mut components)?;
        let third = next_normal_component(&mut components)?;
        if components.next().is_some() {
            return Err(invalid_location("temporary path has too many components"));
        }
        let temporary = match (first, second, third) {
            (directory, Some(name), None) if directory == OsStr::new(TEMPORARY_DIRECTORY) => {
                Self::Root(name)
            }
            (directory, Some(temporary_directory), Some(name))
                if directory == OsStr::new(NAR_DIRECTORY)
                    && temporary_directory == OsStr::new(TEMPORARY_DIRECTORY) =>
            {
                Self::Nar(name)
            }
            _ => {
                return Err(invalid_location(
                    "temporary path is outside temporary storage",
                ));
            }
        };
        if !temporary
            .name()
            .to_str()
            .is_some_and(|name| name.ends_with(".part"))
        {
            return Err(invalid_location(
                "temporary path has an invalid temporary name",
            ));
        }
        Ok(temporary)
    }

    pub(super) fn open_parent(&self, root: &File) -> io::Result<File> {
        match self {
            Self::Root(_) => open_directory_at(root, OsStr::new(TEMPORARY_DIRECTORY)),
            Self::Nar(_) => {
                let nar = open_directory_at(root, OsStr::new(NAR_DIRECTORY))?;
                open_directory_at(&nar, OsStr::new(TEMPORARY_DIRECTORY))
            }
        }
    }

    pub(super) fn name(&self) -> &OsStr {
        match self {
            Self::Root(name) | Self::Nar(name) => name,
        }
    }
}

fn next_normal_component(
    components: &mut std::path::Components<'_>,
) -> io::Result<Option<OsString>> {
    match components.next() {
        Some(Component::Normal(component)) => Ok(Some(component.to_owned())),
        Some(_) => Err(invalid_location("store path has a non-normal component")),
        None => Ok(None),
    }
}

fn invalid_location(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::Path};

    use super::StorePath;

    #[test]
    fn store_path_round_trips_only_known_store_directories() {
        let path = StorePath::parse(Path::new("nar/example.nar")).expect("known path");

        assert_eq!(path.relative_path(), Path::new("nar/example.nar"));
        assert!(StorePath::parse(Path::new("../example.nar")).is_err());
        assert!(StorePath::parse(Path::new("unknown/example.nar")).is_err());
        assert_eq!(
            StorePath::parse(Path::new("nix-cache-info")).expect("root path"),
            StorePath::Root(OsString::from("nix-cache-info")),
        );
    }
}
