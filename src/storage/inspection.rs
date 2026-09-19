//! Read-only discovery and payload inspection; inventory reporting belongs to the caller.

use super::compression::{nar_file_matches, nar_file_size_matches};
use super::{StoreHash, entry_is_regular_at, open_regular_at};
use crate::narinfo::ValidatedPayload;
use crate::object::NarFileName;
use std::{ffi::OsStr, fs::File, io};

pub(crate) enum NarinfoName<'a> {
    Invalid(&'a str),
    Candidate(NarinfoCandidate<'a>),
}

pub(crate) struct NarinfoCandidate<'a> {
    name: &'a OsStr,
    store: StoreHash,
}

impl<'a> NarinfoName<'a> {
    pub(crate) fn classify(name: &'a OsStr) -> Option<Self> {
        // Non-UTF-8 and unrelated root entries retain the ignored-entry policy.
        match name
            .to_str()
            .and_then(|text| text.strip_suffix(".narinfo").map(|route| (text, route)))
        {
            None => None,
            Some((text, route)) => match StoreHash::parse(route) {
                Ok(store) => Some(Self::Candidate(NarinfoCandidate { name, store })),
                Err(_) => Some(Self::Invalid(text)),
            },
        }
    }
}

impl NarinfoCandidate<'_> {
    pub(crate) fn store(&self) -> &StoreHash {
        &self.store
    }

    pub(crate) fn open(&self, root: &File) -> io::Result<Option<File>> {
        match entry_is_regular_at(root, self.name)? {
            false => Ok(None),
            true => open_regular_at(root, self.name).map(Some),
        }
    }
}

pub(crate) enum PayloadEntry<'a> {
    Invalid(&'a str),
    Identified(NarFileName),
}

impl<'a> PayloadEntry<'a> {
    pub(crate) fn identify(directory: &File, name: &'a OsStr) -> io::Result<Option<Self>> {
        match name.to_str() {
            None => Ok(None),
            Some(text) => match NarFileName::parse(text) {
                Ok(payload) => match entry_is_regular_at(directory, name)? {
                    true => Ok(Some(Self::Identified(payload))),
                    false => Ok(Some(Self::Invalid(text))),
                },
                Err(_) => Ok(Some(Self::Invalid(text))),
            },
        }
    }
}

pub(crate) struct ReferencedPayload {
    file: File,
    payload: ValidatedPayload,
}

impl ReferencedPayload {
    pub(crate) fn open(directory: &File, payload: ValidatedPayload) -> io::Result<Option<Self>> {
        let name = payload.representation().file_name();
        match open_regular_at(directory, &name.os_string()) {
            Ok(file) => Ok(Some(Self { file, payload })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn has_expected_size(&self) -> io::Result<bool> {
        nar_file_size_matches(
            &self.file,
            self.payload.representation().encoded_size().get(),
        )
    }

    pub(crate) fn verify_content(self) -> io::Result<bool> {
        nar_file_matches(&self.file, self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    #[test]
    fn non_utf8_names_are_ignored_before_filesystem_access() {
        let metadata_name = OsString::from_vec(b"\xff.narinfo".to_vec());
        assert!(NarinfoName::classify(&metadata_name).is_none());
        // A file in place of the directory makes accidental filesystem access fail.
        let directory = tempfile::tempfile().unwrap();
        let payload_name = OsString::from_vec(b"\xff.nar.zst".to_vec());
        assert!(
            PayloadEntry::identify(&directory, &payload_name)
                .unwrap()
                .is_none()
        );
    }
}
