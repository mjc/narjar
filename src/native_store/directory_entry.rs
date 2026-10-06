use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
};

pub(crate) struct NativeDirectoryEntry {
    filesystem_name: OsString,
    nar_name_length: usize,
}

impl NativeDirectoryEntry {
    pub(crate) fn new(filesystem_name: OsString) -> Self {
        let nar_name_length = nar_entry_name_for_filesystem_name(&filesystem_name).len();
        Self {
            filesystem_name,
            nar_name_length,
        }
    }

    pub(crate) fn nar_name(&self) -> &OsStr {
        // Construction measures a prefix of this same owned name. Sorting
        // doesn't need to rescan case-hack suffixes or own another allocation.
        OsStr::from_bytes(&self.filesystem_name.as_bytes()[..self.nar_name_length])
    }

    pub(crate) fn filesystem_name(&self) -> &OsStr {
        &self.filesystem_name
    }
}

pub(super) fn nar_entry_name_for_filesystem_name(name: &OsStr) -> &OsStr {
    #[cfg(target_os = "macos")]
    let bytes = darwin_case_hack_decoded_name(name.as_bytes());
    #[cfg(not(target_os = "macos"))]
    let bytes = name.as_bytes();
    OsStr::from_bytes(bytes)
}

#[cfg(any(target_os = "macos", test))]
fn darwin_case_hack_decoded_name(name: &[u8]) -> &[u8] {
    const CASE_HACK_MARKER: &[u8] = b"~nix~case~hack~";
    let marker_start = name
        .windows(CASE_HACK_MARKER.len())
        .position(|window| window == CASE_HACK_MARKER)
        .unwrap_or(name.len());
    // Match Nix's default Darwin dump: the first marker ends the NAR name,
    // even when its suffix is empty, nonnumeric, or contains another marker.
    &name[..marker_start]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn darwin_dump_removes_the_first_case_hack_marker_regardless_of_suffix() {
        for name in [
            b"README~nix~case~hack~1".as_slice(),
            b"README~nix~case~hack~12",
            b"README~nix~case~hack~",
            b"README~nix~case~hack~x",
            b"README~nix~case~hack~1~nix~case~hack~2",
        ] {
            assert_eq!(darwin_case_hack_decoded_name(name), b"README");
        }
        assert_eq!(darwin_case_hack_decoded_name(b"README"), b"README");
    }

    #[test]
    fn cached_projection_survives_moves_and_sorting_without_mutating_filesystem_names() {
        let names = [b"z".as_slice(), b"README~nix~case~hack~12", b"a\xff"];
        let mut entries: Vec<_> = names
            .iter()
            .map(|name| NativeDirectoryEntry::new(OsString::from_vec(name.to_vec())))
            .collect();
        entries.sort_unstable_by(|left, right| {
            left.nar_name().as_bytes().cmp(right.nar_name().as_bytes())
        });
        for entry in entries {
            let original = entry.filesystem_name.as_bytes();
            assert!(
                names.contains(&original),
                "opening paths must retain the complete original name"
            );
            let projected = entry.nar_name().as_bytes();
            assert_eq!(
                projected.as_ptr(),
                original.as_ptr(),
                "projection borrows the same owned allocation"
            );
            #[cfg(target_os = "macos")]
            assert_eq!(projected, darwin_case_hack_decoded_name(original));
            #[cfg(not(target_os = "macos"))]
            assert_eq!(projected, original);
        }
    }
}
