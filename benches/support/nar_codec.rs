//! Identical, checked workloads for separate timing and allocation binaries.

#[path = "../../tests/support/nar_fixture.rs"]
mod nar_fixture;

#[cfg(unix)]
#[path = "../../src/native_store/directory_entry.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "shared unit tests are not run by this harness-free benchmark"
)]
mod native_names;

use nar_fixture::Node;
use narjar::nar::{Decoder, Event};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, hint::black_box, io};

fn decode(bytes: &[u8]) -> narjar::nar::DecodeSummary {
    Decoder::new(bytes)
        .decode(&mut |event: Event<'_>| {
            black_box(event);
            Ok::<(), Infallible>(())
        })
        .expect("valid fixture")
}

pub fn run(mut report: impl FnMut(&str, &str, usize, &mut dyn FnMut())) {
    let cases = [
        ("empty", Node::File(0)),
        (
            "tiny-4096",
            Node::directory(4096, |index| Node::File(index % 32)),
        ),
        (
            "links-4096",
            Node::directory(4096, |index| {
                Node::Symlink(format!("../lib/package-{index:06}.so").into_bytes())
            }),
        ),
        (
            "medium-128",
            Node::directory(128, |_| Node::File(64 * 1024 + 3)),
        ),
        ("large-32MiB", Node::File(32 * 1024 * 1024 + 17)),
        (
            "nested",
            Node::directory(32, |_| Node::directory(32, |_| Node::File(31))),
        ),
        (
            "oversized-nested",
            (0..12).fold(Node::File(0), |child, _| {
                Node::Directory(vec![
                    (vec![b'a'; 65_536], Node::File(0)),
                    (vec![b'b'; 65_536], Node::File(0)),
                    (b"z".to_vec(), child),
                ])
            }),
        ),
    ];
    for (name, node) in cases {
        let (bytes, expected) = node.encode(Vec::new());
        let decoded = decode(&bytes);
        assert_eq!(
            expected.raw_sha256,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert_eq!(decoded.raw_sha256, expected.raw_sha256);
        assert_eq!(decoded.raw_size, expected.raw_size);
        assert_eq!(
            (decoded.entries, decoded.files, decoded.symlinks),
            (expected.entries, expected.files, expected.symlinks)
        );
        report(name, "decode", bytes.len(), &mut || {
            black_box(decode(black_box(&bytes)));
        });
        report(name, "encode", bytes.len(), &mut || {
            black_box(node.encode(io::sink()));
        });
    }
    #[cfg(unix)]
    benchmark_native_names(&mut report);
}

#[cfg(unix)]
fn benchmark_native_names(report: &mut impl FnMut(&str, &str, usize, &mut dyn FnMut())) {
    use std::{ffi::OsString, os::unix::ffi::OsStrExt};
    let names: Vec<_> = (0..4096)
        .map(|index| OsString::from(format!("package-{:06}-payload", index * 1543 % 4096)))
        .collect();
    let mut expected: Vec<_> = names.iter().map(|name| name.as_bytes()).collect();
    expected.sort_unstable();
    let mut checked: Vec<_> = names
        .iter()
        .cloned()
        .map(native_names::NativeDirectoryEntry::new)
        .collect();
    checked.sort_unstable_by(|left, right| {
        left.nar_name().as_bytes().cmp(right.nar_name().as_bytes())
    });
    assert_eq!(
        checked
            .iter()
            .map(|entry| entry.nar_name().as_bytes())
            .collect::<Vec<_>>(),
        expected
    );
    let bytes = names.iter().map(|name| name.len()).sum();
    report("native-4096", "project", bytes, &mut || {
        for name in &names {
            black_box(native_names::nar_entry_name_for_filesystem_name(black_box(
                name,
            )));
        }
    });
    report("native-4096", "collect-sort", bytes, &mut || {
        let mut entries: Vec<_> = names
            .iter()
            .cloned()
            .map(native_names::NativeDirectoryEntry::new)
            .collect();
        entries.sort_unstable_by(|left, right| {
            left.nar_name().as_bytes().cmp(right.nar_name().as_bytes())
        });
        black_box(entries);
    });
}
