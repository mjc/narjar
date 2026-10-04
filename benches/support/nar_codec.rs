//! Identical, checked workloads for separate timing and allocation binaries.

#[path = "../../tests/support/nar_fixture.rs"]
mod nar_fixture;

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
}
