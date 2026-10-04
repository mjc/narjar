//! Run with cargo bench --bench nar_codec. Setup and allocation accounting are
//! outside timings; every operation includes Narjar's SHA-256 and limit checks.

#[path = "../tests/support/allocations.rs"]
mod allocations;
#[path = "../tests/support/nar_fixture.rs"]
mod nar_fixture;

use nar_fixture::Node;
use narjar::nar::{Decoder, Event};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, hint::black_box, io, time::Instant};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn decode(bytes: &[u8]) -> narjar::nar::DecodeSummary {
    Decoder::new(bytes)
        .decode(&mut |event: Event<'_>| {
            black_box(event);
            Ok::<(), Infallible>(())
        })
        .expect("valid fixture")
}

fn report(name: &str, operation: &str, bytes: usize, mut run: impl FnMut()) {
    run();
    let (_, allocations) = allocations::measure(&mut run);
    let mut samples = [0_u128; 9];
    for sample in &mut samples {
        let started = Instant::now();
        run();
        *sample = started.elapsed().as_nanos();
    }
    samples.sort_unstable();
    println!(
        "{name}\t{operation}\t{bytes}\t{}\t{}\t{}\t{}\t{}\t{}",
        samples[0],
        samples[4],
        samples[8],
        allocations.calls,
        allocations.bytes,
        allocations.peak_bytes
    );
}

fn main() {
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
    ];
    println!(
        "fixture\toperation\tbytes\tmin_ns\tmedian_ns\tmax_ns\tallocations\tallocated_bytes\tpeak_heap_bytes"
    );
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
        report(name, "decode", bytes.len(), || {
            black_box(decode(black_box(&bytes)));
        });
        report(name, "encode", bytes.len(), || {
            black_box(node.encode(io::sink()));
        });
    }
}
