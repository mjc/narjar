#[path = "support/allocations.rs"]
mod allocations;
#[path = "support/nar_fixture.rs"]
mod nar_fixture;

use nar_fixture::Node;
use narjar::nar::{Decoder, Event};
use std::convert::Infallible;

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

#[test]
fn regular_file_grammar_and_payload_decode_without_heap_allocations() {
    // Neither fixed grammar tokens nor a streamed body need owned metadata.
    // Fixture construction and a sink that retains bytes would obscure that fact.
    let (bytes, expected) = Node::File(64 * 1024 + 17).encode(Vec::new());
    let (actual, measured) = allocations::measure(|| {
        Decoder::new(bytes.as_slice()).decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()))
    });
    let actual = actual.expect("valid regular file");
    assert_eq!(actual.raw_sha256, expected.raw_sha256);
    assert_eq!(actual.raw_size, expected.raw_size);
    assert_eq!(
        measured.calls, 0,
        "grammar tokens must stay on the stack: {measured:?}"
    );
}

#[test]
fn generated_nested_and_symlink_fixtures_preserve_summary_identity() {
    let node = Node::directory(4, |index| {
        Node::directory(4, |_| {
            Node::Symlink(format!("../target-{index}").into_bytes())
        })
    });
    let (bytes, expected) = node.encode(Vec::new());
    let actual = Decoder::new(bytes.as_slice())
        .decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()))
        .expect("nested fixture");
    assert_eq!(actual.raw_sha256, expected.raw_sha256);
    assert_eq!(actual.entries, 20);
    assert_eq!(actual.symlinks, 16);
}

#[test]
fn sibling_names_reuse_two_buffers_instead_of_allocating_per_entry() {
    let (bytes, expected) = Node::directory(4096, |_| Node::File(0)).encode(Vec::new());
    let (actual, measured) = allocations::measure(|| {
        Decoder::new(bytes.as_slice()).decode(&mut |_: Event<'_>| Ok::<(), Infallible>(()))
    });
    assert_eq!(
        actual.expect("ordered siblings").raw_sha256,
        expected.raw_sha256
    );
    assert_eq!(
        measured.calls, 2,
        "only the two directory-name buffers may allocate: {measured:?}"
    );
}
