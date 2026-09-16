use std::{
    fs,
    hint::black_box,
    io::Write,
    net::{TcpListener, TcpStream},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use narjar::{
    http_server::Request,
    inventory::{Inventory, VerificationMode},
    narinfo::TrustedPublicKeys,
    storage::{Directory, NarObjectId, Storage},
};

const OBJECT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

fn report(name: &str, iterations: usize, elapsed: Duration) {
    let ns = elapsed.as_secs_f64() * 1e9 / iterations as f64;
    println!("{name:24} {iterations:>8} iterations {ns:>12.1} ns/op");
}

fn run(name: &str, iterations: usize, mut operation: impl FnMut()) {
    for _ in 0..10 {
        operation();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    report(name, iterations, started.elapsed());
}

fn initialized_storage(root: &Path) -> Storage {
    fs::create_dir_all(root).expect("create storage directory");
    Storage::initialize(&Directory::open(root).expect("open storage directory"))
        .expect("initialize storage")
}

fn bench_request_parse() {
    const ITERATIONS: usize = 1_000;
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind request benchmark");
    let address = listener.local_addr().expect("request benchmark address");
    let writer = thread::spawn(move || {
        for _ in 0..ITERATIONS + 10 {
            let mut stream = TcpStream::connect(address).expect("connect request benchmark");
            stream
                .write_all(b"GET /nar/aaaaaaaa HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("write request benchmark");
        }
    });

    let started = Instant::now();
    for _ in 0..ITERATIONS + 10 {
        let (stream, _) = listener.accept().expect("accept request benchmark");
        let request = Request::read(stream).expect("parse request benchmark");
        black_box(request.url());
    }
    let elapsed = started.elapsed();
    writer.join().expect("request benchmark writer");
    report("http request parse", ITERATIONS, elapsed);
}

fn bench_storage() {
    let directory = tempfile::tempdir().expect("storage benchmark directory");
    let storage = initialized_storage(directory.path());
    let id = NarObjectId::parse(OBJECT_ID).expect("benchmark object id");
    let missing_id = NarObjectId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .expect("missing object id");
    fs::write(
        directory
            .path()
            .join("nar")
            .join(format!("{OBJECT_ID}.nar")),
        [0_u8; 4 * 1024],
    )
    .expect("write benchmark NAR");

    run("open existing NAR", 10_000, || {
        black_box(storage.open_nar(&id).expect("open NAR"));
    });
    run("open missing NAR", 10_000, || {
        black_box(storage.open_nar(&missing_id).expect("open missing NAR"));
    });
}

fn bench_startup() {
    let directory = tempfile::tempdir().expect("startup benchmark directory");
    run("storage initialize", 100, || {
        let root = directory.path().join("cache");
        fs::remove_dir_all(&root).ok();
        black_box(initialized_storage(&root));
    });
}

fn bench_inventory() {
    const FILES: usize = 256;
    let directory = tempfile::tempdir().expect("inventory benchmark directory");
    let storage = initialized_storage(directory.path());
    for index in 0..FILES {
        let mut object_id = [b'a'; 52];
        object_id[0] = NIX32[index / NIX32.len()];
        object_id[1] = NIX32[index % NIX32.len()];
        let name = String::from_utf8(object_id.to_vec()).expect("object name");
        fs::write(directory.path().join("nar").join(format!("{name}.nar")), [])
            .expect("write inventory NAR");
    }
    drop(storage);
    let root = Directory::open(directory.path()).expect("open inventory root");

    run("inventory scan (256 NARs)", 20, || {
        let inventory = Inventory::scan(
            &root,
            &TrustedPublicKeys::default(),
            VerificationMode::Availability,
        )
        .expect("scan inventory");
        black_box(inventory.entries());
    });
}

fn find_header_end_rescanning(input: &[u8], chunk_size: usize) -> Option<usize> {
    let mut received = 0;
    for chunk in input.chunks(chunk_size) {
        received += chunk.len();
        if let Some(offset) = input[..received]
            .array_windows::<4>()
            .position(|window| window == b"\r\n\r\n")
        {
            return Some(offset + 4);
        }
    }
    None
}

fn find_header_end_incrementally_scalar(input: &[u8], chunk_size: usize) -> Option<usize> {
    let mut received = 0;
    let mut scanned_until: usize = 0;
    for chunk in input.chunks(chunk_size) {
        received += chunk.len();
        let search_start = scanned_until.saturating_sub(3);
        if let Some(offset) = find_header_delimiter_scalar(&input[search_start..received]) {
            return Some(search_start + offset + 4);
        }
        scanned_until = received;
    }
    None
}

fn find_header_delimiter_scalar(scanned: &[u8]) -> Option<usize> {
    scanned
        .array_windows::<4>()
        .position(|window| window == b"\r\n\r\n")
}

fn find_header_delimiter(scanned: &[u8]) -> Option<usize> {
    memchr::memmem::find(scanned, b"\r\n\r\n")
}

fn find_header_end_incrementally(input: &[u8], chunk_size: usize) -> Option<usize> {
    let mut received = 0;
    let mut scanned_until: usize = 0;
    for chunk in input.chunks(chunk_size) {
        received += chunk.len();
        let search_start = scanned_until.saturating_sub(3);
        let scanned = &input[search_start..received];
        if let Some(offset) = find_header_delimiter(scanned) {
            return Some(search_start + offset + 4);
        }
        scanned_until = received;
    }
    None
}

fn request_buffer_with_nix_trace_sizes(head_bytes: usize, received_bytes: usize) -> Vec<u8> {
    assert!(head_bytes >= 4);
    assert!(received_bytes >= head_bytes);
    let mut request = vec![b'x'; received_bytes];
    for offset in (16..head_bytes - 4).step_by(32) {
        request[offset..offset + 2].copy_from_slice(b"\r\n");
    }
    request[head_bytes - 4..head_bytes].copy_from_slice(b"\r\n\r\n");
    request
}

fn assert_header_scan_equivalence() {
    for prefix_len in 0..=4096 {
        let mut input = vec![b'x'; prefix_len];
        input.extend_from_slice(b"\r\n\r\n");
        let expected = Some(prefix_len + 4);
        assert_eq!(find_header_end_rescanning(&input, 64), expected);
        assert_eq!(find_header_end_incrementally_scalar(&input, 64), expected);
        assert_eq!(find_header_end_incrementally(&input, 64), expected);
    }

    let without_terminator = vec![b'x'; 4096];
    assert_eq!(find_header_end_rescanning(&without_terminator, 64), None);
    assert_eq!(
        find_header_end_incrementally_scalar(&without_terminator, 64),
        None
    );
    assert_eq!(find_header_end_incrementally(&without_terminator, 64), None);

    let mut repeated_terminator = vec![b'x'; 64];
    repeated_terminator.extend_from_slice(b"\r\n\r\n\r\n\r\n");
    let first_terminator = Some(68);
    assert_eq!(
        find_header_end_rescanning(&repeated_terminator, 64),
        first_terminator
    );
    assert_eq!(
        find_header_end_incrementally_scalar(&repeated_terminator, 64),
        first_terminator
    );
    assert_eq!(
        find_header_end_incrementally(&repeated_terminator, 64),
        first_terminator
    );
}

fn bench_header_scanning() {
    const ITERATIONS: usize = 100_000;
    for (name, head_bytes, received_bytes) in [
        ("Nix GET", 160, 160),
        ("Nix HEAD NAR", 210, 210),
        ("Nix auth GET", 213, 213),
        ("Nix NAR PUT (16 KiB read cap)", 320, 16 * 1024),
    ] {
        let input = request_buffer_with_nix_trace_sizes(head_bytes, received_bytes);
        let expected = Some(head_bytes - 4);
        assert_eq!(find_header_delimiter_scalar(&input), expected);
        assert_eq!(find_header_delimiter(&input), expected);
        run(&format!("header scalar ({name})"), ITERATIONS, || {
            black_box(find_header_delimiter_scalar(&input));
        });
        run(&format!("header memmem ({name})"), ITERATIONS, || {
            black_box(find_header_delimiter(&input));
        });
    }
}

fn main() {
    println!("narjar microbenchmarks (custom std::time harness)");
    assert_header_scan_equivalence();
    bench_header_scanning();
    bench_request_parse();
    bench_storage();
    bench_startup();
    bench_inventory();
}
