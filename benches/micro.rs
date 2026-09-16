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

fn find_header_end_incrementally(input: &[u8], chunk_size: usize) -> Option<usize> {
    let mut received = 0;
    let mut scanned_until: usize = 0;
    for chunk in input.chunks(chunk_size) {
        received += chunk.len();
        let search_start = scanned_until.saturating_sub(3);
        if let Some(offset) = input[search_start..received]
            .array_windows::<4>()
            .position(|window| window == b"\r\n\r\n")
        {
            return Some(search_start + offset + 4);
        }
        scanned_until = received;
    }
    None
}

fn assert_header_scan_equivalence() {
    for prefix_len in 0..=4096 {
        let mut input = vec![b'x'; prefix_len];
        input.extend_from_slice(b"\r\n\r\n");
        let expected = Some(prefix_len + 4);
        assert_eq!(find_header_end_rescanning(&input, 64), expected);
        assert_eq!(find_header_end_incrementally(&input, 64), expected);
    }

    let without_terminator = vec![b'x'; 4096];
    assert_eq!(find_header_end_rescanning(&without_terminator, 64), None);
    assert_eq!(find_header_end_incrementally(&without_terminator, 64), None);
}

fn bench_header_scanning() {
    const ITERATIONS: usize = 100;
    let mut input = vec![b'x'; 4096];
    input.extend_from_slice(b"\r\n\r\n");

    for (chunk_size, rescan_name, incremental_name) in [
        (1, "header rescan (1 B)", "header incremental (1 B)"),
        (4, "header rescan (4 B)", "header incremental (4 B)"),
        (64, "header rescan (64 B)", "header incremental (64 B)"),
        (1024, "header rescan (1 KiB)", "header incremental (1 KiB)"),
    ] {
        run(rescan_name, ITERATIONS, || {
            black_box(find_header_end_rescanning(&input, chunk_size));
        });
        run(incremental_name, ITERATIONS, || {
            black_box(find_header_end_incrementally(&input, chunk_size));
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
