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
    inventory::Inventory,
    narinfo::TrustedPublicKeys,
    storage::{NarObjectId, Storage},
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
    Storage::initialize(root).expect("initialize storage")
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

    run("inventory scan (256 NARs)", 20, || {
        let inventory = Inventory::scan(directory.path(), &TrustedPublicKeys::default(), false)
            .expect("scan inventory");
        black_box(inventory.entries());
    });
}

fn main() {
    println!("narjar microbenchmarks (custom std::time harness)");
    bench_request_parse();
    bench_storage();
    bench_startup();
    bench_inventory();
}
