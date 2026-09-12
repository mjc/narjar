#![no_main]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;

use libfuzzer_sys::fuzz_target;
use narjar::auth::{Authorizer, Permission};
use narjar::http_server::Request;
use tempfile::tempdir;

fn exercise(input: &[u8]) {
    let directory = tempdir().expect("temporary auth directory");
    let auth = directory.path().join("auth");
    std::fs::create_dir(&auth).expect("auth directory");
    std::fs::write(auth.join("write.tokens"), input).expect("write fuzz token file");
    let Ok(authorizer) = Authorizer::load(directory.path()) else {
        return;
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fuzz listener");
    let address = listener.local_addr().expect("listener address");
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect fuzz listener");
        let _ = stream.write_all(&input);
    });

    if let Ok((stream, _)) = listener.accept()
        && let Ok(request) = Request::read(stream)
    {
        let _ = authorizer.allows(&request, Permission::Read);
        let _ = authorizer.allows(&request, Permission::Write);
    }
    writer.join().expect("fuzz writer");
}

fuzz_target!(|input: &[u8]| {
    exercise(input);
});
