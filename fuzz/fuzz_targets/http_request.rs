#![no_main]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;

use libfuzzer_sys::fuzz_target;
use narjar::http_server::Request;

fn exercise(input: &[u8]) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fuzz listener");
    let address = listener.local_addr().expect("listener address");
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect fuzz listener");
        let _ = stream.write_all(&input);
    });

    if let Ok((stream, _)) = listener.accept() {
        let _ = Request::read(stream);
    }
    writer.join().expect("fuzz writer");
}

fuzz_target!(|input: &[u8]| {
    exercise(input);
});
