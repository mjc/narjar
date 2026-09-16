use std::cell::Cell;
use std::io::{self, Read, Write};
use std::rc::Rc;

use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
pub struct BytePosition(Rc<Cell<u64>>);

impl BytePosition {
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.get()
    }
}

pub struct HashingReader<R> {
    inner: R,
    position: BytePosition,
    digest: Sha256,
    bytes: u64,
}

impl<R> HashingReader<R> {
    pub fn new(inner: R) -> (Self, BytePosition) {
        let position = BytePosition::default();
        (
            Self {
                inner,
                position: position.clone(),
                digest: Sha256::new(),
                bytes: 0,
            },
            position,
        )
    }

    pub fn finish(self) -> (R, u64, [u8; 32]) {
        let mut digest = [0; 32];
        digest.copy_from_slice(&self.digest.finalize());
        (self.inner, self.bytes, digest)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.position.0.set(self.position.get() + read as u64);
        self.digest.update(&buffer[..read]);
        self.bytes += read as u64;
        Ok(read)
    }
}

pub struct HashingWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    pub fn finish(self) -> (W, u64, [u8; 32]) {
        let mut digest = [0; 32];
        digest.copy_from_slice(&self.digest.finalize());
        (self.inner, self.bytes, digest)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.digest.update(&buffer[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
