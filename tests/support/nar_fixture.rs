//! Deterministic bounded fixtures shared by allocation regressions and benchmarks.

use std::io::Write;

use narjar::nar_encode::{EncodeSummary, Encoder, Event};

pub enum Node {
    Directory(Vec<(Vec<u8>, Node)>),
    File(usize),
    Symlink(Vec<u8>),
}

impl Node {
    pub fn directory(count: usize, child: impl Fn(usize) -> Self) -> Self {
        Self::Directory(
            (0..count)
                .map(|index| {
                    (
                        format!("package-{index:06}-payload").into_bytes(),
                        child(index),
                    )
                })
                .collect(),
        )
    }

    pub fn encode<W: Write>(&self, writer: W) -> (W, EncodeSummary) {
        let mut encoder = Encoder::new(writer).expect("fixture header");
        self.emit(&mut encoder);
        encoder.finish().expect("complete fixture")
    }

    fn emit<W: Write>(&self, encoder: &mut Encoder<W>) {
        match self {
            Self::Directory(entries) => {
                encoder.push(Event::BeginDirectory).expect("directory");
                for (name, child) in entries {
                    encoder.push(Event::Entry(name)).expect("ordered entry");
                    child.emit(encoder);
                }
                encoder.push(Event::EndDirectory).expect("directory end");
            }
            Self::File(size) => {
                static CONTENTS: [u8; 64 * 1024] = [b'x'; 64 * 1024];
                encoder
                    .push(Event::BeginFile {
                        executable: true,
                        size: *size as u64,
                    })
                    .expect("file");
                for offset in (0..*size).step_by(CONTENTS.len()) {
                    encoder
                        .push(Event::FileChunk(
                            &CONTENTS[..(*size - offset).min(CONTENTS.len())],
                        ))
                        .expect("body");
                }
                encoder.push(Event::EndFile).expect("file end");
            }
            Self::Symlink(target) => encoder.push(Event::Symlink(target)).expect("symlink"),
        }
    }
}
