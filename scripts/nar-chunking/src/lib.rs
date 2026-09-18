use std::io::{self, Read};

use mincdc::{Cdc, MinCdc4, MinCdcHash4, ReadChunker};
use sha2::{Digest, Sha256};

const DEFAULT_MIN_CHUNK_SIZE: usize = 4 * 1024;
const DEFAULT_MAX_CHUNK_SIZE: usize = 12 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkParameters {
    min_size: usize,
    max_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkAlgorithm {
    MinCdcHash4,
    MinCdc4,
}

impl ChunkParameters {
    #[must_use]
    pub const fn new(min_size: usize, max_size: usize) -> Self {
        assert!(min_size > 0 && min_size <= max_size);
        Self { min_size, max_size }
    }

    #[must_use]
    pub const fn eight_kibibyte_window() -> Self {
        Self::new(DEFAULT_MIN_CHUNK_SIZE, DEFAULT_MAX_CHUNK_SIZE)
    }

    #[must_use]
    pub const fn min_size(self) -> usize {
        self.min_size
    }

    #[must_use]
    pub const fn max_size(self) -> usize {
        self.max_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDescriptor {
    offset: u64,
    size: u64,
    sha256: [u8; 32],
}

impl ChunkDescriptor {
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkManifest {
    total_size: u64,
    chunks: Vec<ChunkDescriptor>,
}

impl ChunkManifest {
    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    #[must_use]
    pub fn chunks(&self) -> &[ChunkDescriptor] {
        &self.chunks
    }
}

pub fn chunk_reader<R, StoreChunk>(
    reader: R,
    parameters: ChunkParameters,
    algorithm: ChunkAlgorithm,
    store_chunk: StoreChunk,
) -> io::Result<ChunkManifest>
where
    R: Read,
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    match algorithm {
        ChunkAlgorithm::MinCdcHash4 => {
            chunk_reader_with_cdc(reader, parameters, MinCdcHash4::new(), store_chunk)
        }
        #[allow(deprecated)]
        ChunkAlgorithm::MinCdc4 => {
            chunk_reader_with_cdc(reader, parameters, MinCdc4::new(), store_chunk)
        }
    }
}

fn chunk_reader_with_cdc<R, C, StoreChunk>(
    reader: R,
    parameters: ChunkParameters,
    cdc: C,
    mut store_chunk: StoreChunk,
) -> io::Result<ChunkManifest>
where
    R: Read,
    C: Cdc,
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    let mut chunker = ReadChunker::new(reader, parameters.min_size, parameters.max_size, cdc);
    let mut manifest = ChunkManifest {
        total_size: 0,
        chunks: Vec::new(),
    };

    while let Some(chunk) = chunker.next()? {
        record_chunk(&mut manifest, &mut store_chunk, &chunk)?;
    }
    Ok(manifest)
}

fn record_chunk<StoreChunk>(
    manifest: &mut ChunkManifest,
    store_chunk: &mut StoreChunk,
    chunk: &[u8],
) -> io::Result<()>
where
    StoreChunk: FnMut(ChunkDescriptor, &[u8]) -> io::Result<()>,
{
    let descriptor = ChunkDescriptor {
        offset: manifest.total_size,
        size: u64::try_from(chunk.len()).expect("slice length fits in u64"),
        sha256: Sha256::digest(chunk).into(),
    };
    store_chunk(descriptor, chunk)?;
    manifest.total_size += descriptor.size;
    manifest.chunks.push(descriptor);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use super::{ChunkAlgorithm, ChunkManifest, ChunkParameters, chunk_reader};

    struct FixedReadSize<'a> {
        bytes: &'a [u8],
        read_size: usize,
    }

    impl Read for FixedReadSize<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let read_size = self.read_size.min(output.len()).min(self.bytes.len());
            output[..read_size].copy_from_slice(&self.bytes[..read_size]);
            self.bytes = &self.bytes[read_size..];
            Ok(read_size)
        }
    }

    fn chunk_input(input: &[u8], read_size: usize) -> (ChunkManifest, Vec<Vec<u8>>) {
        let mut chunks = Vec::new();
        let manifest = chunk_reader(
            FixedReadSize {
                bytes: input,
                read_size,
            },
            ChunkParameters::eight_kibibyte_window(),
            ChunkAlgorithm::MinCdcHash4,
            |_, chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            },
        )
        .expect("test input should be readable");
        (manifest, chunks)
    }

    fn test_input() -> Vec<u8> {
        (0usize..(256 * 1024))
            .map(|index| index.wrapping_mul(37) as u8)
            .collect()
    }

    #[test]
    fn reconstruction_preserves_the_raw_nar_bytes() {
        let input = test_input();
        let (_, chunks) = chunk_input(&input, 97);
        let reconstructed = chunks.concat();

        assert_eq!(reconstructed, input);
    }

    #[test]
    fn boundaries_are_independent_of_input_read_sizes() {
        let input = test_input();
        let (small_reads, _) = chunk_input(&input, 31);
        let (large_reads, _) = chunk_input(&input, 64 * 1024);

        assert_eq!(small_reads, large_reads);
    }

    #[test]
    fn descriptors_cover_the_input_and_hash_each_chunk() {
        let input = test_input();
        let (manifest, chunks) = chunk_input(&input, 4096);

        assert_eq!(manifest.total_size(), input.len() as u64);
        assert_eq!(manifest.chunks().len(), chunks.len());
        assert_eq!(
            manifest.chunks().first().map(|chunk| chunk.offset()),
            Some(0)
        );
        assert!(
            manifest
                .chunks()
                .iter()
                .all(|chunk| chunk.size() <= 12 * 1024)
        );
        assert!(
            manifest
                .chunks()
                .iter()
                .zip(&chunks)
                .all(|(descriptor, chunk)| descriptor.size() == chunk.len() as u64)
        );
    }

    #[test]
    fn both_min_cdc_implementations_reconstruct_the_input() {
        let input = test_input();

        for algorithm in [ChunkAlgorithm::MinCdcHash4, ChunkAlgorithm::MinCdc4] {
            let mut reconstructed = Vec::new();
            chunk_reader(
                FixedReadSize {
                    bytes: &input,
                    read_size: 4096,
                },
                ChunkParameters::eight_kibibyte_window(),
                algorithm,
                |_, chunk| {
                    reconstructed.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .expect("test input should be readable");

            assert_eq!(reconstructed, input);
        }
    }

    #[test]
    fn mincdc_hash4_cut_points_are_stable_for_the_pinned_parameters() {
        let input: Vec<_> = (0usize..(32 * 1024))
            .map(|index| index.wrapping_mul(37) as u8)
            .collect();
        let mut descriptors = Vec::new();

        chunk_reader(
            input.as_slice(),
            ChunkParameters::eight_kibibyte_window(),
            ChunkAlgorithm::MinCdcHash4,
            |descriptor, _| {
                descriptors.push((descriptor.offset(), descriptor.size()));
                Ok(())
            },
        )
        .expect("test input should be readable");

        assert_eq!(
            descriptors,
            vec![
                (0, 4271),
                (4271, 4096),
                (8367, 4096),
                (12463, 4096),
                (16559, 4096),
                (20655, 4096),
                (24751, 4096),
                (28847, 3921),
            ]
        );
    }
}
