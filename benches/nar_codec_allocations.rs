//! Allocation counts only: use nar_codec for uninstrumented timings.

#[path = "../tests/support/allocations.rs"]
mod allocations;
#[path = "support/nar_codec.rs"]
mod suite;

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn main() {
    println!("fixture\toperation\tbytes\tallocations\tallocated_bytes\tpeak_heap_bytes");
    suite::run(|name, operation, bytes, run| {
        let (_, counts) = allocations::measure(run);
        println!(
            "{name}\t{operation}\t{bytes}\t{}\t{}\t{}",
            counts.calls, counts.bytes, counts.peak_bytes
        );
    });
}
