//! Throughput only: compiled without allocation instrumentation.

#[path = "support/nar_codec.rs"]
mod suite;

use std::time::Instant;

fn main() {
    println!("fixture\toperation\tbytes\titerations\tmin_ns\tmedian_ns\tmax_ns\tMiB_per_second");
    suite::run(|name, operation, bytes, run| {
        let warmup = Instant::now();
        run();
        let iterations = (20_000_000 / warmup.elapsed().as_nanos().max(1)).clamp(1, 100_000);
        let mut samples = [0_u128; 9];
        for sample in &mut samples {
            let started = Instant::now();
            for _ in 0..iterations {
                run();
            }
            *sample = started.elapsed().as_nanos() / iterations;
        }
        samples.sort_unstable();
        let throughput = bytes as f64 * 1e9 / samples[4].max(1) as f64 / (1024.0 * 1024.0);
        println!(
            "{name}\t{operation}\t{bytes}\t{iterations}\t{}\t{}\t{}\t{throughput:.1}",
            samples[0], samples[4], samples[8]
        );
    });
}
