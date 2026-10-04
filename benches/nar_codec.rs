//! Throughput only: compiled without allocation instrumentation.

#[path = "support/nar_codec_options.rs"]
mod options;
#[path = "support/nar_codec.rs"]
mod suite;

use clap::Parser;
use options::Options;
use std::time::Instant;

fn main() {
    let options = Options::parse();
    let mut selected = 0;
    println!("fixture\toperation\tbytes\titerations\tmin_ns\tmedian_ns\tmax_ns\tMiB_per_second");
    suite::run(|name, operation, bytes, run| {
        if !options.selects(name, operation) {
            return;
        }
        selected += 1;
        let iterations = options.iterations.map_or_else(
            || {
                let warmup = Instant::now();
                run();
                (20_000_000 / warmup.elapsed().as_nanos().max(1)).clamp(1, 100_000)
            },
            |iterations| u128::from(iterations.get()),
        );
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
    assert!(selected > 0, "no fixture/operation matched --filter");
}
