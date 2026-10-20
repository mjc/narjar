use super::ProcessResources;
use std::{fs::File, path::Path};

const MAX_PROCESS_FD_ENTRIES: usize = 16_384;

pub(super) fn sample_process_resources() -> Result<ProcessResources, ()> {
    let status = read_bounded_text("/proc/self/status", 64 * 1024)?;
    let resident_bytes = status_value_kib(&status, "VmRSS:").ok_or(())?;
    let high_water_bytes = status_value_kib(&status, "VmHWM:");
    let threads = status_value(&status, "Threads:");
    let open_file_descriptors = process_open_file_descriptors();
    let (user_cpu_seconds, system_cpu_seconds) = process_cpu_seconds()?;
    Ok(ProcessResources {
        resident_bytes,
        high_water_bytes,
        user_cpu_seconds,
        system_cpu_seconds,
        threads,
        open_file_descriptors,
    })
}

fn read_bounded_text(path: impl AsRef<Path>, limit: u64) -> Result<String, ()> {
    let bytes = crate::cache::records::read_bounded_bytes(File::open(path).map_err(|_| ())?, limit)
        .map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
}

fn status_value_kib(status: &str, name: &str) -> Option<u64> {
    status_value(status, name)?.checked_mul(1024)
}

fn status_value(status: &str, name: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn process_cpu_seconds() -> Result<(f64, f64), ()> {
    let stat = read_bounded_text("/proc/self/stat", 16 * 1024)?;
    let fields = stat
        .rsplit_once(')')
        .ok_or(())?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let user_ticks: u64 = fields.get(11).ok_or(())?.parse().map_err(|_| ())?;
    let system_ticks: u64 = fields.get(12).ok_or(())?.parse().map_err(|_| ())?;
    let ticks_per_second = rustix::param::clock_ticks_per_second();
    if ticks_per_second == 0 {
        return Err(());
    }
    Ok((
        user_ticks as f64 / ticks_per_second as f64,
        system_ticks as f64 / ticks_per_second as f64,
    ))
}

fn process_open_file_descriptors() -> Option<u64> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let observed = entries
        .take(MAX_PROCESS_FD_ENTRIES + 1)
        .try_fold(0_u64, |count, entry| {
            entry.ok()?;
            count.checked_add(1)
        })?;
    (observed <= MAX_PROCESS_FD_ENTRIES as u64).then_some(observed.saturating_sub(1))
}
