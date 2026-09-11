fn main() {
    let _ = gix::open(".");
    println!("variant=high-level");
    if let Ok(milliseconds) = std::env::var("GIX_PROBE_HOLD_MS") {
        std::thread::sleep(std::time::Duration::from_millis(
            milliseconds.parse().expect("valid hold duration"),
        ));
    }
}
