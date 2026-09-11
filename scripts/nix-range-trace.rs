#[cfg(test)]
mod tests {
    use super::range_workload;

    #[test]
    fn workload_covers_start_middle_tail_and_last_byte() {
        let ranges = range_workload(10_000_000, 64 * 1024).unwrap();
        let starts: Vec<u64> = ranges.iter().map(|range| range.0).collect();
        assert!(starts.contains(&0));
        assert!(starts.contains(&1));
        assert!(starts.contains(&5_000_000));
        assert!(starts.contains(&9_000_000));
        assert!(starts.contains(&9_999_999));
        assert!(ranges
            .iter()
            .all(|&(start, end)| start <= end && end < 10_000_000));
    }

    #[test]
    fn workload_accepts_one_mib_chunks() {
        let ranges = range_workload(10_000_000, 1_000_001).unwrap();
        assert!(ranges.contains(&(5_000_000, 6_000_000)));
    }

    #[test]
    fn workload_rejects_empty_nar() {
        assert!(range_workload(0, 64 * 1024).is_err());
    }
}

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn range_workload(length: u64, chunk_size: u64) -> Result<Vec<(u64, u64)>, String> {
    if length == 0 {
        return Err("NAR length must be positive".into());
    }
    if chunk_size == 0 {
        return Err("range size must be positive".into());
    }
    let points = [0, 1, length / 10, length / 2, (length * 9) / 10, length - 1];
    let points: BTreeSet<u64> = points.iter().copied().collect();
    Ok(points
        .into_iter()
        .map(|start| (start, std::cmp::min(length - 1, start + chunk_size - 1)))
        .collect())
}

#[derive(Clone, Debug)]
struct Args {
    cache_url: String,
    store_path: String,
    nar_bytes: u64,
    trusted_public_keys: Vec<String>,
    netrc_file: Option<PathBuf>,
    output: PathBuf,
    fractions: Vec<f64>,
    cold_resumes: usize,
    range_sizes: Vec<u64>,
}

#[derive(Clone, Debug)]
struct Origin {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct ResponseRecord {
    method: String,
    path: String,
    request_headers: Vec<(String, String)>,
    status: u16,
    response_headers: Vec<(String, String)>,
    bytes_sent: u64,
    aborted: bool,
    elapsed_ms: f64,
}

struct ProxyState {
    origin: Origin,
    abort_after: u64,
    aborted: AtomicBool,
    stop: AtomicBool,
    log: Mutex<File>,
    records: Mutex<Vec<ResponseRecord>>,
}

#[derive(Debug)]
struct CopyResult {
    returncode: i32,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "Usage: nix-range-trace --cache-url URL --store-path PATH --nar-bytes BYTES \\
         --trusted-public-key KEY [options] --output DIR"
    );
    eprintln!(
        "Options: --netrc-file FILE --fraction N --cold-resumes N --range-size BYTES"
    );
}

fn next_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = env::args().collect();
    let mut cache_url = None;
    let mut store_path = None;
    let mut nar_bytes = None;
    let mut trusted_public_keys = Vec::new();
    let mut netrc_file = None;
    let mut output = None;
    let mut fractions: Vec<f64> = Vec::new();
    let mut cold_resumes = 32;
    let mut range_sizes = Vec::new();

    let mut index = 1;
    while index < raw.len() {
        match raw[index].as_str() {
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            "--cache-url" => cache_url = Some(next_value(&raw, &mut index, "--cache-url")?),
            "--store-path" => store_path = Some(next_value(&raw, &mut index, "--store-path")?),
            "--nar-bytes" => {
                nar_bytes = Some(
                    next_value(&raw, &mut index, "--nar-bytes")?
                        .parse()
                        .map_err(|_| "--nar-bytes must be an integer")?,
                )
            }
            "--trusted-public-key" => {
                trusted_public_keys.push(next_value(&raw, &mut index, "--trusted-public-key")?)
            }
            "--netrc-file" => netrc_file = Some(PathBuf::from(next_value(
                &raw,
                &mut index,
                "--netrc-file",
            )?)),
            "--output" => output = Some(PathBuf::from(next_value(&raw, &mut index, "--output")?)),
            "--fraction" => fractions.push(
                next_value(&raw, &mut index, "--fraction")?
                    .parse()
                    .map_err(|_| "--fraction must be a number")?,
            ),
            "--cold-resumes" => {
                cold_resumes = next_value(&raw, &mut index, "--cold-resumes")?
                    .parse()
                    .map_err(|_| "--cold-resumes must be a non-negative integer")?
            }
            "--range-size" => range_sizes.push(
                next_value(&raw, &mut index, "--range-size")?
                    .parse()
                    .map_err(|_| "--range-size must be an integer")?,
            ),
            option => return Err(format!("unknown option: {option}")),
        }
        index += 1;
    }

    let cache_url = cache_url.ok_or("--cache-url is required")?;
    let store_path = store_path.ok_or("--store-path is required")?;
    let nar_bytes = nar_bytes.ok_or("--nar-bytes is required")?;
    let output = output.ok_or("--output is required")?;
    if trusted_public_keys.is_empty() {
        return Err("--trusted-public-key is required".into());
    }
    if nar_bytes == 0 {
        return Err("--nar-bytes must be positive".into());
    }
    if fractions.is_empty() {
        fractions = vec![0.1, 0.5, 0.9];
    }
    if range_sizes.is_empty() {
        range_sizes = vec![64 * 1024, 1024 * 1024];
    }
    if fractions.iter().any(|fraction| !fraction.is_finite() || *fraction < 0.0) {
        return Err("--fraction values must be finite and non-negative".into());
    }
    if range_sizes.contains(&0) {
        return Err("--range-size values must be positive".into());
    }

    Ok(Args {
        cache_url,
        store_path,
        nar_bytes,
        trusted_public_keys,
        netrc_file,
        output,
        fractions,
        cold_resumes,
        range_sizes,
    })
}

fn parse_origin(url: &str) -> Result<Origin, String> {
    let authority = url
        .strip_prefix("http://")
        .ok_or("--cache-url must use http:// for the standalone tracer")?
        .split(['/', '?'])
        .next()
        .filter(|value| !value.is_empty())
        .ok_or("--cache-url must include a host and port")?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or("--cache-url must include a host and port")?;
    if host.is_empty() {
        return Err("--cache-url must include a host".into());
    }
    let port = port
        .parse()
        .map_err(|_| "--cache-url port must be an integer")?;
    Ok(Origin {
        host: host.to_owned(),
        port,
    })
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_headers(headers: &[(String, String)]) -> String {
    let mut result = String::from("{");
    for (index, (name, value)) in headers.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        result.push_str(&json_string(&name.to_ascii_lowercase()));
        result.push(':');
        result.push_str(&json_string(value));
    }
    result.push('}');
    result
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn log_line(file: &Mutex<File>, line: &str) {
    if let Ok(mut file) = file.lock() {
        let _ = writeln!(file, "{line}");
    }
}

fn log_response(state: &ProxyState, record: ResponseRecord) {
    let json = format!(
        "{{\"kind\":\"response\",\"method\":{},\"path\":{},\"request_headers\":{},\"response_status\":{},\"response_headers\":{},\"bytes_sent\":{},\"aborted\":{},\"elapsed_ms\":{:.3}}}",
        json_string(&record.method),
        json_string(&record.path),
        json_headers(&record.request_headers),
        record.status,
        json_headers(&record.response_headers),
        record.bytes_sent,
        record.aborted,
        record.elapsed_ms,
    );
    log_line(&state.log, &json);
    if let Ok(mut records) = state.records.lock() {
        records.push(record);
    }
}

fn log_error(state: &ProxyState, request: &Request, error: &io::Error, elapsed_ms: f64) {
    let json = format!(
        "{{\"kind\":\"proxy_error\",\"method\":{},\"path\":{},\"error\":{},\"elapsed_ms\":{:.3}}}",
        json_string(&request.method),
        json_string(&request.path),
        json_string(&error.to_string()),
        elapsed_ms,
    );
    log_line(&state.log, &json);
}

fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4096);
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed 1 MiB",
            ));
        }
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_headers(bytes: &[u8]) -> io::Result<(String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "HTTP headers are not UTF-8")
    })?;
    let mut lines = text.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP request"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "HTTP header has no colon")
        })?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok((first.to_owned(), headers))
}

fn parse_request(stream: &mut TcpStream) -> io::Result<Request> {
    let bytes = read_headers(stream)?;
    let end = header_end(&bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "HTTP request has no header terminator")
    })?;
    let (first, headers) = parse_headers(&bytes[..end])?;
    let mut fields = first.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP method missing"))?;
    let path = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP path missing"))?;
    if fields.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP version missing",
        ));
    }
    Ok(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn write_origin_request(stream: &mut TcpStream, request: &Request, origin: &Origin) -> io::Result<()> {
    write!(stream, "{} {} HTTP/1.1\r\nHost: {}:{}\r\n", request.method, request.path, origin.host, origin.port)?;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"Connection: close\r\n\r\n")
}

fn write_client_response(
    client: &mut TcpStream,
    status_line: &str,
    headers: &[(String, String)],
) -> io::Result<()> {
    write!(client, "{status_line}\r\n")?;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("keep-alive") {
            continue;
        }
        write!(client, "{name}: {value}\r\n")?;
    }
    client.write_all(b"Connection: close\r\n\r\n")
}

fn response_status(status_line: &str) -> io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status missing"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP status is invalid"))
}

fn stream_response(
    client: &mut TcpStream,
    origin: &mut TcpStream,
    request: &Request,
    state: &ProxyState,
    status: u16,
    response_headers: Vec<(String, String)>,
    status_line: &str,
) -> io::Result<ResponseRecord> {
    write_client_response(client, status_line, &response_headers)?;
    let started = Instant::now();
    let mut sent = 0_u64;
    let mut aborted = false;
    let head = request.method.eq_ignore_ascii_case("HEAD");
    let content_length = header_value(&response_headers, "content-length")
        .and_then(|value| value.parse::<u64>().ok());
    let mut remaining = content_length;
    let mut buffer = [0_u8; 1024 * 1024];

    while !head && remaining != Some(0) {
        let mut limit = buffer.len();
        if !state.aborted.load(Ordering::Acquire) && request.path.contains("/nar/") {
            let until_abort = state.abort_after.saturating_sub(sent).max(1);
            limit = limit.min(usize::try_from(until_abort).unwrap_or(usize::MAX));
        }
        let count = origin.read(&mut buffer[..limit])?;
        if count == 0 {
            break;
        }
        client.write_all(&buffer[..count])?;
        sent += count as u64;
        if let Some(left) = &mut remaining {
            *left = left.saturating_sub(count as u64);
        }
        if !state.aborted.load(Ordering::Acquire)
            && request.path.contains("/nar/")
            && sent >= state.abort_after
            && state
                .aborted
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            aborted = true;
            break;
        }
    }

    let record = ResponseRecord {
        method: request.method.clone(),
        path: request.path.clone(),
        request_headers: request.headers.clone(),
        status,
        response_headers,
        bytes_sent: sent,
        aborted,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
    };
    if aborted {
        let _ = client.shutdown(Shutdown::Both);
        let _ = origin.shutdown(Shutdown::Both);
    }
    Ok(record)
}

fn handle_client(mut client: TcpStream, state: Arc<ProxyState>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let request = match parse_request(&mut client) {
        Ok(request) => request,
        Err(_) => return,
    };
    let started = Instant::now();
    let result = (|| {
        let mut origin = TcpStream::connect((state.origin.host.as_str(), state.origin.port))?;
        origin.set_read_timeout(Some(Duration::from_secs(30)))?;
        write_origin_request(&mut origin, &request, &state.origin)?;
        let bytes = read_headers(&mut origin)?;
        let end = header_end(&bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "origin response has no terminator")
        })?;
        let (status_line, response_headers) = parse_headers(&bytes[..end])?;
        let status = response_status(&status_line)?;
        stream_response(
            &mut client,
            &mut origin,
            &request,
            &state,
            status,
            response_headers,
            &status_line,
        )
    })();
    match result {
        Ok(record) => {
            let aborted = record.aborted;
            log_response(&state, record);
            if aborted {
                let _ = client.shutdown(Shutdown::Both);
            }
        }
        Err(error) => log_error(&state, &request, &error, started.elapsed().as_secs_f64() * 1000.0),
    }
}

fn run_proxy(listener: TcpListener, state: Arc<ProxyState>) {
    let _ = listener.set_nonblocking(true);
    let mut clients = Vec::new();
    while !state.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((client, _)) => {
                let state = Arc::clone(&state);
                clients.push(thread::spawn(move || handle_client(client, state)));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    for client in clients {
        let _ = client.join();
    }
}

fn run_copy(
    cache_url: &str,
    destination: &Path,
    store_path: &str,
    trusted_public_keys: &[String],
    netrc_file: Option<&Path>,
    command_log: &Mutex<File>,
) -> io::Result<CopyResult> {
    let mut command = vec![
        "nix".to_owned(),
        "--store".to_owned(),
        format!("local?root={}", destination.display()),
        "copy".to_owned(),
        "--refresh".to_owned(),
        "--from".to_owned(),
        cache_url.to_owned(),
        "--option".to_owned(),
        "require-sigs".to_owned(),
        "true".to_owned(),
        "--option".to_owned(),
        "trusted-public-keys".to_owned(),
        trusted_public_keys.join(" "),
    ];
    if let Some(netrc_file) = netrc_file {
        command.extend([
            "--option".to_owned(),
            "netrc-file".to_owned(),
            netrc_file.display().to_string(),
        ]);
    }
    command.push(store_path.to_owned());

    let command_line = command
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    log_line(command_log, &format!("$ {command_line}"));
    let output = Command::new(&command[0]).args(&command[1..]).output()?;
    if !output.stdout.is_empty() {
        log_line(command_log, &String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        log_line(command_log, &String::from_utf8_lossy(&output.stderr));
    }
    let returncode = output.status.code().unwrap_or(-1);
    log_line(command_log, &format!("exit={returncode}"));
    Ok(CopyResult { returncode })
}

fn start_proxy(state: Arc<ProxyState>) -> io::Result<(u16, thread::JoinHandle<()>, TcpListener)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let wake_listener = listener.try_clone()?;
    let thread_state = Arc::clone(&state);
    let thread = thread::spawn(move || run_proxy(listener, thread_state));
    Ok((port, thread, wake_listener))
}

fn stop_proxy(state: &ProxyState, thread: thread::JoinHandle<()>, wake_listener: TcpListener, port: u16) {
    state.stop.store(true, Ordering::Release);
    let _ = TcpStream::connect(("127.0.0.1", port));
    drop(wake_listener);
    let _ = thread.join();
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn number(value: f64) -> String {
    if value == 0.0 {
        "0".into()
    } else {
        value.to_string()
    }
}

fn case_json(
    fraction: f64,
    abort_after: u64,
    interrupted: i32,
    resumed: i32,
    records: &[ResponseRecord],
    trace: &Path,
    commands: &Path,
) -> String {
    let ranges = records
        .iter()
        .filter_map(|record| {
            record
                .request_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("range"))
                .map(|(_, value)| json_string(value))
        })
        .collect::<Vec<_>>();
    format!(
        "{{\n      \"fraction\": {},\n      \"abort_after_bytes\": {},\n      \"interrupted_returncode\": {},\n      \"resumed_returncode\": {},\n      \"request_count\": {},\n      \"range_headers\": [{}],\n      \"trace\": {},\n      \"commands\": {}\n    }}",
        number(fraction),
        abort_after,
        interrupted,
        resumed,
        records.len(),
        ranges.join(", "),
        json_string(&path_string(trace)),
        json_string(&path_string(commands)),
    )
}

fn run_case(args: &Args, fraction: f64, output: &Path) -> Result<String, String> {
    fs::create_dir_all(output).map_err(|error| error.to_string())?;
    let trace_path = output.join("trace.jsonl");
    let command_path = output.join("commands.txt");
    let destination = output.join("store");
    fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
    let origin = parse_origin(&args.cache_url)?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&trace_path)
        .map_err(|error| error.to_string())?;
    let command_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&command_path)
        .map_err(|error| error.to_string())?;
    let state = Arc::new(ProxyState {
        origin,
        abort_after: ((args.nar_bytes as f64 * fraction) as u64).max(1),
        aborted: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        log: Mutex::new(log),
        records: Mutex::new(Vec::new()),
    });
    let (port, proxy_thread, wake_listener) =
        start_proxy(Arc::clone(&state)).map_err(|error| error.to_string())?;
    let proxy_url = format!("http://127.0.0.1:{port}");
    let results: Result<(CopyResult, CopyResult), String> = (|| {
        let interrupted = run_copy(
            &proxy_url,
            &destination,
            &args.store_path,
            &args.trusted_public_keys,
            args.netrc_file.as_deref(),
            &Mutex::new(command_log),
        )
        .map_err(|error| error.to_string())?;
        let resumed = run_copy(
            &proxy_url,
            &destination,
            &args.store_path,
            &args.trusted_public_keys,
            args.netrc_file.as_deref(),
            &Mutex::new(
                OpenOptions::new()
                    .append(true)
                    .open(&command_path)
                    .map_err(|error| error.to_string())?,
            ),
        )
        .map_err(|error| error.to_string())?;
        Ok((interrupted, resumed))
    })();
    stop_proxy(&state, proxy_thread, wake_listener, port);
    let (interrupted, resumed) = results?;
    let records = state
        .records
        .lock()
        .map_err(|_| "trace records lock poisoned".to_owned())?
        .clone();
    Ok(case_json(
        fraction,
        state.abort_after,
        interrupted.returncode,
        resumed.returncode,
        &records,
        &trace_path,
        &command_path,
    ))
}

fn unique_floats(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(|left, right| left.partial_cmp(right).unwrap());
    values.dedup_by(|left, right| left == right);
    values
}

fn unique_u64(mut values: Vec<u64>) -> Vec<u64> {
    values.sort_unstable();
    values.dedup();
    values
}

fn range_workloads_json(length: u64, sizes: &[u64]) -> Result<String, String> {
    let mut result = String::from("{");
    for (index, size) in sizes.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        let ranges = range_workload(length, *size)?;
        let values = ranges
            .iter()
            .map(|(start, end)| format!("{{\"start\":{start},\"end\":{end}}}"))
            .collect::<Vec<_>>();
        result.push_str(&format!("{}:[{}]", json_string(&size.to_string()), values.join(",")));
    }
    result.push('}');
    Ok(result)
}

fn run() -> Result<(), String> {
    let mut args = parse_args()?;
    if args.output.exists() {
        return Err(format!("output already exists: {}", args.output.display()));
    }
    fs::create_dir_all(&args.output).map_err(|error| error.to_string())?;
    args.fractions = unique_floats(args.fractions);
    args.range_sizes = unique_u64(args.range_sizes);

    let mut cold_results = vec![String::new(); args.cold_resumes];
    for batch in (0..args.cold_resumes).collect::<Vec<_>>().chunks(32) {
        let mut workers = Vec::new();
        for &index in batch {
            let args = args.clone();
            let output = args.output.join(format!("cold-resume-{index:02}"));
            let fraction = args.fractions[index % args.fractions.len()];
            workers.push((index, thread::spawn(move || run_case(&args, fraction, &output))));
        }
        for (index, worker) in workers {
            cold_results[index] = worker
                .join()
                .map_err(|_| "cold-resume worker panicked".to_owned())??;
        }
    }

    let mut fraction_results = Vec::new();
    for fraction in &args.fractions {
        fraction_results.push(run_case(
            &args,
            *fraction,
            &args.output.join(format!("interrupt-{}", number(*fraction))),
        )?);
    }
    let cold_json = cold_results.join(",\n    ");
    let fraction_json = fraction_results.join(",\n    ");
    let summary = format!(
        "{{\n  \"cache_url\": {},\n  \"store_path\": {},\n  \"nar_bytes\": {},\n  \"fractions\": [\n    {}\n  ],\n  \"cold_resumes\": [\n    {}\n  ],\n  \"range_workloads\": {}\n}}\n",
        json_string(&args.cache_url),
        json_string(&args.store_path),
        args.nar_bytes,
        fraction_json,
        cold_json,
        range_workloads_json(args.nar_bytes, &args.range_sizes)?,
    );
    fs::write(args.output.join("summary.json"), summary.as_bytes())
        .map_err(|error| error.to_string())?;
    print!("{summary}");
    Ok(())
}
