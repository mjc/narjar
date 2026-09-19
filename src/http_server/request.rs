use std::{
    fs::File,
    io::{self, Read},
    net::TcpStream,
    ops::Range,
};

#[cfg(test)]
pub(crate) use super::response::FORCE_PORTABLE_FILE_COPY;
pub(super) use super::response::Response;
#[cfg(test)]
pub(super) use super::response::StatusCode;
use super::response::{copy_file_to_stream, invalid_data};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

#[inline]
fn find_header_delimiter(scanned: &[u8]) -> Option<usize> {
    memchr::memmem::find(scanned, b"\r\n\r\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Head,
    Put,
    Other,
}

#[derive(Clone, Debug)]
struct HeaderRange {
    name: Range<usize>,
    value: Range<usize>,
}

impl HeaderRange {
    fn empty() -> Self {
        Self {
            name: 0..0,
            value: 0..0,
        }
    }

    fn from_httparse(buffer: &[u8], header: &httparse::Header<'_>) -> io::Result<Self> {
        let name = buffer
            .subslice_range(header.name.as_bytes())
            .ok_or_else(|| invalid_data("request header name is outside the request"))?;
        let value = buffer
            .subslice_range(header.value)
            .ok_or_else(|| invalid_data("request header value is outside the request"))?;
        std::str::from_utf8(header.value)
            .map_err(|_| invalid_data("request header is not UTF-8"))?;
        Ok(Self {
            name: name.into(),
            value: value.into(),
        })
    }

    fn name<'a>(&self, buffer: &'a [u8]) -> &'a str {
        let name = buffer
            .get(self.name.clone())
            .expect("validated header range");
        std::str::from_utf8(name).expect("validated header name")
    }

    fn value<'a>(&self, buffer: &'a [u8]) -> &'a str {
        let value = buffer
            .get(self.value.clone())
            .expect("validated header range");
        std::str::from_utf8(value).expect("validated header value")
    }
}

#[derive(Clone, Debug)]
struct HeaderRanges {
    ranges: [HeaderRange; MAX_HEADERS],
    len: usize,
}

impl HeaderRanges {
    fn from_httparse(buffer: &[u8], headers: &[httparse::Header<'_>]) -> io::Result<Self> {
        if headers.len() > MAX_HEADERS {
            return Err(invalid_data("too many request headers"));
        }
        let mut ranges = Self {
            ranges: std::array::from_fn(|_| HeaderRange::empty()),
            len: 0,
        };
        for (range, header) in ranges.ranges.iter_mut().zip(headers) {
            *range = HeaderRange::from_httparse(buffer, header)?;
        }
        ranges.len = headers.len();
        Ok(ranges)
    }

    fn iter(&self) -> impl Iterator<Item = &HeaderRange> {
        self.ranges.iter().take(self.len)
    }
}

#[derive(Clone, Debug)]
struct RequestTargetRange(Range<usize>);

impl RequestTargetRange {
    fn from_subslice(buffer: &[u8], target: &[u8]) -> Option<Self> {
        buffer
            .subslice_range(target)
            .map(|range| Self(range.into()))
    }

    fn as_range(&self) -> Range<usize> {
        self.0.clone()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HeaderField<'a>(&'a str);

impl HeaderField<'_> {
    pub fn equiv(&self, name: &str) -> bool {
        self.0.eq_ignore_ascii_case(name)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HeaderValue<'a>(&'a str);

impl HeaderValue<'_> {
    pub fn as_str(&self) -> &str {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RequestHeader<'a> {
    pub field: HeaderField<'a>,
    pub value: HeaderValue<'a>,
}

pub struct Headers<'a> {
    request: &'a Request,
}

impl<'a> Headers<'a> {
    pub fn iter(self) -> impl Iterator<Item = RequestHeader<'a>> {
        self.request.headers.iter().map(|header| RequestHeader {
            field: HeaderField(header.name(&self.request.buffer)),
            value: HeaderValue(header.value(&self.request.buffer)),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct HeaderBoundary {
    end: usize,
    received: usize,
}

impl HeaderBoundary {
    fn detected(end: usize, received: usize) -> Self {
        Self { end, received }
    }

    fn end(self) -> usize {
        self.end
    }

    fn body_prefix(self) -> Range<usize> {
        self.end..self.received
    }
}

struct BufferedHead {
    stream: TcpStream,
    buffer: [u8; MAX_HEADER_BYTES],
    received: usize,
    boundary: HeaderBoundary,
}

struct ParsedHead {
    method: Method,
    url: RequestTargetRange,
    headers: HeaderRanges,
    body_length: Option<usize>,
    keep_alive: bool,
}

pub struct Request {
    stream: TcpStream,
    buffer: [u8; MAX_HEADER_BYTES],
    body_prefix: Range<usize>,
    method: Method,
    url: RequestTargetRange,
    headers: HeaderRanges,
    body_length: Option<usize>,
    body_state: BodyState,
    keep_alive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyState {
    Unread,
    Reading,
    Complete,
    Failed,
}

impl BufferedHead {
    fn read(mut stream: TcpStream) -> Result<Self, (TcpStream, io::Error)> {
        let mut buffer = [0; MAX_HEADER_BYTES];
        let mut received = 0;
        let mut scanned_until: usize = 0;

        loop {
            let search_start = scanned_until.saturating_sub(3);
            let scanned = buffer
                .get(search_start..received)
                .expect("scanner bounds are within the header buffer");
            if let Some(offset) = find_header_delimiter(scanned) {
                let boundary = HeaderBoundary::detected(search_start + offset + 4, received);
                return Ok(Self {
                    stream,
                    buffer,
                    received,
                    boundary,
                });
            }
            scanned_until = received;
            if received == buffer.len() {
                return Err((stream, invalid_data("request headers exceed 16 KiB")));
            }
            let unread = buffer
                .get_mut(received..)
                .expect("received bytes fit the header buffer");
            let read = match stream.read(unread) {
                Ok(0) if received == 0 => {
                    return Err((stream, io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                Ok(0) => return Err((stream, invalid_data("request ended early"))),
                Ok(read) => read,
                Err(error) => return Err((stream, error)),
            };
            received += read;
        }
    }

    fn bytes(&self) -> &[u8] {
        self.buffer
            .get(..self.received)
            .expect("received bytes fit the header buffer")
    }

    fn into_request(self) -> Result<Request, (TcpStream, io::Error)> {
        let parsed = match ParsedHead::parse(&self) {
            Ok(parsed) => parsed,
            Err(error) => return Err((self.stream, error)),
        };
        Ok(Request {
            stream: self.stream,
            buffer: self.buffer,
            body_prefix: self.boundary.body_prefix(),
            method: parsed.method,
            url: parsed.url,
            headers: parsed.headers,
            body_length: parsed.body_length,
            body_state: match parsed.body_length.unwrap_or(0) {
                0 => BodyState::Complete,
                _ => BodyState::Unread,
            },
            keep_alive: parsed.keep_alive,
        })
    }
}

impl ParsedHead {
    fn parse(buffered: &BufferedHead) -> io::Result<Self> {
        let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut parsed_headers);
        let parsed_end = match parsed.parse(buffered.bytes()) {
            Ok(httparse::Status::Complete(end)) => end,
            Ok(httparse::Status::Partial) => return Err(invalid_data("incomplete HTTP request")),
            Err(_) => return Err(invalid_data("malformed HTTP request")),
        };
        if parsed_end != buffered.boundary.end() {
            return Err(invalid_data("HTTP parser disagrees with header boundary"));
        }

        let (method, target, version) = match (parsed.method, parsed.path, parsed.version) {
            (Some(method), Some(target), Some(version)) => (method, target, version),
            _ => return Err(invalid_data("incomplete HTTP request")),
        };
        let url = RequestTargetRange::from_subslice(buffered.bytes(), target.as_bytes())
            .ok_or_else(|| invalid_data("request target is outside the request"))?;
        let headers = HeaderRanges::from_httparse(buffered.bytes(), parsed.headers)?;
        let body_length = request_content_length(buffered.bytes(), &headers)?;
        let keep_alive = request_keeps_connection_alive(version, buffered.bytes(), &headers);

        Ok(Self {
            method: Method::from_http(method),
            url,
            headers,
            body_length,
            keep_alive,
        })
    }
}

impl Method {
    fn from_http(method: &str) -> Self {
        match method {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "PUT" => Self::Put,
            _ => Self::Other,
        }
    }
}

fn request_content_length(buffer: &[u8], headers: &HeaderRanges) -> io::Result<Option<usize>> {
    headers
        .iter()
        .filter(|header| header.name(buffer).eq_ignore_ascii_case("Content-Length"))
        .try_fold(None, |found, header| {
            let length = header
                .value(buffer)
                .parse()
                .map_err(|_| invalid_data("invalid Content-Length"))?;
            match found {
                Some(_) => Err(invalid_data("duplicate Content-Length")),
                None => Ok(Some(length)),
            }
        })
}

fn request_keeps_connection_alive(version: u8, buffer: &[u8], headers: &HeaderRanges) -> bool {
    version == 1
        && !headers.iter().any(|header| {
            header.name(buffer).eq_ignore_ascii_case("Connection")
                && header
                    .value(buffer)
                    .split(',')
                    .any(|value| value.trim().eq_ignore_ascii_case("close"))
        })
}

impl Request {
    pub fn read(stream: TcpStream) -> Result<Self, (TcpStream, io::Error)> {
        BufferedHead::read(stream)?.into_request()
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn url(&self) -> &str {
        let target = self
            .buffer
            .get(self.url.as_range())
            .expect("validated request target range");
        std::str::from_utf8(target).expect("validated request target")
    }

    pub fn headers(&self) -> Headers<'_> {
        Headers { request: self }
    }

    pub fn body_length(&self) -> Option<usize> {
        self.body_length
    }

    pub fn as_reader(&mut self) -> Result<BodyReader<'_>, BodyReaderError> {
        if self.body_state != BodyState::Unread {
            return Err(BodyReaderError::AlreadyConsumed);
        }
        self.body_state = BodyState::Reading;
        Ok(BodyReader {
            stream: &mut self.stream,
            prefix: self
                .buffer
                .get(self.body_prefix.clone())
                .expect("validated body prefix range"),
            prefix_offset: 0,
            remaining: self.body_length.unwrap_or(0),
            state: &mut self.body_state,
        })
    }

    pub fn body_complete(&self) -> bool {
        self.body_state == BodyState::Complete
    }

    pub fn body_reader_started(&self) -> bool {
        matches!(
            self.body_state,
            BodyState::Reading | BodyState::Complete | BodyState::Failed
        )
    }

    pub fn close_after_response(&mut self) {
        self.keep_alive = false;
    }

    pub fn respond<R: Read>(self, response: Response<R>) -> io::Result<Option<TcpStream>> {
        let head = self.method == Method::Head;
        let mut stream = self.stream;
        response.write_to(&mut stream, head, self.keep_alive)?;
        Ok(self.keep_alive.then_some(stream))
    }

    pub fn respond_file(
        self,
        response: Response<io::Empty>,
        mut file: File,
        offset: u64,
        length: u64,
    ) -> io::Result<Option<TcpStream>> {
        let head = self.method == Method::Head;
        let mut stream = self.stream;
        response.write_headers(&mut stream, self.keep_alive)?;
        if !head {
            copy_file_to_stream(&mut file, &mut stream, offset, length)?;
        }
        Ok(self.keep_alive.then_some(stream))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyReaderError {
    AlreadyConsumed,
}

impl std::fmt::Display for BodyReaderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyConsumed => formatter.write_str("request body was already consumed"),
        }
    }
}

impl std::error::Error for BodyReaderError {}

pub struct BodyReader<'a> {
    stream: &'a mut TcpStream,
    prefix: &'a [u8],
    prefix_offset: usize,
    remaining: usize,
    state: &'a mut BodyState,
}

impl Drop for BodyReader<'_> {
    fn drop(&mut self) {
        if *self.state == BodyState::Reading {
            *self.state = BodyState::Failed;
        }
    }
}

impl Read for BodyReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || output.is_empty() {
            return Ok(0);
        }
        let available = self.prefix.len().saturating_sub(self.prefix_offset);
        if available != 0 {
            let count = available.min(output.len()).min(self.remaining);
            output[..count]
                .copy_from_slice(&self.prefix[self.prefix_offset..self.prefix_offset + count]);
            self.prefix_offset += count;
            self.remaining -= count;
            if self.remaining == 0 {
                *self.state = BodyState::Complete;
            }
            return Ok(count);
        }
        let output_length = output.len().min(self.remaining);
        let count = match self.stream.read(&mut output[..output_length]) {
            Ok(count) => count,
            Err(error) => {
                *self.state = BodyState::Failed;
                return Err(error);
            }
        };
        if count == 0 {
            *self.state = BodyState::Failed;
        }
        self.remaining -= count;
        if self.remaining == 0 {
            *self.state = BodyState::Complete;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::{
        BufferedHead, FORCE_PORTABLE_FILE_COPY, HeaderBoundary, MAX_HEADER_BYTES, Method,
        ParsedHead, Request, Response, StatusCode,
    };

    #[test]
    fn parses_headers_without_allocating_header_storage() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream
                .write_all(b"PUT /nar/example.nar HTTP/1.1\r\nContent-Length: 4\r\nX-Test: yes\r\n\r\nbody")
                .expect("write request");
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let mut request = Request::read(stream).expect("parse request");
        assert_eq!(request.method(), Method::Put);
        assert_eq!(request.url(), "/nar/example.nar");
        assert_eq!(request.body_length(), Some(4));
        assert!(
            request
                .headers()
                .iter()
                .any(|header| header.field.equiv("X-Test"))
        );
        let mut body = Vec::new();
        std::io::Read::read_to_end(
            &mut request.as_reader().expect("body is available"),
            &mut body,
        )
        .expect("read body");
        assert_eq!(body, b"body");
        assert!(matches!(
            request.as_reader(),
            Err(super::BodyReaderError::AlreadyConsumed)
        ));
        sender.join().expect("sender should finish");
    }

    #[test]
    fn dropping_a_partial_body_reader_marks_the_body_failed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream
                .write_all(b"PUT /nar/example.nar HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody")
                .expect("write request");
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let mut request = Request::read(stream).expect("parse request");
        let mut reader = request.as_reader().expect("body is available");
        let mut byte = [0; 1];
        reader.read_exact(&mut byte).expect("read body prefix");
        drop(reader);

        assert_eq!(byte, [b'b']);
        assert!(!request.body_complete());
        assert!(matches!(
            request.as_reader(),
            Err(super::BodyReaderError::AlreadyConsumed)
        ));
        sender.join().expect("sender should finish");
    }

    #[test]
    fn parses_a_request_fragmented_at_every_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            for byte in b"GET /nar/example.nar HTTP/1.1\r\nConnection: close\r\n\r\n" {
                stream
                    .write_all(std::slice::from_ref(byte))
                    .expect("write request byte");
            }
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let request = Request::read(stream).expect("parse fragmented request");

        assert_eq!(request.method(), Method::Get);
        assert_eq!(request.url(), "/nar/example.nar");
        assert!(request.body_complete());
        sender.join().expect("sender should finish");
    }

    #[test]
    fn parser_requires_the_scanner_header_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            std::net::TcpStream::connect(address).expect("connect test listener")
        });
        let (stream, _) = listener.accept().expect("accept test connection");
        let bytes = b"GET /healthz HTTP/1.1\r\n\r\n";
        let mut buffer = [0; MAX_HEADER_BYTES];
        buffer[..bytes.len()].copy_from_slice(bytes);
        let buffered = BufferedHead {
            stream,
            buffer,
            received: bytes.len(),
            boundary: HeaderBoundary::detected(bytes.len() - 1, bytes.len()),
        };

        let error = match ParsedHead::parse(&buffered) {
            Ok(_) => panic!("mismatched boundary should be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        drop(buffered);
        sender.join().expect("sender should finish");
    }

    #[test]
    fn file_response_streams_an_exact_range() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("nar");
        fs::write(&path, b"0123456789").expect("write NAR fixture");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream
                .write_all(b"GET /nar/example.nar HTTP/1.1\r\nConnection: close\r\n\r\n")
                .expect("write request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("read response");
            response
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let request = Request::read(stream).expect("parse request");
        let file = fs::File::open(path).expect("open NAR fixture");
        request
            .respond_file(
                Response::new(StatusCode::PARTIAL_CONTENT, std::io::empty(), 4),
                file,
                2,
                4,
            )
            .expect("write file response");
        let response = sender.join().expect("sender should finish");
        assert_eq!(
            response,
            b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\n2345"
        );
    }

    #[test]
    fn file_response_forces_the_portable_fallback() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("nar");
        fs::write(&path, b"0123456789").expect("write NAR fixture");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let sender = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).expect("connect test listener");
            stream
                .write_all(b"GET /nar/example.nar HTTP/1.1\r\nConnection: close\r\n\r\n")
                .expect("write request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("read response");
            response
        });
        let (stream, _) = listener.accept().expect("accept test request");
        let request = Request::read(stream).expect("parse request");
        FORCE_PORTABLE_FILE_COPY.with(|force| force.set(true));
        request
            .respond_file(
                Response::new(StatusCode::PARTIAL_CONTENT, std::io::empty(), 4),
                fs::File::open(path).expect("open NAR fixture"),
                2,
                4,
            )
            .expect("write file response");
        FORCE_PORTABLE_FILE_COPY.with(|force| force.set(false));
        assert!(
            sender
                .join()
                .expect("sender should finish")
                .ends_with(b"\r\n\r\n2345")
        );
    }
}
