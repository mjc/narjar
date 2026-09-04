use std::{
    io::{self, Cursor, Read, Write},
    net::TcpStream,
    ops::Range,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const RESPONSE_HEADERS: usize = 8;

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
        self.request.header_ranges[..self.request.header_count]
            .iter()
            .map(|header| RequestHeader {
                field: HeaderField(
                    std::str::from_utf8(&self.request.buffer[header.name.clone()])
                        .expect("validated header name"),
                ),
                value: HeaderValue(
                    std::str::from_utf8(&self.request.buffer[header.value.clone()])
                        .expect("validated header value"),
                ),
            })
    }
}

pub struct Request {
    stream: TcpStream,
    buffer: [u8; MAX_HEADER_BYTES],
    header_end: usize,
    body_prefix_len: usize,
    method: Method,
    url: Range<usize>,
    header_ranges: [HeaderRange; MAX_HEADERS],
    header_count: usize,
    body_length: Option<usize>,
    body_complete: bool,
}

impl Request {
    pub fn read(stream: TcpStream) -> Result<Self, (TcpStream, io::Error)> {
        let mut request = Self {
            stream,
            buffer: [0; MAX_HEADER_BYTES],
            header_end: 0,
            body_prefix_len: 0,
            method: Method::Other,
            url: 0..0,
            header_ranges: std::array::from_fn(|_| HeaderRange {
                name: 0..0,
                value: 0..0,
            }),
            header_count: 0,
            body_length: None,
            body_complete: true,
        };

        let mut received = 0;
        let header_end = loop {
            if let Some(end) = request.buffer[..received]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                break end + 4;
            }
            if received == request.buffer.len() {
                return Err((
                    request.stream,
                    invalid_data("request headers exceed 16 KiB"),
                ));
            }
            let read = match request.stream.read(&mut request.buffer[received..]) {
                Ok(read) if read != 0 => read,
                Ok(_) => return Err((request.stream, invalid_data("request ended early"))),
                Err(error) => return Err((request.stream, error)),
            };
            received += read;
        };

        let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut parsed_headers);
        match parsed.parse(&request.buffer[..received]) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => {
                return Err((request.stream, invalid_data("incomplete HTTP request")));
            }
            Err(_) => return Err((request.stream, invalid_data("malformed HTTP request"))),
        }

        let Some(request_line_end) = request.buffer[..header_end - 2]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            return Err((request.stream, invalid_data("missing request line")));
        };
        let line = &request.buffer[..request_line_end];
        let mut fields = line.split(|byte| *byte == b' ' || *byte == b'\t');
        let method = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| invalid_data("missing HTTP method"));
        let target = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| invalid_data("missing request target"));
        let version = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| invalid_data("missing HTTP version"));
        if fields.next().is_some() {
            return Err((request.stream, invalid_data("extra request-line fields")));
        }
        let (method, target, version) = match (method, target, version) {
            (Ok(method), Ok(target), Ok(version)) => (method, target, version),
            _ => return Err((request.stream, invalid_data("malformed request line"))),
        };
        if !version.starts_with(b"HTTP/") {
            return Err((request.stream, invalid_data("malformed HTTP version")));
        }
        let target_start = target.as_ptr() as usize - request.buffer.as_ptr() as usize;
        request.url = target_start..target_start + target.len();
        request.method = match method {
            b"GET" => Method::Get,
            b"HEAD" => Method::Head,
            b"PUT" => Method::Put,
            _ => Method::Other,
        };

        let mut line_start = request_line_end + 2;
        while line_start + 2 <= header_end {
            if &request.buffer[line_start..line_start + 2] == b"\r\n" {
                break;
            }
            let line_end = request.buffer[line_start..header_end - 2]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|offset| line_start + offset)
                .ok_or_else(|| invalid_data("unterminated header"));
            let line_end = match line_end {
                Ok(line_end) => line_end,
                Err(error) => return Err((request.stream, error)),
            };
            let colon = request.buffer[line_start..line_end]
                .iter()
                .position(|byte| *byte == b':')
                .map(|offset| line_start + offset);
            let Some(colon) = colon else {
                return Err((request.stream, invalid_data("header has no colon")));
            };
            if request.header_count == MAX_HEADERS {
                return Err((request.stream, invalid_data("too many request headers")));
            }
            let value_start = request.buffer[colon + 1..line_end]
                .iter()
                .position(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(line_end, |offset| colon + 1 + offset);
            let value_end = request.buffer[value_start..line_end]
                .iter()
                .rposition(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(value_start, |offset| value_start + offset + 1);
            request.header_ranges[request.header_count] = HeaderRange {
                name: line_start..colon,
                value: value_start..value_end,
            };
            if std::str::from_utf8(&request.buffer[line_start..colon]).is_err()
                || std::str::from_utf8(&request.buffer[value_start..value_end]).is_err()
            {
                return Err((request.stream, invalid_data("request header is not UTF-8")));
            }
            request.header_count += 1;
            line_start = line_end + 2;
        }

        let mut content_length = None;
        let mut content_length_error = None;
        for header in request.header_ranges[..request.header_count].iter() {
            let name = std::str::from_utf8(&request.buffer[header.name.clone()])
                .expect("validated header name");
            if name.eq_ignore_ascii_case("Content-Length") {
                if content_length.is_some() {
                    content_length_error = Some("duplicate Content-Length");
                    continue;
                }
                let value = std::str::from_utf8(&request.buffer[header.value.clone()])
                    .expect("validated header value");
                match value.parse::<usize>() {
                    Ok(length) => content_length = Some(length),
                    Err(_) => content_length_error = Some("invalid Content-Length"),
                }
            }
        }
        if let Some(error) = content_length_error {
            return Err((request.stream, invalid_data(error)));
        }
        request.header_end = header_end;
        request.body_prefix_len = received - header_end;
        request.body_length = content_length;
        Ok(request)
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn url(&self) -> &str {
        std::str::from_utf8(&self.buffer[self.url.clone()]).expect("validated request target")
    }

    pub fn headers(&self) -> Headers<'_> {
        Headers { request: self }
    }

    pub fn body_length(&self) -> Option<usize> {
        self.body_length
    }

    pub fn as_reader(&mut self) -> BodyReader<'_> {
        BodyReader {
            stream: &mut self.stream,
            prefix: &self.buffer[self.header_end..self.header_end + self.body_prefix_len],
            prefix_offset: 0,
            remaining: self.body_length.unwrap_or(0),
            complete: &mut self.body_complete,
        }
    }

    pub fn body_complete(&self) -> bool {
        self.body_complete
    }

    pub fn respond<R: Read>(self, response: Response<R>) -> io::Result<()> {
        let head = self.method == Method::Head;
        let mut stream = self.stream;
        response.write_to(&mut stream, head)
    }
}

pub struct BodyReader<'a> {
    stream: &'a mut TcpStream,
    prefix: &'a [u8],
    prefix_offset: usize,
    remaining: usize,
    complete: &'a mut bool,
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
            return Ok(count);
        }
        let output_length = output.len().min(self.remaining);
        let count = self.stream.read(&mut output[..output_length])?;
        if count == 0 {
            *self.complete = false;
        }
        self.remaining -= count;
        Ok(count)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StatusCode(pub u16);

#[derive(Debug)]
pub struct ResponseHeader {
    name: &'static str,
    value: HeaderValueOwned,
}

#[derive(Debug)]
enum HeaderValueOwned {
    Static(&'static str),
    Owned(String),
}

impl ResponseHeader {
    pub fn owned(name: &'static str, value: String) -> Self {
        Self {
            name,
            value: HeaderValueOwned::Owned(value),
        }
    }
}

pub struct Response<R> {
    status: StatusCode,
    headers: [Option<ResponseHeader>; RESPONSE_HEADERS],
    header_count: usize,
    body: R,
    content_length: usize,
}

impl Response<io::Empty> {
    pub fn empty(status: StatusCode) -> Self {
        Self::new(status, io::empty(), 0)
    }
}

impl Response<Cursor<Vec<u8>>> {
    pub fn from_data(data: Vec<u8>) -> Self {
        let content_length = data.len();
        Self::new(status(200), Cursor::new(data), content_length)
    }

    pub fn from_string(data: impl Into<String>) -> Self {
        Self::from_data(data.into().into_bytes())
    }
}

impl<R> Response<R> {
    pub fn new(status: StatusCode, body: R, content_length: usize) -> Self {
        Self {
            status,
            headers: [const { None }; RESPONSE_HEADERS],
            header_count: 0,
            body,
            content_length,
        }
    }

    pub fn with_status_code(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn with_header(mut self, header: ResponseHeader) -> Self {
        assert!(
            self.header_count < RESPONSE_HEADERS,
            "too many response headers"
        );
        self.headers[self.header_count] = Some(header);
        self.header_count += 1;
        self
    }

    fn write_to(mut self, stream: &mut TcpStream, head: bool) -> io::Result<()>
    where
        R: Read,
    {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\n",
            self.status.0,
            reason(self.status.0)
        )?;
        for header in self.headers[..self.header_count].iter().flatten() {
            write!(stream, "{}: ", header.name)?;
            match &header.value {
                HeaderValueOwned::Static(value) => stream.write_all(value.as_bytes())?,
                HeaderValueOwned::Owned(value) => stream.write_all(value.as_bytes())?,
            }
            stream.write_all(b"\r\n")?;
        }
        writeln!(stream, "Content-Length: {}\r", self.content_length)?;
        stream.write_all(b"Connection: close\r\n\r\n")?;
        if !head {
            io::copy(&mut self.body, stream)?;
        }
        Ok(())
    }
}

pub fn static_header(name: &'static str, value: &'static str) -> ResponseHeader {
    ResponseHeader {
        name,
        value: HeaderValueOwned::Static(value),
    }
}

pub fn write_status(stream: &mut TcpStream, status: StatusCode) -> io::Result<()> {
    Response::empty(status).write_to(stream, false)
}

fn status(code: u16) -> StatusCode {
    StatusCode(code)
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        206 => "Partial Content",
        409 => "Conflict",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown Status",
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{io::Write, net::TcpListener, thread};

    use super::{Method, Request};

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
        std::io::Read::read_to_end(&mut request.as_reader(), &mut body).expect("read body");
        assert_eq!(body, b"body");
        sender.join().expect("sender should finish");
    }
}
