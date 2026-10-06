use std::{
    fmt::Write as FmtWrite,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    net::TcpStream,
};

#[cfg(test)]
thread_local! {
    pub(crate) static FORCE_PORTABLE_FILE_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusCode(u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectionDisposition {
    KeepAlive,
    Close,
}

impl StatusCode {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const PARTIAL_CONTENT: Self = Self(206);
    pub const BAD_REQUEST: Self = Self(400);
    pub const CONFLICT: Self = Self(409);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const LENGTH_REQUIRED: Self = Self(411);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    pub const RANGE_NOT_SATISFIABLE: Self = Self(416);
    pub const EXPECTATION_FAILED: Self = Self(417);
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    pub const INSUFFICIENT_STORAGE: Self = Self(507);

    pub const fn new(code: u16) -> Option<Self> {
        if code >= 100 && code <= 599 {
            Some(Self(code))
        } else {
            None
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    InvalidName,
    InvalidValue,
}

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
    pub fn owned(name: &'static str, value: String) -> Result<Self, HeaderError> {
        validate_header(name, &value)?;
        Ok(Self {
            name,
            value: HeaderValueOwned::Owned(value),
        })
    }
}

pub struct Response<R> {
    status: StatusCode,
    headers: Vec<ResponseHeader>,
    body: R,
    content_length: usize,
}

#[derive(Debug)]
pub struct TransferFailure {
    pub error: io::Error,
    pub body_bytes: u64,
}

impl TransferFailure {
    pub(super) fn before_body(error: io::Error) -> Self {
        Self::after_body(error, 0)
    }

    fn after_body(error: io::Error, body_bytes: u64) -> Self {
        Self { error, body_bytes }
    }

    fn truncated_body(body_bytes: u64) -> Self {
        Self::after_body(
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file ended before the declared response length",
            ),
            body_bytes,
        )
    }
}

#[derive(Debug)]
pub struct CompletedTransfer {
    pub connection: Option<TcpStream>,
    pub body_bytes: u64,
}

impl Response<io::Empty> {
    pub fn empty(status: StatusCode) -> Self {
        Self::new(status, io::empty(), 0)
    }
}

impl Response<Cursor<Vec<u8>>> {
    pub fn from_data(data: Vec<u8>) -> Self {
        let content_length = data.len();
        Self::new(StatusCode::OK, Cursor::new(data), content_length)
    }

    pub fn from_string(data: impl Into<String>) -> Self {
        Self::from_data(data.into().into_bytes())
    }
}

impl<R> Response<R> {
    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn new(status: StatusCode, body: R, content_length: usize) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
            content_length,
        }
    }

    pub fn with_status_code(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn with_header(mut self, header: ResponseHeader) -> Self {
        self.headers.push(header);
        self
    }

    pub(super) fn write_headers(
        &self,
        stream: &mut TcpStream,
        connection: ConnectionDisposition,
    ) -> io::Result<()> {
        let mut headers = String::new();
        write!(
            &mut headers,
            "HTTP/1.1 {} {}\r\n",
            self.status.get(),
            reason(self.status.get())
        )
        .expect("writing response status to String cannot fail");
        for header in &self.headers {
            write!(&mut headers, "{}: ", header.name)
                .expect("writing response header to String cannot fail");
            match &header.value {
                HeaderValueOwned::Static(value) => headers.push_str(value),
                HeaderValueOwned::Owned(value) => headers.push_str(value),
            }
            headers.push_str("\r\n");
        }
        writeln!(&mut headers, "Content-Length: {}\r", self.content_length)
            .expect("writing response length to String cannot fail");
        headers.push_str(match connection {
            ConnectionDisposition::KeepAlive => "Connection: keep-alive\r\n\r\n",
            ConnectionDisposition::Close => "Connection: close\r\n\r\n",
        });
        stream.write_all(headers.as_bytes())
    }

    pub(super) fn write_to(
        mut self,
        stream: &mut TcpStream,
        head: bool,
        connection: ConnectionDisposition,
    ) -> Result<u64, TransferFailure>
    where
        R: Read,
    {
        self.write_headers(stream, connection)
            .map_err(TransferFailure::before_body)?;
        if !head {
            return BodyWriter::copy_from(stream, &mut self.body);
        }
        Ok(0)
    }
}

struct BodyWriter<'a> {
    stream: &'a mut TcpStream,
    body_bytes: u64,
}

impl BodyWriter<'_> {
    fn copy_from(stream: &mut TcpStream, mut source: impl Read) -> Result<u64, TransferFailure> {
        let mut writer = BodyWriter {
            stream,
            body_bytes: 0,
        };
        io::copy(&mut source, &mut writer)
            .map_err(|error| TransferFailure::after_body(error, writer.body_bytes))
    }
}

impl io::Write for BodyWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.stream.write(buffer)?;
        self.body_bytes = self.body_bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) fn copy_file_to_stream(
    file: &mut File,
    stream: &mut TcpStream,
    offset: u64,
    length: u64,
) -> Result<u64, TransferFailure> {
    #[cfg(test)]
    if FORCE_PORTABLE_FILE_COPY.with(std::cell::Cell::get) {
        return copy_file_to_stream_portable(file, stream, offset, length);
    }
    #[cfg(target_os = "linux")]
    {
        copy_file_to_stream_linux(file, stream, offset, length)
    }
    #[cfg(not(target_os = "linux"))]
    copy_file_to_stream_portable(file, stream, offset, length)
}

#[cfg(target_os = "linux")]
fn copy_file_to_stream_linux(
    file: &mut File,
    stream: &mut TcpStream,
    offset: u64,
    length: u64,
) -> Result<u64, TransferFailure> {
    use rustix::io::Errno;

    // The kernel offset is signed even though rustix accepts a u64.
    i64::try_from(offset).map_err(|_| {
        TransferFailure::before_body(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file offset is too large",
        ))
    })?;
    let mut offset = offset;
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(usize::MAX as u64) as usize;
        match rustix::fs::sendfile(&*stream, &*file, Some(&mut offset), count) {
            Ok(0) => {
                return Err(TransferFailure::truncated_body(length - remaining));
            }
            Ok(sent) => remaining -= sent as u64,
            Err(Errno::INTR) => continue,
            Err(Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP) if length == remaining => {
                return copy_file_to_stream_portable(file, stream, offset, remaining);
            }
            Err(error) => {
                return Err(TransferFailure::after_body(
                    error.into(),
                    length - remaining,
                ));
            }
        }
    }
    Ok(length)
}

fn copy_file_to_stream_portable(
    file: &mut File,
    stream: &mut TcpStream,
    offset: u64,
    length: u64,
) -> Result<u64, TransferFailure> {
    file.seek(SeekFrom::Start(offset))
        .map_err(TransferFailure::before_body)?;
    let copied = BodyWriter::copy_from(stream, file.take(length))?;
    if copied == length {
        Ok(copied)
    } else {
        Err(TransferFailure::truncated_body(copied))
    }
}

pub fn static_header(
    name: &'static str,
    value: &'static str,
) -> Result<ResponseHeader, HeaderError> {
    validate_header(name, value)?;
    Ok(ResponseHeader {
        name,
        value: HeaderValueOwned::Static(value),
    })
}

pub fn write_status(stream: &mut TcpStream, status: StatusCode) -> io::Result<()> {
    Response::empty(status)
        .write_to(stream, false, ConnectionDisposition::Close)
        .map(|_| ())
        .map_err(|failure| failure.error)
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
        417 => "Expectation Failed",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown Status",
    }
}

fn validate_header(name: &str, value: &str) -> Result<(), HeaderError> {
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)))
    {
        return Err(HeaderError::InvalidName);
    }
    if value
        .bytes()
        .any(|byte| byte < 0x20 && byte != b'\t' || byte == 0x7f)
    {
        return Err(HeaderError::InvalidValue);
    }
    Ok(())
}

pub(super) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{Response, ResponseHeader, StatusCode, static_header};

    #[test]
    fn status_codes_are_validated_at_construction() {
        assert_eq!(StatusCode::new(99), None);
        assert_eq!(StatusCode::new(600), None);
        assert_eq!(StatusCode::new(599).map(StatusCode::get), Some(599));
    }

    #[test]
    fn response_headers_reject_invalid_wire_data() {
        assert!(static_header("Bad Name", "value").is_err());
        assert!(static_header("X-Test", "value\r\nInjected: yes").is_err());
        assert!(ResponseHeader::owned("X-Test", "value\n".to_owned()).is_err());
    }

    #[test]
    fn response_header_builder_does_not_panic_at_a_fixed_count() {
        let mut response = Response::empty(StatusCode::OK);
        for _ in 0..9 {
            response = response.with_header(static_header("X-Test", "ok").expect("valid header"));
        }
        assert_eq!(response.headers.len(), 9);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_file_copy_rejects_offsets_above_i64_even_for_an_empty_body() {
        let mut file = tempfile::tempfile().expect("create file");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let _receiver =
            std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect receiver");
        let (mut stream, _) = listener.accept().expect("accept connection");

        let failure =
            super::copy_file_to_stream_linux(&mut file, &mut stream, i64::MAX as u64 + 1, 0)
                .expect_err("offset must fit the signed kernel offset");
        assert_eq!(failure.error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(failure.error.to_string(), "file offset is too large");
        assert_eq!(failure.body_bytes, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_file_copy_falls_back_before_bytes_for_an_unsupported_destination() {
        use std::io::{Read, Write};

        let mut file = tempfile::tempfile().expect("create file");
        file.write_all(b"0123456789").expect("write fixture");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let mut receiver =
            std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect receiver");
        let (mut stream, _) = listener.accept().expect("accept connection");
        rustix::fs::fcntl_setfl(&stream, rustix::fs::OFlags::APPEND)
            .expect("set append flag on socket");
        let mut offset = 2;
        assert_eq!(
            rustix::fs::sendfile(&stream, &file, Some(&mut offset), 5),
            Err(rustix::io::Errno::INVAL),
            "append-flagged destination must require the portable path"
        );

        assert_eq!(
            super::copy_file_to_stream_linux(&mut file, &mut stream, 2, 5)
                .expect("portable fallback should send the range"),
            5
        );
        drop(stream);
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).expect("read range");
        assert_eq!(received, b"23456");
    }
}
