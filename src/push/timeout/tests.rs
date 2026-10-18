use std::{
    collections::VecDeque,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Instant,
};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use ureq::{
    http::{StatusCode, Uri},
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::LazyBuffers,
    },
};

use super::*;

const IDLE: Duration = Duration::from_secs(1);
const NO_DEADLINE: NextTimeout = NextTimeout {
    after: TransportDuration::NotHappening,
    reason: Timeout::Global,
};

#[derive(Debug, PartialEq)]
enum IoCall {
    Send(Vec<u8>, NextTimeout),
    Receive(NextTimeout),
}

#[derive(Debug)]
struct RecordedTransport {
    buffers: LazyBuffers,
    response: &'static [u8],
    calls: Arc<Mutex<Vec<IoCall>>>,
    tls: bool,
    open: bool,
    stall_send: bool,
}

impl RecordedTransport {
    fn new(response: &'static [u8], calls: Arc<Mutex<Vec<IoCall>>>) -> Self {
        Self {
            buffers: LazyBuffers::new(1024, 1024),
            response,
            calls,
            tls: true,
            open: false,
            stall_send: false,
        }
    }
}

impl Transport for RecordedTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.calls.lock().unwrap().push(IoCall::Send(
            self.buffers.output()[..amount].to_vec(),
            timeout,
        ));
        if self.stall_send {
            assert!(!timeout.after.is_not_happening());
            return Err(ureq::Error::Timeout(timeout.reason));
        }
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.calls.lock().unwrap().push(IoCall::Receive(timeout));
        if self.response.is_empty() {
            assert!(!timeout.after.is_not_happening());
            return Err(ureq::Error::Timeout(timeout.reason));
        }
        let input = self.buffers.input_append_buf();
        let count = input.len().min(self.response.len()).min(1);
        input[..count].copy_from_slice(&self.response[..count]);
        self.response = &self.response[count..];
        self.buffers.input_appended(count);
        Ok(true)
    }

    fn is_open(&mut self) -> bool {
        self.open
    }

    fn is_tls(&self) -> bool {
        self.tls
    }
}

#[test]
fn connection_deadlines_do_not_limit_transfer_phases() {
    let agent = idle_agent(IDLE);
    let timeouts = agent.config().timeouts();
    assert_eq!(timeouts.resolve, Some(IDLE));
    assert_eq!(timeouts.connect, Some(IDLE));
    assert_eq!(timeouts.global, None);
    assert_eq!(timeouts.per_call, None);
    assert_eq!(timeouts.send_body, None);
    assert_eq!(timeouts.recv_body, None);
}

#[test]
fn every_io_gets_a_fresh_idle_budget_without_relaxing_stricter_deadlines() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut transport = IdleTransport {
        inner: Box::new(RecordedTransport::new(b"abcdef", calls.clone())),
        timeout: IDLE,
    };
    let supplied = [
        NO_DEADLINE,
        NextTimeout {
            after: Duration::from_secs(10).into(),
            reason: Timeout::PerCall,
        },
        NextTimeout {
            after: Duration::from_millis(10).into(),
            reason: Timeout::Global,
        },
        NextTimeout {
            after: Duration::ZERO.into(),
            reason: Timeout::Connect,
        },
        NextTimeout {
            after: IDLE.into(),
            reason: Timeout::Await100,
        },
        NO_DEADLINE,
    ];
    for timeout in supplied {
        transport.buffers().output()[..3].copy_from_slice(b"nar");
        transport.transmit_output(3, timeout).unwrap();
        transport.await_input(timeout).unwrap();
    }
    let calls = calls.lock().unwrap();
    let (pairs, remainder) = calls.as_chunks::<2>();
    assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let (send, receive) = match index {
            0 | 1 | 5 => (
                NextTimeout {
                    after: IDLE.into(),
                    reason: Timeout::SendBody,
                },
                NextTimeout {
                    after: IDLE.into(),
                    reason: Timeout::RecvBody,
                },
            ),
            2..=4 => (supplied[index], supplied[index]),
            _ => unreachable!(),
        };
        assert_eq!(
            pair,
            &[
                IoCall::Send(b"nar".to_vec(), send),
                IoCall::Receive(receive)
            ]
        );
    }
    assert_eq!(transport.buffers().input(), b"abcdef");
}

#[test]
fn transport_keeps_tls_and_pool_liveness_flags() {
    for tls in [false, true] {
        for open in [false, true] {
            let mut inner = RecordedTransport::new(b"", Arc::default());
            inner.tls = tls;
            inner.open = open;
            let mut transport = IdleTransport {
                inner: Box::new(inner),
                timeout: IDLE,
            };
            assert_eq!(transport.is_tls(), tls);
            assert_eq!(transport.is_open(), open);
        }
    }
}

#[test]
fn stalled_writes_and_reads_propagate_timeout_errors() {
    let mut inner = RecordedTransport::new(b"", Arc::default());
    inner.stall_send = true;
    let mut transport = IdleTransport {
        inner: Box::new(inner),
        timeout: IDLE,
    };
    assert!(matches!(
        transport.transmit_output(0, NO_DEADLINE),
        Err(ureq::Error::Timeout(Timeout::SendBody))
    ));
    assert!(matches!(
        transport.await_input(NO_DEADLINE),
        Err(ureq::Error::Timeout(Timeout::RecvBody))
    ));
}

#[derive(Debug)]
struct ScriptedConnector {
    responses: Arc<Mutex<VecDeque<&'static [u8]>>>,
    calls: Arc<Mutex<Vec<IoCall>>>,
}

impl Connector for ScriptedConnector {
    type Out = Box<dyn Transport>;

    fn connect(
        &self,
        details: &ConnectionDetails<'_>,
        _: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        assert_eq!(details.timeout.reason, Timeout::Connect);
        assert!(details.timeout.after <= IDLE.into());
        assert_eq!(details.config.timeouts().resolve, Some(IDLE));
        let response = self.responses.lock().unwrap().pop_front().unwrap();
        Ok(Some(Box::new(RecordedTransport::new(
            response,
            self.calls.clone(),
        ))))
    }
}

#[derive(Debug)]
struct FixedResolver;

impl Resolver for FixedResolver {
    fn resolve(
        &self,
        _: &Uri,
        _: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        assert_eq!(timeout.reason, Timeout::Resolve);
        assert!(timeout.after <= IDLE.into());
        let mut addresses = self.empty();
        addresses.push("127.0.0.1:1".parse().unwrap());
        Ok(addresses)
    }
}

pub(crate) fn assert_redirect_retry_and_new_connections_keep_idle_timeouts(
    put: impl FnOnce(&Agent) -> StatusCode,
) {
    let responses = Arc::new(Mutex::new(VecDeque::from([
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
    ])));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let agent = Agent::with_parts(
        connection_config(IDLE),
        ScriptedConnector {
            responses: responses.clone(),
            calls: calls.clone(),
        }
        .chain(IdleConnector { timeout: IDLE }),
        FixedResolver,
    );
    let status = put(&agent);
    assert_eq!(status, StatusCode::CREATED);
    assert!(responses.lock().unwrap().is_empty());
    let calls = calls.lock().unwrap();
    assert!(calls.iter().any(|call| matches!(call, IoCall::Send(_, _))));
    assert!(calls.iter().any(|call| matches!(call, IoCall::Receive(_))));
    for call in calls.iter() {
        let timeout = match call {
            IoCall::Send(_, timeout) | IoCall::Receive(timeout) => timeout,
        };
        assert_eq!(timeout.after, IDLE.into());
    }
}

fn accept(listener: &TcpListener) -> TcpStream {
    let timeout = Timespec::try_from(Duration::from_secs(30)).unwrap();
    let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
    assert_eq!(poll(&mut descriptors, Some(&timeout)).unwrap(), 1);
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
}

fn read_headers(reader: &mut impl BufRead) {
    for line in reader.lines() {
        if line.unwrap().is_empty() {
            return;
        }
    }
    panic!("request ended before its headers");
}

struct DelayedSource {
    remaining: usize,
}

impl Read for DelayedSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || output.is_empty() {
            return Ok(0);
        }
        // Deliberate source pacing, not synchronization between test threads.
        thread::sleep(IDLE / 2);
        output[0] = b'n';
        self.remaining -= 1;
        Ok(1)
    }
}

#[test]
fn progressing_upload_outlives_the_configured_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/nar", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut reader = BufReader::new(accept(&listener));
        read_headers(&mut reader);
        let mut body = [0; 4];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"nnnn");
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let started = Instant::now();
    let response = idle_agent(IDLE)
        .put(&url)
        .config()
        .proxy(None)
        .build()
        .header("Content-Length", "4")
        .send(ureq::SendBody::from_owned_reader(DelayedSource {
            remaining: 4,
        }));
    server.join().unwrap();
    assert_eq!(response.unwrap().status(), StatusCode::CREATED);
    assert!(started.elapsed() > IDLE);
}

#[test]
fn stalled_response_headers_and_body_time_out_on_loopback() {
    for prefix in [
        b"".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/nar", listener.local_addr().unwrap());
        let (release, wait) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut reader = BufReader::new(accept(&listener));
            read_headers(&mut reader);
            reader.get_mut().write_all(prefix).unwrap();
            // Also bounds a broken implementation that forgets the idle timeout.
            let _ = wait.recv_timeout(Duration::from_secs(30));
        });
        let result = idle_agent(IDLE)
            .get(&url)
            .config()
            .proxy(None)
            .build()
            .call()
            .and_then(|mut response| response.body_mut().read_to_vec());
        let _ = release.send(());
        server.join().unwrap();
        assert!(matches!(result, Err(ureq::Error::Timeout(_))), "{result:?}");
    }
}
