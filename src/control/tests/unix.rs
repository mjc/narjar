use super::*;
use rustix::io::Errno;
use std::os::unix::net::UnixStream;

#[test]
#[cfg(target_os = "linux")]
fn online_requests_accept_non_utf8_cache_paths_without_serializing_them() {
    use std::os::unix::ffi::OsStringExt;
    // ZFS can require UTF-8 names; tmpfs lets this exercise the wire boundary.
    let parent = tempfile::tempdir_in("/dev/shm").unwrap();
    let root = parent
        .path()
        .join(std::ffi::OsString::from_vec(b"cache-\xff".to_vec()));
    std::fs::create_dir(&root).unwrap();
    let metrics = Arc::new(Metrics::default());
    let service = ControlService::start_with_collector(
        &root,
        Arc::new(AtomicBool::new(false)),
        metrics,
        |_| Reply::Failed(ControlFailure::Stopping),
    )
    .unwrap();
    let error = collect(&root, options(), RetryPolicy::default())
        .err()
        .unwrap();
    service
        .finish(Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert!(
        error.to_string().contains("shutting down"),
        "valid Unix paths must reach the collector: {error}"
    );
}

#[test]
fn transient_accept_errors_preserve_the_listener_and_admit_the_next_request() {
    let root = tempfile::tempdir().unwrap();
    let bound = socket::BoundSocket::bind(root.path()).unwrap();
    let mut client = socket::connect(root.path()).unwrap();
    protocol::write_frame(&mut client, &options()).unwrap();
    let (sender, receiver) = bounded(1);
    let busy = AtomicBool::new(false);
    let stopping = AtomicBool::new(false);
    let daemon_stopping = AtomicBool::new(false);
    let metrics = Metrics::default();
    let mut errors = [
        Errno::AGAIN,
        Errno::INTR,
        Errno::CONNABORTED,
        Errno::MFILE,
        Errno::NFILE,
        Errno::NOBUFS,
        Errno::NOMEM,
    ]
    .into_iter();
    dispatch_requests(
        bound,
        sender,
        &busy,
        &stopping,
        &daemon_stopping,
        &metrics,
        |listener| {
            assert!(socket::socket_path(root.path()).exists());
            if let Some(error) = errors.next() {
                return Err(error.into());
            }
            let (connection, _) = listener.accept()?;
            stopping.store(true, Ordering::Release);
            Ok(connection)
        },
    )
    .expect("transient accept failures must leave collection usable");
    let mut job = receiver
        .try_recv()
        .expect("the next request must be queued");
    assert_eq!(job.options.target_bytes, Some(0));
    send_recorded_reply(
        &mut job.connection,
        Reply::Failed(ControlFailure::Changed),
        &metrics,
    );
    assert!(matches!(
        protocol::read_frame::<Reply>(&mut client).unwrap(),
        Reply::Failed(ControlFailure::Changed)
    ));
    assert!(!socket::socket_path(root.path()).exists());
}

#[test]
fn shutdown_during_a_transient_accept_error_stops_before_accepting_again() {
    for daemon_shutdown in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let bound = socket::BoundSocket::bind(root.path()).unwrap();
        let (sender, _receiver) = bounded(1);
        let stopping = AtomicBool::new(false);
        let daemon_stopping = AtomicBool::new(false);
        let mut calls = 0;
        dispatch_requests(
            bound,
            sender,
            &AtomicBool::new(false),
            &stopping,
            &daemon_stopping,
            &Metrics::default(),
            |_| {
                calls += 1;
                if daemon_shutdown {
                    &daemon_stopping
                } else {
                    &stopping
                }
                .store(true, Ordering::Release);
                Err(rustix::io::Errno::MFILE.into())
            },
        )
        .expect("shutdown during resource exhaustion must finish normally");
        assert_eq!(calls, 1);
        assert!(!socket::socket_path(root.path()).exists());
    }
}

#[test]
fn a_fatal_accept_error_is_returned_and_removes_the_owned_socket() {
    let root = tempfile::tempdir().unwrap();
    let bound = socket::BoundSocket::bind(root.path()).unwrap();
    let (sender, receiver) = bounded(1);
    let error = dispatch_requests(
        bound,
        sender,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &Metrics::default(),
        |_| Err(rustix::io::Errno::BADF.into()),
    )
    .unwrap_err();
    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::BADF.raw_os_error())
    );
    assert!(receiver.recv().is_err());
    assert!(!socket::socket_path(root.path()).exists());
}

#[test]
fn accepted_nonblocking_streams_become_blocking_before_queueing_and_replying() {
    let (connection, mut client) = UnixStream::pair().unwrap();
    connection.set_nonblocking(true).unwrap();
    protocol::write_frame(&mut client, &options()).unwrap();
    let (sender, receiver) = bounded(1);
    let busy = AtomicBool::new(false);
    queue_collection_request(connection, &sender, &busy, &Metrics::default()).unwrap();
    let mut job = receiver
        .try_recv()
        .expect("the decoded request must be queued");
    assert!(
        !rustix::fs::fcntl_getfl(&job.connection)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK),
        "BSD-inherited nonblocking mode must not bypass protocol deadlines"
    );
    assert!(busy.load(Ordering::Acquire));
    protocol::write_frame(&mut job.connection, &Reply::Failed(ControlFailure::Busy)).unwrap();
    assert!(matches!(
        protocol::read_frame::<Reply>(&mut client).unwrap(),
        Reply::Failed(ControlFailure::Busy)
    ));
}
