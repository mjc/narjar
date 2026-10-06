//! The Nix worker-protocol operations needed to hold temporary GC roots.
//!
//! Root lifetime is the lifetime of this connection. No builds, substitutions,
//! configuration changes, or general-purpose daemon operations are exposed.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

const WORKER_MAGIC_CLIENT: u64 = 0x6e69_7863;
const WORKER_MAGIC_DAEMON: u64 = 0x6478_696f;
// Negotiate the small stable rooting protocol, without activity/error-info
// extensions used by newer clients. Current Nix daemons still support it.
const ROOTING_PROTOCOL_VERSION: u64 = 0x0112;
const ADD_TEMP_ROOT: u64 = 11;
const STDERR_LOG: u64 = 0x6f6c_6d67;
const STDERR_DONE: u64 = 0x616c_7473;
const STDERR_ERROR: u64 = 0x6378_7470;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

pub(crate) struct DaemonRoots {
    stream: UnixStream,
}

impl DaemonRoots {
    pub(crate) fn hold(state_dir: &Path, paths: &[String]) -> io::Result<Self> {
        let stream = UnixStream::connect(state_dir.join("daemon-socket/socket"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut roots = Self { stream };
        roots.negotiate_rooting_protocol()?;
        paths
            .iter()
            .try_for_each(|path| roots.register_temporary_root(path))?;
        Ok(roots)
    }

    fn negotiate_rooting_protocol(&mut self) -> io::Result<()> {
        self.write_number(WORKER_MAGIC_CLIENT)?;
        self.write_number(ROOTING_PROTOCOL_VERSION)?;
        let magic = self.read_number()?;
        let version = self.read_number()?;
        if magic != WORKER_MAGIC_DAEMON || version >> 8 != 1 || version < ROOTING_PROTOCOL_VERSION {
            return Err(invalid_protocol("unsupported Nix daemon rooting protocol"));
        }
        self.write_number(0)?; // obsolete CPU affinity
        self.write_number(0)?; // obsolete reserve-space flag
        self.read_completion()
    }

    fn register_temporary_root(&mut self, path: &str) -> io::Result<()> {
        let basename = path
            .strip_prefix("/nix/store/")
            .ok_or_else(|| invalid_protocol("temporary root is not a concrete store path"))?;
        narjar::__private::storage::validate_store_basename(basename)
            .map_err(|_| invalid_protocol("invalid temporary-root store basename"))?;
        self.write_number(ADD_TEMP_ROOT)?;
        self.write_string(path)?;
        self.read_completion()?;
        match self.read_number()? {
            1 => Ok(()),
            _ => Err(invalid_protocol(
                "Nix daemon did not acknowledge the temporary root",
            )),
        }
    }

    fn read_completion(&mut self) -> io::Result<()> {
        for _ in 0..1024 {
            match self.read_number()? {
                STDERR_DONE => return Ok(()),
                STDERR_LOG => {
                    self.read_string()?;
                }
                STDERR_ERROR => {
                    let message = self.read_string()?;
                    let _status = self.read_number()?;
                    return Err(io::Error::other(format!("Nix daemon: {message}")));
                }
                _ => return Err(invalid_protocol("unexpected Nix daemon rooting reply")),
            }
        }
        Err(invalid_protocol("too many Nix daemon log messages"))
    }

    fn write_number(&mut self, value: u64) -> io::Result<()> {
        self.stream.write_all(&value.to_le_bytes())
    }

    fn read_number(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.stream.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_string(&mut self, value: &str) -> io::Result<()> {
        self.write_number(value.len() as u64)?;
        self.stream.write_all(value.as_bytes())?;
        self.stream
            .write_all(&[0; 8][..value.len().wrapping_neg() & 7])
    }

    fn read_string(&mut self) -> io::Result<String> {
        let length = usize::try_from(self.read_number()?)
            .ok()
            .filter(|length| *length <= MAX_MESSAGE_BYTES)
            .ok_or_else(|| invalid_protocol("oversized Nix daemon rooting message"))?;
        let mut bytes = vec![0; length];
        self.stream.read_exact(&mut bytes)?;
        let mut padding = [0; 8];
        self.stream
            .read_exact(&mut padding[..length.wrapping_neg() & 7])?;
        if padding != [0; 8] {
            return Err(invalid_protocol("invalid Nix daemon string padding"));
        }
        String::from_utf8(bytes).map_err(|_| invalid_protocol("Nix daemon message is not UTF-8"))
    }
}

fn invalid_protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_daemon_messages_are_rejected_before_allocation() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&(MAX_MESSAGE_BYTES as u64 + 1).to_le_bytes())
            .unwrap();
        let error = DaemonRoots { stream }.read_string().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn daemon_errors_keep_the_original_message() {
        let (stream, peer) = UnixStream::pair().unwrap();
        let mut sender = DaemonRoots { stream: peer };
        sender.write_number(STDERR_ERROR).unwrap();
        sender.write_string("path was collected").unwrap();
        sender.write_number(1).unwrap();
        let error = DaemonRoots { stream }.read_completion().unwrap_err();
        assert!(error.to_string().contains("path was collected"));
    }

    #[test]
    fn handshake_and_root_registration_retain_the_connection_until_drop() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("daemon-socket")).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.path().join("daemon-socket/socket"))
                .unwrap();
        let path = "/nix/store/00000000000000000000000000000000-test";
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer = DaemonRoots { stream };
            assert_eq!(peer.read_number().unwrap(), WORKER_MAGIC_CLIENT);
            assert_eq!(peer.read_number().unwrap(), ROOTING_PROTOCOL_VERSION);
            peer.write_number(WORKER_MAGIC_DAEMON).unwrap();
            peer.write_number(0x0126).unwrap();
            assert_eq!(peer.read_number().unwrap(), 0);
            assert_eq!(peer.read_number().unwrap(), 0);
            peer.write_number(STDERR_DONE).unwrap();
            assert_eq!(peer.read_number().unwrap(), ADD_TEMP_ROOT);
            assert_eq!(peer.read_string().unwrap(), path);
            peer.write_number(STDERR_DONE).unwrap();
            peer.write_number(1).unwrap();
            let mut byte = [0];
            assert_eq!(peer.stream.read(&mut byte).unwrap(), 0);
        });
        let roots = DaemonRoots::hold(directory.path(), &[path.to_owned()]).unwrap();
        drop(roots);
        worker.join().unwrap();
    }
}
