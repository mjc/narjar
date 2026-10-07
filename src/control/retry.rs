use std::{io, num::NonZeroU32, time::Duration};

use super::{ControlFailure, Reply};
use narjar::__private::storage::gc::GcReport;

#[derive(Clone, Copy)]
pub(crate) struct RetryPolicy {
    attempts: NonZeroU32,
    delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: NonZeroU32::new(1).unwrap(),
            delay: Duration::ZERO,
        }
    }
}

impl RetryPolicy {
    pub(crate) fn new(attempts: NonZeroU32, delay: Duration) -> io::Result<Self> {
        match attempts.get() <= 16 && delay <= Duration::from_secs(30) {
            true => Ok(Self { attempts, delay }),
            false => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GC retries are limited to 16 attempts with at most 30 seconds between attempts",
            )),
        }
    }
}

pub(super) fn request_with_retry(
    policy: RetryPolicy,
    mut request: impl FnMut() -> io::Result<Reply>,
    mut pause: impl FnMut(Duration),
) -> io::Result<GcReport> {
    (0..policy.attempts.get())
        .find_map(|attempt| match request() {
            Ok(Reply::Completed(report)) => Some(Ok(*report)),
            Ok(Reply::Failed(error @ (ControlFailure::Busy | ControlFailure::Changed))) => {
                match attempt + 1 < policy.attempts.get() {
                    true => {
                        eprintln!(
                            "narjar gc: {error}; retry {}/{}",
                            attempt + 2,
                            policy.attempts
                        );
                        pause(policy.delay);
                        None
                    }
                    false => Some(Err(io::Error::other(error))),
                }
            }
            Ok(Reply::Failed(
                error @ (ControlFailure::BackendMismatch
                | ControlFailure::Stopping
                | ControlFailure::Policy(_)
                | ControlFailure::Storage(_)),
            )) => Some(Err(io::Error::other(error))),
            Err(error) => Some(Err(error)),
        })
        .expect("a nonzero retry budget always reaches a terminal attempt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_snapshots_are_retried_but_a_transport_failure_is_terminal() {
        let mut replies = [
            Ok(Reply::Failed(ControlFailure::Changed)),
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "ambiguous reply",
            )),
        ]
        .into_iter();
        let mut calls = 0;
        let mut pauses = 0;
        let error = request_with_retry(
            RetryPolicy::new(NonZeroU32::new(3).unwrap(), Duration::ZERO).unwrap(),
            || {
                calls += 1;
                replies.next().unwrap()
            },
            |_| pauses += 1,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(calls, 2);
        assert_eq!(pauses, 1);
    }

    #[test]
    fn contention_uses_exactly_the_requested_attempt_budget_without_real_sleeps() {
        let mut calls = 0;
        let mut pauses = Vec::new();
        let policy = RetryPolicy::new(NonZeroU32::new(3).unwrap(), Duration::from_secs(1)).unwrap();
        let error = request_with_retry(
            policy,
            || {
                calls += 1;
                Ok(Reply::Failed(ControlFailure::Busy))
            },
            |delay| pauses.push(delay),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("busy"));
        assert_eq!(calls, 3);
        assert_eq!(pauses, [Duration::from_secs(1), Duration::from_secs(1)]);
    }

    #[test]
    fn transport_and_storage_failures_are_never_retried_after_ambiguous_mutation() {
        for failure in [
            ControlFailure::BackendMismatch,
            ControlFailure::Stopping,
            ControlFailure::Policy("invalid".into()),
            ControlFailure::Storage("disk".into()),
        ] {
            let mut failure = Some(failure);
            let mut calls = 0;
            let result = request_with_retry(
                RetryPolicy::new(NonZeroU32::new(3).unwrap(), Duration::ZERO).unwrap(),
                || {
                    calls += 1;
                    Ok(Reply::Failed(failure.take().unwrap()))
                },
                |_| panic!("non-contention failure must not sleep"),
            );
            assert!(result.is_err());
            assert_eq!(calls, 1);
        }
    }
}
