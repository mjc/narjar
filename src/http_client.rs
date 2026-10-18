use std::time::Duration;

use ureq::{
    Agent, Timeout,
    config::Config,
    unversioned::{
        resolver::DefaultResolver,
        transport::{
            Buffers, ConnectionDetails, Connector, DefaultConnector, NextTimeout, Transport,
            time::Duration as TransportDuration,
        },
    },
};

pub(crate) fn idle_agent(timeout: Duration) -> Agent {
    Agent::with_parts(
        connection_config(timeout),
        DefaultConnector::default().chain(IdleConnector { timeout }),
        DefaultResolver::default(),
    )
}

fn connection_config(timeout: Duration) -> Config {
    Agent::config_builder()
        .timeout_resolve(Some(timeout))
        .timeout_connect(Some(timeout))
        .build()
}

#[derive(Debug)]
struct IdleConnector {
    timeout: Duration,
}

impl Connector<Box<dyn Transport>> for IdleConnector {
    type Out = IdleTransport;

    fn connect(
        &self,
        _: &ConnectionDetails<'_>,
        chained: Option<Box<dyn Transport>>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(|inner| IdleTransport {
            inner,
            timeout: self.timeout,
        }))
    }
}

#[derive(Debug)]
struct IdleTransport {
    inner: Box<dyn Transport>,
    timeout: Duration,
}

impl Transport for IdleTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.inner.transmit_output(
            amount,
            idle_timeout(timeout, self.timeout, Timeout::SendBody),
        )
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.inner
            .await_input(idle_timeout(timeout, self.timeout, Timeout::RecvBody))
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }

    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

fn idle_timeout(supplied: NextTimeout, idle: Duration, reason: Timeout) -> NextTimeout {
    match supplied.after {
        TransportDuration::Exact(after) if after <= idle => supplied,
        TransportDuration::Exact(_) | TransportDuration::NotHappening => NextTimeout {
            after: idle.into(),
            reason,
        },
    }
}

#[cfg(test)]
#[path = "push/timeout/tests.rs"]
pub(crate) mod tests;
