//! Adapter backends. Every send takes a request approved by `obdcracker-safety`, so no backend can put
//! anything on the bus that the policy hasn't allowed.

use std::fmt;
use std::time::{Duration, SystemTime};

use obdcracker_safety::Approved;

mod audit;
pub mod discover;
mod dry_run;
pub mod dtc;
pub mod elm;
mod exchange;
pub mod fingerprint;
pub mod gateway;
pub mod link;
mod mock;
pub mod scan;
mod session;
pub mod sweep;
pub mod tp20;

pub use audit::{Audited, log_failure};
pub use dry_run::DryRun;
pub use exchange::{Expect, Timing, exchange};
pub use mock::Mock;
pub use session::{ExtendedSession, Left, S3, SessionError};

/// A reply from one module: the CAN ID it came from and its reassembled payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The CAN ID the reply came from.
    pub source: u32,
    /// The reassembled reply, service ID first.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Why a send or receive failed.
pub enum Error {
    /// No reply arrived in time.
    Timeout,
    /// The module said it was busy (response-pending, NRC 0x78) but didn't answer before its
    /// wait ended: P2* ran out, it went over [`Timing::max_pending`], or the adapter stopped
    /// listening (a plain ELM327 may not wait P2*). Returned by [`exchange`] for one module.
    StillPending,
    /// The adapter or its driver failed.
    Adapter(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response before the timeout"),
            Self::StillPending => f.write_str(
                "the module said it was busy (response-pending) but didn't answer in time",
            ),
            Self::Adapter(message) => write!(f, "adapter error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// A connection to the bus through one adapter.
pub trait Transport {
    /// Sends one approved request. Unapproved bytes can't be passed in.
    fn send(&mut self, request: &Approved) -> Result<(), Error>;
    /// Waits up to `timeout` for the next reply.
    fn recv(&mut self, timeout: Duration) -> Result<Response, Error>;
    /// With `Some(wait)`, waits up to `wait` for each reply, or as near to it as the adapter
    /// can, until called again with `None`, which restores the usual wait. An adapter that
    /// learns shorter waits from how fast modules answer (the ELM327's adaptive timing) stops
    /// doing so, so a module slow to answer isn't missed. Sends nothing on the bus.
    ///
    /// Returns how long the adapter now waits for a reply (`None` after `None`), which can be
    /// less than `wait` (an ELM327 waits at most about 1 s) or more (it never waits less than
    /// usual). The default does nothing and returns `wait`, for a transport that waits for
    /// whatever timeout `recv` is given.
    ///
    /// # Errors
    ///
    /// The adapter refused the setting or failed.
    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        Ok(wait)
    }
    /// What the adapter did besides carrying requests and replies since this was last called,
    /// oldest first, for the audit log ([`Audited`] takes them after every call). The default
    /// has none.
    fn take_events(&mut self) -> Vec<LinkEvent> {
        Vec::new()
    }
    /// Reads whatever is left of the last request's replies, so it can be reported
    /// ([`LinkEvent::Unread`]) before the session ends: [`Audited`] calls it when dropped. Sends
    /// nothing on the bus. The default does nothing.
    ///
    /// # Errors
    ///
    /// The adapter failed while finishing the request.
    fn settle(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Something an adapter did besides carrying a request or a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEvent {
    /// A command to the adapter itself, such as an ELM327's `AT SH 7E0`, and the lines it
    /// answered with (as many as were read, if it failed). Commands never reach the bus.
    Command {
        /// When it was sent.
        at: SystemTime,
        /// The command, as written.
        command: String,
        /// Its answer's lines, such as `OK`.
        answer: Vec<String>,
    },
    /// A line the adapter printed for a request after nothing read it any more, dropped before
    /// the next request: such as a late reply, or one from a module nobody waited for.
    Unread {
        /// When the driver read it from the link, which may be before it was dropped.
        at: SystemTime,
        /// The line as the adapter printed it.
        line: String,
    },
    /// A status line the adapter printed for a request instead of a reply, such as an ELM327's
    /// `NO DATA` when nothing answered. One that fails a request the caller is waiting on, such
    /// as `CAN ERROR`, is returned as an error instead.
    Status {
        /// When the driver read it from the link.
        at: SystemTime,
        /// The line as the adapter printed it.
        line: String,
    },
    /// How many events, or lines the adapter printed, were dropped because there was no room to
    /// keep them until something took them.
    Lost(usize),
}

/// Bytes as space-separated upper-case hex, the way CAN tools print them: `02 09 02`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
