//! Adapter backends. Every send takes a request approved by `obdcracker-safety`, so no backend can put
//! anything on the bus that the policy hasn't allowed.

use std::fmt;
use std::time::Duration;

use obdcracker_safety::Approved;

mod audit;
mod dry_run;
mod exchange;
mod mock;

pub use audit::Audited;
pub use dry_run::DryRun;
pub use exchange::{Expect, Timing, exchange};
pub use mock::Mock;

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
    /// The adapter or its driver failed.
    Adapter(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response before the timeout"),
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
