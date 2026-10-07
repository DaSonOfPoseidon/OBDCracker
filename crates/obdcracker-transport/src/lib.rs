//! Adapter backends. Every send takes a request approved by `obdcracker-safety`, so no backend can put
//! anything on the bus that the policy hasn't allowed.

use std::fmt;
use std::time::Duration;

use obdcracker_safety::Approved;

mod mock;

pub use mock::Mock;

/// A reply from one module: the CAN ID it came from and its reassembled payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub source: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub trait Transport {
    fn send(&mut self, request: &Approved) -> Result<(), Error>;
    fn recv(&mut self, timeout: Duration) -> Result<Response, Error>;
}
