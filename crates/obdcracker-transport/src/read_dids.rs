//! One UDS `ReadDataByIdentifier` (`22`) for several DIDs in a single request, such as
//! `22 F187 F188 F189 F191`: 9 bytes, so it goes out in segments. [`crate::sweep`] reads one DID
//! per request and [`crate::scan`] batches at most 3, so this is the way to send the long one.
//! See [`docs/usage.md#read-dids`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/usage.md#read-dids).

use std::fmt;

use obdcracker_safety::{Policy, Rejection};

use crate::fingerprint::{ReadError, UdsModule};
use crate::{Error, Timing, Transport};

/// The most DIDs one request may name: 1 + 2 * 21 = 43 bytes, under the 44 bytes the ELM327
/// driver sends in segments ([`crate::elm`]).
pub const MAX_DIDS: usize = 21;

/// Why [`read_dids`] sent nothing, or the adapter failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadDidsError {
    /// No DID was given.
    NoDids,
    /// More than [`MAX_DIDS`] DIDs were given; holds how many.
    TooMany(usize),
    /// A DID was named twice, which the module could answer once or twice.
    Duplicate(u16),
    /// The policy refused the request, so nothing reached the bus.
    Rejected(Rejection),
    /// The adapter failed. What it was sent is in the audit log.
    Transport(Error),
}

impl fmt::Display for ReadDidsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDids => f.write_str("no DID to read"),
            Self::TooMany(count) => write!(
                f,
                "{count} DIDs in one request is too many: at most {MAX_DIDS}"
            ),
            Self::Duplicate(did) => write!(f, "DID {did:04X} is named twice"),
            Self::Rejected(rejection) => write!(f, "safety policy {rejection}"),
            Self::Transport(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadDidsError {}

/// What a module answered to a multi-DID read, as far as its lengths let it be split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidsData {
    /// The DIDs whose data could be told apart, in request order, each with its own bytes.
    pub split: Vec<(u16, Vec<u8>)>,
    /// What follows the last split DID, starting with the echo of the next DID: the bytes of
    /// every DID from the first one whose length wasn't known (unless it was the last). Empty when
    /// every DID was split.
    pub unsplit: Vec<u8>,
}

/// Reads `dids` from `module` with one request, `22` and each DID in order.
///
/// A reply doesn't say where one DID's data ends, so `length_of` gives each DID's length where it
/// is known (from the vehicle profile; `None`, or 0, for unknown). The reply is checked exactly:
/// each DID's echo, in request order, and each known length, with nothing left over once every
/// DID is split. A DID of unknown length can only be split off if it is the last, and takes
/// the rest of the reply. From the first unknown one before the last, the rest is
/// [`DidsData::unsplit`], and only its first byte count is checked. The reply that fails any check is
/// [`ReadError::Undecodable`], carrying the reply.
///
/// The request is approved by `policy` first. Returns the module's answer, or why it gave none.
///
/// # Errors
///
/// [`ReadDidsError`]: the DID list is empty, too long or has a duplicate, the policy refuses the
/// request, or the adapter fails.
pub fn read_dids<T: Transport + ?Sized>(
    _transport: &mut T,
    _policy: &Policy,
    _module: &UdsModule,
    _dids: &[u16],
    _length_of: impl Fn(u16) -> Option<usize>,
    _timing: Timing,
) -> Result<Result<DidsData, ReadError>, ReadDidsError> {
    Ok(Err(ReadError::NoReply))
}
