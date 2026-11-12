//! One UDS `ReadDataByIdentifier` (`22`) for several DIDs in a single request, such as
//! `22 F187 F188 F189 F191`: 9 bytes, so it goes out in segments. [`crate::sweep`] reads one DID
//! per request and [`crate::scan`] batches at most 3, so this is the way to send the long one.
//! See [`docs/usage.md#read-dids`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/usage.md#read-dids).

use std::fmt;

use obdcracker_core::response::{self, Error as ReplyError};
use obdcracker_core::uds::READ_DATA_BY_IDENTIFIER;
use obdcracker_safety::{Policy, Protocol, Rejection, Target};

use crate::fingerprint::{FingerprintError, ReadError, UdsModule, ask};
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
///
/// Every DID asked for is in `split`, in `left_out`, or among the DIDs of `unsplit` (the ones from
/// the first DID that is in neither), and `split` and `left_out` together are the DIDs asked for
/// up to that one, in request order.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidsData {
    /// The DIDs whose data could be told apart, in request order, each with its own bytes.
    #[cfg_attr(feature = "serde", serde(with = "crate::json::did_data"))]
    pub split: Vec<(u16, Vec<u8>)>,
    /// The DIDs asked for that the reply left out, which is how a module says it doesn't support
    /// them (ISO 14229-1), in request order. Only those before the first DID of `unsplit`: after
    /// that point nothing says which DIDs the bytes hold.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::json::did_list"))]
    pub left_out: Vec<u16>,
    /// What follows the last split DID, starting with the echo of the next DID that wasn't left
    /// out: the bytes of every DID from the first one whose length wasn't known (unless it was the
    /// last). Empty when every DID was split or left out.
    #[cfg_attr(feature = "serde", serde(with = "crate::json::bytes"))]
    pub unsplit: Vec<u8>,
}

/// Checks a list of DIDs for [`read_dids`] without sending anything, so a caller that sends
/// something first can refuse a bad list before it does.
///
/// # Errors
///
/// [`ReadDidsError::NoDids`], [`ReadDidsError::TooMany`] or [`ReadDidsError::Duplicate`].
pub fn check_dids(dids: &[u16]) -> Result<(), ReadDidsError> {
    if dids.is_empty() {
        return Err(ReadDidsError::NoDids);
    }
    if dids.len() > MAX_DIDS {
        return Err(ReadDidsError::TooMany(dids.len()));
    }
    for (index, did) in dids.iter().enumerate() {
        if dids[..index].contains(did) {
            return Err(ReadDidsError::Duplicate(*did));
        }
    }
    Ok(())
}

/// Reads `dids` from `module` with one request, `22` and each DID in order.
///
/// A reply doesn't say where one DID's data ends, so `length_of` gives each DID's length where it
/// is known (from the vehicle profile; `None`, or 0, where it isn't). A module leaves out of its
/// reply the DIDs it doesn't support, so the reply is checked as follows:
///
/// - Each echo is one of the DIDs not yet matched, so the DIDs stay in request order and none
///   repeats. The DIDs skipped to reach it are [`DidsData::left_out`], and so are those after the
///   last echo.
/// - A DID of known length takes exactly that many bytes. The length of a DID the reply leaves out
///   doesn't matter.
/// - A DID of unknown length that is the last one asked for takes the rest of the reply, and needs
///   at least one byte. One before the last can't be split off: from its echo, the rest is
///   [`DidsData::unsplit`], and is checked only for the echo and one data byte.
/// - Nothing is left over once the last DID is split, and a reply that leaves out every DID
///   isn't one (a module with none of them answers `7F 22 31`).
///
/// A reply that fails any check is [`ReadError::Undecodable`], carrying the reply.
///
/// The request is approved by `policy` first. Returns the module's answer, or why it gave none.
///
/// With 4 or more DIDs the request is over 7 bytes, and an [`crate::elm::Elm`] sends that only
/// once an earlier request has shown that the adapter echoes each character as it reads it
/// (otherwise it fails with [`Error::Adapter`], writing nothing): send a single-frame request
/// first, such as this function with one DID.
///
/// # Errors
///
/// [`ReadDidsError`]: the DID list is empty, too long or has a duplicate, the policy refuses the
/// request, or the adapter fails.
pub fn read_dids<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    dids: &[u16],
    length_of: impl Fn(u16) -> Option<usize>,
    timing: Timing,
) -> Result<Result<DidsData, ReadError>, ReadDidsError> {
    check_dids(dids)?;
    let mut payload = vec![READ_DATA_BY_IDENTIFIER];
    payload.extend(dids.iter().flat_map(|did| did.to_be_bytes()));
    let request = policy
        .approve(Protocol::Uds, Target::physical(module.request_id), &payload)
        .map_err(ReadDidsError::Rejected)?;
    ask(transport, &request, module.response_id, timing, |reply| {
        split(reply, dids, &length_of)
    })
    .map_err(|e| match e {
        FingerprintError::Transport(e) => ReadDidsError::Transport(e),
        // Only an extended session or a policy check yields these, and this asks for neither.
        e => ReadDidsError::Transport(Error::Adapter(e.to_string())),
    })
}

// `reply` against the DIDs asked for, in order.
fn split(
    reply: &[u8],
    dids: &[u16],
    length_of: &impl Fn(u16) -> Option<usize>,
) -> Result<DidsData, ReplyError> {
    let mut rest = response::positive(READ_DATA_BY_IDENTIFIER, reply)?;
    if rest.is_empty() {
        return Err(ReplyError::TooShort);
    }
    let mut split = Vec::with_capacity(dids.len());
    let mut left_out = Vec::new();
    // The first DID the reply hasn't matched yet.
    let mut next = 0;
    while !rest.is_empty() {
        if next == dids.len() {
            return Err(ReplyError::Malformed);
        }
        let (echo, after) = rest.split_at_checked(2).ok_or(ReplyError::TooShort)?;
        let offset = dids[next..]
            .iter()
            .position(|did| did.to_be_bytes() == echo)
            .ok_or(ReplyError::Malformed)?;
        left_out.extend_from_slice(&dids[next..next + offset]);
        let did = dids[next + offset];
        next += offset + 1;
        match length_of(did).filter(|&length| length > 0) {
            Some(length) => {
                let (data, after_data) =
                    after.split_at_checked(length).ok_or(ReplyError::TooShort)?;
                split.push((did, data.to_vec()));
                rest = after_data;
            }
            None if after.is_empty() => return Err(ReplyError::TooShort),
            None if next == dids.len() => {
                split.push((did, after.to_vec()));
                rest = &[];
            }
            None => {
                return Ok(DidsData {
                    split,
                    left_out,
                    unsplit: rest.to_vec(),
                });
            }
        }
    }
    left_out.extend_from_slice(&dids[next..]);
    Ok(DidsData {
        split,
        left_out,
        unsplit: Vec::new(),
    })
}
