//! A read-only DID sweep: one `ReadDataByIdentifier` (`22`) per DID over a range, to find what a
//! module answers that no profile lists yet, such as the head-up display's adaptation values.
//!
//! It only reads, so it needs nothing beyond the read-only tier, but it sends one request per DID:
//! a whole range is 65 536 of them. Give it the narrowest range that can hold what you're after.

use std::ops::RangeInclusive;

use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::{self, DiagnosticSession};
use obdcracker_safety::{Policy, Target};

use crate::fingerprint::{FingerprintError, ReadError, UdsModule};
use crate::scan::{Ask, Direct, session_error};
use crate::{Error, ExtendedSession, S3, SessionError, Timing, Transport};

/// What [`sweep_dids`] does beyond reading in the default session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepOptions {
    /// Read in the extended diagnostic session, entered first (`10 03`), kept with
    /// `TesterPresent` and left at the end (`10 01`), with these S3 timings. `None`, the default,
    /// reads in the default session.
    pub extended: Option<S3>,
}

/// What a sweep found, and where it stopped if it didn't finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// Each DID the module has, in order: its value, or why it refused it. A DID refused as out
    /// of range (NRC 0x31) isn't there, so it isn't listed. A DID that went unanswered is
    /// listed as [`ReadError::NoReply`], as it may be worth reading again, unless the sweep
    /// stopped before an answer came after it: then [`Stop::at`] is at or before it.
    pub found: Vec<(u16, Result<Vec<u8>, ReadError>)>,
    /// Where the sweep stopped early, if it did: sweep again from [`Stop::at`] to go on.
    pub stop: Option<Stop>,
}

impl Sweep {
    /// How many DIDs in [`Sweep::found`] the module answered, with a value or a refusal: all
    /// but those listed as [`ReadError::NoReply`].
    #[must_use]
    pub fn answered(&self) -> usize {
        self.found
            .iter()
            .filter(|(_, value)| *value != Err(ReadError::NoReply))
            .count()
    }
}

/// Where and why a sweep stopped before the end of its range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    /// Where to resume: the first DID it didn't read, or the first of the unanswered DIDs just
    /// before it.
    pub at: u16,
    /// Why it stopped.
    pub why: Why,
}

/// Why a sweep stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// The module stopped answering ([`ReadError::NoReply`] [`QUIET_LIMIT`] times in a row),
    /// refused `22` itself (service not supported, in this session or at all, or a bad format),
    /// or refused the extended session or didn't confirm it.
    Module(ReadError),
    /// The adapter failed, such as `BUFFER FULL`; its state may be unknown, so connect again.
    Adapter(Error),
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(ReadError::NoReply) => f.write_str("the module stopped answering"),
            Self::Module(e) => e.fmt(f),
            Self::Adapter(e) => e.fmt(f),
        }
    }
}

// Refusals of the request as a whole rather than of one DID (ISO 14229-1): the service or the
// session doesn't allow it, or the request's format is wrong. Every later read would get the same.
const SERVICE_REFUSALS: [Nrc; 4] = [
    Nrc::ServiceNotSupported,
    Nrc::SubFunctionNotSupported,
    Nrc::IncorrectMessageLength,
    Nrc::ServiceNotSupportedInActiveSession,
];

/// How many DIDs in a row may go unanswered before a sweep takes the module to be gone.
pub const QUIET_LIMIT: usize = 3;

/// Reads each DID in `range` from `module`, in order, and returns those it has.
///
/// Every read is approved by `policy` before the first is sent, and with
/// [`SweepOptions::extended`] so are the session's own requests; the policy must then know the
/// module's reply ID (narrow it with the vehicle profile), or [`FingerprintError::Session`] is
/// returned with nothing sent. The sweep stops early, keeping what it found, when the module
/// goes quiet ([`QUIET_LIMIT`]), refuses `22` itself or the session, or the adapter fails
/// ([`Stop`]).
///
/// # Errors
///
/// The policy refuses a request, or the extended session can't be used with it.
pub fn sweep_dids<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    range: RangeInclusive<u16>,
    timing: Timing,
    options: &SweepOptions,
) -> Result<Sweep, FingerprintError> {
    sweep_dids_reporting(transport, policy, module, range, timing, options, |_| {})
}

/// [`sweep_dids`], calling `progress` with each DID once it's been read.
///
/// # Errors
///
/// As [`sweep_dids`].
pub fn sweep_dids_reporting<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    range: RangeInclusive<u16>,
    timing: Timing,
    options: &SweepOptions,
    mut progress: impl FnMut(u16),
) -> Result<Sweep, FingerprintError> {
    let target = Target::Physical(module.request_id);
    let approve = |payload: &[u8]| {
        policy
            .approve(target, payload)
            .map_err(FingerprintError::Rejected)
    };
    // A RangeInclusive's iterator stops at its end, even at u16::MAX.
    let requests = range
        .clone()
        .map(|did| Ok((did, approve(&uds::read_did(did))?)))
        .collect::<Result<Vec<_>, FingerprintError>>()?;
    let Some(&first) = requests.first().map(|(did, _)| did) else {
        return Ok(Sweep {
            found: Vec::new(),
            stop: None,
        });
    };
    if let Some(s3) = options.extended {
        // What `ExtendedSession` sends, checked now so nothing is sent if it can't be.
        let enter = approve(&uds::session_control(DiagnosticSession::Extended))?;
        approve(&uds::tester_present())?;
        approve(&uds::session_control(DiagnosticSession::Default))?;
        if enter.reply_id().is_none() {
            return Err(FingerprintError::Session(SessionError::UnknownReplyId));
        }
        let mut session = match ExtendedSession::enter(transport, policy, target, timing, s3) {
            Ok(session) => session,
            // Dropping a session that may have been entered sent `10 01`.
            Err(e) => {
                return Ok(Sweep {
                    found: Vec::new(),
                    stop: Some(Stop {
                        at: first,
                        why: stopped(session_error(e)),
                    }),
                });
            }
        };
        let sweep = read_each(&mut session, &requests, &mut progress);
        // A module that doesn't confirm `10 01` leaves the session after S3.
        if let Err(e) = session.end()
            && let Err(FingerprintError::Transport(e)) = session_error(e)
            && sweep.stop.is_none()
        {
            return Ok(Sweep {
                stop: Some(Stop {
                    // Everything was read; sweeping again from the last DID repeats one read.
                    at: *range.end(),
                    why: Why::Adapter(e),
                }),
                ..sweep
            });
        }
        return Ok(sweep);
    }
    let mut direct = Direct {
        transport,
        response_id: module.response_id,
        timing,
    };
    Ok(read_each(&mut direct, &requests, &mut progress))
}

// Why a sweep stops, from a failure to read or to use the session.
fn stopped(failure: Result<ReadError, FingerprintError>) -> Why {
    match failure {
        Ok(e) => Why::Module(e),
        Err(FingerprintError::Transport(e)) => Why::Adapter(e),
        // Approved up front with the same policy and target, so not expected; still a stop.
        Err(e) => Why::Adapter(Error::Adapter(e.to_string())),
    }
}

fn read_each(
    asker: &mut impl Ask,
    requests: &[(u16, obdcracker_safety::Approved)],
    progress: &mut impl FnMut(u16),
) -> Sweep {
    let mut found = Vec::new();
    // DIDs that went unanswered since the last answer. Each ends up listed as `NoReply` or
    // covered by `Stop::at`, never neither.
    let mut quiet: Vec<u16> = Vec::new();
    let unanswered = |quiet: &mut Vec<u16>| {
        quiet
            .drain(..)
            .map(|did| (did, Err(ReadError::NoReply)))
            .collect::<Vec<_>>()
    };
    for (did, request) in requests {
        // Where to resume after a stop that no answer came before: the first unanswered DID.
        let resume = quiet.first().copied().unwrap_or(*did);
        let value = match asker.ask(request, |payload| {
            Ok(uds::decode_did(payload, *did)?.to_vec())
        }) {
            Ok(value) => value,
            Err(e) => {
                return Sweep {
                    found,
                    stop: Some(Stop {
                        at: resume,
                        why: stopped(Err(e)),
                    }),
                };
            }
        };
        progress(*did);
        match value {
            Err(ReadError::NoReply) => {
                quiet.push(*did);
                if quiet.len() == QUIET_LIMIT {
                    return Sweep {
                        found,
                        stop: Some(Stop {
                            at: resume,
                            why: Why::Module(ReadError::NoReply),
                        }),
                    };
                }
            }
            // Not there, but the module answered, so the DIDs before it are listed.
            Err(ReadError::Reply(ReplyError::Negative(refusal)))
                if refusal.nrc == Nrc::RequestOutOfRange =>
            {
                found.extend(unanswered(&mut quiet));
            }
            // A refusal of `22` itself, not of this DID: nothing more will read.
            Err(e @ ReadError::Reply(ReplyError::Negative(refusal)))
                if SERVICE_REFUSALS.contains(&refusal.nrc) =>
            {
                found.extend(unanswered(&mut quiet));
                return Sweep {
                    found,
                    stop: Some(Stop {
                        at: *did,
                        why: Why::Module(e),
                    }),
                };
            }
            // A session refused on the way (re-entered after it lapsed): nothing more will read,
            // and nothing since the last answer was.
            Err(e @ ReadError::SessionRefused(_)) => {
                return Sweep {
                    found,
                    stop: Some(Stop {
                        at: resume,
                        why: Why::Module(e),
                    }),
                };
            }
            value => {
                found.extend(unanswered(&mut quiet));
                found.push((*did, value));
            }
        }
    }
    // Fewer than QUIET_LIMIT unanswered at the end: listed, as there's nothing to resume.
    found.extend(unanswered(&mut quiet));
    Sweep { found, stop: None }
}
