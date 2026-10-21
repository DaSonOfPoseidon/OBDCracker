//! A read-only DID sweep: one `ReadDataByIdentifier` (`22`) per DID over a range, to find what a
//! module answers that no profile lists yet, such as the head-up display's adaptation values.
//!
//! It only reads, so it needs nothing beyond the read-only tier, but it sends one request per DID:
//! a whole range is 65 536 of them. Give it the narrowest range that can hold what you're after.

use std::ops::RangeInclusive;

use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::{self, DiagnosticSession};
use obdcracker_safety::{Policy, Protocol, Target};

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
    /// of range (NRC 0x31) isn't there, so it isn't listed. A DID that got no final answer is
    /// listed as [`ReadError::NoReply`] or [`ReadError::StillPending`], as it may be worth
    /// reading again, unless the sweep stopped before an answer came after it: then
    /// [`Stop::at`] is at or before it.
    pub found: Vec<(u16, Result<Vec<u8>, ReadError>)>,
    /// Where the sweep stopped early, if it did: sweep again from [`Stop::at`] to go on.
    pub stop: Option<Stop>,
    /// With [`SweepOptions::extended`]: why the module may still be in the extended session
    /// afterwards, as it refused `10 01` or didn't answer it. It returns to the default session by
    /// itself once S3 runs out without a `TesterPresent` (5 s by default).
    pub still_extended: Option<ReadError>,
    /// Whether a read went without a final answer: its answer may still arrive, and be taken
    /// for the answer to a later read on this connection, as UDS refusals don't name the DID.
    /// Connect again before reading from this module again.
    pub out_of_step: bool,
}

impl Sweep {
    /// How many DIDs in [`Sweep::found`] the module answered, with a value or a refusal: all
    /// but those listed as [`ReadError::NoReply`] or [`ReadError::StillPending`].
    #[must_use]
    pub fn answered(&self) -> usize {
        self.found
            .iter()
            .filter(|(_, value)| {
                !matches!(value, Err(ReadError::NoReply | ReadError::StillPending))
            })
            .count()
    }
}

/// Where and why a sweep stopped before the end of its range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    /// Where to resume: the first DID it didn't read, or the first of the unanswered DIDs just
    /// before it, or for [`Why::Unmatched`] the DID whose answer couldn't be told from a late one.
    pub at: u16,
    /// Why it stopped.
    pub why: Why,
}

/// Why a sweep stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// The module stopped answering ([`ReadError::NoReply`] or [`ReadError::StillPending`],
    /// [`QUIET_LIMIT`] times in a row),
    /// refused `22` itself (service not supported, in this session or at all, or a bad format),
    /// said it was busy (NRC 0x21: sweep again from [`Stop::at`] a little later), rejected a DID
    /// with no reason given (NRC 0x10, which may be its answer to every DID: that DID is listed,
    /// and [`Stop::at`] is the next one), or refused the
    /// extended session or didn't confirm it.
    Module(ReadError),
    /// After a DID went unanswered, a later read got a refusal or a reply it couldn't decode (such
    /// as another DID's value), which may be the late answer to the earlier one: UDS refusals
    /// don't name the DID. Later
    /// replies may then answer earlier requests, so the sweep stops. Sweeping again from
    /// [`Stop::at`] on a fresh connection asks that DID first.
    Unmatched(ReadError),
    /// The adapter failed, such as `BUFFER FULL`; its state may be unknown, so connect again.
    Adapter(Error),
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(ReadError::NoReply) => f.write_str("the module stopped answering"),
            Self::Module(e) => e.fmt(f),
            Self::Unmatched(e) => write!(f, "a reply may have answered an earlier request ({e})"),
            Self::Adapter(e) => e.fmt(f),
        }
    }
}

// Refusals of the request as a whole rather than of one DID (ISO 14229-1): the service or the
// session doesn't allow it, or the request's format is wrong. Every later read would get the same.
// Busy, repeat request: asking the next DID at once would only keep the module busy.
const SERVICE_REFUSALS: [Nrc; 6] = [
    Nrc::BusyRepeatRequest,
    Nrc::ServiceNotSupported,
    Nrc::SubFunctionNotSupported,
    Nrc::IncorrectMessageLength,
    Nrc::SubFunctionNotSupportedInActiveSession,
    Nrc::ServiceNotSupportedInActiveSession,
];

/// How many DIDs in a row may go without a final answer (no reply, or response-pending past
/// [`Timing::max_pending`]) before a sweep takes the module to be gone or stuck.
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

/// [`sweep_dids`], calling `progress` with each DID once its read was sent and answered or
/// timed out. If the extended session's keepalive or re-entry fails before a read goes out, that
/// DID isn't reported and the sweep stops there. Resume from [`Stop::at`], not the last DID
/// reported.
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
    let target = Target::physical(module.request_id);
    let approve = |payload: &[u8]| {
        policy
            .approve(Protocol::Uds, target, payload)
            .map_err(FingerprintError::Rejected)
    };
    // A RangeInclusive's iterator stops at its end, even at u16::MAX.
    let requests = range
        .clone()
        .map(|did| Ok((did, approve(&uds::read_did(did))?)))
        .collect::<Result<Vec<_>, FingerprintError>>()?;
    let Some(&first) = requests.first().map(|(did, _)| did) else {
        return Ok(Sweep {
            still_extended: None,
            found: Vec::new(),
            stop: None,
            out_of_step: false,
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
            // A session that may have been entered was left, or why it may not have been is
            // reported.
            Err(e) => {
                let (entry, still_extended) = match e {
                    SessionError::Unconfirmed { entry, leave } => {
                        (*entry, session_error(*leave).ok())
                    }
                    e => (e, None),
                };
                return Ok(Sweep {
                    still_extended,
                    found: Vec::new(),
                    stop: Some(Stop {
                        at: first,
                        why: stopped(session_error(entry)),
                    }),
                    // A session request's late answer isn't a read's.
                    out_of_step: false,
                });
            }
        };
        let sweep = read_each(&mut session, &requests, &mut progress);
        // A module that doesn't confirm `10 01` leaves the session after S3. An adapter that
        // fails then is in an unknown state, which matters more than why the sweep stopped.
        return Ok(match session.end().map_err(session_error) {
            Err(Ok(e)) => Sweep {
                still_extended: Some(e),
                ..sweep
            },
            Err(Err(FingerprintError::Transport(e))) => {
                let stop = match sweep.stop {
                    Some(
                        stop @ Stop {
                            why: Why::Adapter(_),
                            ..
                        },
                    ) => stop,
                    Some(Stop { at, .. }) => Stop {
                        at,
                        why: Why::Adapter(e),
                    },
                    // Everything was read; sweeping again from the last DID repeats one read.
                    None => Stop {
                        at: *range.end(),
                        why: Why::Adapter(e),
                    },
                };
                Sweep {
                    stop: Some(stop),
                    ..sweep
                }
            }
            // The other failures can't happen: the session's requests were approved up front.
            Ok(()) | Err(Err(_)) => sweep,
        });
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

// A sweep that stopped at `at`.
fn halt(
    found: Vec<(u16, Result<Vec<u8>, ReadError>)>,
    at: u16,
    why: Why,
    out_of_step: bool,
) -> Sweep {
    Sweep {
        found,
        stop: Some(Stop { at, why }),
        still_extended: None,
        out_of_step,
    }
}

fn read_each(
    asker: &mut impl Ask,
    requests: &[(u16, obdcracker_safety::Approved)],
    progress: &mut impl FnMut(u16),
) -> Sweep {
    let mut found = Vec::new();
    // DIDs that got no final answer (no reply, or response-pending past the limit) since the
    // last answer. Each ends up listed with its error or covered by `Stop::at`, never neither.
    let mut quiet: Vec<(u16, ReadError)> = Vec::new();
    // Whether any read went without a final answer: its answer may still come, as another's,
    // at any later read on this connection.
    let mut out_of_step = false;
    let unanswered = |quiet: &mut Vec<(u16, ReadError)>| {
        quiet
            .drain(..)
            .map(|(did, e)| (did, Err(e)))
            .collect::<Vec<_>>()
    };
    for (did, request) in requests {
        // Where to resume after a stop that no answer came before: the first unanswered DID.
        let resume = quiet.first().map_or(*did, |(did, _)| *did);
        let answer = asker.ask_sent(request, |payload| {
            Ok(uds::decode_did(payload, *did)?.to_vec())
        });
        let value = match answer {
            Ok((true, value)) => {
                progress(*did);
                value
            }
            // The session's keepalive or re-entry failed before the read was sent. Going on
            // would report later DIDs past this one, and a caller checkpointing on progress
            // would skip it, so the sweep stops here.
            Ok((false, value)) => {
                let e = value.err().unwrap_or(ReadError::NoReply);
                return halt(found, resume, Why::Module(e), out_of_step);
            }
            Err(e) => {
                return halt(found, resume, stopped(Err(e)), out_of_step);
            }
        };
        // After an unanswered read, a refusal or a reply that can't be decoded (another DID's
        // value) may be the late answer to that one, even past answers that were plainly this
        // connection's own. Asking again could leave this DID's own answer queued for the next.
        if out_of_step && let Err(e @ (ReadError::Reply(_) | ReadError::Undecodable { .. })) = value
        {
            found.extend(unanswered(&mut quiet));
            return halt(found, *did, Why::Unmatched(e), true);
        }
        match value {
            Err(e @ (ReadError::NoReply | ReadError::StillPending)) => {
                quiet.push((*did, e.clone()));
                out_of_step = true;
                if quiet.len() == QUIET_LIMIT {
                    return halt(found, resume, Why::Module(e), true);
                }
            }
            // Not there, but the module answered, so the DIDs before it are listed.
            Err(ReadError::Reply(ReplyError::Negative(refusal)))
                if refusal.nrc == Nrc::RequestOutOfRange =>
            {
                found.extend(unanswered(&mut quiet));
            }
            // No reason given, so it may be every DID's answer: listed, and the sweep stops
            // before the next DID, so going on always gets further.
            Err(e @ ReadError::Reply(ReplyError::Negative(refusal)))
                if refusal.nrc == Nrc::GeneralReject =>
            {
                found.extend(unanswered(&mut quiet));
                found.push((*did, Err(e.clone())));
                let next = requests
                    .iter()
                    .map(|(next, _)| *next)
                    .find(|next| next > did);
                if let Some(at) = next {
                    return halt(found, at, Why::Module(e), out_of_step);
                }
            }
            // A refusal of `22` itself, not of this DID: nothing more will read now.
            Err(e @ ReadError::Reply(ReplyError::Negative(refusal)))
                if SERVICE_REFUSALS.contains(&refusal.nrc) =>
            {
                found.extend(unanswered(&mut quiet));
                return halt(found, *did, Why::Module(e), out_of_step);
            }
            value => {
                found.extend(unanswered(&mut quiet));
                found.push((*did, value));
            }
        }
    }
    // Fewer than QUIET_LIMIT unanswered at the end: listed, as there's nothing to resume.
    found.extend(unanswered(&mut quiet));
    Sweep {
        found,
        stop: None,
        still_extended: None,
        out_of_step,
    }
}
