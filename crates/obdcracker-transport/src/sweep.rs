//! A read-only DID sweep: one `ReadDataByIdentifier` (`22`) per DID over a range, to find what a
//! module answers that no profile lists yet. A whole range is 65 536 requests, so give it the
//! narrowest range that can hold what you're after. See [`docs/scanning.md#sweeps`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/scanning.md#sweeps).

use std::ops::RangeInclusive;
use std::time::Duration;

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
    /// Read in the extended diagnostic session, with these S3 timings. `None`, the default,
    /// reads in the default session.
    pub extended: Option<S3>,
    /// Wait up to this long for each reply, or as near to it as the transport can
    /// ([`Transport::patient`], such as [`crate::discover::PATIENT_WAIT`]), so a module that
    /// answers slowly isn't taken as silent and its late answer as the next read's. Each read
    /// then takes longer. Patience ends afterwards whatever happens. `None`, the default, waits
    /// as usual.
    pub patient: Option<Duration>,
}

/// What a sweep found, and where it stopped if it didn't finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// Each DID the module has, in order: its value, or why it refused it. A DID refused as out
    /// of range (NRC 0x31) isn't listed. One with no final answer is listed as
    /// [`ReadError::NoReply`] or [`ReadError::StillPending`]; if the sweep stopped before an
    /// answer came after it, [`Stop::at`] is at or before it.
    pub found: Vec<(u16, Result<Vec<u8>, ReadError>)>,
    /// Where the sweep stopped early, if it did: sweep again from [`Stop::at`] to go on.
    pub stop: Option<Stop>,
    /// With [`SweepOptions::extended`]: why the module may still be in the extended session
    /// afterwards, as it refused `10 01` or didn't answer it.
    pub still_extended: Option<ReadError>,
    /// Whether a read, or with [`SweepOptions::extended`] a session request, went without a
    /// definite answer ([`crate::Left::out_of_step`]), so an answer may still arrive and be taken
    /// for a later request's. Connect again before reading from this module again.
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
    /// The module stopped answering ([`QUIET_LIMIT`] unanswered reads in a row), refused `22`
    /// itself (not supported, or a bad format), said it was busy (NRC 0x21: sweep again from
    /// [`Stop::at`] a little later), rejected a DID with no reason (NRC 0x10: that DID is
    /// listed and [`Stop::at`] is the next one), or refused or didn't confirm the extended
    /// session.
    Module(ReadError),
    /// After a DID went unanswered, a later read got a refusal or an undecodable reply, which
    /// may be the late answer to the earlier one. Sweeping again from [`Stop::at`] on a fresh
    /// connection asks that DID first.
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

// Refusals of the request as a whole rather than of one DID (ISO 14229-1), so every later read
// would get the same; busy included, as asking again at once would only keep the module busy.
const SERVICE_REFUSALS: [Nrc; 6] = [
    Nrc::BusyRepeatRequest,
    Nrc::ServiceNotSupported,
    Nrc::SubFunctionNotSupported,
    Nrc::IncorrectMessageLength,
    Nrc::SubFunctionNotSupportedInActiveSession,
    Nrc::ServiceNotSupportedInActiveSession,
];

/// How many DIDs in a row may go without a final answer (no reply, or response-pending past
/// [`Timing::max_pending`]) before a sweep stops.
pub const QUIET_LIMIT: usize = 3;

/// Reads each DID in `range` from `module`, in order, and returns those it has.
///
/// Every read is approved by `policy` before the first is sent, and with
/// [`SweepOptions::extended`] so are the session's own requests; the policy must then know the
/// module's reply ID, or [`FingerprintError::Session`] is returned with nothing sent. The sweep
/// stops early, keeping what it found ([`Stop`]).
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
/// timed out. Resume from [`Stop::at`], not the last DID reported.
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
    progress: impl FnMut(u16),
) -> Result<Sweep, FingerprintError> {
    let target = Target::physical(module.request_id);
    let approve = |payload: &[u8]| {
        policy
            .approve(Protocol::Uds, target, payload)
            .map_err(FingerprintError::Rejected)
    };
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
    if options.extended.is_some() {
        // What `ExtendedSession` sends, approved now so nothing is sent if it can't be.
        let enter = approve(&uds::session_control(DiagnosticSession::Extended))?;
        approve(&uds::tester_present())?;
        approve(&uds::session_control(DiagnosticSession::Default))?;
        if enter.reply_id().is_none() {
            return Err(FingerprintError::Session(SessionError::UnknownReplyId));
        }
    }
    let Some(wait) = options.patient else {
        return Ok(sweep_approved(
            transport, policy, module, &requests, timing, options, progress,
        ));
    };
    let timing = match transport.patient(Some(wait)) {
        Ok(waits) => Timing {
            p2: timing.p2.max(waits.unwrap_or(wait)),
            ..timing
        },
        Err(e) => {
            // It may have changed part of the adapter's timing before failing: undo what it can.
            let _ = transport.patient(None);
            return Ok(halt(Vec::new(), first, Why::Adapter(e), false));
        }
    };
    let sweep = sweep_approved(
        transport, policy, module, &requests, timing, options, progress,
    );
    Ok(match transport.patient(None) {
        Ok(_) => sweep,
        Err(e) => with_adapter_failure(sweep, e, *range.end()),
    })
}

// The sweep once every request it may send is approved. `requests` isn't empty.
fn sweep_approved<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    requests: &[(u16, obdcracker_safety::Approved)],
    timing: Timing,
    options: &SweepOptions,
    mut progress: impl FnMut(u16),
) -> Sweep {
    let target = Target::physical(module.request_id);
    let (first, last) = (requests[0].0, requests[requests.len() - 1].0);
    if let Some(s3) = options.extended {
        let mut session = match ExtendedSession::enter(transport, policy, target, timing, s3) {
            Ok(session) => session,
            // `still_extended` reports why a session that may have been entered wasn't left.
            Err(e) => {
                // Only a plain refusal is a definite answer; after anything else, the late
                // answer to `10 03` or `10 01` may still arrive.
                let out_of_step = !matches!(&e, SessionError::Refused(reply) if crate::session::plainly_refused(reply));
                let (entry, still_extended) = match e {
                    SessionError::Unconfirmed { entry, leave } => {
                        (*entry, session_error(*leave).ok())
                    }
                    e => (e, None),
                };
                return Sweep {
                    still_extended,
                    found: Vec::new(),
                    stop: Some(Stop {
                        at: first,
                        why: stopped(session_error(entry)),
                    }),
                    out_of_step,
                };
            }
        };
        let sweep = read_each(&mut session, requests, &mut progress);
        let left = session.end();
        let retried = matches!(left, Err(SessionError::Retried(_)));
        return match left.map_err(session_error) {
            Err(Ok(e)) => Sweep {
                still_extended: Some(e),
                out_of_step: sweep.out_of_step || retried,
                ..sweep
            },
            Err(Err(FingerprintError::Transport(e))) => with_adapter_failure(sweep, e, last),
            Ok(left) => Sweep {
                out_of_step: sweep.out_of_step || left.out_of_step,
                ..sweep
            },
            // The other failures can't happen: the session's requests were approved up front.
            Err(Err(_)) => sweep,
        };
    }
    let mut direct = Direct {
        transport,
        response_id: module.response_id,
        timing,
    };
    read_each(&mut direct, requests, &mut progress)
}

// An adapter failure after the reads leaves it in an unknown state, so it outranks why the sweep
// stopped.
fn with_adapter_failure(sweep: Sweep, e: Error, last: u16) -> Sweep {
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
            at: last,
            why: Why::Adapter(e),
        },
    };
    Sweep {
        stop: Some(stop),
        ..sweep
    }
}

fn stopped(failure: Result<ReadError, FingerprintError>) -> Why {
    match failure {
        Ok(e) => Why::Module(e),
        Err(FingerprintError::Transport(e)) => Why::Adapter(e),
        // Approved up front with the same policy and target, so not expected; still a stop.
        Err(e) => Why::Adapter(Error::Adapter(e.to_string())),
    }
}

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
    // DIDs with no final answer since the last answer: each ends up listed or covered by `Stop::at`.
    let mut quiet: Vec<(u16, ReadError)> = Vec::new();
    let mut out_of_step = false;
    let unanswered = |quiet: &mut Vec<(u16, ReadError)>| {
        quiet
            .drain(..)
            .map(|(did, e)| (did, Err(e)))
            .collect::<Vec<_>>()
    };
    for (did, request) in requests {
        // Where to resume: the first unanswered DID.
        let resume = quiet.first().map_or(*did, |(did, _)| *did);
        let answer = asker.ask_sent(request, |payload| {
            Ok(uds::decode_did(payload, *did)?.to_vec())
        });
        let value = match answer {
            Ok((true, value)) => {
                progress(*did);
                value
            }
            // Keepalive or re-entry failed before the read was sent: stop here, or a caller
            // checkpointing on progress would skip this DID.
            Ok((false, value)) => {
                let e = value.err().unwrap_or(ReadError::NoReply);
                return halt(found, resume, Why::Module(e), out_of_step);
            }
            Err(e) => {
                return halt(found, resume, stopped(Err(e)), out_of_step);
            }
        };
        // After an unanswered read, a refusal or undecodable reply may be its late answer, even
        // past answers that were plainly this connection's own (docs/scanning.md#sweeps).
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
            // Not there, but the module answered, so earlier unanswered DIDs are listed.
            Err(ReadError::Reply(ReplyError::Negative(refusal)))
                if refusal.nrc == Nrc::RequestOutOfRange =>
            {
                found.extend(unanswered(&mut quiet));
            }
            // No reason given, so it may be every DID's answer: list it and stop after it.
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
    found.extend(unanswered(&mut quiet));
    Sweep {
        found,
        stop: None,
        still_extended: None,
        out_of_step,
    }
}
