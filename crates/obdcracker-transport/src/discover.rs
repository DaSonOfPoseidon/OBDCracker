//! Looking for modules a vehicle profile doesn't list: each candidate request ID gets one read of
//! its spare part number (UDS `22 F187`), and whatever answers, a refusal included, is there.

use obdcracker_core::uds::{self, did};
use obdcracker_safety::{ModuleIds, Policy, Rejection, Target};

use crate::fingerprint::{DidValue, FingerprintError, ReadError, ask, decode_did_value};
use std::time::Duration;

use crate::{Timing, Transport};

/// A module that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The CAN ID the request went to.
    pub request_id: u32,
    /// The CAN ID it answered on.
    pub response_id: u32,
    /// Its spare part number (F187), or the refusal it answered with.
    pub part_number: Result<DidValue, ReadError>,
}

/// How long [`discover_patiently`] asks the transport to wait for each reply, for a caller with
/// no better figure: long enough for a module just woken, or one whose replies a gateway routes
/// slowly (an STN chip can wait this long; a plain ELM327 waits about 1 s at most).
pub const PATIENT_WAIT: Duration = Duration::from_secs(5);

/// [`discover`], waiting up to `wait` for each reply, or as near to it as the transport can
/// ([`Transport::patient`]). For candidates a quicker pass may have missed. Returns what answered,
/// and how long the transport waited for each reply. Patience ends afterwards whatever happens,
/// even if the transport failed to become patient; the first error is the one reported.
///
/// # Errors
///
/// As [`discover`], or the transport can't be made patient or stop being so.
pub fn discover_patiently<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    candidates: &[ModuleIds],
    timing: Timing,
    wait: Duration,
) -> Result<(Vec<Found>, Duration), FingerprintError> {
    let waits = match transport.patient(Some(wait)) {
        Ok(waits) => waits.unwrap_or(wait),
        Err(error) => {
            // It may have changed part of the adapter's timing before failing: undo what it can.
            let _ = transport.patient(None);
            return Err(FingerprintError::Transport(error));
        }
    };
    let timing = Timing {
        p2: timing.p2.max(waits),
        ..timing
    };
    let found = discover(transport, policy, candidates, timing);
    let ended = transport.patient(None).map_err(FingerprintError::Transport);
    let found = found?;
    ended?;
    Ok((found, waits))
}

/// Reads the spare part number from each candidate, in order, and returns those that answered.
///
/// `policy` must be narrowed to the candidates (as `Profile::narrow_for_discovery` does), so
/// each request goes only to a candidate's request ID and carries its reply ID, which the
/// adapter then listens for alone. Every request is approved before the first is sent: a
/// candidate the policy refuses, or gives another reply ID, stops discovery with nothing sent.
/// A timeout only means nothing is there; an adapter error stops discovery.
pub fn discover<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    candidates: &[ModuleIds],
    timing: Timing,
) -> Result<Vec<Found>, FingerprintError> {
    let requests = candidates
        .iter()
        .map(|candidate| {
            let request = policy
                .approve(
                    Target::Physical(candidate.request),
                    &uds::read_did(did::SPARE_PART_NUMBER),
                )
                .map_err(FingerprintError::Rejected)?;
            // The reply ID the adapter will listen for must be the one the candidate answers on.
            if request.reply_id() != Some(candidate.reply) {
                return Err(FingerprintError::Rejected(Rejection::WrongTarget));
            }
            Ok((candidate, request))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut found = Vec::new();
    for (candidate, request) in requests {
        let part_number = ask(transport, &request, candidate.reply, timing, |payload| {
            decode_did_value(payload, did::SPARE_PART_NUMBER)
        })?;
        if part_number != Err(ReadError::NoReply) {
            found.push(Found {
                request_id: candidate.request,
                response_id: candidate.reply,
                part_number,
            });
        }
    }
    Ok(found)
}
