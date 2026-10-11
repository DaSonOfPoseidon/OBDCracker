//! Looking for modules a vehicle profile doesn't list: each candidate request ID gets one read of
//! its spare part number (UDS `22 F187`), and whatever answers, a refusal included, is there.

use obdcracker_core::uds::{self, did};
use obdcracker_safety::{ModuleIds, Policy, Rejection, Target};

use crate::fingerprint::{DidValue, FingerprintError, ReadError, ask, decode_did_value};
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
