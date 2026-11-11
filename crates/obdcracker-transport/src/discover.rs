//! Looking for modules a vehicle profile doesn't list: each candidate request ID gets one read of
//! its spare part number (UDS `22 F187`), and whatever answers, a refusal included, is there.

use obdcracker_core::uds::{self, did};
use obdcracker_safety::{ModuleIds, Policy, Protocol, Rejection, Target};

use crate::fingerprint::{DidValue, FingerprintError, ReadError, ask, decode_did_value};
use std::time::Duration;

use crate::voltage::{LowVoltage, VoltageWatch};
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

/// What [`discover_with`] does beyond reading every candidate once at the transport's usual pace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoverOptions {
    /// Wait up to this long for each reply, or as near to it as the transport can
    /// ([`Transport::patient`]), as [`discover_patiently`] does. `None`, the default, waits as
    /// usual.
    pub patient: Option<Duration>,
    /// Re-check the supply voltage every so many candidates and stop when it is too low
    /// ([`Discovered::low_voltage`]). The count starts again with each call. `None`, the default,
    /// never checks.
    pub voltage_watch: Option<VoltageWatch>,
}

/// What [`discover_with`] found, and whether it stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Each module that answered, in the order the candidates were asked.
    pub found: Vec<Found>,
    /// With [`DiscoverOptions::patient`], how long the transport waited for each reply.
    pub waited: Option<Duration>,
    /// Set if the supply voltage was too low when [`DiscoverOptions::voltage_watch`] re-checked
    /// it: the candidates after [`LowVoltage::after`] weren't asked.
    pub low_voltage: Option<LowVoltage>,
}

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
    let options = DiscoverOptions {
        patient: Some(wait),
        ..DiscoverOptions::default()
    };
    let discovered = discover_with(transport, policy, candidates, timing, &options)?;
    Ok((discovered.found, discovered.waited.unwrap_or(wait)))
}

/// [`discover`] with `options`: patience as [`discover_patiently`] has it, and a watch on the
/// supply voltage that stops discovery early, keeping what answered.
///
/// # Errors
///
/// As [`discover_patiently`] when it is patient, else as [`discover`].
pub fn discover_with<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    candidates: &[ModuleIds],
    timing: Timing,
    options: &DiscoverOptions,
) -> Result<Discovered, FingerprintError> {
    let Some(wait) = options.patient else {
        let (found, low_voltage) =
            discover_watching(transport, policy, candidates, timing, options.voltage_watch)?;
        return Ok(Discovered {
            found,
            waited: None,
            low_voltage,
        });
    };
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
    let found = discover_watching(transport, policy, candidates, timing, options.voltage_watch);
    let ended = transport.patient(None).map_err(FingerprintError::Transport);
    let (found, low_voltage) = found?;
    ended?;
    Ok(Discovered {
        found,
        waited: Some(waits),
        low_voltage,
    })
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
    discover_watching(transport, policy, candidates, timing, None).map(|(found, _)| found)
}

// Discovery, stopping early if `watch` finds the supply voltage too low.
fn discover_watching<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    candidates: &[ModuleIds],
    timing: Timing,
    watch: Option<VoltageWatch>,
) -> Result<(Vec<Found>, Option<LowVoltage>), FingerprintError> {
    let requests = candidates
        .iter()
        .map(|candidate| {
            let request = policy
                .approve(
                    Protocol::Uds,
                    Target::physical(candidate.request),
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
    for (done, (candidate, request)) in requests.into_iter().enumerate() {
        if let Some(low) =
            watch.and_then(|watch| watch.stop_after(done, || transport.supply_voltage()))
        {
            return Ok((found, Some(low)));
        }
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
    Ok((found, None))
}
