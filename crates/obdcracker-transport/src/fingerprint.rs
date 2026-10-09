//! Identifying the software on a car: calibration IDs, CVNs and identification DIDs.

use std::fmt;

use obdcracker_core::obd::{self, Cvn};
use obdcracker_core::response;
use obdcracker_core::uds::{self, did};
use obdcracker_safety::{Approved, Policy, Rejection, Target};

use crate::{Error, Expect, Response, Timing, Transport, exchange};

/// The identification DIDs read from each module, in this order: spare part number (F187),
/// software number (F188), software version (F189), hardware number (F191) and ODX file (F19E).
pub const IDENTIFICATION_DIDS: [u16; 5] = [
    did::SPARE_PART_NUMBER,
    did::SOFTWARE_NUMBER,
    did::SOFTWARE_VERSION,
    did::HARDWARE_NUMBER,
    did::ODX_FILE,
];

/// A module to identify over UDS, by its CAN IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdsModule {
    /// What to call it in the results, such as `engine`.
    pub name: String,
    /// The CAN ID requests go to.
    pub request_id: u32,
    /// The CAN ID it answers on.
    pub response_id: u32,
}

impl Fingerprint {
    /// Whether anything answered at all: a calibration ID, CVN or DID value, or a refusal.
    /// False means the car (or the adapter's link to it) was silent.
    #[must_use]
    pub fn anything_answered(&self) -> bool {
        let answered = |e: &ReadError| *e != ReadError::NoReply;
        !self.ecus.is_empty()
            || self
                .modules
                .iter()
                .flat_map(|m| &m.dids)
                .any(|(_, value)| value.as_ref().err().is_none_or(answered))
    }
}

impl UdsModule {
    /// The engine ECU at its OBD-II address (request 0x7E0, reply 0x7E8, ISO 15765-4).
    #[must_use]
    pub fn obd_engine() -> Self {
        Self {
            name: "engine".to_owned(),
            request_id: 0x7E0,
            response_id: 0x7E8,
        }
    }

    /// The transmission ECU at its OBD-II address (request 0x7E1, reply 0x7E9, ISO 15765-4).
    #[must_use]
    pub fn obd_transmission() -> Self {
        Self {
            name: "transmission".to_owned(),
            request_id: 0x7E1,
            response_id: 0x7E9,
        }
    }
}

/// What identifies the software on a car: each emissions ECU's calibration IDs and CVNs, and
/// each module's identification DIDs. A tune changes the CVNs, and usually the calibration IDs
/// and software versions too, so comparing fingerprints shows what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Every ECU that answered OBD-II mode 09 PID 04 or 06, by reply CAN ID.
    pub ecus: Vec<Calibration>,
    /// The modules asked for, in the order given.
    pub modules: Vec<Identification>,
}

/// One emissions ECU's calibrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calibration {
    /// The CAN ID the ECU answered on.
    pub source: u32,
    /// Its calibration IDs (mode 09 PID 04).
    pub calids: Result<Vec<String>, ReadError>,
    /// Its calibration verification numbers (mode 09 PID 06), one per calibration ID, in the same
    /// order. [`ReadError::CountMismatch`] if the counts differ.
    pub cvns: Result<Vec<Cvn>, ReadError>,
}

/// One module's identification DIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identification {
    /// The module's name, from [`UdsModule::name`].
    pub name: String,
    /// The CAN ID it answers on.
    pub response_id: u32,
    /// Each of [`IDENTIFICATION_DIDS`] and its text, without padding.
    pub dids: Vec<(u16, Result<String, ReadError>)>,
}

/// Why one value is missing from a fingerprint. Modules often don't support every DID, so this
/// doesn't stop the others being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// Nothing answered in time.
    NoReply,
    /// The reply was a refusal or couldn't be decoded.
    Reply(response::Error),
    /// The CVNs don't pair with the calibration IDs: J1979 gives one CVN per calibration ID, so
    /// neither can be trusted to say which calibration a CVN checks. The raw replies are in the
    /// audit log.
    CountMismatch {
        /// How many calibration IDs the ECU reported.
        calids: usize,
        /// How many CVNs it reported.
        cvns: usize,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReply => f.write_str("no reply"),
            Self::Reply(e) => e.fmt(f),
            Self::CountMismatch { calids, cvns } => {
                write!(f, "{cvns} CVNs for {calids} calibration IDs")
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// Why a fingerprint couldn't be taken at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    /// The policy refused a request. Every request is approved before anything is sent, so
    /// nothing reached the bus.
    Rejected(Rejection),
    /// The adapter failed. What was read before then is lost; the audit log has it.
    Transport(Error),
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(rejection) => write!(f, "safety policy {rejection}"),
            Self::Transport(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for FingerprintError {}

/// Reads a car's [`Fingerprint`]: mode 09 PIDs 04 and 06 from every emissions ECU, then each of
/// [`IDENTIFICATION_DIDS`] from each module, one DID per request so no DID lengths are needed.
///
/// Every request is approved by `policy` before the first is sent. A timeout or refusal only
/// loses that value; an adapter error stops the fingerprint.
pub fn fingerprint<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    modules: &[UdsModule],
    timing: Timing,
) -> Result<Fingerprint, FingerprintError> {
    let approve = |target, payload: &[u8]| {
        policy
            .approve(target, payload)
            .map_err(FingerprintError::Rejected)
    };
    let calid_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x04))?;
    let cvn_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x06))?;
    let did_requests = modules
        .iter()
        .map(|module| {
            IDENTIFICATION_DIDS
                .iter()
                .map(|&did| {
                    Ok((
                        did,
                        approve(Target::Physical(module.request_id), &uds::read_did(did))?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let calids = broadcast(transport, &calid_request, timing)?;
    let cvns = broadcast(transport, &cvn_request, timing)?;
    let mut sources: Vec<u32> = calids.iter().chain(&cvns).map(|r| r.source).collect();
    sources.sort_unstable();
    sources.dedup();
    let ecus = sources
        .into_iter()
        .map(|source| {
            let calids: Result<Vec<String>, _> = from(&calids, source, |payload| {
                obd::decode_calids(payload)?
                    .map(|calid| calid.map(str::to_owned))
                    .collect()
            });
            let cvns = match from(&cvns, source, |payload| -> Result<Vec<Cvn>, _> {
                Ok(obd::decode_cvns(payload)?.collect())
            }) {
                Ok(cvns) => match &calids {
                    Ok(ids) if ids.len() != cvns.len() => Err(ReadError::CountMismatch {
                        calids: ids.len(),
                        cvns: cvns.len(),
                    }),
                    _ => Ok(cvns),
                },
                Err(e) => Err(e),
            };
            Calibration {
                source,
                calids,
                cvns,
            }
        })
        .collect();

    let mut identified = Vec::with_capacity(modules.len());
    for (module, requests) in modules.iter().zip(did_requests) {
        let mut dids = Vec::with_capacity(requests.len());
        for (did, request) in requests {
            let value = match exchange(
                transport,
                &request,
                Expect::Module(module.response_id),
                timing,
            ) {
                Ok(replies) => replies.first().map_or(Err(ReadError::NoReply), |reply| {
                    uds::decode_did(&reply.payload, did)
                        .and_then(uds::decode_text)
                        .map(str::to_owned)
                        .map_err(ReadError::Reply)
                }),
                Err(Error::Timeout) => Err(ReadError::NoReply),
                Err(e) => return Err(FingerprintError::Transport(e)),
            };
            dids.push((did, value));
        }
        identified.push(Identification {
            name: module.name.clone(),
            response_id: module.response_id,
            dids,
        });
    }
    Ok(Fingerprint {
        ecus,
        modules: identified,
    })
}

// Every emissions ECU's answer to a broadcast.
fn broadcast<T: Transport + ?Sized>(
    transport: &mut T,
    request: &Approved,
    timing: Timing,
) -> Result<Vec<Response>, FingerprintError> {
    exchange(transport, request, Expect::ObdEcus, timing).map_err(FingerprintError::Transport)
}

// Decodes `source`'s reply among `replies`, or NoReply if it didn't answer.
fn from<V>(
    replies: &[Response],
    source: u32,
    decode: impl FnOnce(&[u8]) -> Result<V, response::Error>,
) -> Result<V, ReadError> {
    let reply = replies
        .iter()
        .find(|r| r.source == source)
        .ok_or(ReadError::NoReply)?;
    decode(&reply.payload).map_err(ReadError::Reply)
}
