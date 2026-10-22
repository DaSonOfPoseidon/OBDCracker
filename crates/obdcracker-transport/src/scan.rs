//! A read-only scan: what the default diagnostic session lets a tester read from a car's
//! emissions ECUs over OBD-II, and from each module over UDS.

use std::collections::{BTreeMap, BTreeSet};

use obdcracker_core::obd::{self, Dtc, SupportedPids, Unit, Value};
use obdcracker_core::response::{self, Error as ReplyError};
use obdcracker_core::uds::{self, DiagnosticSession, DtcCount, DtcRecord, did};
use obdcracker_safety::{Approved, Policy, Protocol, Target};

use crate::fingerprint::{
    DidValue, FingerprintError, ReadError, UdsModule, ask, broadcast, decode_did_value, decoded,
    from,
};
use crate::{Error, ExtendedSession, S3, SessionError, Timing, Transport};

/// The identification DIDs (ISO 14229-1 annex C) read from every module, in this order:
/// F187, F188, F189, F18A, F18B, F18C, F190 (VIN), F191, F192, F193, F194, F195, F197, F19E.
pub const SCAN_DIDS: [u16; 14] = [
    did::SPARE_PART_NUMBER,
    did::SOFTWARE_NUMBER,
    did::SOFTWARE_VERSION,
    0xF18A,
    0xF18B,
    0xF18C,
    did::VIN,
    did::HARDWARE_NUMBER,
    0xF192,
    0xF193,
    0xF194,
    0xF195,
    did::SYSTEM_NAME,
    did::ODX_FILE,
];

/// The DTC status bits scan asks for (ISO 14229-1 D.2), without the "not tested" bits.
/// See docs/scanning.md#dtcs.
pub const FAULT_MASK: u8 = 0xAF;

/// Why a scan couldn't be taken at all.
pub type ScanError = FingerprintError;

/// A module to scan, and the DIDs its vehicle profile adds to [`SCAN_DIDS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanModule {
    /// Where it sits on the bus.
    pub module: UdsModule,
    /// More DIDs to read after [`SCAN_DIDS`], or how to show one of them that has no fixed
    /// format, such as F18B. Each DID is read once, in its first entry's format. A DID
    /// ISO 14229-1 makes text ([`did::is_text`]) stays text, and F190 must be a VIN or
    /// [`DidValue::NotSet`].
    pub extra_dids: Vec<ExtraDid>,
}

/// A DID a vehicle profile adds, and how to show its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraDid {
    /// The 2-byte identifier.
    pub id: u16,
    /// How to show its value.
    pub format: DidFormat,
    /// Its value's length in bytes, if the module always sends this many. DIDs with a length
    /// are read up to three to a request (docs/scanning.md#did-batching).
    pub length: Option<u16>,
    /// The diagnostic session the module reads it in. One that needs the extended session is
    /// read only when [`ScanOptions::extended`] asks for it.
    pub session: DiagnosticSession,
}

/// What [`scan_with`] does beyond [`scan`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanOptions {
    /// Read the DIDs that need the extended session ([`ExtraDid::session`]), with these S3
    /// timings ([`ExtendedSession`]). `None`, the default, changes no module's session, and
    /// those DIDs are [`ReadError::NeedsExtendedSession`].
    pub extended: Option<S3>,
}

/// How to show a DID's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidFormat {
    /// Text, or the bytes if they aren't printable.
    Text,
    /// Always the bytes, even when they happen to be printable, such as a coding value.
    Hex,
}

/// Everything a scan read.
#[derive(Debug, Clone, PartialEq)]
pub struct Scan {
    /// Every ECU that answered an OBD-II request, by reply CAN ID.
    pub ecus: Vec<ObdEcu>,
    /// The modules asked for, in the order given.
    pub modules: Vec<ModuleScan>,
}

impl Scan {
    /// Whether anything answered at all, a refusal included. False means the car (or the
    /// adapter's link to it) was silent.
    #[must_use]
    pub fn anything_answered(&self) -> bool {
        !self.ecus.is_empty() || self.modules.iter().any(|m| m.answered)
    }
}

/// A mode 01 PID and its value.
pub type PidReading = (u8, Result<PidValue, ReadError>);

/// One emissions ECU's OBD-II data.
#[derive(Debug, Clone, PartialEq)]
pub struct ObdEcu {
    /// The CAN ID the ECU answered on.
    pub source: u32,
    /// Each mode 01 PID the ECU says it supports, other than the bitmap PIDs (00, 20, …), and
    /// its value. An error if its first bitmap (PID 00) was missing or couldn't be decoded. A
    /// later bitmap that's missing or garbled ends its list there ([`ObdEcu::pids_cut_short`]).
    pub pids: Result<Vec<PidReading>, ReadError>,
    /// Where its PID list was cut short, if it was: the later bitmap PID (20, 40, …) it said it
    /// supports but that was missing or couldn't be decoded, and why. No PID from that page on
    /// was read.
    pub pids_cut_short: Option<(u8, ReadError)>,
    /// The mode 09 PIDs it supports (mode 09 PID 00).
    pub supported_info: Result<Vec<u8>, ReadError>,
    /// Its name (mode 09 PID 0A), as `acronym-name`, such as `ECM-EngineControl`.
    pub ecu_name: Result<String, ReadError>,
    /// Its stored emissions DTCs (mode 03).
    pub stored_dtcs: Result<Vec<Dtc>, ReadError>,
}

/// A mode 01 PID's value.
#[derive(Debug, Clone, PartialEq)]
pub enum PidValue {
    /// A physical quantity.
    Quantity {
        /// The value, scaled per SAE J1979.
        value: f32,
        /// Its unit.
        unit: Unit,
    },
    /// A PID that isn't decoded yet: its data bytes, as received.
    Raw(Vec<u8>),
}

/// One module's identification and DTCs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleScan {
    /// The module's name, from [`UdsModule::name`].
    pub name: String,
    /// The CAN ID it answers on.
    pub response_id: u32,
    /// Each of [`SCAN_DIDS`], then each of [`ScanModule::extra_dids`], and its value. Batching
    /// and re-reads: docs/scanning.md#did-batching.
    pub dids: Vec<(u16, Result<DidValue, ReadError>)>,
    /// How it encodes DTCs, and how many have a [`FAULT_MASK`] bit set (`ReadDTCInformation`
    /// 0x01).
    pub dtc_count: Result<DtcCount, ReadError>,
    /// Its DTCs with a [`FAULT_MASK`] bit set, and their status (`ReadDTCInformation` 0x02).
    /// Only bits the module says it supports count.
    pub dtcs: Result<Vec<DtcRecord>, ReadError>,
    /// Whether the module answered anything at all, a refusal included. It can be true when
    /// every value above is [`ReadError::NoReply`] (docs/scanning.md#did-batching).
    pub answered: bool,
}

/// Scans a car, reading only: OBD-II from every emissions ECU (the supported PID bitmaps, then
/// each supported mode 01 PID; mode 09 PIDs 00 and 0A; mode 03), then each module's DIDs and
/// DTCs over UDS. It never changes a module's diagnostic session, so DIDs that need the extended
/// session are [`ReadError::NeedsExtendedSession`]; [`scan_with`] can read them.
///
/// Every request it could send is approved by `policy` before the first is sent. A timeout or
/// refusal only loses that value; an adapter error stops the scan.
pub fn scan<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    modules: &[ScanModule],
    timing: Timing,
) -> Result<Scan, ScanError> {
    scan_with(transport, policy, modules, timing, &ScanOptions::default())
}

/// [`scan`], with `options`.
///
/// With [`ScanOptions::extended`], each module with DIDs that need the extended session is put
/// in it (`10 03`) after its other reads and returned to the default session (`10 01`). Those
/// requests are approved before anything is sent too, and the policy must know each such
/// module's reply ID, or [`FingerprintError::Session`] is returned. A module that refuses the
/// session or doesn't answer loses only those DIDs. See docs/scanning.md#when-a-session-fails.
pub fn scan_with<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    modules: &[ScanModule],
    timing: Timing,
    options: &ScanOptions,
) -> Result<Scan, ScanError> {
    let approve = |target, payload: &[u8]| {
        policy
            .approve(Protocol::Uds, target, payload)
            .map_err(FingerprintError::Rejected)
    };
    // Which PIDs are asked for depends on the bitmaps, so all are approved up front.
    let pid_requests = (0..=u8::MAX)
        .map(|pid| approve(Target::ObdFunctional, &obd::current_data(pid)))
        .collect::<Result<Vec<_>, _>>()?;
    let info_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x00))?;
    let name_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x0A))?;
    let dtc_request = approve(Target::ObdFunctional, &obd::stored_dtcs())?;
    let module_requests = modules
        .iter()
        .map(|scanned| module_requests(policy, scanned, options))
        .collect::<Result<Vec<ModuleRequests>, ScanError>>()?;

    let supported = supported_pids(transport, &pid_requests, timing)?;
    let mut values = pid_values(transport, &pid_requests, &supported, timing)?;

    let info = broadcast(transport, &info_request, timing)?;
    let names = broadcast(transport, &name_request, timing)?;
    let dtcs = broadcast(transport, &dtc_request, timing)?;
    let sources: BTreeSet<u32> = supported
        .keys()
        .copied()
        .chain(info.iter().chain(&names).chain(&dtcs).map(|r| r.source))
        .collect();
    let ecus = sources
        .into_iter()
        .map(|source| {
            let (pids, pids_cut_short) = supported
                .get(&source)
                .cloned()
                .unwrap_or((Err(ReadError::NoReply), None));
            ObdEcu {
                source,
                pids: pids.map(|_| values.remove(&source).unwrap_or_default()),
                pids_cut_short,
                supported_info: from(&info, source, |payload| {
                    Ok(obd::decode_supported_info(payload)?.iter().collect())
                }),
                ecu_name: from(&names, source, |payload| {
                    let name = obd::decode_ecu_name(payload)?;
                    Ok(format!("{}-{}", name.acronym, name.name))
                }),
                stored_dtcs: from(&dtcs, source, |payload| {
                    Ok(obd::decode_stored_dtcs(payload)?.collect())
                }),
            }
        })
        .collect();

    let mut scanned = Vec::with_capacity(modules.len());
    for (scanned_module, requests) in modules.iter().zip(module_requests) {
        scanned.push(scan_module(
            transport,
            policy,
            &scanned_module.module,
            &requests,
            timing,
            options,
        )?);
    }
    Ok(Scan {
        ecus,
        modules: scanned,
    })
}

fn module_requests(
    policy: &Policy,
    scanned: &ScanModule,
    options: &ScanOptions,
) -> Result<ModuleRequests, ScanError> {
    let approve = |target, payload: &[u8]| {
        policy
            .approve(Protocol::Uds, target, payload)
            .map_err(FingerprintError::Rejected)
    };
    let target = Target::physical(scanned.module.request_id);
    let did_requests = |dids: Vec<ExtraDid>| {
        let batches = batches_of(&dids)
            .into_iter()
            .map(|batch| {
                let mut payload = vec![uds::READ_DATA_BY_IDENTIFIER];
                for &index in &batch {
                    payload.extend(dids[index].id.to_be_bytes());
                }
                Ok((batch, approve(target, &payload)?))
            })
            .collect::<Result<Vec<_>, ScanError>>()?;
        let dids = dids
            .into_iter()
            .map(|extra| Ok((extra, approve(target, &uds::read_did(extra.id))?)))
            .collect::<Result<Vec<_>, ScanError>>()?;
        Ok::<_, ScanError>(DidRequests { dids, batches })
    };
    let dids = dids_of(scanned);
    let order = dids.iter().map(|did| did.id).collect();
    let (extended, default): (Vec<_>, Vec<_>) = dids
        .into_iter()
        .partition(|did| did.session == DiagnosticSession::Extended);
    let extended = did_requests(extended)?;
    if options.extended.is_some() && !extended.dids.is_empty() {
        // What `ExtendedSession` sends, approved now so nothing is sent if it can't be.
        let enter = approve(target, &uds::session_control(DiagnosticSession::Extended))?;
        approve(target, &uds::tester_present())?;
        approve(target, &uds::session_control(DiagnosticSession::Default))?;
        if enter.reply_id().is_none() {
            return Err(FingerprintError::Session(SessionError::UnknownReplyId));
        }
    }
    Ok(ModuleRequests {
        order,
        default: did_requests(default)?,
        extended,
        count: approve(target, &uds::dtc_count_by_status_mask(FAULT_MASK))?,
        dtcs: approve(target, &uds::dtcs_by_status_mask(FAULT_MASK))?,
    })
}

// `order` is the order the module's DID values are given in.
struct ModuleRequests {
    order: Vec<u16>,
    default: DidRequests,
    extended: DidRequests,
    count: Approved,
    dtcs: Approved,
}

// A read for each DID, and the multi-DID reads (by the indexes of the DIDs they read).
struct DidRequests {
    dids: Vec<(ExtraDid, Approved)>,
    batches: Vec<(Vec<usize>, Approved)>,
}

// Sends one read: straight to the transport, or through an extended session.
pub(crate) trait Ask {
    fn ask<V>(
        &mut self,
        request: &Approved,
        decode: impl FnOnce(&[u8]) -> Result<V, ReplyError>,
    ) -> Result<Result<V, ReadError>, ScanError> {
        self.ask_sent(request, decode).map(|(_, value)| value)
    }

    // `ask`, also saying whether `request` was sent: a session's keepalive can fail before it.
    fn ask_sent<V>(
        &mut self,
        request: &Approved,
        decode: impl FnOnce(&[u8]) -> Result<V, ReplyError>,
    ) -> Result<(bool, Result<V, ReadError>), ScanError>;
}

pub(crate) struct Direct<'a, T: ?Sized> {
    pub(crate) transport: &'a mut T,
    pub(crate) response_id: u32,
    pub(crate) timing: Timing,
}

impl<T: Transport + ?Sized> Ask for Direct<'_, T> {
    fn ask_sent<V>(
        &mut self,
        request: &Approved,
        decode: impl FnOnce(&[u8]) -> Result<V, ReplyError>,
    ) -> Result<(bool, Result<V, ReadError>), ScanError> {
        // Nothing comes before the request, and failing to send it is an adapter failure.
        ask(
            self.transport,
            request,
            self.response_id,
            self.timing,
            decode,
        )
        .map(|value| (true, value))
    }
}

impl<T: Transport + ?Sized> Ask for ExtendedSession<'_, T> {
    fn ask_sent<V>(
        &mut self,
        request: &Approved,
        decode: impl FnOnce(&[u8]) -> Result<V, ReplyError>,
    ) -> Result<(bool, Result<V, ReadError>), ScanError> {
        if let Err(e) = self.keep_alive().and_then(|()| self.prepare(request)) {
            return session_error(e).map(|e| (false, Err(e)));
        }
        match self.exchange_prepared(request) {
            Ok(reply) => Ok((true, decoded(&reply.payload, decode))),
            Err(e) => session_error(e).map(|e| (true, Err(e))),
        }
    }
}

// What a session failure means for the values it was for: a lost answer or refusal loses only
// those, an adapter failure stops the scan. See docs/scanning.md#when-a-session-fails.
pub(crate) fn session_error(e: SessionError) -> Result<ReadError, ScanError> {
    match e {
        SessionError::Transport(Error::Timeout) => Ok(ReadError::NoReply),
        SessionError::Transport(Error::StillPending) => Ok(ReadError::StillPending),
        SessionError::Transport(e) => Err(FingerprintError::Transport(e)),
        // As far as the values go the session wasn't entered; the module leaves by itself after S3.
        SessionError::Unconfirmed { entry, .. } => session_error(*entry),
        // A refusal of `10 03` or `3E 00`, or a positive answer with unusable timing.
        SessionError::Refused(reply) => {
            let sid = match *reply.as_slice() {
                // A refusal: `7F <service ID> <code>`.
                [0x7F, sid, ..] => sid,
                // A positive answer's service ID is the request's plus 0x40.
                [sid, ..] => sid.wrapping_sub(0x40),
                [] => uds::DIAGNOSTIC_SESSION_CONTROL,
            };
            Ok(ReadError::SessionRefused {
                error: response::positive(sid, &reply)
                    .err()
                    .unwrap_or(ReplyError::Malformed),
                reply,
            })
        }
        e => Err(FingerprintError::Session(e)),
    }
}

// Three DIDs (7 bytes) fit one CAN frame, which every adapter driver can send.
const BATCH: usize = 3;
const READ_DIDS_REPLY: u8 = uds::READ_DATA_BY_IDENTIFIER + 0x40;

// The most a short ISO-TP first frame declares.
const MAX_REPLY: usize = 4095;

// Groups the DIDs with a length, in order, up to BATCH a request and as many as one reply can
// carry. A DID left alone, or with length 0, is read on its own.
fn batches_of(dids: &[ExtraDid]) -> Vec<Vec<usize>> {
    let mut batches = Vec::new();
    let mut batch: Vec<usize> = Vec::new();
    let mut reply = 1;
    for (index, did) in dids.iter().enumerate() {
        let Some(length) = did.length.filter(|&length| length > 0) else {
            continue;
        };
        let size = 2 + usize::from(length);
        if batch.len() == BATCH || reply + size > MAX_REPLY {
            batches.push(std::mem::take(&mut batch));
            reply = 1;
        }
        batch.push(index);
        reply += size;
    }
    batches.push(batch);
    batches.retain(|batch| batch.len() > 1);
    batches
}

// Splits a multi-DID reply by the lengths asked for. A module may leave DIDs out (ISO 14229-1),
// but those it sends must come in order, each at its length, with nothing left over.
fn split_batch(payload: &[u8], layout: &[(u16, usize)]) -> Result<Vec<(u16, Vec<u8>)>, ReplyError> {
    let mut rest = response::positive(uds::READ_DATA_BY_IDENTIFIER, payload)?;
    let mut layout = layout.iter();
    let mut values = Vec::new();
    while let [high, low, after @ ..] = rest {
        let id = u16::from_be_bytes([*high, *low]);
        let &(_, length) = layout
            .find(|(want, _)| *want == id)
            .ok_or(ReplyError::Malformed)?;
        let (data, next) = after.split_at_checked(length).ok_or(ReplyError::TooShort)?;
        values.push((id, data.to_vec()));
        rest = next;
    }
    if values.is_empty() || !rest.is_empty() {
        return Err(ReplyError::Malformed);
    }
    Ok(values)
}

// One ECU's supported PIDs so far, the bitmap that comes next, and where its chain broke.
struct Chain {
    pids: Result<Vec<u8>, ReadError>,
    next: Option<u8>,
    cut_short: Option<(u8, ReadError)>,
}

type Supported = (Result<Vec<u8>, ReadError>, Option<(u8, ReadError)>);

// Each ECU that answered the first bitmap and the PIDs it supports, per
// docs/scanning.md#module-discovery. PID E0 is the last bitmap.
fn supported_pids<T: Transport + ?Sized>(
    transport: &mut T,
    pid_requests: &[Approved],
    timing: Timing,
) -> Result<BTreeMap<u32, Supported>, ScanError> {
    let mut chains: BTreeMap<u32, Chain> = BTreeMap::new();
    let mut base = 0u8;
    loop {
        let replies = broadcast(transport, &pid_requests[usize::from(base)], timing)?;
        let after = base.checked_add(0x20);
        for reply in &replies {
            let chain = if base == 0 {
                chains.entry(reply.source).or_insert(Chain {
                    pids: Ok(Vec::new()),
                    next: Some(0),
                    cut_short: None,
                })
            } else {
                match chains.get_mut(&reply.source) {
                    Some(chain) if chain.next == Some(base) => chain,
                    // A page this ECU didn't say it supports.
                    _ => continue,
                }
            };
            chain.next = None;
            match decoded(&reply.payload, |payload| decode_bitmap(payload, base)) {
                Ok(bitmap) => {
                    if let Ok(pids) = &mut chain.pids {
                        pids.extend(bitmap.iter().filter(|pid| pid % 0x20 != 0));
                    }
                    chain.next = after.filter(|&after| bitmap.contains(after));
                }
                Err(e) if base == 0 => chain.pids = Err(e),
                Err(e) => chain.cut_short = Some((base, e)),
            }
        }
        // Said this page comes next but didn't answer it.
        for chain in chains.values_mut() {
            if chain.next == Some(base) {
                chain.next = None;
                chain.cut_short = Some((base, ReadError::NoReply));
            }
        }
        match after {
            Some(after) if chains.values().any(|chain| chain.next == Some(after)) => base = after,
            _ => break,
        }
    }
    Ok(chains
        .into_iter()
        .map(|(source, chain)| (source, (chain.pids, chain.cut_short)))
        .collect())
}

fn pid_values<T: Transport + ?Sized>(
    transport: &mut T,
    pid_requests: &[Approved],
    supported: &BTreeMap<u32, Supported>,
    timing: Timing,
) -> Result<BTreeMap<u32, Vec<PidReading>>, ScanError> {
    let wanted: BTreeSet<u8> = supported
        .values()
        .filter_map(|(pids, _)| pids.as_ref().ok())
        .flatten()
        .copied()
        .collect();
    let mut values: BTreeMap<u32, Vec<PidReading>> = BTreeMap::new();
    for pid in wanted {
        let replies = broadcast(transport, &pid_requests[usize::from(pid)], timing)?;
        for (&source, (pids, _)) in supported {
            if pids.as_ref().is_ok_and(|pids| pids.contains(&pid)) {
                let value = from(&replies, source, |payload| decode_pid_value(payload, pid));
                values.entry(source).or_default().push((pid, value));
            }
        }
    }
    Ok(values)
}

fn scan_module<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    requests: &ModuleRequests,
    timing: Timing,
    options: &ScanOptions,
) -> Result<ModuleScan, ScanError> {
    let response_id = module.response_id;
    let mut direct = Direct {
        transport,
        response_id,
        timing,
    };
    let (mut dids, mut batch_answered) = read_dids(&mut direct, &requests.default)?;
    let dtc_count = direct.ask(&requests.count, uds::decode_dtc_count)?;
    let dtcs = direct.ask(&requests.dtcs, |payload| {
        let (availability, records) = uds::decode_dtcs_by_status_mask(payload)?;
        Ok(records
            .filter(|record| record.status.0 & availability.0 & FAULT_MASK != 0)
            .collect())
    })?;
    let replied =
        |e: &ReadError| !matches!(e, ReadError::NoReply | ReadError::NeedsExtendedSession);
    let answered = |dids: &[(u16, Result<DidValue, ReadError>)], batch_answered| {
        batch_answered
            || dids
                .iter()
                .any(|(_, value)| value.as_ref().err().is_none_or(replied))
            || dtc_count.as_ref().err().is_none_or(replied)
            || dtcs.as_ref().err().is_none_or(replied)
    };
    let extended = &requests.extended;
    if !extended.dids.is_empty() {
        let unread = |e: ReadError| {
            extended
                .dids
                .iter()
                .map(move |(did, _)| (did.id, Err(e.clone())))
        };
        match options.extended {
            None => dids.extend(unread(ReadError::NeedsExtendedSession)),
            // A module that answered nothing isn't there: no session to enter.
            Some(_) if !answered(&dids, batch_answered) => dids.extend(unread(ReadError::NoReply)),
            Some(s3) => {
                let target = Target::physical(module.request_id);
                match ExtendedSession::enter(transport, policy, target, timing, s3) {
                    Ok(mut session) => {
                        let (values, answered) = read_dids(&mut session, extended)?;
                        dids.extend(values);
                        batch_answered |= answered;
                        // A module that doesn't confirm `10 01` leaves the session after S3.
                        if let Err(e) = session.end() {
                            session_error(e)?;
                        }
                    }
                    // Dropping a session that may have been entered sent `10 01`.
                    Err(e) => dids.extend(unread(session_error(e)?)),
                }
            }
        }
    }
    let answered = answered(&dids, batch_answered);
    // Each session's values were read apart: back to SCAN_DIDS, then the profile's.
    dids.sort_by_key(|(id, _)| requests.order.iter().position(|did| did == id));
    Ok(ModuleScan {
        name: module.name.clone(),
        response_id,
        dids,
        dtc_count,
        dtcs,
        answered,
    })
}

// Reads each DID in `requests`, and whether any multi-DID read got an answer, which the values
// may not show.
#[allow(clippy::type_complexity)]
fn read_dids(
    asker: &mut impl Ask,
    requests: &DidRequests,
) -> Result<(Vec<(u16, Result<DidValue, ReadError>)>, bool), ScanError> {
    let did_requests = &requests.dids;
    let mut values: Vec<Option<Result<DidValue, ReadError>>> = vec![None; did_requests.len()];
    let mut batch_answered = false;
    for index in 0..did_requests.len() {
        if values[index].is_some() {
            continue;
        }
        // A multi-DID read goes where its first DID comes.
        let Some((batch, request)) = requests.batches.iter().find(|(b, _)| b[0] == index) else {
            let (ExtraDid { id, format, .. }, request) = &did_requests[index];
            values[index] =
                Some(asker.ask(request, |payload| decode_scanned(payload, *id, *format))?);
            continue;
        };
        let layout: Vec<(u16, usize)> = batch
            .iter()
            .filter_map(|&i| {
                let did = did_requests[i].0;
                Some((did.id, usize::from(did.length?)))
            })
            .collect();
        // On a refusal, silence or a misfit reply, every DID in it is read alone next.
        let found = asker.ask(request, |payload| split_batch(payload, &layout))?;
        batch_answered |= found.as_ref().err() != Some(&ReadError::NoReply);
        let found = found.unwrap_or_default();
        for (id, data) in found {
            if let Some(&i) = batch.iter().find(|&&i| did_requests[i].0.id == id) {
                let mut single = vec![READ_DIDS_REPLY];
                single.extend(id.to_be_bytes());
                single.extend(data);
                let format = did_requests[i].0.format;
                values[i] = Some(decoded(&single, |single| {
                    decode_scanned(single, id, format)
                }));
            }
        }
        // Then the DIDs it left out. A late multi-DID reply could pass for the first DID's, so
        // each must be exactly its length (docs/scanning.md#did-batching).
        for &i in batch {
            if values[i].is_none() {
                let (
                    ExtraDid {
                        id, format, length, ..
                    },
                    request,
                ) = &did_requests[i];
                values[i] = Some(asker.ask(request, |payload| {
                    let data = uds::decode_did(payload, *id)?;
                    if length.is_some_and(|length| data.len() != usize::from(length)) {
                        return Err(ReplyError::Malformed);
                    }
                    decode_scanned(payload, *id, *format)
                })?);
            }
        }
    }
    let dids = did_requests
        .iter()
        .zip(values)
        .map(|((did, _), value)| (did.id, value.unwrap_or(Err(ReadError::NoReply))))
        .collect();
    Ok((dids, batch_answered))
}

// SCAN_DIDS, then the module's other extra DIDs, each once, as docs/scanning.md#did-batching says.
fn dids_of(scanned: &ScanModule) -> Vec<ExtraDid> {
    let mut dids: Vec<ExtraDid> = SCAN_DIDS
        .iter()
        .map(|&id| ExtraDid {
            id,
            format: DidFormat::Text,
            length: None,
            session: DiagnosticSession::Default,
        })
        .collect();
    let mut seen = BTreeSet::new();
    for &extra in &scanned.extra_dids {
        if !seen.insert(extra.id) {
            continue;
        }
        match dids.iter_mut().find(|did| did.id == extra.id) {
            Some(did) => {
                did.length = extra.length;
                did.session = extra.session;
                if !did::is_text(did.id) {
                    did.format = extra.format;
                }
            }
            None => dids.push(extra),
        }
    }
    dids
}

// ISO 14229-1 makes F190 a VIN, so anything there but a VIN or the placeholder is malformed.
fn decode_scanned(payload: &[u8], id: u16, format: DidFormat) -> Result<DidValue, ReplyError> {
    match format {
        DidFormat::Text if id == did::VIN => {
            let data = uds::decode_did(payload, id)?;
            if obd::is_vin_placeholder(data) {
                return Ok(DidValue::NotSet);
            }
            Ok(DidValue::Text(obd::check_vin(data)?.to_owned()))
        }
        DidFormat::Text => decode_did_value(payload, id),
        DidFormat::Hex => Ok(DidValue::Bytes(uds::decode_did(payload, id)?.to_vec())),
    }
}

fn single_reading(payload: &[u8], pid: u8) -> Result<Value<'_>, ReplyError> {
    let mut readings = obd::decode_current_data(payload)?;
    let reading = readings.next().ok_or(ReplyError::TooShort)??;
    if reading.pid != pid || readings.next().is_some() {
        return Err(ReplyError::Malformed);
    }
    Ok(reading.value)
}

fn decode_bitmap(payload: &[u8], base: u8) -> Result<SupportedPids, ReplyError> {
    match single_reading(payload, base)? {
        Value::Supported(bitmap) => Ok(bitmap),
        _ => Err(ReplyError::Malformed),
    }
}

fn decode_pid_value(payload: &[u8], pid: u8) -> Result<PidValue, ReplyError> {
    match single_reading(payload, pid)? {
        Value::Quantity { value, unit } => Ok(PidValue::Quantity { value, unit }),
        Value::Raw(data) => Ok(PidValue::Raw(data.to_vec())),
        Value::Supported(_) => Err(ReplyError::Malformed),
    }
}
