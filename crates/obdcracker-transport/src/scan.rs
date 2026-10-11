//! A read-only scan: what the default diagnostic session lets a tester read from a car's
//! emissions ECUs over OBD-II, and from each module over UDS.

use std::collections::{BTreeMap, BTreeSet};

use obdcracker_core::obd::{self, Dtc, SupportedPids, Unit, Value};
use obdcracker_core::response::Error as ReplyError;
use obdcracker_core::uds::{self, DtcCount, DtcRecord, did};
use obdcracker_safety::{Approved, Policy, Target};

use crate::fingerprint::{
    DidValue, FingerprintError, ReadError, UdsModule, ask, broadcast, decode_did_value, from,
};
use crate::{Timing, Transport};

/// The identification DIDs (ISO 14229-1 annex C) read from every module, in this order: spare
/// part number (F187), software number (F188), software version (F189), system supplier
/// (F18A), manufacture date (F18B), serial number (F18C), VIN (F190), hardware number (F191),
/// supplier hardware number and version (F192, F193), supplier software number and version
/// (F194, F195), system name (F197) and ODX file (F19E).
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

/// The DTC status bits scan asks for (ISO 14229-1 D.2): failed, failed this operation cycle,
/// pending, confirmed, failed since the last clear (an intermittent fault that passes now) and
/// warning lamp. The "not tested" bits are left out: with them, a module lists every DTC it has
/// never tested, which on the A7 is its whole DTC table (#49).
pub const FAULT_MASK: u8 = 0xAF;

/// Why a scan couldn't be taken at all.
pub type ScanError = FingerprintError;

/// A module to scan, and the DIDs its vehicle profile adds to [`SCAN_DIDS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanModule {
    /// Where it sits on the bus.
    pub module: UdsModule,
    /// More DIDs to read after [`SCAN_DIDS`], such as VAG's F1A3 or 0600, or how to show one of
    /// [`SCAN_DIDS`] that has no fixed format, such as the manufacture date (F18B). Each DID is
    /// read once, however often it's listed, in its first entry's format. A DID ISO 14229-1
    /// makes text ([`did::is_text`]) stays text, and F190 must be a VIN.
    pub extra_dids: Vec<ExtraDid>,
}

/// A DID a vehicle profile adds, and how to show its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraDid {
    /// The 2-byte identifier.
    pub id: u16,
    /// How to show its value.
    pub format: DidFormat,
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
        let answered = |e: &ReadError| *e != ReadError::NoReply;
        !self.ecus.is_empty()
            || self.modules.iter().any(|m| {
                m.dids
                    .iter()
                    .any(|(_, value)| value.as_ref().err().is_none_or(answered))
                    || m.dtc_count.as_ref().err().is_none_or(answered)
                    || m.dtcs.as_ref().err().is_none_or(answered)
            })
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
    /// later bitmap that's missing or garbled ends its list there.
    pub pids: Result<Vec<PidReading>, ReadError>,
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
    /// Each of [`SCAN_DIDS`], then each of [`ScanModule::extra_dids`], and its value.
    pub dids: Vec<(u16, Result<DidValue, ReadError>)>,
    /// How it encodes DTCs, and how many have a [`FAULT_MASK`] bit set (`ReadDTCInformation`
    /// 0x01).
    pub dtc_count: Result<DtcCount, ReadError>,
    /// Its DTCs with a [`FAULT_MASK`] bit set, and their status (`ReadDTCInformation` 0x02).
    /// Only bits the module says it supports count, so a module that ignores the mask can't
    /// list untested DTCs.
    pub dtcs: Result<Vec<DtcRecord>, ReadError>,
}

/// Scans a car, reading only: OBD-II from every emissions ECU (the supported PID bitmaps, then
/// each supported mode 01 PID; mode 09 PIDs 00 and 0A; mode 03), then each module's DIDs and
/// DTCs over UDS. It never changes a module's diagnostic session.
///
/// Every request it could send is approved by `policy` before the first is sent. A timeout or
/// refusal only loses that value; an adapter error stops the scan.
pub fn scan<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    modules: &[ScanModule],
    timing: Timing,
) -> Result<Scan, ScanError> {
    let approve = |target, payload: &[u8]| {
        policy
            .approve(target, payload)
            .map_err(FingerprintError::Rejected)
    };
    // Which PIDs are asked for depends on the bitmaps, so every one is approved up front.
    let pid_requests = (0..=u8::MAX)
        .map(|pid| approve(Target::ObdFunctional, &obd::current_data(pid)))
        .collect::<Result<Vec<_>, _>>()?;
    let info_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x00))?;
    let name_request = approve(Target::ObdFunctional, &obd::vehicle_info(0x0A))?;
    let dtc_request = approve(Target::ObdFunctional, &obd::stored_dtcs())?;
    let module_requests = modules
        .iter()
        .map(|scanned| {
            let target = Target::Physical(scanned.module.request_id);
            let dids = dids_of(scanned)
                .into_iter()
                .map(|extra| Ok((extra, approve(target, &uds::read_did(extra.id))?)))
                .collect::<Result<Vec<_>, _>>()?;
            let count = approve(target, &uds::dtc_count_by_status_mask(FAULT_MASK))?;
            let dtcs = approve(target, &uds::dtcs_by_status_mask(FAULT_MASK))?;
            Ok((dids, count, dtcs))
        })
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
        .map(|source| ObdEcu {
            source,
            pids: supported
                .get(&source)
                .cloned()
                .unwrap_or(Err(ReadError::NoReply))
                .map(|_| values.remove(&source).unwrap_or_default()),
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
        })
        .collect();

    let mut scanned = Vec::with_capacity(modules.len());
    for (scanned_module, requests) in modules.iter().zip(module_requests) {
        scanned.push(scan_module(
            transport,
            &scanned_module.module,
            requests,
            timing,
        )?);
    }
    Ok(Scan {
        ecus,
        modules: scanned,
    })
}

// A module's DID reads, then its DTC count and DTC list requests, all approved.
type ModuleRequests = (Vec<(ExtraDid, Approved)>, Approved, Approved);

// One ECU's supported PIDs so far, and the bitmap it said comes next, if any.
struct Chain {
    pids: Result<Vec<u8>, ReadError>,
    next: Option<u8>,
}

// Each ECU that answered the first bitmap and the PIDs it supports. Each ECU's chain follows only
// the bitmaps it says it supports, and ends at a missing or garbled one, even while another
// ECU's chain keeps the requests going. PID E0 is the last bitmap.
fn supported_pids<T: Transport + ?Sized>(
    transport: &mut T,
    pid_requests: &[Approved],
    timing: Timing,
) -> Result<BTreeMap<u32, Result<Vec<u8>, ReadError>>, ScanError> {
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
                })
            } else {
                match chains.get_mut(&reply.source) {
                    Some(chain) if chain.next == Some(base) => chain,
                    // A page this ECU didn't say it supports.
                    _ => continue,
                }
            };
            chain.next = None;
            match decode_bitmap(&reply.payload, base) {
                Ok(bitmap) => {
                    if let Ok(pids) = &mut chain.pids {
                        pids.extend(bitmap.iter().filter(|pid| pid % 0x20 != 0));
                    }
                    chain.next = after.filter(|&after| bitmap.contains(after));
                }
                Err(e) if base == 0 => chain.pids = Err(ReadError::Reply(e)),
                Err(_) => {}
            }
        }
        // An ECU that said this page comes next but didn't answer it ends its chain here.
        for chain in chains.values_mut() {
            if chain.next == Some(base) {
                chain.next = None;
            }
        }
        match after {
            Some(after) if chains.values().any(|chain| chain.next == Some(after)) => base = after,
            _ => break,
        }
    }
    Ok(chains
        .into_iter()
        .map(|(source, chain)| (source, chain.pids))
        .collect())
}

// Each supported PID's value from each ECU that supports it, one broadcast per PID.
fn pid_values<T: Transport + ?Sized>(
    transport: &mut T,
    pid_requests: &[Approved],
    supported: &BTreeMap<u32, Result<Vec<u8>, ReadError>>,
    timing: Timing,
) -> Result<BTreeMap<u32, Vec<PidReading>>, ScanError> {
    let wanted: BTreeSet<u8> = supported
        .values()
        .filter_map(|pids| pids.as_ref().ok())
        .flatten()
        .copied()
        .collect();
    let mut values: BTreeMap<u32, Vec<PidReading>> = BTreeMap::new();
    for pid in wanted {
        let replies = broadcast(transport, &pid_requests[usize::from(pid)], timing)?;
        for (&source, pids) in supported {
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
    module: &UdsModule,
    (did_requests, count_request, dtcs_request): ModuleRequests,
    timing: Timing,
) -> Result<ModuleScan, ScanError> {
    let response_id = module.response_id;
    let mut dids = Vec::with_capacity(did_requests.len());
    for (ExtraDid { id, format }, request) in did_requests {
        let value = ask(transport, &request, response_id, timing, |payload| {
            decode_scanned(payload, id, format)
        })?;
        dids.push((id, value));
    }
    let dtc_count = ask(
        transport,
        &count_request,
        response_id,
        timing,
        uds::decode_dtc_count,
    )?;
    let dtcs = ask(transport, &dtcs_request, response_id, timing, |payload| {
        let (availability, records) = uds::decode_dtcs_by_status_mask(payload)?;
        Ok(records
            .filter(|record| record.status.0 & availability.0 & FAULT_MASK != 0)
            .collect())
    })?;
    Ok(ModuleScan {
        name: module.name.clone(),
        response_id,
        dids,
        dtc_count,
        dtcs,
    })
}

// SCAN_DIDS, then the module's other extra DIDs, each once. A DID takes its first extra entry's
// format, except one ISO 14229-1 makes text; a SCAN_DIDS entry with no extra entry is text.
fn dids_of(scanned: &ScanModule) -> Vec<ExtraDid> {
    let mut dids: Vec<ExtraDid> = SCAN_DIDS
        .iter()
        .map(|&id| ExtraDid {
            id,
            format: DidFormat::Text,
        })
        .collect();
    let mut seen = BTreeSet::new();
    for &extra in &scanned.extra_dids {
        if !seen.insert(extra.id) {
            continue;
        }
        match dids.iter_mut().find(|did| did.id == extra.id) {
            Some(did) if !did::is_text(did.id) => did.format = extra.format,
            Some(_) => {}
            None => dids.push(extra),
        }
    }
    dids
}

// A DID's value in `format`. ISO 14229-1 makes F190 a VIN, so anything else there is malformed.
fn decode_scanned(payload: &[u8], id: u16, format: DidFormat) -> Result<DidValue, ReplyError> {
    match format {
        DidFormat::Text if id == did::VIN => {
            let vin = obd::check_vin(uds::decode_did(payload, id)?)?;
            Ok(DidValue::Text(vin.to_owned()))
        }
        DidFormat::Text => decode_did_value(payload, id),
        DidFormat::Hex => Ok(DidValue::Bytes(uds::decode_did(payload, id)?.to_vec())),
    }
}

// The one reading in a single-PID mode 01 reply, which must be `pid`.
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
