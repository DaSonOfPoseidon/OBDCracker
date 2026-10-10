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
    0xF197,
    did::ODX_FILE,
];

// Every status bit, so every stored DTC is listed whatever its state.
const DTC_MASK: u8 = 0xFF;

/// Why a scan couldn't be taken at all.
pub type ScanError = FingerprintError;

/// A module to scan, and the DIDs its vehicle profile adds to [`SCAN_DIDS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanModule {
    /// Where it sits on the bus.
    pub module: UdsModule,
    /// More DIDs to read after [`SCAN_DIDS`], such as VAG's F1A3 or 0600. Each DID is read
    /// once, however often it's listed.
    pub extra_dids: Vec<u16>,
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
    /// How it encodes DTCs, and how many it has stored (`ReadDTCInformation` 0x01, every status
    /// bit).
    pub dtc_count: Result<DtcCount, ReadError>,
    /// Its stored DTCs and their status (`ReadDTCInformation` 0x02, every status bit).
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
                .map(|did| Ok((did, approve(target, &uds::read_did(did))?)))
                .collect::<Result<Vec<_>, _>>()?;
            let count = approve(target, &uds::dtc_count_by_status_mask(DTC_MASK))?;
            let dtcs = approve(target, &uds::dtcs_by_status_mask(DTC_MASK))?;
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
type ModuleRequests = (Vec<(u16, Approved)>, Approved, Approved);

// Each ECU that answered the first bitmap and the PIDs it supports, following the bitmaps while
// any ECU says the next one is supported. PID E0 is the last bitmap.
fn supported_pids<T: Transport + ?Sized>(
    transport: &mut T,
    pid_requests: &[Approved],
    timing: Timing,
) -> Result<BTreeMap<u32, Result<Vec<u8>, ReadError>>, ScanError> {
    let mut supported: BTreeMap<u32, Result<Vec<u8>, ReadError>> = BTreeMap::new();
    let mut base = 0u8;
    loop {
        let replies = broadcast(transport, &pid_requests[usize::from(base)], timing)?;
        let next = base.checked_add(0x20);
        let mut more = false;
        for reply in &replies {
            let decoded = decode_bitmap(&reply.payload, base);
            let list = supported.entry(reply.source).or_insert_with(|| {
                // Only the first bitmap starts a list; an ECU that skipped it has none.
                if base == 0 {
                    Ok(Vec::new())
                } else {
                    Err(ReadError::NoReply)
                }
            });
            let Ok(pids) = list else { continue };
            match decoded {
                Ok(bitmap) => {
                    pids.extend(bitmap.iter().filter(|pid| pid % 0x20 != 0));
                    more |= next.is_some_and(|next| bitmap.contains(next));
                }
                Err(e) if base == 0 => *list = Err(ReadError::Reply(e)),
                Err(_) => {}
            }
        }
        match next {
            Some(next) if more => base = next,
            _ => break,
        }
    }
    Ok(supported)
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
    for (did, request) in did_requests {
        let value = ask(transport, &request, response_id, timing, |payload| {
            decode_did_value(payload, did)
        })?;
        dids.push((did, value));
    }
    let dtc_count = ask(
        transport,
        &count_request,
        response_id,
        timing,
        uds::decode_dtc_count,
    )?;
    let dtcs = ask(transport, &dtcs_request, response_id, timing, |payload| {
        Ok(uds::decode_dtcs_by_status_mask(payload)?.1.collect())
    })?;
    Ok(ModuleScan {
        name: module.name.clone(),
        response_id,
        dids,
        dtc_count,
        dtcs,
    })
}

// SCAN_DIDS, then the module's extra DIDs, each once.
fn dids_of(scanned: &ScanModule) -> Vec<u16> {
    let mut dids = SCAN_DIDS.to_vec();
    for &did in &scanned.extra_dids {
        if !dids.contains(&did) {
            dids.push(did);
        }
    }
    dids
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
