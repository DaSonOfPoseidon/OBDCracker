//! The fixture file format: what each simulated module answers. Addresses come from the profile.
//! See [`docs/fixtures.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/fixtures.md).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use obdcracker_core::obd;
use serde::Deserialize;

use crate::FixtureError;
use crate::ecu::{Did, FreezeFrame, Obd, RawReply};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureFile {
    #[serde(rename = "ecu", default)]
    pub(crate) ecus: Vec<EcuFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EcuFixture {
    pub(crate) module: String,
    dtc_format: Option<u8>,
    #[serde(default = "every_status_bit")]
    status_availability: u8,
    #[serde(default = "every_dtc_report")]
    dtc_reports: Vec<u8>,
    #[serde(default)]
    dtc_pending: u8,
    obd: Option<ObdFixture>,
    #[serde(rename = "did", default)]
    dids: Vec<DidFixture>,
    #[serde(rename = "dtc", default)]
    dtcs: Vec<DtcFixture>,
    #[serde(rename = "raw", default)]
    raw: Vec<RawFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFixture {
    request: String,
    reply: String,
    #[serde(default)]
    pending: u8,
}

// The ReadDTCInformation sub-functions the sim implements.
const DTC_REPORTS: [u8; 5] = [0x01, 0x02, 0x04, 0x06, 0x0A];

fn every_status_bit() -> u8 {
    0xFF
}

fn every_dtc_report() -> Vec<u8> {
    DTC_REPORTS.to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DtcService {
    pub(crate) format: u8,
    pub(crate) availability: u8,
    pub(crate) reports: Vec<u8>,
    pub(crate) dtcs: Vec<(u32, u8)>,
    pub(crate) pending: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObdFixture {
    vin: Option<String>,
    #[serde(default)]
    calids: Vec<String>,
    #[serde(default)]
    cvns: Vec<String>,
    ecu_name: Option<EcuNameFixture>,
    #[serde(default)]
    dtcs: Vec<String>,
    #[serde(default)]
    pids: BTreeMap<String, String>,
    pending_dtcs: Option<Vec<String>>,
    permanent_dtcs: Option<Vec<String>>,
    freeze_frame: Option<FreezeFrameFixture>,
    monitor_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeFrameFixture {
    cause: Option<String>,
    #[serde(default)]
    pids: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EcuNameFixture {
    acronym: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DidFixture {
    id: u16,
    text: Option<String>,
    hex: Option<String>,
    #[serde(default)]
    session: SessionFixture,
    #[serde(default)]
    pending: u8,
    nrc: Option<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SessionFixture {
    #[default]
    Default,
    Extended,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DtcFixture {
    code: u32,
    status: u8,
}

const VIN_LEN: usize = 17;
const CALID_LEN: usize = 16;
const CVN_LEN: usize = 4;
const ACRONYM_LEN: usize = 4;
const ECU_NAME_LEN: usize = 15;

fn value_error(what: &str, value: &str) -> FixtureError {
    FixtureError::Value(format!("{what}: {value:?}"))
}

// `from_str_radix` also takes a leading `+`, so check every character first.
fn is_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

// Whether `data` is exactly one reading of `pid`, as obd::decode_current_data reads it. A PID
// the decoder doesn't know takes any length.
fn decodes_exactly(pid: u8, data: &[u8]) -> bool {
    let mut reply = vec![0x41, pid];
    reply.extend(data);
    obd::decode_current_data(&reply).is_ok_and(|mut readings| {
        matches!(readings.next(), Some(Ok(_))) && readings.next().is_none()
    })
}

fn is_printable(text: &str) -> bool {
    text.bytes().all(|b| (0x20..0x7F).contains(&b))
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, FixtureError> {
    let bytes = text
        .split_whitespace()
        .map(|byte| {
            if byte.len() == 2 && is_hex(byte) {
                u8::from_str_radix(byte, 16).ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| value_error("bad hex bytes", text))?;
    if bytes.is_empty() {
        return Err(value_error("empty hex bytes", text));
    }
    Ok(bytes)
}

fn padded(text: &str, len: usize, what: &str) -> Result<Vec<u8>, FixtureError> {
    if text.trim().is_empty() || text.len() > len || !is_printable(text) {
        return Err(value_error(what, text));
    }
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(len, 0);
    Ok(bytes)
}

fn dtc_code(text: &str) -> Result<u16, FixtureError> {
    let bad = || value_error("bad DTC", text);
    let mut chars = text.chars();
    let system: u16 = match chars.next() {
        Some('P') => 0,
        Some('C') => 1,
        Some('B') => 2,
        Some('U') => 3,
        _ => return Err(bad()),
    };
    let digits = chars.as_str();
    if digits.len() != 4 || !is_hex(digits) {
        return Err(bad());
    }
    let low = u16::from_str_radix(digits, 16).map_err(|_| bad())?;
    let code = system << 14 | low;
    // 0x0000 (P0000) is the padding mode 03 replies use, not a code (SAE J1979).
    if low > 0x3FFF || code == 0 {
        return Err(bad());
    }
    Ok(code)
}

// A table of PIDs to data, for mode 01 or a freeze frame (`mode` names it). The cause PID (02) of
// a freeze frame is its own field, so `except` refuses it.
fn pid_table(
    table: &BTreeMap<String, String>,
    mode: &str,
    except: Option<u8>,
) -> Result<BTreeMap<u8, Vec<u8>>, FixtureError> {
    let mut pids = BTreeMap::new();
    for (pid, data) in table {
        let id = u8::from_str_radix(pid, 16)
            .ok()
            .filter(|id| {
                pid.len() == 2 && is_hex(pid) && !id.is_multiple_of(0x20) && Some(*id) != except
            })
            .ok_or_else(|| {
                value_error(&format!("bad {mode} PID (bitmap PIDs are computed)"), pid)
            })?;
        let data = hex_bytes(data)?;
        if !decodes_exactly(id, &data) {
            return Err(value_error(
                "wrong data length for this PID (SAE J1979)",
                pid,
            ));
        }
        if pids.insert(id, data).is_some() {
            return Err(value_error(&format!("{mode} PID listed twice"), pid));
        }
    }
    Ok(pids)
}

// A list of OBD DTCs of one mode: up to 255 (the count is a byte), none P0000, none twice.
fn dtc_list(codes: &[String], mode: &str) -> Result<Vec<u16>, FixtureError> {
    if codes.len() > usize::from(u8::MAX) {
        return Err(FixtureError::Value(format!("too many {mode} DTCs")));
    }
    let mut list = Vec::new();
    for dtc in codes {
        let code = dtc_code(dtc)?;
        if list.contains(&code) {
            return Err(value_error(&format!("{mode} DTC listed twice"), dtc));
        }
        list.push(code);
    }
    Ok(list)
}

// Monitor IDs (mode 06), 2 hex digits each. The bitmap IDs (0x00, 0x20, …) are computed.
fn monitor_ids(ids: &[String]) -> Result<BTreeSet<u8>, FixtureError> {
    let mut set = BTreeSet::new();
    for id in ids {
        let mid = u8::from_str_radix(id, 16)
            .ok()
            .filter(|mid| id.len() == 2 && is_hex(id) && !mid.is_multiple_of(0x20))
            .ok_or_else(|| value_error("bad monitor ID (bitmap IDs are computed)", id))?;
        if !set.insert(mid) {
            return Err(value_error("monitor ID listed twice", id));
        }
    }
    Ok(set)
}

impl FreezeFrameFixture {
    fn build(&self) -> Result<FreezeFrame, FixtureError> {
        let cause = self.cause.as_deref().map(dtc_code).transpose()?;
        let pids = pid_table(&self.pids, "freeze frame", Some(0x02))?;
        if cause.is_none() && !pids.is_empty() {
            return Err(FixtureError::Value(
                "a freeze frame with PIDs needs a cause (without one it is empty: P0000)".into(),
            ));
        }
        Ok(FreezeFrame { cause, pids })
    }
}

impl ObdFixture {
    fn build(&self) -> Result<Obd, FixtureError> {
        let mut obd = Obd::default();
        obd.pids = pid_table(&self.pids, "mode 01", None)?;
        obd.pending_dtcs = self
            .pending_dtcs
            .as_deref()
            .map(|codes| dtc_list(codes, "pending"))
            .transpose()?;
        obd.permanent_dtcs = self
            .permanent_dtcs
            .as_deref()
            .map(|codes| dtc_list(codes, "permanent"))
            .transpose()?;
        obd.freeze_frame = self
            .freeze_frame
            .as_ref()
            .map(FreezeFrameFixture::build)
            .transpose()?;
        obd.monitor_ids = self.monitor_ids.as_deref().map(monitor_ids).transpose()?;
        if let Some(vin) = &self.vin {
            if obd::check_vin(vin.as_bytes()).is_err() {
                return Err(value_error(
                    "VIN must be 17 digits and upper case letters other than I, O and Q",
                    vin,
                ));
            }
            obd.info.insert(0x02, (1, padded(vin, VIN_LEN, "bad VIN")?));
        }
        if self.calids.len() != self.cvns.len() {
            return Err(FixtureError::Value(
                "each calibration ID needs one CVN".into(),
            ));
        }
        if !self.calids.is_empty() {
            let count = u8::try_from(self.calids.len())
                .map_err(|_| FixtureError::Value("too many calibration IDs".into()))?;
            let mut calids = Vec::new();
            let mut cvns = Vec::new();
            for (calid, cvn) in self.calids.iter().zip(&self.cvns) {
                // "" is an empty slot (all 0x00), which the A7's engine sends (#46).
                if calid.is_empty() {
                    calids.extend([0; CALID_LEN]);
                } else {
                    calids.extend(padded(calid, CALID_LEN, "bad calibration ID")?);
                }
                let cvn_bytes = hex_bytes(cvn)?;
                if cvn_bytes.len() != CVN_LEN {
                    return Err(value_error("CVN must be 4 bytes", cvn));
                }
                cvns.extend(cvn_bytes);
            }
            obd.info.insert(0x04, (count, calids));
            obd.info.insert(0x06, (count, cvns));
        }
        if let Some(name) = &self.ecu_name {
            if name.acronym.contains(' ') || name.name.contains(' ') {
                return Err(value_error("ECU names have no blanks", &name.name));
            }
            let mut bytes = padded(&name.acronym, ACRONYM_LEN, "bad ECU acronym")?;
            bytes.push(b'-');
            bytes.extend(padded(&name.name, ECU_NAME_LEN, "bad ECU name")?);
            obd.info.insert(0x0A, (1, bytes));
        }
        obd.dtcs = dtc_list(&self.dtcs, "stored")?;
        Ok(obd)
    }
}

impl DidFixture {
    fn build(&self) -> Result<Did, FixtureError> {
        let data = match (&self.text, &self.hex, self.nrc) {
            (Some(text), None, None) if !text.trim().is_empty() && is_printable(text) => {
                Ok(text.as_bytes().to_vec())
            }
            (None, Some(hex), None) => Ok(hex_bytes(hex)?),
            // 0x00 isn't an NRC, and 0x78 (response-pending) isn't a refusal.
            (None, None, Some(nrc)) if nrc != 0x00 && nrc != 0x78 => Err(nrc),
            _ => {
                return Err(FixtureError::Value(format!(
                    "DID 0x{:04X} needs one non-blank printable text or hex value, or an NRC \
                     other than 0x00 and 0x78",
                    self.id
                )));
            }
        };
        Ok(Did {
            id: self.id,
            data,
            extended_only: self.session == SessionFixture::Extended,
            pending: self.pending,
        })
    }
}

impl RawFixture {
    fn build(&self) -> Result<RawReply, FixtureError> {
        let request = hex_bytes(&self.request)?;
        let reply = hex_bytes(&self.reply)?;
        // Session control changes the module's state, which a raw reply would skip.
        if request.first() == Some(&0x10) {
            return Err(value_error(
                "a raw reply can't stand in for session control",
                &self.request,
            ));
        }
        // After response-pending, the final reply comes even to a suppressed request.
        let answers = if self.pending > 0 {
            obdcracker_core::response::answers_after_pending
        } else {
            obdcracker_core::response::answers
        };
        if !answers(&request, &reply) {
            return Err(value_error(
                "raw reply doesn't answer its request",
                &self.reply,
            ));
        }
        Ok(RawReply {
            request,
            reply,
            pending: self.pending,
        })
    }
}

impl EcuFixture {
    pub(crate) fn obd(&self) -> Result<Option<Obd>, FixtureError> {
        self.obd.as_ref().map(ObdFixture::build).transpose()
    }

    pub(crate) fn dids(&self) -> Result<Vec<Did>, FixtureError> {
        let mut seen = HashSet::new();
        for did in &self.dids {
            if !seen.insert(did.id) {
                return Err(FixtureError::Value(format!(
                    "module {}: DID 0x{:04X} is listed twice",
                    self.module, did.id
                )));
            }
        }
        self.dids.iter().map(DidFixture::build).collect()
    }

    pub(crate) fn raw(&self) -> Result<Vec<RawReply>, FixtureError> {
        let raw = self
            .raw
            .iter()
            .map(RawFixture::build)
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = HashSet::new();
        for entry in &raw {
            if !seen.insert(&entry.request) {
                return Err(FixtureError::Value(format!(
                    "module {}: raw request {:02X?} is listed twice",
                    self.module, entry.request
                )));
            }
        }
        Ok(raw)
    }

    pub(crate) fn dtc_service(&self) -> Result<DtcService, FixtureError> {
        let error = |what: String| FixtureError::Value(format!("module {}: {what}", self.module));
        if self.dtc_reports.is_empty() {
            return Err(error("dtc_reports can't be empty".into()));
        }
        let mut seen = HashSet::new();
        for &report in &self.dtc_reports {
            if !DTC_REPORTS.contains(&report) || !seen.insert(report) {
                return Err(error(format!(
                    "DTC report 0x{report:02X} is unknown or listed twice"
                )));
            }
        }
        if self.dtc_format.is_some() && !self.dtc_reports.contains(&0x01) {
            return Err(error(
                "dtc_format is only sent in the count report (0x01)".into(),
            ));
        }
        let dtcs = self.dtcs()?;
        if let Some(&(code, status)) = dtcs
            .iter()
            .find(|&&(_, status)| status & !self.status_availability != 0)
        {
            return Err(error(format!(
                "DTC 0x{code:06X} has status bits 0x{status:02X} outside status_availability"
            )));
        }
        Ok(DtcService {
            format: self.dtc_format.unwrap_or(0x01),
            availability: self.status_availability,
            reports: self.dtc_reports.clone(),
            dtcs,
            pending: self.dtc_pending,
        })
    }

    fn dtcs(&self) -> Result<Vec<(u32, u8)>, FixtureError> {
        // The DTC count reply (0x19 0x01) has a 16-bit count.
        if self.dtcs.len() > usize::from(u16::MAX) {
            return Err(FixtureError::Value(format!(
                "module {}: more UDS DTCs than a 16-bit count holds",
                self.module
            )));
        }
        let mut seen = HashSet::new();
        for dtc in &self.dtcs {
            if dtc.code > 0x00FF_FFFF {
                return Err(FixtureError::Value(format!(
                    "UDS DTC 0x{:X} is longer than 3 bytes",
                    dtc.code
                )));
            }
            // 0x000000 is no code, and 0xFFFFFF is the "all groups" value (ISO 14229-1).
            if dtc.code == 0 || dtc.code == 0x00FF_FFFF {
                return Err(FixtureError::Value(format!(
                    "module {}: UDS DTC 0x{:06X} isn't a single code",
                    self.module, dtc.code
                )));
            }
            if !seen.insert(dtc.code) {
                return Err(FixtureError::Value(format!(
                    "module {}: UDS DTC 0x{:06X} is listed twice",
                    self.module, dtc.code
                )));
            }
        }
        Ok(self.dtcs.iter().map(|dtc| (dtc.code, dtc.status)).collect())
    }
}
