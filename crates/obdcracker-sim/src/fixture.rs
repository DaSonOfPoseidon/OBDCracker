// The fixture file format: what each simulated module answers. Addresses come from the profile.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use crate::FixtureError;
use crate::ecu::{Did, Obd};

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
    // ISO 14229-1 D.4; 0x01 (ISO 14229-1's own format) unless the fixture says otherwise.
    #[serde(default = "iso14229_format")]
    pub(crate) dtc_format: u8,
    obd: Option<ObdFixture>,
    #[serde(rename = "did", default)]
    dids: Vec<DidFixture>,
    #[serde(rename = "dtc", default)]
    dtcs: Vec<DtcFixture>,
}

fn iso14229_format() -> u8 {
    0x01
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
    // Mode 01 PID (2 hex digits) → data bytes as hex
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

// Only hex digits: from_str_radix also takes a leading `+`.
fn is_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

// SAE J1979, as obd::decode_vin checks it.
fn is_vin_char(b: u8) -> bool {
    (b.is_ascii_digit() || b.is_ascii_uppercase()) && !matches!(b, b'I' | b'O' | b'Q')
}

fn is_printable(text: &str) -> bool {
    text.bytes().all(|b| (0x20..0x7F).contains(&b))
}

// Space-separated hex bytes, such as `0C 80`.
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

// `text` as bytes, 0x00-padded to `len`. Must be printable ASCII and fit.
fn padded(text: &str, len: usize, what: &str) -> Result<Vec<u8>, FixtureError> {
    if text.is_empty() || text.len() > len || !is_printable(text) {
        return Err(value_error(what, text));
    }
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(len, 0);
    Ok(bytes)
}

// An SAE J2012 code such as `P0299` as its two bytes.
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
    if low > 0x3FFF {
        return Err(bad());
    }
    Ok(system << 14 | low)
}

impl ObdFixture {
    fn build(&self) -> Result<Obd, FixtureError> {
        let mut obd = Obd::default();
        for (pid, data) in &self.pids {
            let id = u8::from_str_radix(pid, 16)
                .ok()
                .filter(|id| pid.len() == 2 && is_hex(pid) && !id.is_multiple_of(0x20))
                .ok_or_else(|| value_error("bad mode 01 PID (bitmap PIDs are computed)", pid))?;
            obd.pids.insert(id, hex_bytes(data)?);
        }
        if let Some(vin) = &self.vin {
            if vin.len() != VIN_LEN || !vin.bytes().all(is_vin_char) {
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
                calids.extend(padded(calid, CALID_LEN, "bad calibration ID")?);
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
        if self.dtcs.len() > usize::from(u8::MAX) {
            return Err(FixtureError::Value("too many OBD DTCs".into()));
        }
        obd.dtcs = self
            .dtcs
            .iter()
            .map(|dtc| dtc_code(dtc))
            .collect::<Result<_, _>>()?;
        Ok(obd)
    }
}

impl DidFixture {
    fn build(&self) -> Result<Did, FixtureError> {
        let data = match (&self.text, &self.hex) {
            (Some(text), None) if !text.is_empty() && is_printable(text) => {
                text.as_bytes().to_vec()
            }
            (None, Some(hex)) => hex_bytes(hex)?,
            _ => {
                return Err(FixtureError::Value(format!(
                    "DID 0x{:04X} needs one non-empty printable text or hex value",
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

    pub(crate) fn dtcs(&self) -> Result<Vec<(u32, u8)>, FixtureError> {
        self.dtcs
            .iter()
            .map(|dtc| {
                if dtc.code > 0x00FF_FFFF {
                    Err(FixtureError::Value(format!(
                        "UDS DTC 0x{:X} is longer than 3 bytes",
                        dtc.code
                    )))
                } else {
                    Ok((dtc.code, dtc.status))
                }
            })
            .collect()
    }
}
