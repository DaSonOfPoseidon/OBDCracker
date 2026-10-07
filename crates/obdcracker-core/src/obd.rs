//! OBD-II (SAE J1979) requests and reply decoding, in the CAN format of ISO 15765-4.
//!
//! The request builders return payload bytes, which still have to pass the safety policy
//! before they can be sent. Each decoder takes one module's reassembled reply.

use core::fmt;
use core::slice;

use crate::response::{Error, positive};

/// Mode 01: current powertrain data.
pub const CURRENT_DATA: u8 = 0x01;

/// Mode 03: stored (confirmed) emissions DTCs.
pub const STORED_DTCS: u8 = 0x03;

/// Mode 09: vehicle information.
pub const VEHICLE_INFO: u8 = 0x09;

/// A mode 01 request for one PID.
#[must_use]
pub fn current_data(pid: u8) -> [u8; 2] {
    [CURRENT_DATA, pid]
}

/// The unit a decoded value is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Percent, 0 to 100.
    Percent,
    /// Degrees Celsius.
    Celsius,
    /// Revolutions per minute.
    Rpm,
    /// Kilometres per hour.
    KilometresPerHour,
    /// Volts.
    Volts,
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Percent => "%",
            Self::Celsius => "°C",
            Self::Rpm => "rpm",
            Self::KilometresPerHour => "km/h",
            Self::Volts => "V",
        })
    }
}

/// Which of the 32 PIDs after a bitmap PID (0x00, 0x20, 0x40, …) a module supports. The last
/// bit says whether the next bitmap PID is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportedPids {
    base: u8,
    bits: u32,
}

impl SupportedPids {
    /// Builds a bitmap from the bitmap PID it answers and its four data bytes.
    #[must_use]
    pub fn new(base: u8, data: [u8; 4]) -> Self {
        Self {
            base,
            bits: u32::from_be_bytes(data),
        }
    }

    /// Whether `pid` is in this bitmap's range and marked supported.
    #[must_use]
    pub fn contains(&self, pid: u8) -> bool {
        match pid.checked_sub(self.base) {
            Some(offset @ 1..=32) => self.bits & (1 << (32 - u32::from(offset))) != 0,
            _ => false,
        }
    }

    /// The supported PIDs, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (1..=32u8)
            .filter_map(|offset| self.base.checked_add(offset))
            .filter(|&pid| self.contains(pid))
    }
}

/// A decoded PID value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    /// A physical quantity.
    Quantity {
        /// The value, scaled per SAE J1979.
        value: f32,
        /// Its unit.
        unit: Unit,
    },
    /// A supported-PID bitmap (PIDs 0x00, 0x20, 0x40, …).
    Supported(SupportedPids),
    /// A PID this crate doesn't decode yet, with the bytes left in the reply.
    Raw(&'a [u8]),
}

/// One PID and its value from a reply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading<'a> {
    /// The PID.
    pub pid: u8,
    /// Its decoded value.
    pub value: Value<'a>,
}

// The PIDs with a known data length and formula, per SAE J1979.
fn decode_pid(pid: u8, data: &[u8]) -> Option<(usize, Value<'static>)> {
    let byte = |i: usize| data.get(i).copied().map(f32::from);
    let word = || Some(byte(0)? * 256.0 + byte(1)?);
    let quantity = |value, unit| Value::Quantity { value, unit };
    let decoded = match pid {
        0x00 | 0x20 | 0x40 | 0x60 | 0x80 | 0xA0 | 0xC0 | 0xE0 => {
            let bytes = data.get(..4)?.try_into().ok()?;
            (4, Value::Supported(SupportedPids::new(pid, bytes)))
        }
        0x04 | 0x11 => (1, quantity(byte(0)? * 100.0 / 255.0, Unit::Percent)),
        0x05 | 0x0F => (1, quantity(byte(0)? - 40.0, Unit::Celsius)),
        0x0C => (2, quantity(word()? / 4.0, Unit::Rpm)),
        0x0D => (1, quantity(byte(0)?, Unit::KilometresPerHour)),
        0x42 => (2, quantity(word()? / 1000.0, Unit::Volts)),
        _ => return None,
    };
    Some(decoded)
}

fn is_known(pid: u8) -> bool {
    // A long enough buffer decodes every known PID.
    decode_pid(pid, &[0; 4]).is_some()
}

/// Decodes a mode 01 reply into its readings, one per PID.
///
/// A PID this crate doesn't know comes back as [`Value::Raw`] holding the rest of the reply,
/// since its length is unknown, and ends the readings.
pub fn decode_current_data(reply: &[u8]) -> Result<Readings<'_>, Error> {
    let rest = positive(CURRENT_DATA, reply)?;
    if rest.is_empty() {
        return Err(Error::TooShort);
    }
    Ok(Readings { rest })
}

/// The readings in a mode 01 reply. A truncated reading yields [`Error::TooShort`] and ends it.
#[derive(Debug, Clone)]
pub struct Readings<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Readings<'a> {
    type Item = Result<Reading<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&pid, data) = self.rest.split_first()?;
        if !is_known(pid) {
            self.rest = &[];
            return Some(Ok(Reading {
                pid,
                value: Value::Raw(data),
            }));
        }
        let Some((len, value)) = decode_pid(pid, data) else {
            self.rest = &[];
            return Some(Err(Error::TooShort));
        };
        self.rest = &data[len..];
        Some(Ok(Reading { pid, value }))
    }
}

/// A mode 03 request for every stored emissions DTC.
#[must_use]
pub fn stored_dtcs() -> [u8; 1] {
    [STORED_DTCS]
}

/// A two-byte diagnostic trouble code, shown in the SAE J2012 form such as `P0401`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dtc(u16);

impl Dtc {
    /// Wraps the code's two bytes, as sent on the bus.
    #[must_use]
    pub fn new(code: u16) -> Self {
        Self(code)
    }

    /// The code's two bytes.
    #[must_use]
    pub fn code(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Dtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The top two bits pick the system: powertrain, chassis, body or network.
        let system = ['P', 'C', 'B', 'U'][usize::from(self.0 >> 14)];
        write!(f, "{system}{:04X}", self.0 & 0x3FFF)
    }
}

/// Decodes a mode 03 reply: a count byte, then that many two-byte codes.
pub fn decode_stored_dtcs(reply: &[u8]) -> Result<Dtcs<'_>, Error> {
    let (&count, codes) = positive(STORED_DTCS, reply)?
        .split_first()
        .ok_or(Error::TooShort)?;
    if codes.len() != usize::from(count) * 2 {
        return Err(Error::Malformed);
    }
    Ok(Dtcs(codes.as_chunks::<2>().0.iter()))
}

/// The codes in a mode 03 reply.
#[derive(Debug, Clone)]
pub struct Dtcs<'a>(slice::Iter<'a, [u8; 2]>);

impl Iterator for Dtcs<'_> {
    type Item = Dtc;

    fn next(&mut self) -> Option<Dtc> {
        self.0.next().map(|&pair| Dtc(u16::from_be_bytes(pair)))
    }
}

/// A mode 09 request for one PID.
#[must_use]
pub fn vehicle_info(pid: u8) -> [u8; 2] {
    [VEHICLE_INFO, pid]
}

const CALID_LEN: usize = 16;
const CVN_LEN: usize = 4;
const VIN_LEN: usize = 17;
const ECU_NAME_LEN: usize = 20;

// A mode 09 reply for `pid`: the item count and the data after it.
fn info(reply: &[u8], pid: u8) -> Result<(usize, &[u8]), Error> {
    let rest = positive(VEHICLE_INFO, reply)?;
    let [got, count, data @ ..] = rest else {
        return Err(Error::TooShort);
    };
    if *got != pid {
        return Err(Error::Malformed);
    }
    Ok((usize::from(*count), data))
}

// Printable ASCII after trimming the trailing 0x00 padding.
fn text(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let text = &bytes[..end];
    if !text.iter().all(|&b| b == b' ' || b.is_ascii_graphic()) {
        return Err(Error::Malformed);
    }
    core::str::from_utf8(text).map_err(|_| Error::Malformed)
}

/// Decodes the mode 09 PID 00 reply: which vehicle information PIDs 01 to 20 are supported.
pub fn decode_supported_info(reply: &[u8]) -> Result<SupportedPids, Error> {
    let rest = positive(VEHICLE_INFO, reply)?;
    let [0x00, a, b, c, d, ..] = *rest else {
        return Err(Error::Malformed);
    };
    Ok(SupportedPids::new(0x00, [a, b, c, d]))
}

/// Decodes the mode 09 PID 02 reply: the 17-character VIN.
pub fn decode_vin(reply: &[u8]) -> Result<&str, Error> {
    let (count, data) = info(reply, 0x02)?;
    if count != 1 || data.len() != VIN_LEN || !data.iter().all(u8::is_ascii_alphanumeric) {
        return Err(Error::Malformed);
    }
    text(data)
}

/// Decodes the mode 09 PID 04 reply: each calibration ID (the software calibration's name),
/// with its padding removed. A module may report several.
pub fn decode_calids(reply: &[u8]) -> Result<Calids<'_>, Error> {
    let (count, data) = info(reply, 0x04)?;
    if data.len() != count * CALID_LEN {
        return Err(Error::Malformed);
    }
    Ok(Calids(data.as_chunks::<CALID_LEN>().0.iter()))
}

/// The calibration IDs in a mode 09 PID 04 reply. One that isn't printable text yields
/// [`Error::Malformed`].
#[derive(Debug, Clone)]
pub struct Calids<'a>(slice::Iter<'a, [u8; CALID_LEN]>);

impl<'a> Iterator for Calids<'a> {
    type Item = Result<&'a str, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|calid| text(calid))
    }
}

/// A calibration verification number: a checksum of the calibration in the module, shown as
/// 8 hex digits. A changed calibration (such as a tune) has a different CVN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cvn(pub [u8; CVN_LEN]);

impl fmt::Display for Cvn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02X}"))
    }
}

/// Decodes the mode 09 PID 06 reply: one CVN per calibration ID.
pub fn decode_cvns(reply: &[u8]) -> Result<Cvns<'_>, Error> {
    let (count, data) = info(reply, 0x06)?;
    if data.len() != count * CVN_LEN {
        return Err(Error::Malformed);
    }
    Ok(Cvns(data.as_chunks::<CVN_LEN>().0.iter()))
}

/// The CVNs in a mode 09 PID 06 reply.
#[derive(Debug, Clone)]
pub struct Cvns<'a>(slice::Iter<'a, [u8; CVN_LEN]>);

impl Iterator for Cvns<'_> {
    type Item = Cvn;

    fn next(&mut self) -> Option<Cvn> {
        self.0.next().map(|&cvn| Cvn(cvn))
    }
}

/// A module's name from mode 09 PID 0A, such as `ECM` / `EngineControl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcuName<'a> {
    /// The short name, up to 4 characters.
    pub acronym: &'a str,
    /// The full name, up to 15 characters.
    pub name: &'a str,
}

/// Decodes the mode 09 PID 0A reply: 4 bytes of acronym, `-`, then 15 bytes of name.
pub fn decode_ecu_name(reply: &[u8]) -> Result<EcuName<'_>, Error> {
    let (count, data) = info(reply, 0x0A)?;
    if count != 1 || data.len() != ECU_NAME_LEN || data[4] != b'-' {
        return Err(Error::Malformed);
    }
    Ok(EcuName {
        acronym: text(&data[..4])?,
        name: text(&data[5..])?,
    })
}
