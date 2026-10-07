//! OBD-II (SAE J1979) requests and reply decoding, in the CAN format of ISO 15765-4.
//!
//! The request builders return payload bytes, which still have to pass the safety policy
//! before they can be sent. Each decoder takes one module's reassembled reply.

use core::fmt;

use crate::response::{Error, positive};

/// Mode 01: current powertrain data.
pub const CURRENT_DATA: u8 = 0x01;

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
