//! The text forms the types a command's result holds take in a document (`docs/json.md`): each is
//! read back exactly as it is written, so a malformed value is an error and never a different one.

use core::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serialize, Serializer};

use crate::obd::{Cvn, Dtc};
use crate::response::Nrc;
use crate::uds::{DtcFormat, DtcStatus, UdsDtc};

struct Text<T> {
    expected: &'static str,
    parse: fn(&str) -> Option<T>,
}

impl<T> Visitor<'_> for Text<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expected)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        (self.parse)(text).ok_or_else(|| E::invalid_value(de::Unexpected::Str(text), &self))
    }
}

fn read<'de, D: Deserializer<'de>, T>(
    deserializer: D,
    expected: &'static str,
    parse: fn(&str) -> Option<T>,
) -> Result<T, D::Error> {
    deserializer.deserialize_str(Text { expected, parse })
}

// Exactly `digits` upper-case hex digits: no sign, no prefix, no lower case.
fn hex(text: &str, digits: usize) -> Option<u32> {
    if text.len() != digits
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

fn hex_byte(text: &str) -> Option<u8> {
    u8::try_from(hex(text, 2)?).ok()
}

// A byte as two hex digits, for `#[serde(with = "...")]`.
pub(crate) mod byte {
    use serde::{Deserializer, Serializer};

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `with` passes a reference"
    )]
    pub(crate) fn serialize<S: Serializer>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{byte:02X}"))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        super::read(deserializer, super::BYTE, super::hex_byte)
    }
}

const BYTE: &str = "a byte as two upper-case hex digits";

fn parse_dtc(text: &str) -> Option<Dtc> {
    let (system, digits) = text.split_at_checked(1)?;
    let system = match system {
        "P" => 0,
        "C" => 1,
        "B" => 2,
        "U" => 3,
        _ => return None,
    };
    // Display prints only the low 14 bits after the system letter.
    let code = hex(digits, 4).filter(|&code| code <= 0x3FFF)?;
    Some(Dtc::new(u16::try_from((system << 14) | code).ok()?))
}

fn parse_uds_dtc(text: &str) -> Option<UdsDtc> {
    hex(text, 6).map(UdsDtc::new)
}

fn parse_cvn(text: &str) -> Option<Cvn> {
    hex(text, 8).map(|cvn| Cvn(cvn.to_be_bytes()))
}

impl Serialize for Dtc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Dtc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(deserializer, "a DTC such as P0401", parse_dtc)
    }
}

impl Serialize for UdsDtc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for UdsDtc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "a UDS DTC as six upper-case hex digits",
            parse_uds_dtc,
        )
    }
}

impl Serialize for Cvn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Cvn {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "a CVN as eight upper-case hex digits",
            parse_cvn,
        )
    }
}

impl Serialize for DtcStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        byte::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DtcStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte::deserialize(deserializer).map(Self)
    }
}

impl Serialize for DtcFormat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        byte::serialize(&self.code(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DtcFormat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte::deserialize(deserializer).map(Self::from)
    }
}

impl Serialize for Nrc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        byte::serialize(&self.code(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Nrc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte::deserialize(deserializer).map(Self::from)
    }
}
