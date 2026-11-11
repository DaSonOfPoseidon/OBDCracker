//! How the result types are written as JSON, and read back exactly as written: byte strings, CAN
//! IDs, DIDs and a result's value or error each have one text form, and any other text is an error.
//! Use the `with` modules for a type of your own that holds one of them. See `docs/json.md`.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, DeserializeOwned, MapAccess, Visitor};
use serde::ser::{self, SerializeMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hex;

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
fn hex_digits(text: &str, digits: usize) -> Option<u32> {
    if text.len() != digits
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

/// Parses bytes written as upper-case hex pairs separated by single spaces (`1A 2B`; nothing for
/// no bytes), the form [`crate::hex`] prints. `None` for anything else.
#[must_use]
pub fn parse_bytes(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split(' ')
        .map(|pair| u8::try_from(hex_digits(pair, 2)?).ok())
        .collect()
}

const MAX_CAN_ID: u32 = 0x1FFF_FFFF;

// 3 digits for an 11-bit ID, 8 for a 29-bit one. One a 3-digit form could hold is written in it.
fn can_id_text(id: u32) -> Option<String> {
    match id {
        0..=0x7FF => Some(format!("{id:03X}")),
        0x800..=MAX_CAN_ID => Some(format!("{id:08X}")),
        _ => None,
    }
}

fn parse_can_id(text: &str) -> Option<u32> {
    match text.len() {
        3 => hex_digits(text, 3).filter(|&id| id <= 0x7FF),
        8 => hex_digits(text, 8).filter(|&id| id <= MAX_CAN_ID),
        _ => None,
    }
}

fn parse_did(text: &str) -> Option<u16> {
    u16::try_from(hex_digits(text, 4)?).ok()
}

fn parse_byte(text: &str) -> Option<u8> {
    u8::try_from(hex_digits(text, 2)?).ok()
}

struct BytesRef<'a>(&'a [u8]);

impl Serialize for BytesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(self.0))
    }
}

struct Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "bytes as upper-case hex pairs separated by single spaces",
            parse_bytes,
        )
        .map(Self)
    }
}

struct CanId(u32);

impl Serialize for CanId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = can_id_text(self.0).ok_or_else(|| {
            ser::Error::custom(format_args!("{:X} isn't a 29-bit CAN ID", self.0))
        })?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for CanId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "a CAN ID as 3 or 8 upper-case hex digits",
            parse_can_id,
        )
        .map(Self)
    }
}

struct Did(u16);

impl Serialize for Did {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:04X}", self.0))
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "a DID as four upper-case hex digits",
            parse_did,
        )
        .map(Self)
    }
}

struct Byte(u8);

impl Serialize for Byte {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:02X}", self.0))
    }
}

impl<'de> Deserialize<'de> for Byte {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        read(
            deserializer,
            "a byte as two upper-case hex digits",
            parse_byte,
        )
        .map(Self)
    }
}

// A result is `{"value": ...}` or `{"error": ...}`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Wire<V, E> {
    Value(V),
    Error(E),
}

impl<V, E> From<Wire<V, E>> for Result<V, E> {
    fn from(wire: Wire<V, E>) -> Self {
        match wire {
            Wire::Value(value) => Ok(value),
            Wire::Error(error) => Err(error),
        }
    }
}

fn wire<V, E>(result: &Result<V, E>) -> Wire<&V, &E> {
    match result {
        Ok(value) => Wire::Value(value),
        Err(error) => Wire::Error(error),
    }
}

fn wire_bytes<E>(result: &Result<Vec<u8>, E>) -> Wire<BytesRef<'_>, &E> {
    match result {
        Ok(bytes) => Wire::Value(BytesRef(bytes)),
        Err(error) => Wire::Error(error),
    }
}

type DidResults<T, E> = Vec<(u16, Result<T, E>)>;

// The name a list entry's key has in its object.
trait Key {
    const NAME: &'static str;
}

impl Key for Did {
    const NAME: &'static str = "did";
}

impl Key for Byte {
    const NAME: &'static str = "pid";
}

// A list entry: an object with its key and then `value` or `error`, one of them and only one.
struct Item<K, V, E> {
    key: K,
    outcome: Wire<V, E>,
}

impl<K: Key + Serialize, V: Serialize, E: Serialize> Serialize for Item<K, V, E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(K::NAME, &self.key)?;
        match &self.outcome {
            Wire::Value(value) => map.serialize_entry("value", value)?,
            Wire::Error(error) => map.serialize_entry("error", error)?,
        }
        map.end()
    }
}

struct ItemVisitor<K, V, E>(PhantomData<(K, V, E)>);

impl<'de, K: Key + Deserialize<'de>, V: Deserialize<'de>, E: Deserialize<'de>> Visitor<'de>
    for ItemVisitor<K, V, E>
{
    type Value = Item<K, V, E>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "an object with {:?} and one of \"value\" and \"error\"",
            K::NAME
        )
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut key = None;
        let mut outcome = None;
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                name if name == K::NAME => {
                    if key.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field(K::NAME));
                    }
                }
                "value" | "error" => {
                    let next = if name == "value" {
                        Wire::Value(map.next_value()?)
                    } else {
                        Wire::Error(map.next_value()?)
                    };
                    if outcome.replace(next).is_some() {
                        return Err(de::Error::custom(
                            "an entry has more than one of \"value\" and \"error\"",
                        ));
                    }
                }
                _ => {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
        }
        Ok(Item {
            key: key.ok_or_else(|| de::Error::missing_field(K::NAME))?,
            outcome: outcome
                .ok_or_else(|| de::Error::custom("an entry has neither \"value\" nor \"error\""))?,
        })
    }
}

impl<'de, K: Key + Deserialize<'de>, V: Deserialize<'de>, E: Deserialize<'de>> Deserialize<'de>
    for Item<K, V, E>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ItemVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
struct DidData {
    did: Did,
    data: Bytes,
}

#[derive(Serialize, Deserialize)]
struct PidFailure<E> {
    pid: Byte,
    error: E,
}

#[derive(Serialize)]
struct PidList<'a>(#[serde(serialize_with = "pid_list_ser")] &'a [u8]);

fn pid_list_ser<S: Serializer>(pids: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(pids.iter().map(|&pid| Byte(pid)))
}

/// A byte string as upper-case hex pairs separated by spaces, such as `"1A 2A 40"`, for
/// `#[serde(with = "obdcracker_transport::json::bytes")]` on a `Vec<u8>`.
pub mod bytes {
    use super::{Bytes, BytesRef, Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `bytes` as hex pairs.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        BytesRef(bytes).serialize(serializer)
    }

    /// Reads hex pairs; odd digits, non-hex, lower case and odd spacing are errors.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        Bytes::deserialize(deserializer).map(|bytes| bytes.0)
    }
}

/// A CAN ID as 3 upper-case hex digits (11-bit) or 8 (29-bit), such as `"7E8"` or `"17FE0010"`,
/// for `#[serde(with = "obdcracker_transport::json::can_id")]` on a `u32`.
pub mod can_id {
    use super::{CanId, Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `id`; an error if it doesn't fit 29 bits.
    pub fn serialize<S: Serializer>(id: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        CanId(*id).serialize(serializer)
    }

    /// Reads a 3-digit ID of at most 0x7FF or an 8-digit one of at most 0x1FFFFFFF.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        CanId::deserialize(deserializer).map(|id| id.0)
    }
}

/// A byte as two upper-case hex digits, such as `"FF"`, for
/// `#[serde(with = "obdcracker_transport::json::byte")]` on a `u8`.
pub mod byte {
    use super::{Byte, Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `byte` as two hex digits.
    pub fn serialize<S: Serializer>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        Byte(*byte).serialize(serializer)
    }

    /// Reads exactly two upper-case hex digits.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        Byte::deserialize(deserializer).map(|pid| pid.0)
    }
}

/// A DID as four upper-case hex digits, such as `"F187"`, for
/// `#[serde(with = "obdcracker_transport::json::did")]` on a `u16`.
pub mod did {
    use super::{Deserialize, Deserializer, Did, Serialize, Serializer};

    /// Writes `did` as four hex digits.
    pub fn serialize<S: Serializer>(did: &u16, serializer: S) -> Result<S::Ok, S::Error> {
        Did(*did).serialize(serializer)
    }

    /// Reads exactly four upper-case hex digits.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
        Did::deserialize(deserializer).map(|did| did.0)
    }
}

/// A list of DIDs, each as in [`did`], for a `Vec<u16>`.
pub mod did_list {
    use super::{Deserialize, Deserializer, Did, Serializer};

    /// Writes each DID as four hex digits.
    pub fn serialize<S: Serializer>(dids: &[u16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(dids.iter().map(|&did| Did(did)))
    }

    /// Reads each DID as four upper-case hex digits.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u16>, D::Error> {
        let dids = Vec::<Did>::deserialize(deserializer)?;
        Ok(dids.into_iter().map(|did| did.0).collect())
    }
}

// A decoded PID's value: a finite number, so the document never holds a NaN or infinity that JSON
// writes as `null` and can't read back.
pub(crate) mod finite {
    use super::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `with` passes a reference"
    )]
    pub(crate) fn serialize<S: Serializer>(value: &f32, serializer: S) -> Result<S::Ok, S::Error> {
        if !value.is_finite() {
            return Err(ser::Error::custom(format_args!(
                "{value} isn't a finite number"
            )));
        }
        value.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f32, D::Error> {
        let value = f32::deserialize(deserializer)?;
        if value.is_finite() {
            Ok(value)
        } else {
            Err(de::Error::custom(format_args!(
                "{value} isn't a finite number"
            )))
        }
    }
}

/// A `Result<T, E>` as `{"value": ...}` or `{"error": ...}`, for
/// `#[serde(with = "obdcracker_transport::json::outcome")]` on a field of that type.
pub mod outcome {
    use super::{Deserialize, DeserializeOwned, Deserializer, Serialize, Serializer, Wire, wire};

    /// Writes the value or the error.
    pub fn serialize<T: Serialize, E: Serialize, S: Serializer>(
        result: &Result<T, E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        wire(result).serialize(serializer)
    }

    /// Reads an object with `value` or `error`; one with both, or neither, is an error.
    pub fn deserialize<'de, T, E, D>(deserializer: D) -> Result<Result<T, E>, D::Error>
    where
        T: DeserializeOwned,
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        Wire::<T, E>::deserialize(deserializer).map(Into::into)
    }
}

// `Result<Vec<u8>, E>` of PIDs, as a list of hex pairs.
pub(crate) mod outcome_pids {
    use super::{
        Byte, Deserialize, DeserializeOwned, Deserializer, PidList, Serialize, Serializer, Wire,
    };

    pub(crate) fn serialize<E: Serialize, S: Serializer>(
        result: &Result<Vec<u8>, E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match result {
            Ok(pids) => Wire::<_, &E>::Value(PidList(pids)),
            Err(error) => Wire::Error(error),
        }
        .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, E, D>(deserializer: D) -> Result<Result<Vec<u8>, E>, D::Error>
    where
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        let wire = Wire::<Vec<Byte>, E>::deserialize(deserializer)?;
        Ok(match wire {
            Wire::Value(pids) => Ok(pids.into_iter().map(|pid| pid.0).collect()),
            Wire::Error(error) => Err(error),
        })
    }
}

// `Option<Result<T, E>>`, `null` for `None`.
pub(crate) mod option_outcome {
    use super::{Deserialize, DeserializeOwned, Deserializer, Serialize, Serializer, Wire, wire};

    #[expect(clippy::ref_option, reason = "serde's `with` passes a reference")]
    pub(crate) fn serialize<T: Serialize, E: Serialize, S: Serializer>(
        result: &Option<Result<T, E>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        result.as_ref().map(wire).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, T, E, D>(
        deserializer: D,
    ) -> Result<Option<Result<T, E>>, D::Error>
    where
        T: DeserializeOwned,
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        Option::<Wire<T, E>>::deserialize(deserializer).map(|wire| wire.map(Into::into))
    }
}

// `Vec<(u16, Result<T, E>)>` as a list of `{"did": ..., "value": ...}` or `{"did": ..., "error": ...}`.
pub(crate) mod did_outcomes {
    use super::{
        Deserialize, DeserializeOwned, Deserializer, Did, DidResults, Item, Serialize, Serializer,
        wire,
    };

    pub(crate) fn serialize<T: Serialize, E: Serialize, S: Serializer>(
        items: &[(u16, Result<T, E>)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(items.iter().map(|(did, result)| Item {
            key: Did(*did),
            outcome: wire(result),
        }))
    }

    pub(crate) fn deserialize<'de, T, E, D>(deserializer: D) -> Result<DidResults<T, E>, D::Error>
    where
        T: DeserializeOwned,
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        let items = Vec::<Item<Did, T, E>>::deserialize(deserializer)?;
        Ok(items
            .into_iter()
            .map(|item| (item.key.0, item.outcome.into()))
            .collect())
    }
}

// `Vec<(u16, Result<Vec<u8>, E>)>`, as `did_outcomes` with the bytes as hex.
pub(crate) mod did_outcomes_bytes {
    use super::{
        Bytes, Deserialize, DeserializeOwned, Deserializer, Did, DidResults, Item, Serialize,
        Serializer, Wire, wire_bytes,
    };

    pub(crate) fn serialize<E: Serialize, S: Serializer>(
        items: &[(u16, Result<Vec<u8>, E>)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(items.iter().map(|(did, result)| Item {
            key: Did(*did),
            outcome: wire_bytes(result),
        }))
    }

    pub(crate) fn deserialize<'de, E, D>(
        deserializer: D,
    ) -> Result<DidResults<Vec<u8>, E>, D::Error>
    where
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        let items = Vec::<Item<Did, Bytes, E>>::deserialize(deserializer)?;
        Ok(items
            .into_iter()
            .map(|item| {
                let result = match item.outcome {
                    Wire::Value(bytes) => Ok(bytes.0),
                    Wire::Error(error) => Err(error),
                };
                (item.key.0, result)
            })
            .collect())
    }
}

// `Vec<(u16, Vec<u8>)>` as a list of `{"did": ..., "data": ...}`.
pub(crate) mod did_data {
    use super::{BytesRef, Deserialize, Deserializer, Did, DidData, Serialize, Serializer};

    #[derive(Serialize)]
    struct Item<'a> {
        did: Did,
        data: BytesRef<'a>,
    }

    pub(crate) fn serialize<S: Serializer>(
        items: &[(u16, Vec<u8>)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(items.iter().map(|(did, data)| Item {
            did: Did(*did),
            data: BytesRef(data),
        }))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<(u16, Vec<u8>)>, D::Error> {
        let items = Vec::<DidData>::deserialize(deserializer)?;
        Ok(items
            .into_iter()
            .map(|item| (item.did.0, item.data.0))
            .collect())
    }
}

// `Result<Vec<(u8, Result<T, E>)>, E>`: each PID as `{"pid": ..., "value": ...}` or
// `{"pid": ..., "error": ...}`, or the whole list's `{"error": ...}`.
pub(crate) mod pid_readings {
    use super::{
        Byte, Deserialize, DeserializeOwned, Deserializer, Item, Serialize, Serializer, Wire, wire,
    };

    type Readings<T, E> = Vec<(u8, Result<T, E>)>;

    pub(crate) fn serialize<T: Serialize, E: Serialize, S: Serializer>(
        result: &Result<Readings<T, E>, E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match result {
            Ok(items) => Wire::<_, &E>::Value(
                items
                    .iter()
                    .map(|(pid, result)| Item {
                        key: Byte(*pid),
                        outcome: wire(result),
                    })
                    .collect::<Vec<_>>(),
            ),
            Err(error) => Wire::Error(error),
        }
        .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, T, E, D>(
        deserializer: D,
    ) -> Result<Result<Readings<T, E>, E>, D::Error>
    where
        T: DeserializeOwned,
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        let wire = Wire::<Vec<Item<Byte, T, E>>, E>::deserialize(deserializer)?;
        Ok(match wire {
            Wire::Value(items) => Ok(items
                .into_iter()
                .map(|item| (item.key.0, item.outcome.into()))
                .collect()),
            Wire::Error(error) => Err(error),
        })
    }
}

// `Option<(u8, E)>` as `{"pid": ..., "error": ...}`.
pub(crate) mod pid_failure {
    use super::{
        Byte, Deserialize, DeserializeOwned, Deserializer, PidFailure, Serialize, Serializer,
    };

    #[expect(clippy::ref_option, reason = "serde's `with` passes a reference")]
    pub(crate) fn serialize<E: Serialize, S: Serializer>(
        failure: &Option<(u8, E)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        failure
            .as_ref()
            .map(|(pid, error)| PidFailure {
                pid: Byte(*pid),
                error,
            })
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, E, D>(deserializer: D) -> Result<Option<(u8, E)>, D::Error>
    where
        E: DeserializeOwned,
        D: Deserializer<'de>,
    {
        Option::<PidFailure<E>>::deserialize(deserializer)
            .map(|failure| failure.map(|failure| (failure.pid.0, failure.error)))
    }
}
