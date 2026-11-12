//! How a [`MonitorStatus`] is written in a document (`docs/json.md`): its named fields and one entry
//! for each monitor its engine type has. A document that doesn't say each of them exactly once is an
//! error, and the reserved bits of bytes C and D aren't kept, so it reads back equal.

use core::fmt;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::ser::{Error as _, SerializeMap, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    COMPRESSION_MONITORS, IgnitionType, Monitor, MonitorKind, MonitorStatus, SPARK_MONITORS,
};

const KINDS: [MonitorKind; 16] = [
    MonitorKind::Misfire,
    MonitorKind::FuelSystem,
    MonitorKind::Components,
    MonitorKind::Catalyst,
    MonitorKind::HeatedCatalyst,
    MonitorKind::EvaporativeSystem,
    MonitorKind::SecondaryAir,
    MonitorKind::AcRefrigerant,
    MonitorKind::OxygenSensor,
    MonitorKind::OxygenSensorHeater,
    MonitorKind::EgrVvt,
    MonitorKind::NmhcCatalyst,
    MonitorKind::NoxScr,
    MonitorKind::BoostPressure,
    MonitorKind::ExhaustGasSensor,
    MonitorKind::ParticulateFilter,
];

const MAX_COUNT: u8 = 0x7F;

struct Monitors<'a>(&'a MonitorStatus);

impl Serialize for Monitors<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.monitors().count()))?;
        for (kind, monitor) in self.0.monitors() {
            map.serialize_entry(kind.name(), &monitor)?;
        }
        map.end()
    }
}

impl Serialize for MonitorStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.dtc_count > MAX_COUNT {
            return Err(S::Error::custom("a DTC count is at most 127"));
        }
        let mut status = serializer.serialize_struct("MonitorStatus", 4)?;
        status.serialize_field("mil_on", &self.mil_on)?;
        status.serialize_field("dtc_count", &self.dtc_count)?;
        status.serialize_field("ignition", &self.ignition)?;
        status.serialize_field("monitors", &Monitors(self))?;
        status.end()
    }
}

// The monitors a document gave, by position in `KINDS`.
struct Found([Option<Monitor>; 16]);

struct KindName(Option<usize>);

impl<'de> Deserialize<'de> for KindName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;
        impl Visitor<'_> for Name {
            type Value = KindName;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a monitor name")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<KindName, E> {
                Ok(KindName(KINDS.iter().position(|kind| kind.name() == text)))
            }
        }
        deserializer.deserialize_str(Name)
    }
}

impl<'de> Deserialize<'de> for Found {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> Visitor<'de> for Entries {
            type Value = Found;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of monitors")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Found, A::Error> {
                let mut found = [None; 16];
                while let Some(KindName(index)) = map.next_key()? {
                    let Some(index) = index else {
                        map.next_value::<IgnoredAny>()?;
                        continue;
                    };
                    if found[index].replace(map.next_value()?).is_some() {
                        return Err(de::Error::custom("a monitor is given twice"));
                    }
                }
                Ok(Found(found))
            }
        }
        deserializer.deserialize_map(Entries)
    }
}

enum Field {
    MilOn,
    DtcCount,
    Ignition,
    Monitors,
    Other,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;
        impl Visitor<'_> for Name {
            type Value = Field;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Field, E> {
                Ok(match text {
                    "mil_on" => Field::MilOn,
                    "dtc_count" => Field::DtcCount,
                    "ignition" => Field::Ignition,
                    "monitors" => Field::Monitors,
                    _ => Field::Other,
                })
            }
        }
        deserializer.deserialize_str(Name)
    }
}

fn once<T, E: de::Error>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E> {
    if slot.replace(value).is_some() {
        return Err(E::duplicate_field(field));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for MonitorStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Status;
        impl<'de> Visitor<'de> for Status {
            type Value = MonitorStatus;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a monitor status")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MonitorStatus, A::Error> {
                let (mut mil_on, mut dtc_count, mut ignition, mut found) = (None, None, None, None);
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::MilOn => once(&mut mil_on, map.next_value()?, "mil_on")?,
                        Field::DtcCount => once(&mut dtc_count, map.next_value()?, "dtc_count")?,
                        Field::Ignition => once(&mut ignition, map.next_value()?, "ignition")?,
                        Field::Monitors => once(&mut found, map.next_value()?, "monitors")?,
                        Field::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                let missing = |name| de::Error::missing_field(name);
                let dtc_count: u8 = dtc_count.ok_or_else(|| missing("dtc_count"))?;
                if dtc_count > MAX_COUNT {
                    return Err(de::Error::custom("a DTC count is at most 127"));
                }
                assemble(
                    mil_on.ok_or_else(|| missing("mil_on"))?,
                    dtc_count,
                    ignition.ok_or_else(|| missing("ignition"))?,
                    found.ok_or_else(|| missing("monitors"))?,
                )
            }
        }
        deserializer.deserialize_map(Status)
    }
}

// Exactly the monitors this engine type has, each given once.
fn assemble<E: de::Error>(
    mil_on: bool,
    dtc_count: u8,
    ignition: IgnitionType,
    Found(found): Found,
) -> Result<MonitorStatus, E> {
    let table: &[(u8, MonitorKind)] = match ignition {
        IgnitionType::Spark => &SPARK_MONITORS,
        IgnitionType::Compression => &COMPRESSION_MONITORS,
    };
    let common = [
        MonitorKind::Misfire,
        MonitorKind::FuelSystem,
        MonitorKind::Components,
    ];
    let expected = |kind: &MonitorKind| {
        common.contains(kind) || table.iter().any(|(_, engine)| engine == kind)
    };
    for (kind, monitor) in KINDS.iter().zip(&found) {
        if monitor.is_some() != expected(kind) {
            return Err(E::custom(format_args!(
                "the monitor {} is {} for this engine type",
                kind.name(),
                if monitor.is_some() {
                    "not one"
                } else {
                    "missing"
                }
            )));
        }
    }
    let get = |kind: MonitorKind| {
        let index = KINDS.iter().position(|&k| k == kind);
        index.and_then(|i| found[i]).unwrap_or(Monitor {
            supported: false,
            complete: false,
        })
    };
    let (mut engine_supported, mut engine_incomplete) = (0, 0);
    for &(bit, kind) in table {
        let monitor = get(kind);
        engine_supported |= u8::from(monitor.supported) << bit;
        engine_incomplete |= u8::from(!monitor.complete) << bit;
    }
    Ok(MonitorStatus {
        mil_on,
        dtc_count,
        ignition,
        misfire: get(MonitorKind::Misfire),
        fuel_system: get(MonitorKind::FuelSystem),
        components: get(MonitorKind::Components),
        engine_supported,
        engine_incomplete,
    })
}
