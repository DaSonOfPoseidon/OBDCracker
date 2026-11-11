//! The document `--json` prints: an envelope around one command's result (`docs/json.md`).

use obdcracker_core::uds::UdsDtc;
use obdcracker_transport::dtc::DtcDetail;
use obdcracker_transport::elm::AdapterInfo;
use obdcracker_transport::fingerprint::{ReadError, UdsModule};
use obdcracker_transport::json;
use obdcracker_transport::read_dids::DidsData;
use obdcracker_transport::sweep::Sweep;
use serde::{Deserialize, Serialize};

use crate::BUILD;

// Raised on any change that breaks a reader of the version before it. A reader refuses a version
// above the one it knows.
pub(crate) const SCHEMA: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "RawEnvelope<T>")]
pub(crate) struct Envelope<T> {
    pub(crate) schema: u32,
    pub(crate) command: String,
    pub(crate) obdcracker: String,
    pub(crate) result: T,
}

#[derive(Deserialize)]
struct RawEnvelope<T> {
    schema: u32,
    command: String,
    obdcracker: String,
    result: T,
}

impl<T> TryFrom<RawEnvelope<T>> for Envelope<T> {
    type Error = String;

    fn try_from(raw: RawEnvelope<T>) -> Result<Self, String> {
        if !(1..=SCHEMA).contains(&raw.schema) {
            return Err(format!(
                "schema {} isn't one this build reads (1 to {SCHEMA})",
                raw.schema
            ));
        }
        Ok(Self {
            schema: raw.schema,
            command: raw.command,
            obdcracker: raw.obdcracker,
            result: raw.result,
        })
    }
}

// Prints `result` as the document of `command` on stdout. False, with the reason on stderr and
// nothing on stdout, if it can't be written.
pub(crate) fn print<T: Serialize>(command: &str, result: &T) -> bool {
    let document = Envelope {
        schema: SCHEMA,
        command: command.to_owned(),
        obdcracker: BUILD.version.to_owned(),
        result,
    };
    match serde_json::to_string(&document) {
        Ok(text) => {
            println!("{text}");
            true
        }
        Err(e) => {
            eprintln!("can't write the JSON document: {e}");
            false
        }
    }
}

// What `vin` read: each emissions ECU whose reply was a VIN.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct VinReading {
    #[serde(with = "json::can_id")]
    pub(crate) source: u32,
    pub(crate) vin: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Ports {
    pub(crate) ports: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct AdapterReport {
    pub(crate) adapter: AdapterInfo,
    pub(crate) link: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct SweepReport {
    pub(crate) module: UdsModule,
    #[serde(with = "json::did")]
    pub(crate) first: u16,
    #[serde(with = "json::did")]
    pub(crate) last: u16,
    pub(crate) sweep: Sweep,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReadDidsReport {
    pub(crate) module: UdsModule,
    #[serde(with = "json::did_list")]
    pub(crate) dids: Vec<u16>,
    #[serde(with = "json::outcome")]
    pub(crate) read: Result<DidsData, ReadError>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct DtcReport {
    pub(crate) module: UdsModule,
    pub(crate) dtc: UdsDtc,
    #[serde(with = "json::byte")]
    pub(crate) record: u8,
    pub(crate) detail: DtcDetail,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn read(document: &serde_json::Value) -> Result<Envelope<Ports>, serde_json::Error> {
        serde_json::from_value(document.clone())
    }

    fn envelope(schema: u32) -> serde_json::Value {
        json!({
            "schema": schema,
            "command": "ports",
            "obdcracker": "0.1.0",
            "result": {"ports": ["/dev/ttyUSB0"]},
        })
    }

    #[test]
    fn the_known_schema_reads() {
        let read = read(&envelope(1)).unwrap();
        assert_eq!((read.schema, read.command.as_str()), (1, "ports"));
        assert_eq!(read.result.ports, ["/dev/ttyUSB0"]);
    }

    #[test]
    fn a_schema_above_the_known_one_or_below_the_first_is_refused() {
        for schema in [0, SCHEMA + 1, u32::MAX] {
            let error = read(&envelope(schema)).unwrap_err().to_string();
            assert!(error.contains("isn't one this build reads"), "{error}");
        }
    }

    #[test]
    fn unknown_fields_are_ignored_and_known_ones_are_required() {
        let mut document = envelope(1);
        document["added later"] = json!([1]);
        document["result"]["too"] = json!(null);
        assert!(read(&document).is_ok());
        for missing in ["schema", "command", "obdcracker", "result"] {
            let mut document = envelope(1);
            document.as_object_mut().unwrap().remove(missing);
            assert!(read(&document).is_err(), "{missing}");
        }
    }

    #[test]
    fn what_print_writes_reads_back() {
        let written = Envelope {
            schema: SCHEMA,
            command: "ports".to_owned(),
            obdcracker: BUILD.version.to_owned(),
            result: &Ports {
                ports: vec!["COM3".to_owned()],
            },
        };
        let text = serde_json::to_string(&written).unwrap();
        let read: Envelope<Ports> = serde_json::from_str(&text).unwrap();
        assert_eq!(read.result.ports, ["COM3"]);
        assert_eq!(read.schema, SCHEMA);
    }
}
