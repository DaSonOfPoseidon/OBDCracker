//! The result types as JSON: each is read back equal to what was written, the text forms are the
//! ones `docs/json.md` lists, and text that isn't one of them is an error.
#![cfg(feature = "serde")]

use std::fmt::Debug;

use obdcracker_core::obd::{Cvn, Dtc, Unit};
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_core::uds::{DtcCount, DtcFormat, DtcRecord, DtcStatus, UdsDtc};
use obdcracker_transport::Response;
use obdcracker_transport::dtc::{DtcDetail, RecordData};
use obdcracker_transport::elm::AdapterInfo;
use obdcracker_transport::fingerprint::{
    Calibration, DidValue, Fingerprint, Identification, ReadError, UdsModule,
};
use obdcracker_transport::json::{self, parse_bytes};
use obdcracker_transport::read_dids::DidsData;
use obdcracker_transport::scan::{ModuleScan, ObdEcu, PidValue, Scan};
use obdcracker_transport::sweep::{Stop, Sweep, Why};
use obdcracker_transport::voltage::LowVoltage;
use obdcracker_transport::{Error, hex};
use proptest::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// Writes `value`, checks the document is `expected` when given, and reads it back equal.
fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    value: &T,
    expected: Option<Value>,
) -> Value {
    let text = serde_json::to_string(value).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    if let Some(expected) = expected {
        assert_eq!(document, expected, "{text}");
    }
    assert_eq!(&serde_json::from_str::<T>(&text).unwrap(), value, "{text}");
    document
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Bytes(#[serde(with = "json::bytes")] Vec<u8>);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Id(#[serde(with = "json::can_id")] u32);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Did(#[serde(with = "json::did")] u16);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Dids(#[serde(with = "json::did_list")] Vec<u16>);

fn from_text<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(json!(text))
}

#[test]
fn bytes_are_upper_case_spaced_hex() {
    for (bytes, text) in [
        (vec![], ""),
        (vec![0x00], "00"),
        (vec![0xFF], "FF"),
        (vec![0x1A, 0x2A, 0x40], "1A 2A 40"),
    ] {
        round_trip(&Bytes(bytes), Some(json!(text)));
    }
    let long: Vec<u8> = (0..4095u32)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    assert_eq!(round_trip(&Bytes(long.clone()), None), json!(hex(&long)));
}

#[test]
fn bytes_reject_anything_else() {
    for bad in [
        "1", "1A 2", "1A2A", "1a", "1A  2A", " 1A", "1A ", "1A,2A", "GG", "+1", "1A\n2A", "ÀÀ",
        "1A 2A 4",
    ] {
        assert!(from_text::<Bytes>(bad).is_err(), "{bad:?}");
        assert_eq!(parse_bytes(bad), None, "{bad:?}");
    }
    assert!(serde_json::from_value::<Bytes>(json!([26, 42])).is_err());
}

#[test]
fn can_ids_are_three_or_eight_digits() {
    round_trip(&Id(0x7E8), Some(json!("7E8")));
    round_trip(&Id(0), Some(json!("000")));
    round_trip(&Id(0x7FF), Some(json!("7FF")));
    round_trip(&Id(0x800), Some(json!("00000800")));
    round_trip(&Id(0x17FE_0010), Some(json!("17FE0010")));
    round_trip(&Id(0x1FFF_FFFF), Some(json!("1FFFFFFF")));
}

#[test]
fn can_ids_outside_29_bits_are_refused_both_ways() {
    assert!(serde_json::to_string(&Id(0x2000_0000)).is_err());
    assert!(serde_json::to_string(&Id(u32::MAX)).is_err());
    for bad in [
        "800",
        "FFF",
        "7e8",
        "7E",
        "7E88",
        "20000000",
        "FFFFFFFF",
        "17FE001",
        "17FE00100",
        "+7E8",
        "",
    ] {
        assert!(from_text::<Id>(bad).is_err(), "{bad:?}");
    }
    // An ID a 3-digit form holds has no other spelling.
    for short in ["00000000", "00000123", "000007FF"] {
        assert!(from_text::<Id>(short).is_err(), "{short}");
    }
    assert_eq!(from_text::<Id>("00000800").unwrap(), Id(0x800));
}

#[test]
fn dids_are_four_digits() {
    round_trip(&Did(0xF187), Some(json!("F187")));
    round_trip(&Did(0), Some(json!("0000")));
    round_trip(&Dids(vec![0xF187, 0x0001]), Some(json!(["F187", "0001"])));
    round_trip(&Dids(vec![]), Some(json!([])));
    for bad in ["F18", "F1870", "f187", "+187", "F 87", ""] {
        assert!(from_text::<Did>(bad).is_err(), "{bad:?}");
    }
    assert!(serde_json::from_value::<Dids>(json!(["F187", "F18"])).is_err());
}

fn refusal() -> ReadError {
    ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x22,
        nrc: Nrc::RequestOutOfRange,
    }))
}

fn sample_fingerprint() -> Fingerprint {
    Fingerprint {
        ecus: vec![
            Calibration {
                source: 0x7E8,
                calids: Ok(vec![Some("8K0907401F".to_owned()), None]),
                cvns: Ok(vec![Cvn([0x12, 0xAB, 0x34, 0xCD]), Cvn([0; 4])]),
            },
            Calibration {
                source: 0x7E9,
                calids: Err(ReadError::NoReply),
                cvns: Err(ReadError::CountMismatch { calids: 2, cvns: 1 }),
            },
        ],
        modules: vec![Identification {
            name: "engine".to_owned(),
            response_id: 0x7E8,
            dids: vec![
                (0xF187, Ok(DidValue::Text("8K0907401F".to_owned()))),
                (0xF191, Ok(DidValue::Bytes(vec![0x00, 0xFF]))),
                (0xF190, Ok(DidValue::NotSet)),
                (0xF188, Err(refusal())),
                (
                    0xF189,
                    Err(ReadError::Undecodable {
                        error: ReplyError::TooShort,
                        reply: vec![0x62, 0xF1],
                    }),
                ),
                (0xF19E, Err(ReadError::NeedsExtendedSession)),
            ],
        }],
    }
}

#[test]
fn a_fingerprint_is_written_as_documented() {
    round_trip(
        &sample_fingerprint(),
        Some(json!({
            "ecus": [
                {
                    "source": "7E8",
                    "calids": {"value": ["8K0907401F", null]},
                    "cvns": {"value": ["12AB34CD", "00000000"]},
                },
                {
                    "source": "7E9",
                    "calids": {"error": "NoReply"},
                    "cvns": {"error": {"CountMismatch": {"calids": 2, "cvns": 1}}},
                },
            ],
            "modules": [{
                "name": "engine",
                "response_id": "7E8",
                "dids": [
                    {"did": "F187", "value": {"Text": "8K0907401F"}},
                    {"did": "F191", "value": {"Bytes": "00 FF"}},
                    {"did": "F190", "value": "NotSet"},
                    {"did": "F188", "error": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}},
                    {"did": "F189", "error": {"Undecodable": {"error": "TooShort", "reply": "62 F1"}}},
                    {"did": "F19E", "error": "NeedsExtendedSession"},
                ],
            }],
        })),
    );
}

#[test]
fn an_empty_fingerprint_and_scan_round_trip() {
    let fingerprint = Fingerprint {
        ecus: vec![],
        modules: vec![],
    };
    round_trip(&fingerprint, Some(json!({"ecus": [], "modules": []})));
    let scan = Scan {
        ecus: vec![],
        modules: vec![],
    };
    round_trip(&scan, Some(json!({"ecus": [], "modules": []})));
}

fn sample_scan() -> Scan {
    Scan {
        ecus: vec![ObdEcu {
            source: 0x7E8,
            pids: Ok(vec![
                (
                    0x0C,
                    Ok(PidValue::Quantity {
                        value: 812.5,
                        unit: Unit::Rpm,
                    }),
                ),
                (0x0D, Ok(PidValue::Raw(vec![0x01, 0x02]))),
                (0x0E, Err(ReadError::NoReply)),
            ]),
            pids_cut_short: Some((0x40, ReadError::StillPending)),
            supported_info: Ok(vec![0x00, 0x02, 0x0A]),
            ecu_name: Ok("ECM-EngineControl".to_owned()),
            stored_dtcs: Ok(vec![Dtc::new(0x0401)]),
        }],
        modules: vec![ModuleScan {
            name: "transmission".to_owned(),
            response_id: 0x7E9,
            dids: vec![(0xF191, Ok(DidValue::Text("0BK927156AM".to_owned())))],
            dtc_count: Ok(DtcCount {
                availability: DtcStatus(0xFF),
                format: DtcFormat::SaeJ2012Da00,
                count: 1,
            }),
            dtcs: Ok(vec![DtcRecord {
                dtc: UdsDtc::new(0x0004_0100),
                status: DtcStatus(0x2F),
            }]),
            answered: true,
        }],
    }
}

#[test]
fn a_scan_is_written_as_documented() {
    round_trip(
        &sample_scan(),
        Some(json!({
            "ecus": [{
                "source": "7E8",
                "pids": {"value": [
                    {"pid": "0C", "value": {"Quantity": {"value": 812.5, "unit": "Rpm"}}},
                    {"pid": "0D", "value": {"Raw": "01 02"}},
                    {"pid": "0E", "error": "NoReply"},
                ]},
                "pids_cut_short": {"pid": "40", "error": "StillPending"},
                "supported_info": {"value": ["00", "02", "0A"]},
                "ecu_name": {"value": "ECM-EngineControl"},
                "stored_dtcs": {"value": ["P0401"]},
            }],
            "modules": [{
                "name": "transmission",
                "response_id": "7E9",
                "dids": [{"did": "F191", "value": {"Text": "0BK927156AM"}}],
                "dtc_count": {"value": {"availability": "FF", "format": "00", "count": 1}},
                "dtcs": {"value": [{"dtc": "040100", "status": "2F"}]},
                "answered": true,
            }],
        })),
    );
}

#[test]
fn scan_failures_round_trip() {
    let mut scan = sample_scan();
    scan.ecus[0].pids = Err(ReadError::NoReply);
    scan.ecus[0].pids_cut_short = None;
    scan.ecus[0].supported_info = Err(refusal());
    scan.ecus[0].ecu_name = Err(ReadError::NoReply);
    scan.ecus[0].stored_dtcs = Ok(vec![]);
    scan.modules[0].dtc_count = Err(ReadError::NoReply);
    scan.modules[0].dtcs = Err(ReadError::NoReply);
    scan.modules[0].answered = false;
    let document = round_trip(&scan, None);
    assert_eq!(document["ecus"][0]["pids"], json!({"error": "NoReply"}));
    assert_eq!(document["ecus"][0]["pids_cut_short"], Value::Null);
}

#[test]
fn a_29_bit_module_keeps_its_id_in_a_scan() {
    let mut scan = sample_scan();
    scan.modules[0].response_id = 0x17FE_0010;
    let document = round_trip(&scan, None);
    assert_eq!(document["modules"][0]["response_id"], json!("17FE0010"));
}

#[test]
fn a_pid_value_that_is_not_finite_is_an_error_to_write_and_to_read() {
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let value = PidValue::Quantity {
            value,
            unit: Unit::Percent,
        };
        assert!(serde_json::to_string(&value).is_err(), "{value:?}");
    }
    let null = json!({"Quantity": {"value": null, "unit": "Percent"}});
    assert!(serde_json::from_value::<PidValue>(null).is_err());
    let text = json!({"Quantity": {"value": "NaN", "unit": "Percent"}});
    assert!(serde_json::from_value::<PidValue>(text).is_err());
}

#[test]
fn a_whole_number_value_reads_back_as_the_same_quantity() {
    let value = PidValue::Quantity {
        value: 40.0,
        unit: Unit::Celsius,
    };
    round_trip(&value, None);
    let from_integer: PidValue =
        serde_json::from_value(json!({"Quantity": {"value": 40, "unit": "Celsius"}})).unwrap();
    assert_eq!(from_integer, value);
}

fn sample_sweep() -> Sweep {
    Sweep {
        found: vec![
            (0x0600, Ok(vec![0x01, 0x02])),
            (0x0601, Ok(vec![])),
            (0x0602, Err(refusal())),
            (0x0603, Err(ReadError::NoReply)),
        ],
        stop: Some(Stop {
            at: 0x0603,
            why: Why::Module(ReadError::NoReply),
        }),
        still_extended: Some(ReadError::NoReply),
        out_of_step: true,
    }
}

#[test]
fn a_sweep_is_written_as_documented() {
    round_trip(
        &sample_sweep(),
        Some(json!({
            "found": [
                {"did": "0600", "value": "01 02"},
                {"did": "0601", "value": ""},
                {"did": "0602", "error": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}},
                {"did": "0603", "error": "NoReply"},
            ],
            "stop": {"at": "0603", "why": {"Module": "NoReply"}},
            "still_extended": "NoReply",
            "out_of_step": true,
        })),
    );
}

#[test]
fn every_reason_a_sweep_stopped_round_trips() {
    let whys = [
        (
            Why::Module(refusal()),
            json!({"Module": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}}),
        ),
        (
            Why::Unmatched(ReadError::NoReply),
            json!({"Unmatched": "NoReply"}),
        ),
        (
            Why::LowVoltage(LowVoltage {
                after: 50,
                millivolts: 11_500,
            }),
            json!({"LowVoltage": {"after": 50, "millivolts": 11500}}),
        ),
        (Why::Adapter(Error::Timeout), json!({"Adapter": "Timeout"})),
        (
            Why::Adapter(Error::StillPending),
            json!({"Adapter": "StillPending"}),
        ),
        (
            Why::Adapter(Error::Adapter("BUFFER FULL".to_owned())),
            json!({"Adapter": {"Adapter": "BUFFER FULL"}}),
        ),
    ];
    for (why, expected) in whys {
        round_trip(&why, Some(expected));
    }
    let finished = Sweep {
        found: vec![],
        stop: None,
        still_extended: None,
        out_of_step: false,
    };
    round_trip(
        &finished,
        Some(json!({"found": [], "stop": null, "still_extended": null, "out_of_step": false})),
    );
}

#[test]
fn a_dtc_detail_is_written_as_documented() {
    let detail = DtcDetail {
        snapshots: Ok(RecordData {
            status: DtcStatus(0x2F),
            records: vec![0x01, 0x01, 0xF4, 0x40, 0x12],
        }),
        extended_data: Some(Err(refusal())),
        out_of_step: false,
    };
    round_trip(
        &detail,
        Some(json!({
            "snapshots": {"value": {"status": "2F", "records": "01 01 F4 40 12"}},
            "extended_data": {"error": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}},
            "out_of_step": false,
        })),
    );
    let not_asked = DtcDetail {
        snapshots: Err(ReadError::NoReply),
        extended_data: None,
        out_of_step: true,
    };
    round_trip(
        &not_asked,
        Some(json!({
            "snapshots": {"error": "NoReply"},
            "extended_data": null,
            "out_of_step": true,
        })),
    );
    let none_stored = RecordData {
        status: DtcStatus(0),
        records: vec![],
    };
    round_trip(&none_stored, Some(json!({"status": "00", "records": ""})));
}

#[test]
fn split_and_unsplit_dids_are_written_as_documented() {
    let data = DidsData {
        split: vec![(0xF187, vec![0x30, 0x42]), (0xF188, vec![])],
        unsplit: vec![0xF1, 0x89, 0x00],
    };
    round_trip(
        &data,
        Some(json!({
            "split": [{"did": "F187", "data": "30 42"}, {"did": "F188", "data": ""}],
            "unsplit": "F1 89 00",
        })),
    );
    let all_split = DidsData {
        split: vec![],
        unsplit: vec![],
    };
    round_trip(&all_split, Some(json!({"split": [], "unsplit": ""})));
}

#[test]
fn adapter_info_and_modules_round_trip() {
    let info = AdapterInfo {
        id: "ELM327 v1.4b".to_owned(),
        stn: None,
        voltage: Some("12.6V".to_owned()),
    };
    round_trip(
        &info,
        Some(json!({"id": "ELM327 v1.4b", "stn": null, "voltage": "12.6V"})),
    );
    let module = UdsModule {
        name: "gateway".to_owned(),
        request_id: 0x17FC_0010,
        response_id: 0x17FE_0010,
    };
    round_trip(
        &module,
        Some(json!({"name": "gateway", "request_id": "17FC0010", "response_id": "17FE0010"})),
    );
}

#[test]
fn a_response_keeps_what_equality_compares_and_drops_the_bus_time() {
    let reply =
        Response::new(0x7E8, vec![0x49, 0x02, 0x01]).at_bus_time(Some(std::time::Instant::now()));
    let document = round_trip(
        &reply,
        Some(json!({"source": "7E8", "payload": "49 02 01"})),
    );
    assert_eq!(document.as_object().unwrap().len(), 2);
}

#[test]
fn unknown_fields_are_ignored_and_known_ones_are_required() {
    let scan: Scan =
        serde_json::from_value(json!({"ecus": [], "modules": [], "added later": {"x": 1}}))
            .unwrap();
    assert_eq!(scan.ecus, vec![]);
    assert!(serde_json::from_value::<Scan>(json!({"ecus": []})).is_err());
    let calibration = json!({
        "source": "7E8",
        "calids": {"value": []},
        "cvns": {"value": []},
        "later": true,
    });
    assert!(serde_json::from_value::<Calibration>(calibration).is_ok());
}

#[test]
fn fields_added_to_a_value_or_error_object_and_to_a_list_entry_are_ignored() {
    let mut document = serde_json::to_value(sample_scan()).unwrap();
    let mut fingerprint = serde_json::to_value(sample_fingerprint()).unwrap();
    let mut detail = serde_json::to_value(DtcDetail {
        snapshots: Ok(RecordData {
            status: DtcStatus(0x2F),
            records: vec![0x01],
        }),
        extended_data: Some(Err(refusal())),
        out_of_step: false,
    })
    .unwrap();
    // Each `value`/`error` object a result type writes, and each entry of a list of them.
    for value in [&mut document, &mut fingerprint, &mut detail] {
        add_a_field_everywhere(value);
    }
    assert_eq!(
        serde_json::from_value::<Scan>(document).unwrap(),
        sample_scan()
    );
    assert_eq!(
        serde_json::from_value::<Fingerprint>(fingerprint).unwrap(),
        sample_fingerprint()
    );
    let detail: DtcDetail = serde_json::from_value(detail).unwrap();
    assert_eq!(detail.snapshots.unwrap().records, [0x01]);
    assert_eq!(detail.extended_data, Some(Err(refusal())));
}

// Adds `"added later": 1` to every object that has `value` or `error`.
fn add_a_field_everywhere(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.contains_key("value") || object.contains_key("error") {
                object.insert("added later".to_owned(), json!(1));
            }
            object.values_mut().for_each(add_a_field_everywhere);
        }
        Value::Array(items) => items.iter_mut().for_each(add_a_field_everywhere),
        _ => {}
    }
}

#[test]
fn malformed_forms_inside_a_result_are_errors() {
    let bad_id = json!({"source": "7E", "calids": {"value": []}, "cvns": {"value": []}});
    assert!(serde_json::from_value::<Calibration>(bad_id).is_err());
    let both = json!({"did": "F187", "value": "NotSet", "error": "NoReply"});
    let identification = json!({"name": "x", "response_id": "7E8", "dids": [both]});
    assert!(serde_json::from_value::<Identification>(identification).is_err());
    let neither = json!({"name": "x", "response_id": "7E8", "dids": [{"did": "F187"}]});
    assert!(serde_json::from_value::<Identification>(neither).is_err());
    let wrong_did =
        json!({"name": "x", "response_id": "7E8", "dids": [{"did": "F18", "value": "NotSet"}]});
    assert!(serde_json::from_value::<Identification>(wrong_did).is_err());
    let twice = r#"{"name": "x", "response_id": "7E8", "dids":
        [{"did": "F187", "value": "NotSet", "value": "NotSet"}]}"#;
    assert!(serde_json::from_str::<Identification>(twice).is_err());
    let key_twice = r#"{"name": "x", "response_id": "7E8", "dids":
        [{"did": "F187", "did": "F188", "value": "NotSet"}]}"#;
    assert!(serde_json::from_str::<Identification>(key_twice).is_err());
    let both_in_field = json!({"source": "7E8",
        "calids": {"value": [], "error": "NoReply"}, "cvns": {"value": []}});
    assert!(serde_json::from_value::<Calibration>(both_in_field).is_err());
    let bad_bytes = json!({"found": [{"did": "0600", "value": "1"}], "stop": null,
        "still_extended": null, "out_of_step": false});
    assert!(serde_json::from_value::<Sweep>(bad_bytes).is_err());
}

fn any_read_error() -> impl Strategy<Value = ReadError> {
    prop_oneof![
        Just(ReadError::NoReply),
        Just(ReadError::StillPending),
        Just(ReadError::NeedsExtendedSession),
        (any::<u8>(), any::<u8>()).prop_map(|(sid, nrc)| ReadError::Reply(ReplyError::Negative(
            NegativeResponse {
                sid,
                nrc: Nrc::from(nrc)
            }
        ))),
        (any::<u8>(), prop::collection::vec(any::<u8>(), 0..8)).prop_map(|(sid, reply)| {
            ReadError::Undecodable {
                error: ReplyError::WrongService(sid),
                reply,
            }
        }),
        (0usize..5, 0usize..5).prop_map(|(calids, cvns)| ReadError::CountMismatch { calids, cvns }),
    ]
}

fn any_can_id() -> impl Strategy<Value = u32> {
    prop_oneof![0u32..=0x7FF, 0x800u32..=0x1FFF_FFFF]
}

proptest! {
    #[test]
    fn any_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let text = hex(&bytes);
        prop_assert_eq!(parse_bytes(&text), Some(bytes.clone()));
        round_trip(&Bytes(bytes), None);
    }

    // Whatever reads is exactly what was written, and nothing panics.
    #[test]
    fn arbitrary_text_never_panics_and_only_canonical_text_reads(text in "\\PC{0,24}") {
        if let Some(bytes) = parse_bytes(&text) {
            prop_assert_eq!(hex(&bytes), text.clone());
        }
        if let Ok(id) = from_text::<Id>(&text) {
            prop_assert_eq!(serde_json::to_value(&id).unwrap(), json!(text.clone()));
        }
        if let Ok(Did(did)) = from_text::<Did>(&text) {
            prop_assert_eq!(format!("{did:04X}"), text);
        }
    }

    #[test]
    fn near_miss_hex_text_never_panics(text in "[0-9A-Fa-f +-]{0,14}") {
        if let Some(bytes) = parse_bytes(&text) {
            prop_assert_eq!(hex(&bytes), text.clone());
        }
        let _ = from_text::<Id>(&text);
        let _ = from_text::<Did>(&text);
    }

    #[test]
    fn can_ids_round_trip(id in any_can_id()) {
        round_trip(&Id(id), None);
    }

    #[test]
    fn dids_round_trip(did in any::<u16>()) {
        round_trip(&Did(did), None);
    }

    #[test]
    fn finite_quantities_round_trip(value in any::<f32>().prop_filter("finite", |v| v.is_finite())) {
        round_trip(&PidValue::Quantity { value, unit: Unit::Kilopascals }, None);
    }

    #[test]
    fn did_results_round_trip(
        entries in prop::collection::vec(
            (any::<u16>(), prop_oneof![
                prop::collection::vec(any::<u8>(), 0..6).prop_map(|b| Ok(DidValue::Bytes(b))),
                "[ -~]{0,8}".prop_map(|t| Ok(DidValue::Text(t))),
                Just(Ok(DidValue::NotSet)),
                any_read_error().prop_map(Err),
            ]),
            0..6,
        ),
        id in any_can_id(),
    ) {
        round_trip(&Identification { name: "m".to_owned(), response_id: id, dids: entries }, None);
    }

    #[test]
    fn sweeps_round_trip(
        found in prop::collection::vec(
            (any::<u16>(), prop_oneof![
                prop::collection::vec(any::<u8>(), 0..6).prop_map(Ok),
                any_read_error().prop_map(Err),
            ]),
            0..6,
        ),
        at in any::<u16>(),
        out_of_step in any::<bool>(),
    ) {
        let sweep = Sweep {
            found,
            stop: Some(Stop { at, why: Why::Unmatched(ReadError::NoReply) }),
            still_extended: None,
            out_of_step,
        };
        round_trip(&sweep, None);
    }
}
