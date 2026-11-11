//! The core types' text forms in a document: each is read back exactly as written, and any other
//! text is an error.
#![cfg(feature = "serde")]

use obdcracker_core::obd::{Cvn, Dtc, Unit};
use obdcracker_core::response::{Error, NegativeResponse, Nrc};
use obdcracker_core::uds::{DtcCount, DtcFormat, DtcRecord, DtcStatus, UdsDtc};
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) -> String {
    let text = serde_json::to_string(value).unwrap();
    assert_eq!(&serde_json::from_str::<T>(&text).unwrap(), value, "{text}");
    text
}

fn read<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(json!(text))
}

#[test]
fn dtc_is_its_j2012_text() {
    assert_eq!(round_trip(&Dtc::new(0x0401)), r#""P0401""#);
    assert_eq!(round_trip(&Dtc::new(0x4123)), r#""C0123""#);
    assert_eq!(round_trip(&Dtc::new(0x8ABC)), r#""B0ABC""#);
    assert_eq!(round_trip(&Dtc::new(0xFFFF)), r#""U3FFF""#);
    assert_eq!(round_trip(&Dtc::new(0x0000)), r#""P0000""#);
}

#[test]
fn dtc_rejects_text_the_display_form_never_writes() {
    for bad in [
        "", "P", "P040", "P04011", "p0401", "P040a", "X0401", "P+401", " P0401", "P0401 ", "P4000",
        "P 401", "0401", "É0401", "P04É",
    ] {
        assert!(read::<Dtc>(bad).is_err(), "{bad:?}");
    }
    assert!(serde_json::from_value::<Dtc>(json!(0x0401)).is_err());
    assert!(serde_json::from_value::<Dtc>(json!(null)).is_err());
}

#[test]
fn uds_dtc_is_six_hex_digits() {
    assert_eq!(round_trip(&UdsDtc::new(0x16A0)), r#""0016A0""#);
    assert_eq!(round_trip(&UdsDtc::new(0)), r#""000000""#);
    assert_eq!(round_trip(&UdsDtc::new(0xFF_FFFF)), r#""FFFFFF""#);
}

#[test]
fn uds_dtc_keeps_its_24_bit_mask_and_masks_nothing() {
    for bad in [
        "1000000", "01000000", "FFFFFFFF", "16A0", "0016a0", "+016A0", "0016A", "00 16A0", "",
    ] {
        assert!(read::<UdsDtc>(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn cvn_is_eight_hex_digits() {
    assert_eq!(round_trip(&Cvn([0x12, 0xAB, 0x34, 0xCD])), r#""12AB34CD""#);
    assert_eq!(round_trip(&Cvn([0; 4])), r#""00000000""#);
    for bad in [
        "12AB34C",
        "12AB34CDE",
        "12ab34cd",
        "+2AB34CD",
        "12AB 34CD",
        "",
    ] {
        assert!(read::<Cvn>(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn status_format_and_nrc_are_a_byte_of_hex() {
    assert_eq!(round_trip(&DtcStatus(0x2F)), r#""2F""#);
    assert_eq!(round_trip(&DtcStatus(0x00)), r#""00""#);
    assert_eq!(round_trip(&DtcFormat::SaeJ2012Da00), r#""00""#);
    assert_eq!(round_trip(&DtcFormat::Other(0x42)), r#""42""#);
    assert_eq!(round_trip(&Nrc::RequestOutOfRange), r#""31""#);
    assert_eq!(round_trip(&Nrc::Other(0x99)), r#""99""#);
    for bad in ["2", "2F0", "2f", "+F", "G0", ""] {
        assert!(read::<DtcStatus>(bad).is_err(), "{bad:?}");
        assert!(read::<DtcFormat>(bad).is_err(), "{bad:?}");
        assert!(read::<Nrc>(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn reply_errors_use_hex_bytes() {
    let refused = Error::Negative(NegativeResponse {
        sid: 0x22,
        nrc: Nrc::RequestOutOfRange,
    });
    assert_eq!(
        round_trip(&refused),
        r#"{"Negative":{"sid":"22","nrc":"31"}}"#
    );
    assert_eq!(
        round_trip(&Error::WrongService(0x7F)),
        r#"{"WrongService":"7F"}"#
    );
    assert_eq!(round_trip(&Error::TooShort), r#""TooShort""#);
    assert_eq!(round_trip(&Error::Malformed), r#""Malformed""#);
}

#[test]
fn dtc_records_and_counts_round_trip() {
    let record = DtcRecord {
        dtc: UdsDtc::new(0x16A0),
        status: DtcStatus(0x2F),
    };
    assert_eq!(round_trip(&record), r#"{"dtc":"0016A0","status":"2F"}"#);
    let count = DtcCount {
        availability: DtcStatus(0xFF),
        format: DtcFormat::Iso14229,
        count: 3,
    };
    assert_eq!(
        round_trip(&count),
        r#"{"availability":"FF","format":"01","count":3}"#
    );
}

#[test]
fn units_round_trip_by_name() {
    assert_eq!(round_trip(&Unit::Celsius), r#""Celsius""#);
    assert_eq!(round_trip(&Unit::Count), r#""Count""#);
}

#[test]
fn unknown_fields_are_ignored() {
    let record: DtcRecord =
        serde_json::from_value(json!({"dtc": "0016A0", "status": "2F", "later": [1, 2]})).unwrap();
    assert_eq!(record.dtc, UdsDtc::new(0x16A0));
}

proptest! {
    #[test]
    fn dtc_round_trips_for_every_code(code in any::<u16>()) {
        round_trip(&Dtc::new(code));
    }

    #[test]
    fn uds_dtc_round_trips_for_every_code(code in 0u32..=0xFF_FFFF) {
        round_trip(&UdsDtc::new(code));
    }

    #[test]
    fn cvn_round_trips_for_every_value(bytes in any::<[u8; 4]>()) {
        round_trip(&Cvn(bytes));
    }

    #[test]
    fn byte_forms_round_trip_for_every_byte(byte in any::<u8>()) {
        round_trip(&DtcStatus(byte));
        round_trip(&DtcFormat::from(byte));
        round_trip(&Nrc::from(byte));
    }

    // Anything that reads is exactly what was written, so no other spelling gets in.
    #[test]
    fn arbitrary_text_never_panics_and_only_canonical_text_reads(text in "\\PC{0,12}") {
        if let Ok(dtc) = read::<Dtc>(&text) {
            prop_assert_eq!(dtc.to_string(), text.clone());
        }
        if let Ok(dtc) = read::<UdsDtc>(&text) {
            prop_assert_eq!(dtc.to_string(), text.clone());
        }
        if let Ok(cvn) = read::<Cvn>(&text) {
            prop_assert_eq!(cvn.to_string(), text.clone());
        }
        if let Ok(status) = read::<DtcStatus>(&text) {
            prop_assert_eq!(format!("{:02X}", status.0), text.clone());
        }
        if let Ok(nrc) = read::<Nrc>(&text) {
            prop_assert_eq!(format!("{:02X}", nrc.code()), text.clone());
        }
    }

    #[test]
    fn near_miss_text_never_panics(text in "[PCBUpcbu0-9A-Fa-f+ -]{0,9}") {
        if let Ok(dtc) = read::<Dtc>(&text) {
            prop_assert_eq!(dtc.to_string(), text.clone());
        }
        if let Ok(dtc) = read::<UdsDtc>(&text) {
            prop_assert_eq!(dtc.to_string(), text.clone());
        }
        if let Ok(cvn) = read::<Cvn>(&text) {
            prop_assert_eq!(cvn.to_string(), text);
        }
    }
}
