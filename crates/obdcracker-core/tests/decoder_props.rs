//! Every OBD-II and UDS decoder on arbitrary bytes: ECU replies are untrusted, so decoders return
//! errors and never panic.

use obdcracker_core::obd::{self, Dtc, SupportedPids};
use obdcracker_core::{response, uds};
use proptest::prelude::*;

// Arbitrary replies, half of them starting with a plausible service ID so decoding gets past
// the first check.
fn any_reply() -> impl Strategy<Value = Vec<u8>> {
    let sid = prop::sample::select(vec![0x41u8, 0x43, 0x49, 0x59, 0x62, 0x7F]);
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..64),
        (sid, prop::collection::vec(any::<u8>(), 0..64)).prop_map(|(sid, mut rest)| {
            rest.insert(0, sid);
            rest
        }),
    ]
}

proptest! {
    #[test]
    fn answers_never_panics(request in any_reply(), reply in any_reply()) {
        let _ = obdcracker_core::response::answers(&request, &reply);
        let _ = obdcracker_core::response::answers_after_pending(&request, &reply);
    }

    #[test]
    fn obd_decoders_never_panic(reply in any_reply()) {
        if let Ok(readings) = obd::decode_current_data(&reply) {
            readings.for_each(drop);
        }
        if let Ok(dtcs) = obd::decode_stored_dtcs(&reply) {
            dtcs.for_each(|dtc| drop(dtc.to_string()));
        }
        let _ = obd::decode_supported_info(&reply);
        let _ = obd::decode_vin(&reply);
        if let Ok(calids) = obd::decode_calids(&reply) {
            calids.for_each(drop);
        }
        if let Ok(cvns) = obd::decode_cvns(&reply) {
            cvns.for_each(|cvn| drop(cvn.to_string()));
        }
        let _ = obd::decode_ecu_name(&reply);
    }

    #[test]
    fn uds_decoders_never_panic(
        reply in any_reply(),
        did in any::<u16>(),
        layout in prop::collection::vec((any::<u16>(), 0usize..80), 0..4),
    ) {
        let _ = response::positive(0x22, &reply);
        let _ = uds::decode_did(&reply, did);
        if let Ok(values) = uds::decode_dids(&reply, &layout) {
            values.for_each(drop);
        }
        let _ = uds::decode_text(&reply);
        let _ = uds::decode_dtc_count(&reply);
        for decode in [uds::decode_dtcs_by_status_mask, uds::decode_supported_dtcs] {
            if let Ok((_, records)) = decode(&reply) {
                records.for_each(|record| drop(record.dtc.to_string()));
            }
        }
        if let Ok(count) = uds::decode_dtc_count(&reply) {
            let _ = uds::UdsDtc::new(0x04_01_00).j2012(count.format);
        }
    }

    #[test]
    fn dtc_text_is_a_system_letter_and_four_hex_digits(code in any::<u16>()) {
        let text = Dtc::new(code).to_string();
        prop_assert_eq!(text.len(), 5);
        prop_assert!("PCBU".contains(&text[..1]));
        let digits = u16::from_str_radix(&text[1..], 16).unwrap();
        // The system letter and the digits together give back the code.
        let system = u16::try_from("PCBU".find(&text[..1]).unwrap()).unwrap();
        prop_assert_eq!(system << 14 | digits, code);
    }

    #[test]
    fn supported_pids_iterate_exactly_the_contained_ones(base in prop::sample::select(vec![0u8, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]), data in any::<[u8; 4]>()) {
        let supported = SupportedPids::new(base, data);
        let listed: Vec<u8> = supported.iter().collect();
        let contained: Vec<u8> = (0..=u8::MAX).filter(|&pid| supported.contains(pid)).collect();
        prop_assert_eq!(listed, contained);
    }
}
