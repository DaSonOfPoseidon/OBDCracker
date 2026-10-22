//! Every OBD-II and UDS decoder on arbitrary bytes: ECU replies are untrusted, so decoders return
//! errors and never panic.

use obdcracker_core::obd::{self, Dtc, SupportedPids};
use obdcracker_core::{response, uds};
use proptest::prelude::*;

// Arbitrary replies, half of them starting with a plausible service ID so decoding gets past
// the first check.
fn any_reply() -> impl Strategy<Value = Vec<u8>> {
    let sid = prop::sample::select(vec![0x41u8, 0x43, 0x49, 0x50, 0x59, 0x62, 0x7F]);
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
    fn session_timing_decoder_never_panics(reply in any_reply()) {
        for session in [uds::DiagnosticSession::Default, uds::DiagnosticSession::Extended] {
            let _ = uds::decode_session_timing(&reply, session);
        }
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
    fn dtc_detail_decoders_take_exactly_what_follows_the_echo(
        reply in any_reply(),
        code in 0u32..=0xFF_FFFF,
        record in any::<u8>(),
        records in prop::collection::vec(any::<u8>(), 0..32),
        status in any::<u8>(),
    ) {
        let dtc = uds::UdsDtc::new(code);
        let _ = uds::decode_dtc_snapshots(&reply, dtc, record);
        let _ = uds::decode_dtc_extended_data(&reply, dtc, record);
        // A well-formed reply for this DTC gives back its status and every byte after it. A
        // record number alone is cut short.
        prop_assume!(records.len() != 1);
        let [_, high, mid, low] = code.to_be_bytes();
        for sub in [0x04, 0x06] {
            let mut reply = vec![0x59, sub, high, mid, low, status];
            reply.extend(&records);
            let got = if sub == 0x04 {
                uds::decode_dtc_snapshots(&reply, dtc, 0xFF)
            } else {
                uds::decode_dtc_extended_data(&reply, dtc, 0xFF)
            }
            .unwrap();
            prop_assert_eq!(got.status, uds::DtcStatus(status));
            prop_assert_eq!(got.records, &records[..]);
        }
    }

    #[test]
    fn dtc_text_is_a_system_letter_and_four_hex_digits(code in any::<u16>()) {
        let text = Dtc::new(code).to_string();
        prop_assert_eq!(text.len(), 5);
        prop_assert!("PCBU".contains(&text[..1]));
        let digits = u16::from_str_radix(&text[1..], 16).unwrap();
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

proptest! {
    #[test]
    fn tp20_decoders_never_panic_and_messages_fit_their_buffer(
        reply in any_reply(),
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..10), 0..40),
    ) {
        use obdcracker_core::tp20;
        let _ = tp20::decode_channel_setup(&reply);
        let _ = tp20::decode_channel_parameters(&reply);
        let _ = tp20::Frame::parse(&reply);
        let mut buf = [0u8; 32];
        let mut reassembler = tp20::Reassembler::new(&mut buf[..]);
        for frame in &frames {
            if let Ok(tp20::Progress::Complete { payload, .. }) = reassembler.feed(frame) {
                prop_assert!(!payload.is_empty() && payload.len() <= 32);
            }
        }
    }

    #[test]
    fn tp20_block_sizes_past_15_are_malformed(block_size in 16u8..) {
        let reply = [0xA1, block_size, 0x8A, 0xFF, 0x4A, 0xFF];
        prop_assert_eq!(
            obdcracker_core::tp20::decode_channel_parameters(&reply),
            Err(obdcracker_core::tp20::Error::Malformed)
        );
    }

    #[test]
    fn every_tp20_request_frame_reads_back(sequence in 0u8..=0x0F, payload in prop::collection::vec(any::<u8>(), 1..=5)) {
        use obdcracker_core::tp20;
        let frame = tp20::data_frame(sequence, &payload).unwrap();
        let mut buf = [0u8; 8];
        let mut reassembler = tp20::Reassembler::new(&mut buf[..]);
        prop_assert_eq!(
            reassembler.feed(frame.data()),
            Ok(tp20::Progress::Complete { payload: &payload[..], ack: Some((sequence + 1) & 0x0F) })
        );
    }
}
