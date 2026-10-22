//! UDS (ISO 14229-1) request building and reply decoding.

mod read_data_by_identifier {
    use obdcracker_core::response::{Error, NegativeResponse, Nrc};
    use obdcracker_core::uds::{decode_did, decode_dids, decode_text, did, read_did};

    fn reply(did: u16, data: &[u8]) -> Vec<u8> {
        let mut reply = vec![0x62];
        reply.extend_from_slice(&did.to_be_bytes());
        reply.extend_from_slice(data);
        reply
    }

    #[test]
    fn builds_the_request() {
        assert_eq!(read_did(did::VIN), [0x22, 0xF1, 0x90]);
    }

    #[test]
    fn knows_which_standard_identifiers_are_text() {
        // ISO 14229-1 annex C: the part, software, hardware, system and ODX names, and the VIN.
        for text in [0xF187, 0xF188, 0xF189, 0xF190, 0xF191, 0xF197, 0xF19E] {
            assert!(did::is_text(text), "0x{text:04X}");
        }
        // Dates, serial numbers, supplier data and manufacturer DIDs have no fixed format.
        for free in [
            0xF18A, 0xF18B, 0xF18C, 0xF192, 0xF19F, 0x0600, 0x0000, 0xFFFF,
        ] {
            assert!(!did::is_text(free), "0x{free:04X}");
        }
    }

    #[test]
    fn returns_the_data_after_the_echoed_identifier() {
        let reply = reply(did::VIN, b"WAUZZZ4G1EN000000");
        assert_eq!(decode_did(&reply, did::VIN), Ok(&b"WAUZZZ4G1EN000000"[..]));
    }

    #[test]
    fn rejects_another_identifier_or_no_data() {
        assert_eq!(
            decode_did(&reply(did::SPARE_PART_NUMBER, b"x"), did::VIN),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_did(&reply(did::VIN, b""), did::VIN),
            Err(Error::TooShort)
        );
        assert_eq!(decode_did(&[0x62, 0xF1], did::VIN), Err(Error::TooShort));
    }

    #[test]
    fn passes_on_refusals() {
        assert_eq!(
            decode_did(&[0x7F, 0x22, 0x31], did::VIN),
            Err(Error::Negative(NegativeResponse {
                sid: 0x22,
                nrc: Nrc::RequestOutOfRange
            }))
        );
    }

    #[test]
    fn splits_a_multi_identifier_reply_by_known_lengths() {
        let mut reply = reply(did::SPARE_PART_NUMBER, b"4G0907589F ");
        reply.extend_from_slice(&did::SOFTWARE_VERSION.to_be_bytes());
        reply.extend_from_slice(b"0003");
        let layout = [(did::SPARE_PART_NUMBER, 11), (did::SOFTWARE_VERSION, 4)];
        let values: Vec<_> = decode_dids(&reply, &layout)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            values,
            [
                (did::SPARE_PART_NUMBER, &b"4G0907589F "[..]),
                (did::SOFTWARE_VERSION, &b"0003"[..])
            ]
        );
    }

    #[test]
    fn multi_identifier_reply_must_match_the_layout_exactly() {
        let reply = reply(did::SPARE_PART_NUMBER, b"4G0907589F ");
        let wrong_did = [(did::VIN, 11)];
        assert_eq!(
            decode_dids(&reply, &wrong_did).unwrap().next(),
            Some(Err(Error::Malformed))
        );
        let too_long = [(did::SPARE_PART_NUMBER, 12)];
        assert_eq!(
            decode_dids(&reply, &too_long).unwrap().next(),
            Some(Err(Error::TooShort))
        );
        let leftover = [(did::SPARE_PART_NUMBER, 10)];
        let results: Vec<_> = decode_dids(&reply, &leftover).unwrap().collect();
        assert_eq!(results.last(), Some(&Err(Error::Malformed)));
    }

    #[test]
    fn multi_identifier_decode_needs_at_least_one_did() {
        assert_eq!(decode_dids(&[0x62], &[]).err(), Some(Error::Malformed));
    }

    #[test]
    fn multi_identifier_layout_needs_a_length_for_every_did() {
        let layout = [(did::VIN, 0)];
        assert_eq!(
            decode_dids(&reply(did::VIN, b""), &layout).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn identification_text_drops_padding() {
        assert_eq!(decode_text(b"4G0907589F  \0\0"), Ok("4G0907589F"));
        assert_eq!(decode_text(b"0003"), Ok("0003"));
        assert_eq!(decode_text(b"40\x01"), Err(Error::Malformed));
    }

    #[test]
    fn names_the_identification_dids() {
        assert_eq!(
            [
                did::SPARE_PART_NUMBER,
                did::SOFTWARE_NUMBER,
                did::SOFTWARE_VERSION,
                did::VIN,
                did::HARDWARE_NUMBER,
                did::ODX_FILE,
            ],
            [0xF187, 0xF188, 0xF189, 0xF190, 0xF191, 0xF19E]
        );
    }
}

mod read_dtc_information {
    use obdcracker_core::obd::Dtc;
    use obdcracker_core::response::Error;
    use obdcracker_core::uds::{
        DtcCount, DtcData, DtcFormat, DtcRecord, DtcStatus, J2012Dtc, UdsDtc, decode_dtc_count,
        decode_dtc_extended_data, decode_dtc_snapshots, decode_dtcs_by_status_mask,
        decode_supported_dtcs, dtc_count_by_status_mask, dtc_extended_data, dtc_snapshots,
        dtcs_by_status_mask, supported_dtcs,
    };

    // The A7 gateway's 0016A0, from session 5 (#92).
    const GATEWAY_DTC: u32 = 0x00_16_A0;

    #[test]
    fn a_status_shows_its_flags_in_bit_order() {
        assert_eq!(DtcStatus(0x00).to_string(), "no flags");
        assert_eq!(DtcStatus(0x09).to_string(), "failed, confirmed");
        assert_eq!(
            DtcStatus(0x50).to_string(),
            "not tested since clear, not tested this cycle"
        );
        assert_eq!(
            DtcStatus(0xFF).to_string(),
            "failed, failed this cycle, pending, confirmed, not tested since clear, \
             failed since clear, not tested this cycle, lamp"
        );
    }

    #[test]
    fn builds_the_requests() {
        assert_eq!(dtc_count_by_status_mask(0xFF), [0x19, 0x01, 0xFF]);
        assert_eq!(dtcs_by_status_mask(0x08), [0x19, 0x02, 0x08]);
        assert_eq!(supported_dtcs(), [0x19, 0x0A]);
        let dtc = UdsDtc::new(GATEWAY_DTC);
        assert_eq!(
            dtc_snapshots(dtc, 0xFF),
            [0x19, 0x04, 0x00, 0x16, 0xA0, 0xFF]
        );
        assert_eq!(
            dtc_extended_data(dtc, 0x01),
            [0x19, 0x06, 0x00, 0x16, 0xA0, 0x01]
        );
    }

    #[test]
    fn decodes_a_dtcs_snapshots_and_extended_data_as_raw_records() {
        let dtc = UdsDtc::new(GATEWAY_DTC);
        let snapshots = [
            0x59, 0x04, 0x00, 0x16, 0xA0, 0x01, 0x01, 0x02, 0x02, 0x00, 0x12, 0x02, 0x03, 0x34,
        ];
        assert_eq!(
            decode_dtc_snapshots(&snapshots, dtc, 0xFF),
            Ok(DtcData {
                status: DtcStatus(0x01),
                records: &[0x01, 0x02, 0x02, 0x00, 0x12, 0x02, 0x03, 0x34],
            })
        );
        assert_eq!(
            decode_dtc_snapshots(&snapshots, dtc, 0x01).map(|data| data.records.len()),
            Ok(8)
        );
        let extended = [0x59, 0x06, 0x00, 0x16, 0xA0, 0x01, 0x01, 0x05];
        assert_eq!(
            decode_dtc_extended_data(&extended, dtc, 0xFF),
            Ok(DtcData {
                status: DtcStatus(0x01),
                records: &[0x01, 0x05],
            })
        );
        assert_eq!(
            decode_dtc_snapshots(&[0x59, 0x04, 0x00, 0x16, 0xA0, 0x01], dtc, 0xFF),
            Ok(DtcData {
                status: DtcStatus(0x01),
                records: &[],
            })
        );
    }

    #[test]
    fn a_dtc_detail_reply_must_echo_the_dtc_and_record_asked_for() {
        let dtc = UdsDtc::new(GATEWAY_DTC);
        for (reply, record, error) in [
            (
                &[0x59, 0x04, 0x00, 0x16, 0xA1, 0x01][..],
                0xFF,
                Error::Malformed,
            ),
            (
                &[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01],
                0xFF,
                Error::Malformed,
            ),
            (
                &[0x59, 0x04, 0x00, 0x16, 0xA0, 0x01, 0x02, 0x00],
                0x01,
                Error::Malformed,
            ),
            (&[0x59, 0x04, 0x00, 0x16, 0xA0], 0xFF, Error::TooShort),
            (
                &[0x59, 0x04, 0x00, 0x16, 0xA0, 0x01, 0x01],
                0xFF,
                Error::TooShort,
            ),
            (&[0x59, 0x04, 0x00], 0xFF, Error::TooShort),
            (&[0x59], 0xFF, Error::TooShort),
        ] {
            assert_eq!(
                decode_dtc_snapshots(reply, dtc, record),
                Err(error),
                "{reply:02X?}"
            );
        }
        // 0xFE asks for every OBD extended data record (ISO 14229-1), so any record number may
        // come first.
        assert_eq!(
            decode_dtc_extended_data(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01, 0x90, 0x07], dtc, 0xFE)
                .map(|data| data.records),
            Ok(&[0x90, 0x07][..])
        );
        assert_eq!(
            decode_dtc_extended_data(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01, 0x02, 0x07], dtc, 0x01),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_dtc_extended_data(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01, 0x01], dtc, 0xFF),
            Err(Error::TooShort)
        );
    }

    #[test]
    fn decodes_the_dtc_count() {
        assert_eq!(
            decode_dtc_count(&[0x59, 0x01, 0xFF, 0x01, 0x00, 0x03]),
            Ok(DtcCount {
                availability: DtcStatus(0xFF),
                format: DtcFormat::Iso14229,
                count: 3
            })
        );
        assert_eq!(
            decode_dtc_count(&[0x59, 0x01, 0xFF, 0x01, 0x00]),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn decodes_dtcs_by_status_mask() {
        let reply = [
            0x59, 0x02, 0xFF, 0x04, 0x01, 0x00, 0x88, 0xC1, 0x00, 0x00, 0x24,
        ];
        let (availability, records) = decode_dtcs_by_status_mask(&reply).unwrap();
        assert_eq!(availability, DtcStatus(0xFF));
        let records: Vec<DtcRecord> = records.collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].dtc, UdsDtc::new(0x04_01_00));
        assert_eq!(records[0].dtc.to_string(), "040100");
        assert!(records[0].status.confirmed());
        assert!(records[0].status.warning_indicator_requested());
        assert!(!records[0].status.pending());
        assert_eq!(
            records[1]
                .dtc
                .j2012(DtcFormat::SaeJ2012Da00)
                .unwrap()
                .to_string(),
            "U0100-00"
        );
        assert!(records[1].status.pending());
        assert!(records[1].status.test_failed_since_last_clear());
        assert!(!records[1].status.confirmed());
    }

    #[test]
    fn three_byte_dtc_reads_as_j2012_only_in_a_j2012_format() {
        let dtc = UdsDtc::new(0x04_01_1C);
        assert_eq!(dtc.code(), 0x04_01_1C);
        let expected = Some(J2012Dtc {
            dtc: Dtc::new(0x0401),
            failure_type: 0x1C,
        });
        assert_eq!(dtc.j2012(DtcFormat::SaeJ2012Da00), expected);
        assert_eq!(dtc.j2012(DtcFormat::SaeJ2012Da04), expected);
        // ISO 14229-1's own format is manufacturer-defined, and J1939 is unrelated
        assert_eq!(dtc.j2012(DtcFormat::Iso14229), None);
        assert_eq!(dtc.j2012(DtcFormat::SaeJ1939), None);
        assert_eq!(dtc.j2012(DtcFormat::Other(0x07)), None);
    }

    #[test]
    fn dtc_formats_round_trip() {
        for code in 0..=u8::MAX {
            assert_eq!(DtcFormat::from(code).code(), code);
        }
        assert_eq!(DtcFormat::from(0x00), DtcFormat::SaeJ2012Da00);
        assert_eq!(DtcFormat::from(0x03), DtcFormat::Iso11992);
        assert_eq!(DtcFormat::from(0x04), DtcFormat::SaeJ2012Da04);
    }

    #[test]
    fn decodes_supported_dtcs_in_the_same_record_format() {
        let (_, records) =
            decode_supported_dtcs(&[0x59, 0x0A, 0x7F, 0x04, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(records.count(), 1);
    }

    #[test]
    fn rejects_partial_records_and_other_subfunctions() {
        assert_eq!(
            decode_dtcs_by_status_mask(&[0x59, 0x02, 0xFF, 0x04, 0x01, 0x00]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_dtcs_by_status_mask(&[0x59, 0x01, 0xFF, 0x01, 0x00, 0x03]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_dtcs_by_status_mask(&[0x59, 0x02]).err(),
            Some(Error::TooShort)
        );
    }

    #[test]
    fn each_decoder_accepts_only_its_own_subfunction() {
        // Every supported DTC (0x0A) must not pass as the DTCs matching a mask (0x02)
        let supported = [0x59, 0x0A, 0x7F, 0x04, 0x01, 0x00, 0x00];
        let by_mask = [0x59, 0x02, 0xFF, 0x04, 0x01, 0x00, 0x88];
        assert_eq!(
            decode_dtcs_by_status_mask(&supported).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_supported_dtcs(&by_mask).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn status_bits_follow_iso_14229() {
        let status = DtcStatus(0b0101_0101);
        assert!(status.test_failed());
        assert!(!status.test_failed_this_operation_cycle());
        assert!(status.pending());
        assert!(!status.confirmed());
        assert!(status.test_not_completed_since_last_clear());
        assert!(!status.test_failed_since_last_clear());
        assert!(status.test_not_completed_this_operation_cycle());
        assert!(!status.warning_indicator_requested());
    }
}

mod session {
    use core::time::Duration;

    use obdcracker_core::response::{Error, NegativeResponse, Nrc};
    use obdcracker_core::uds::{
        DiagnosticSession, SessionTiming, decode_session_timing, session_control, tester_present,
    };

    #[test]
    fn decodes_the_timing_a_module_gives() {
        // P2server_max in ms, P2*server_max in 10 ms units (ISO 14229-2).
        assert_eq!(
            decode_session_timing(
                &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
                DiagnosticSession::Extended
            ),
            Ok(SessionTiming {
                p2: Duration::from_millis(50),
                p2_star: Duration::from_secs(5),
            })
        );
        assert_eq!(
            decode_session_timing(
                &[0x50, 0x01, 0xFF, 0xFF, 0xFF, 0xFF],
                DiagnosticSession::Default
            ),
            Ok(SessionTiming {
                p2: Duration::from_millis(65_535),
                p2_star: Duration::from_millis(655_350),
            })
        );
    }

    #[test]
    fn rejects_a_session_timing_reply_that_does_not_fit() {
        let extended = DiagnosticSession::Extended;
        assert_eq!(
            decode_session_timing(&[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4], extended),
            Err(Error::Malformed)
        );
        for short in [&[0x50][..], &[0x50, 0x03], &[0x50, 0x03, 0x00, 0x32, 0x01]] {
            assert_eq!(decode_session_timing(short, extended), Err(Error::TooShort));
        }
        assert_eq!(
            decode_session_timing(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4, 0x00], extended),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_session_timing(&[0x7F, 0x10, 0x22], extended),
            Err(Error::Negative(NegativeResponse {
                sid: 0x10,
                nrc: Nrc::ConditionsNotCorrect,
            }))
        );
    }

    #[test]
    fn builds_the_requests() {
        assert_eq!(session_control(DiagnosticSession::Default), [0x10, 0x01]);
        assert_eq!(session_control(DiagnosticSession::Extended), [0x10, 0x03]);
        // Not `3E 80`: a suppressed reply makes an ELM adapter wait out its timeout.
        assert_eq!(tester_present(), [0x3E, 0x00]);
    }
}
