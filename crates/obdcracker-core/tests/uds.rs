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
        DtcCount, DtcFormat, DtcRecord, DtcStatus, J2012Dtc, UdsDtc, decode_dtc_count, decode_dtcs,
        dtc_count_by_status_mask, dtcs_by_status_mask, supported_dtcs,
    };

    #[test]
    fn builds_the_requests() {
        assert_eq!(dtc_count_by_status_mask(0xFF), [0x19, 0x01, 0xFF]);
        assert_eq!(dtcs_by_status_mask(0x08), [0x19, 0x02, 0x08]);
        assert_eq!(supported_dtcs(), [0x19, 0x0A]);
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
        // P0401-00 confirmed with the warning lamp on; U0100-00 pending
        let reply = [
            0x59, 0x02, 0xFF, 0x04, 0x01, 0x00, 0x88, 0xC1, 0x00, 0x00, 0x24,
        ];
        let (availability, records) = decode_dtcs(&reply).unwrap();
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
        let (_, records) = decode_dtcs(&[0x59, 0x0A, 0x7F, 0x04, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(records.count(), 1);
    }

    #[test]
    fn rejects_partial_records_and_other_subfunctions() {
        assert_eq!(
            decode_dtcs(&[0x59, 0x02, 0xFF, 0x04, 0x01, 0x00]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_dtcs(&[0x59, 0x01, 0xFF, 0x01, 0x00, 0x03]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(decode_dtcs(&[0x59, 0x02]).err(), Some(Error::TooShort));
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
