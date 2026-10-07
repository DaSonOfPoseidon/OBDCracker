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
