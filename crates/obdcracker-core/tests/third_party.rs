//! Test vectors ported from independent implementations, so a misreading of the standards that
//! our own golden frames share gets caught. Sources (MIT, see `THIRD_PARTY.md`):
//!
//! - python-can-isotp, `test/test_helper_classes.py` and `test/test_transport_layer_logic.py`
//! - python-udsoncan, `test/client/test_read_data_by_identifier.py`,
//!   `test/client/test_read_dtc_information.py` and `test/test_response.py`
//!
//! Only read-only (T0) services are ported. Where the sources accept something ISO 14229-1 or
//! ISO 15765-2 doesn't allow on classic CAN, the test pins our stricter answer and says why.
//! Whether to tolerate non-compliant ECUs' zero padding anyway is #36.

// Bytes counting up from `start`, wrapping at 0x100: the sources' `make_payload`.
fn payload(len: usize, start: usize) -> Vec<u8> {
    (start..start + len)
        .map(|i| u8::try_from(i % 0x100).unwrap())
        .collect()
}

mod isotp_frames {
    use core::time::Duration;

    use obdcracker_core::isotp::{Addressing, Error, FlowControl, FlowStatus, Frame};

    use super::payload;

    fn parse(bytes: &[u8]) -> Result<Frame<'_>, Error> {
        Frame::parse(bytes, Addressing::Normal)
    }

    // test_decode_single_frame_no_escape_sequence
    #[test]
    fn single_frames() {
        assert_eq!(parse(&[]), Err(Error::BadFrameSize));
        for len in 1..=7 {
            let data = payload(len, 0);
            let mut frame = vec![u8::try_from(len).unwrap()];
            frame.extend(&data);
            assert_eq!(parse(&frame), Ok(Frame::Single(&data)), "length {len}");
            // One byte short
            assert_eq!(parse(&frame[..len]), Err(Error::BadLength), "length {len}");
            // Padding after the payload is ignored.
            frame.resize(8, 0xAA);
            assert_eq!(parse(&frame), Ok(Frame::Single(&data)), "length {len}");
        }
    }

    // test_decode_single_frame_escape_sequence: `00 <len>` is CAN FD's single frame escape. On
    // classic CAN a single frame length of 0 is invalid (ISO 15765-2), which the source agrees
    // with for `00 00`.
    #[test]
    fn single_frame_escape_is_can_fd_only() {
        assert_eq!(parse(&[0x00]), Err(Error::BadLength));
        assert_eq!(parse(&[0x00, 0x00]), Err(Error::BadLength));
        assert_eq!(parse(&[0x00, 0x00, 0xAA]), Err(Error::BadLength));
        assert_eq!(parse(&[0x00, 0x03, 1, 2, 3]), Err(Error::BadLength));
    }

    // test_decode_first_frame_no_escape_sequence, normal use: a full frame of a longer payload
    #[test]
    fn first_frames() {
        assert_eq!(parse(&[0x10]), Err(Error::BadLength));
        assert_eq!(parse(&[0x1F]), Err(Error::BadLength));
        for len in 10..0x1FF_u16 {
            let data = payload(usize::from(len), 0);
            let [high, low] = len.to_be_bytes();
            let mut frame = vec![0x10 | high, low];
            frame.extend(&data[..6]);
            assert_eq!(
                parse(&frame),
                Ok(Frame::First {
                    len: u32::from(len),
                    data: &data[..6]
                }),
                "length {len}"
            );
        }
    }

    // The source accepts first frames that ISO 15765-2 rules out: a length that fits a single
    // frame, or a frame shorter than 8 bytes. Receivers must ignore both.
    #[test]
    fn first_frames_the_standard_rules_out() {
        assert_eq!(parse(&[0x10, 0x02]), Err(Error::BadLength));
        assert_eq!(parse(&[0x10, 0x02, 0x11]), Err(Error::BadLength));
        assert_eq!(
            parse(&[0x10, 0x07, 1, 2, 3, 4, 5, 6]),
            Err(Error::BadLength)
        );
        assert_eq!(parse(&[0x10, 0x0A, 1, 2, 3, 4, 5]), Err(Error::BadLength));
    }

    // test_decode_first_frame_with_escape_sequence
    #[test]
    fn first_frame_escape() {
        for incomplete in [
            &[0x10, 0x00][..],
            &[0x10, 0x00, 0xAA],
            &[0x10, 0x00, 0xAA, 0xBB],
            &[0x10, 0x00, 0xAA, 0xBB, 0xCC],
        ] {
            assert_eq!(
                parse(incomplete),
                Err(Error::BadLength),
                "{incomplete:02X?}"
            );
        }
        assert_eq!(
            parse(&[0x10, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22]),
            Ok(Frame::First {
                len: 0xAABB_CCDD,
                data: &[0x11, 0x22]
            })
        );
        // The source also takes an escaped length of 4095 or less; ISO 15765-2 keeps the escape
        // for longer payloads.
        assert_eq!(
            parse(&[0x10, 0x00, 0x00, 0x00, 0x00, 33, 0, 1]),
            Err(Error::BadLength)
        );
    }

    // test_decode_consecutive_frame
    #[test]
    fn consecutive_frames() {
        assert_eq!(
            parse(&[0x20, 0x11]),
            Ok(Frame::Consecutive {
                seq: 0,
                data: &[0x11]
            })
        );
        assert_eq!(
            parse(&[0x2A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            Ok(Frame::Consecutive {
                seq: 0xA,
                data: &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
            })
        );
        // The source accepts a consecutive frame with no data, which carries nothing to
        // reassemble.
        assert_eq!(parse(&[0x20]), Err(Error::BadLength));
    }

    fn flow_control(status: FlowStatus, block_size: u8, st_min: Duration) -> Frame<'static> {
        Frame::FlowControl(FlowControl {
            status,
            block_size,
            st_min,
        })
    }

    // test_decode_flow_control
    #[test]
    fn flow_control_frames() {
        assert_eq!(parse(&[0x30]), Err(Error::BadLength));
        assert_eq!(parse(&[0x30, 0x00]), Err(Error::BadLength));
        assert_eq!(
            parse(&[0x30, 0x00, 0x00]),
            Ok(flow_control(FlowStatus::ContinueToSend, 0, Duration::ZERO))
        );
        assert_eq!(
            parse(&[0x31, 0x00, 0x00]),
            Ok(flow_control(FlowStatus::Wait, 0, Duration::ZERO))
        );
        assert_eq!(
            parse(&[0x32, 0x01, 0x01]),
            Ok(flow_control(
                FlowStatus::Overflow,
                1,
                Duration::from_millis(1)
            ))
        );
        for status in 0x33..=0x3F {
            assert_eq!(
                parse(&[status, 0x00, 0x00]),
                Err(Error::Unsupported),
                "{status:02X}"
            );
        }
        assert_eq!(
            parse(&[0x30, 0xFF, 0x00]),
            Ok(flow_control(
                FlowStatus::ContinueToSend,
                0xFF,
                Duration::ZERO
            ))
        );
    }

    // test_decode_flow_control: STmin in milliseconds, hundreds of microseconds, and reserved
    // values read as 127 ms
    #[test]
    fn separation_times() {
        let st_min = |byte| match parse(&[0x30, 0xA5, byte]) {
            Ok(Frame::FlowControl(fc)) => fc.st_min,
            other => panic!("{byte:02X}: {other:?}"),
        };
        for byte in 0x00..=0x7F {
            assert_eq!(st_min(byte), Duration::from_millis(u64::from(byte)));
        }
        for byte in 0xF1..=0xF9 {
            assert_eq!(
                st_min(byte),
                Duration::from_micros(u64::from(byte - 0xF0) * 100)
            );
        }
        for byte in (0x80..=0xF0).chain(0xFA..=0xFF) {
            assert_eq!(st_min(byte), Duration::from_millis(127), "{byte:02X}");
        }
    }
}

mod isotp_reassembly {
    use core::time::Duration;

    use obdcracker_core::isotp::{
        Addressing, Error, FlowControl, FlowStatus, Progress, Reassembler,
    };

    use super::payload;

    fn receiver(len: usize) -> Reassembler<Vec<u8>> {
        Reassembler::new(vec![0; len], Addressing::Normal)
    }

    fn paced(len: usize, block_size: u8, st_min_ms: u64) -> Reassembler<Vec<u8>> {
        receiver(len)
            .with_flow_control(fc(block_size, st_min_ms))
            .unwrap()
    }

    fn fc(block_size: u8, st_min_ms: u64) -> FlowControl {
        FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size,
            st_min: Duration::from_millis(st_min_ms),
        }
    }

    // The first frame for `data`, with the 12-bit length or, over 4095 bytes, the escape.
    fn first(data: &[u8]) -> (Vec<u8>, usize) {
        let len = u32::try_from(data.len()).unwrap();
        let [_, _, high, low] = len.to_be_bytes();
        let mut frame = if len <= 4095 {
            vec![0x10 | high, low]
        } else {
            let mut frame = vec![0x10, 0x00];
            frame.extend(len.to_be_bytes());
            frame
        };
        let start = 8 - frame.len();
        frame.extend(&data[..start]);
        (frame, start)
    }

    fn consecutive(seq: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x20 | u8::try_from(seq & 0x0F).unwrap()];
        frame.extend(data);
        frame
    }

    // Feeds a whole transfer and returns the payload, and after which consecutive frames
    // (counting from 1) flow control was asked for.
    fn receive(rx: &mut Reassembler<Vec<u8>>, data: &[u8]) -> (Vec<u8>, Vec<usize>) {
        let (frame, mut n) = first(data);
        assert!(matches!(rx.feed(&frame), Ok(Progress::SendFlowControl(_))));
        let mut flow_controls = Vec::new();
        let mut seq = 1;
        loop {
            let end = (n + 7).min(data.len());
            match rx.feed(&consecutive(seq, &data[n..end])).unwrap() {
                Progress::Complete(got) => return (got.to_vec(), flow_controls),
                Progress::SendFlowControl(_) => flow_controls.push(seq),
                Progress::Pending => {}
            }
            n = end;
            seq += 1;
        }
    }

    // test_receive_multiframe, test_receive_2_multiframe
    #[test]
    fn two_transfers_in_a_row() {
        let data = payload(10, 0);
        let mut rx = receiver(64);
        for _ in 0..2 {
            assert_eq!(receive(&mut rx, &data), (data.clone(), vec![]));
        }
    }

    // test_receive_multiframe_check_flowcontrol
    #[test]
    fn sends_the_configured_flow_control() {
        let data = payload(10, 0);
        let mut rx = paced(64, 5, 2);
        assert_eq!(
            rx.feed(&first(&data).0),
            Ok(Progress::SendFlowControl(fc(5, 2)))
        );
        assert_eq!(
            rx.feed(&consecutive(1, &data[6..])),
            Ok(Progress::Complete(&data[..]))
        );
    }

    // test_long_multiframe_2_flow_control, test_long_multiframe_blocksize_zero
    #[test]
    fn asks_again_after_each_block() {
        let data = payload(30, 0);
        assert_eq!(
            receive(&mut paced(64, 3, 5), &data),
            (data.clone(), vec![3])
        );
        assert_eq!(receive(&mut paced(64, 0, 5), &data), (data, vec![]));
    }

    // test_receive_4095_multiframe_check_blocksize
    #[test]
    fn longest_short_transfer_with_every_small_block_size() {
        let data = payload(4095, 0);
        for block_size in 1..10 {
            let (got, flow_controls) = receive(&mut paced(4095, block_size, 2), &data);
            assert_eq!(got, data, "block size {block_size}");
            // 585 consecutive frames; flow control after each full block but the last frame.
            let expected: Vec<_> = (1..585)
                .filter(|n| n % usize::from(block_size) == 0)
                .collect();
            assert_eq!(flow_controls, expected, "block size {block_size}");
        }
    }

    // test_receive_4096_multiframe, test_receive_10000_multiframe: the 32-bit length escape
    #[test]
    fn escaped_lengths() {
        for len in [4096, 10_000] {
            let data = payload(len, 0);
            assert_eq!(
                receive(&mut receiver(11_000), &data).0,
                data,
                "length {len}"
            );
        }
    }

    // test_receive_multiframe_bad_seqnum
    #[test]
    fn a_skipped_sequence_number_ends_the_transfer() {
        let data = payload(10, 0);
        let mut rx = paced(64, 1, 0);
        rx.feed(&first(&data).0).unwrap();
        assert_eq!(
            rx.feed(&consecutive(2, &data[6..])),
            Err(Error::WrongSequence)
        );
        assert_eq!(
            rx.feed(&consecutive(1, &data[6..])),
            Err(Error::UnexpectedFrame)
        );
    }

    // test_receive_multiframe_interrupting_another
    #[test]
    fn a_first_frame_restarts_the_transfer() {
        let old = payload(10, 0);
        let new = payload(10, 1);
        let mut rx = receiver(64);
        rx.feed(&first(&old).0).unwrap();
        rx.feed(&first(&new).0).unwrap();
        assert_eq!(
            rx.feed(&consecutive(1, &new[6..])),
            Ok(Progress::Complete(&new[..]))
        );
    }

    // test_receive_single_frame_interrupt_multiframe_then_recover
    #[test]
    fn a_single_frame_interrupts_and_the_next_transfer_recovers() {
        let abandoned = payload(16, 0);
        let single = payload(5, 2);
        let next = payload(16, 1);
        let mut rx = receiver(64);
        rx.feed(&first(&abandoned).0).unwrap();
        rx.feed(&consecutive(1, &abandoned[6..13])).unwrap();
        let mut frame = vec![0x05];
        frame.extend(&single);
        assert_eq!(rx.feed(&frame), Ok(Progress::Complete(&single[..])));
        assert_eq!(receive(&mut rx, &next).0, next);
    }

    // test_receive_overflow_handling
    #[test]
    fn a_transfer_too_long_for_the_buffer_overflows() {
        let data = payload(33, 0);
        let mut rx = receiver(32);
        assert_eq!(rx.feed(&first(&data).0), Err(Error::Overflow));
        assert_eq!(
            rx.feed(&consecutive(1, &data[6..13])),
            Err(Error::UnexpectedFrame)
        );
        assert_eq!(receive(&mut rx, &data[..32]).0, &data[..32]);
    }
}

mod uds_read_data_by_identifier {
    use obdcracker_core::response::{Error, NegativeResponse, Nrc};
    use obdcracker_core::uds::{decode_did, decode_dids, read_did};

    const MULTI: &[u8] =
        b"\x62\x00\x01\x12\x34\x00\x02\x56\x78\x00\x04\x61\x62\x63\x64\x65\x00\x03\x11";
    const LAYOUT: &[(u16, usize)] = &[(1, 2), (2, 2), (4, 5), (3, 1)];

    // test_rdbi_single_success
    #[test]
    fn single_did() {
        assert_eq!(read_did(0x0001), [0x22, 0x00, 0x01]);
        assert_eq!(
            decode_did(b"\x62\x00\x01\x12\x34", 0x0001),
            Ok(&[0x12, 0x34][..])
        );
    }

    // test_rdbi_multiple_success
    #[test]
    fn several_dids() {
        let values: Vec<_> = decode_dids(MULTI, LAYOUT)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            values,
            [
                (1, &b"\x12\x34"[..]),
                (2, b"\x56\x78"),
                (4, b"abcde"),
                (3, b"\x11")
            ]
        );
    }

    fn decode_all(reply: &[u8], layout: &[(u16, usize)]) -> Result<Vec<(u16, Vec<u8>)>, Error> {
        decode_dids(reply, layout)?
            .map(|r| r.map(|(did, data)| (did, data.to_vec())))
            .collect()
    }

    // test_rdbi_multiple_zero_padding_*: the source tolerates trailing 0x00 by default. ISO-TP
    // padding sits outside the payload length (ISO 15765-2), so bytes past the last DID are a
    // malformed reply here.
    #[test]
    fn zero_padding_after_the_last_did_is_malformed() {
        let reply = b"\x62\x00\x01\x12\x34\x00\x02\x56\x78\x00\x03\x11";
        let layout = [(1, 2), (2, 2), (3, 1)];
        assert!(decode_all(reply, &layout).is_ok());
        for pad in 1..=5 {
            let mut padded = reply.to_vec();
            padded.resize(reply.len() + pad, 0);
            assert_eq!(
                decode_all(&padded, &layout),
                Err(Error::Malformed),
                "{pad} bytes"
            );
        }
    }

    // test_rdbi_incomplete_response_exception
    #[test]
    fn a_reply_cut_short_is_too_short() {
        assert_eq!(
            decode_all(
                b"\x62\x00\x01\x12\x34\x00\x02\x56\x78\x00\x03",
                &[(1, 2), (2, 2), (3, 1)]
            ),
            Err(Error::TooShort)
        );
    }

    // test_rdbi_unknown_did_exception, test_rdbi_unwanted_did_exception
    #[test]
    fn a_did_out_of_order_or_not_asked_for_is_malformed() {
        let reply = b"\x62\x00\x09\x12\x34\x00\x02\x56\x78\x00\x03\x11";
        assert_eq!(
            decode_all(reply, &[(1, 2), (2, 2), (3, 1)]),
            Err(Error::Malformed)
        );
        let reply = b"\x62\x00\x01\x12\x34\x00\x02\x56\x78\x00\x03\x11";
        assert_eq!(decode_all(reply, &[(1, 2), (3, 1)]), Err(Error::Malformed));
    }

    // test_rdbi_invalidservice_exception, test_rdbi_wrongservice_exception,
    // test_peek_rdbi_negative_exception
    #[test]
    fn wrong_or_negative_replies() {
        assert_eq!(
            decode_did(b"\x00\x00\x01\x12\x34", 1),
            Err(Error::WrongService(0x00))
        );
        assert_eq!(
            decode_did(b"\x50\x00\x01\x12\x34", 1),
            Err(Error::WrongService(0x50))
        );
        assert_eq!(
            decode_did(b"\x7F\x22\x10", 1),
            Err(Error::Negative(NegativeResponse {
                sid: 0x22,
                nrc: Nrc::GeneralReject
            }))
        );
    }
}

mod uds_read_dtc_information {
    use obdcracker_core::response::Error;
    use obdcracker_core::uds::{
        DtcFormat, DtcRecord, DtcStatus, UdsDtc, decode_dtc_count, decode_dtcs_by_status_mask,
        decode_supported_dtcs, dtc_count_by_status_mask, dtcs_by_status_mask, supported_dtcs,
    };

    // TestReportNumberOfDTCByStatusMask (subfunction 0x01)
    #[test]
    fn dtc_count() {
        assert_eq!(dtc_count_by_status_mask(0x5A), [0x19, 0x01, 0x5A]);
        let count = decode_dtc_count(b"\x59\x01\xFB\x01\x12\x34").unwrap();
        assert_eq!(count.availability, DtcStatus(0xFB));
        assert_eq!(count.format, DtcFormat::Iso14229);
        assert_eq!(count.count, 0x1234);

        assert_eq!(
            decode_dtc_count(b"\x59\x02\xFB\x01\x12\x34"),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_dtc_count(b"\x6F\x01\xFB\x01\x12\x34"),
            Err(Error::WrongService(0x6F))
        );
        assert_eq!(decode_dtc_count(b"\x59"), Err(Error::TooShort));
        for short in [
            &b"\x59\x01"[..],
            b"\x59\x01\xFB",
            b"\x59\x01\xFB\x01",
            b"\x59\x01\xFB\x01\x12",
        ] {
            assert_eq!(
                decode_dtc_count(short),
                Err(Error::Malformed),
                "{short:02X?}"
            );
        }
    }

    // test_normal_behaviour_harmless_extra_byte: the source ignores bytes after the count.
    // ISO 14229-1 gives this reply a fixed length, so extra bytes make it malformed here.
    #[test]
    fn dtc_count_with_extra_bytes_is_malformed() {
        assert_eq!(
            decode_dtc_count(b"\x59\x01\xFB\x01\x12\x34\x00\x11\x22"),
            Err(Error::Malformed)
        );
    }

    type Decode = fn(&[u8]) -> Result<(DtcStatus, obdcracker_core::uds::DtcRecords<'_>), Error>;

    // TestReportDTCByStatusMask (0x02) and TestReportSupportedDTC (0x0A) share a reply format.
    const RECORD_REPLIES: [(u8, Decode); 2] = [
        (0x02, decode_dtcs_by_status_mask),
        (0x0A, decode_supported_dtcs),
    ];

    fn records(decode: Decode, reply: &[u8]) -> Result<(u8, Vec<(u32, u8)>), Error> {
        let (availability, records) = decode(reply)?;
        Ok((
            availability.0,
            records
                .map(|DtcRecord { dtc, status }| (dtc.code(), status.0))
                .collect(),
        ))
    }

    fn reply(sub: u8, rest: &[u8]) -> Vec<u8> {
        let mut reply = vec![0x59, sub];
        reply.extend(rest);
        reply
    }

    #[test]
    fn dtc_records() {
        assert_eq!(dtcs_by_status_mask(0x5A), [0x19, 0x02, 0x5A]);
        assert_eq!(supported_dtcs(), [0x19, 0x0A]);
        for (sub, decode) in RECORD_REPLIES {
            let normal = reply(sub, b"\xFB\x12\x34\x56\x20\x12\x34\x57\x60");
            assert_eq!(
                records(decode, &normal),
                Ok((0xFB, vec![(0x12_3456, 0x20), (0x12_3457, 0x60)])),
                "{sub:02X}"
            );
            // test_dtc_duplicate: both are kept; avoiding duplicates is the server's job.
            let duplicate = reply(sub, b"\xFB\x12\x34\x56\x20\x12\x34\x56\x60");
            assert_eq!(
                records(decode, &duplicate),
                Ok((0xFB, vec![(0x12_3456, 0x20), (0x12_3456, 0x60)])),
                "{sub:02X}"
            );
            // test_no_dtc
            assert_eq!(records(decode, &reply(sub, b"\xFB")), Ok((0xFB, vec![])));
            // test_bad_response_subfunction, test_bad_response_service, test_bad_response_length
            assert_eq!(
                records(decode, &reply(sub + 1, b"\xFB")),
                Err(Error::Malformed)
            );
            assert_eq!(
                records(decode, &[0x6F, sub, 0xFB]),
                Err(Error::WrongService(0x6F))
            );
            assert_eq!(records(decode, b"\x59"), Err(Error::TooShort));
            assert_eq!(records(decode, &[0x59, sub]), Err(Error::TooShort));
        }
    }

    // test_normal_behaviour_zeropadding_*: by default the source drops trailing 0x00 bytes, and
    // an all-zero record with them. Neither is padding by ISO 15765-2, which keeps padding
    // outside the payload length, so here a partial record is malformed and a whole one is a
    // record. Telling DTC 000000 apart from a real code is left to the caller.
    #[test]
    fn zero_padding_after_the_records() {
        for (sub, decode) in RECORD_REPLIES {
            let normal = reply(sub, b"\xFB\x12\x34\x56\x20\x12\x34\x57\x60");
            for pad in 1..=3 {
                let mut padded = normal.clone();
                padded.resize(normal.len() + pad, 0);
                assert_eq!(
                    records(decode, &padded),
                    Err(Error::Malformed),
                    "{sub:02X}, {pad} bytes"
                );
            }
            let mut padded = normal.clone();
            padded.resize(normal.len() + 4, 0);
            let (_, got) = records(decode, &padded).unwrap();
            assert_eq!(got.last(), Some(&(0, 0)), "{sub:02X}");
            assert_eq!(UdsDtc::new(0).code(), 0);
        }
    }
}

mod responses {
    use obdcracker_core::response::{Error, NegativeResponse, Nrc, positive};

    // test_from_payload_basic_positive, test_from_payload_custom_data_positive
    #[test]
    fn positive_replies() {
        assert_eq!(positive(0x3E, b"\x7E\x00"), Ok(&[0x00][..]));
        assert_eq!(
            positive(0x3E, b"\x7E\x01\x12\x34\x56\x78"),
            Ok(&[0x01, 0x12, 0x34, 0x56, 0x78][..])
        );
    }

    // test_from_payload_basic_negative
    #[test]
    fn negative_replies() {
        assert_eq!(
            positive(0x3E, b"\x7F\x3E\x10"),
            Err(Error::Negative(NegativeResponse {
                sid: 0x3E,
                nrc: Nrc::GeneralReject
            }))
        );
    }

    // test_from_payload_custom_data_negative: the source keeps bytes after the code. ISO 14229-1's
    // negative response is exactly three bytes, so here that's malformed.
    #[test]
    fn negative_reply_with_extra_bytes_is_malformed() {
        assert_eq!(
            positive(0x3E, b"\x7F\x3E\x10\x12\x34\x56\x78"),
            Err(Error::Malformed)
        );
    }

    // test_from_empty_payload, test_from_bad_payload
    #[test]
    fn empty_or_unknown_replies() {
        assert_eq!(positive(0x3E, b""), Err(Error::TooShort));
        assert_eq!(positive(0x3E, b"\xFF\xFF"), Err(Error::WrongService(0xFF)));
    }

    // udsoncan/ResponseCode.py: every code we name has the same value there.
    #[test]
    fn negative_response_codes() {
        let codes = [
            (0x10, Nrc::GeneralReject),
            (0x11, Nrc::ServiceNotSupported),
            (0x12, Nrc::SubFunctionNotSupported),
            (0x13, Nrc::IncorrectMessageLength),
            (0x14, Nrc::ResponseTooLong),
            (0x21, Nrc::BusyRepeatRequest),
            (0x22, Nrc::ConditionsNotCorrect),
            (0x24, Nrc::RequestSequenceError),
            (0x31, Nrc::RequestOutOfRange),
            (0x33, Nrc::SecurityAccessDenied),
            (0x35, Nrc::InvalidKey),
            (0x36, Nrc::ExceededNumberOfAttempts),
            (0x37, Nrc::RequiredTimeDelayNotExpired),
            (0x78, Nrc::ResponsePending),
            (0x7E, Nrc::SubFunctionNotSupportedInActiveSession),
            (0x7F, Nrc::ServiceNotSupportedInActiveSession),
        ];
        for (code, nrc) in codes {
            assert_eq!(Nrc::from(code), nrc);
            assert_eq!(nrc.code(), code);
        }
        assert!(Nrc::from(0x78).is_pending());
    }
}
