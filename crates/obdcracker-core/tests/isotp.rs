//! ISO-TP framing against ISO 15765-2 examples.

use obdcracker_core::isotp::single_frame;

#[test]
fn prefixes_the_payload_with_its_length() {
    // ISO 15765-2 single frame: PCI nibble 0, length nibble, then data. Mode 09 PID 02 (VIN).
    assert_eq!(
        single_frame(&[0x09, 0x02]).unwrap().as_bytes(),
        [0x02, 0x09, 0x02]
    );
}

#[test]
fn fits_up_to_seven_bytes() {
    let payload = [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90];
    let frame = single_frame(&payload).unwrap();
    assert_eq!(frame.as_bytes()[0], 0x07);
    assert_eq!(&frame.as_bytes()[1..], payload);
}

#[test]
fn refuses_empty_and_oversized_payloads() {
    assert_eq!(single_frame(&[]), None);
    assert_eq!(single_frame(&[0; 8]), None);
}

mod parse {
    use core::time::Duration;

    use obdcracker_core::isotp::{Addressing, Error, FlowControl, FlowStatus, Frame};

    fn parse(bytes: &[u8]) -> Result<Frame<'_>, Error> {
        Frame::parse(bytes, Addressing::Normal)
    }

    #[test]
    fn single_frame_ignores_padding() {
        // 7E8 reply to mode 01 PID 0D (speed 0x32 = 50 km/h), padded to 8 bytes with 0x55
        assert_eq!(
            parse(&[0x03, 0x41, 0x0D, 0x32, 0x55, 0x55, 0x55, 0x55]),
            Ok(Frame::Single(&[0x41, 0x0D, 0x32]))
        );
    }

    #[test]
    fn first_frame_carries_the_total_length() {
        // First frame of a mode 09 PID 02 VIN reply: 20 bytes in total
        assert_eq!(
            parse(&[0x10, 0x14, 0x49, 0x02, 0x01, 0x31, 0x44, 0x34]),
            Ok(Frame::First {
                len: 20,
                data: &[0x49, 0x02, 0x01, 0x31, 0x44, 0x34]
            })
        );
    }

    #[test]
    fn first_frame_length_uses_twelve_bits() {
        assert_eq!(
            parse(&[0x1F, 0xFF, 1, 2, 3, 4, 5, 6]),
            Ok(Frame::First {
                len: 4095,
                data: &[1, 2, 3, 4, 5, 6]
            })
        );
    }

    #[test]
    fn consecutive_frame_carries_its_sequence_number() {
        assert_eq!(
            parse(&[0x21, 0x47, 0x50, 0x30, 0x30, 0x52, 0x35, 0x35]),
            Ok(Frame::Consecutive {
                seq: 1,
                data: &[0x47, 0x50, 0x30, 0x30, 0x52, 0x35, 0x35]
            })
        );
    }

    #[test]
    fn flow_control_decodes_status_block_size_and_separation_time() {
        assert_eq!(
            parse(&[0x30, 0x00, 0x00]),
            Ok(Frame::FlowControl(FlowControl {
                status: FlowStatus::ContinueToSend,
                block_size: 0,
                st_min: Duration::ZERO,
            }))
        );
        assert_eq!(
            parse(&[0x31, 0x08, 0x14]),
            Ok(Frame::FlowControl(FlowControl {
                status: FlowStatus::Wait,
                block_size: 8,
                st_min: Duration::from_millis(20),
            }))
        );
        let overflow = parse(&[0x32, 0, 0]).unwrap();
        assert!(matches!(
            overflow,
            Frame::FlowControl(FlowControl {
                status: FlowStatus::Overflow,
                ..
            })
        ));
    }

    #[test]
    fn separation_time_covers_milliseconds_microseconds_and_reserved_values() {
        let st_min = |byte| match parse(&[0x30, 0, byte]).unwrap() {
            Frame::FlowControl(fc) => fc.st_min,
            other => panic!("{other:?}"),
        };
        assert_eq!(st_min(0x7F), Duration::from_millis(127));
        assert_eq!(st_min(0xF1), Duration::from_micros(100));
        assert_eq!(st_min(0xF9), Duration::from_micros(900));
        // Reserved values mean the longest separation time (ISO 15765-2)
        for reserved in [0x80, 0xF0, 0xFA, 0xFF] {
            assert_eq!(
                st_min(reserved),
                Duration::from_millis(127),
                "{reserved:02X}"
            );
        }
    }

    #[test]
    fn extended_addressing_checks_and_skips_the_address_byte() {
        // Toyota-style body module behind 0x750 with sub-address 0x40
        let toyota = Addressing::Extended(0x40);
        assert_eq!(
            Frame::parse(&[0x40, 0x03, 0x61, 0x01, 0xAA, 0, 0, 0], toyota),
            Ok(Frame::Single(&[0x61, 0x01, 0xAA]))
        );
        assert_eq!(
            Frame::parse(&[0x40, 0x10, 0x20, 1, 2, 3, 4, 5], toyota),
            Ok(Frame::First {
                len: 32,
                data: &[1, 2, 3, 4, 5]
            })
        );
        assert_eq!(
            Frame::parse(&[0x41, 0x03, 0x61, 0x01, 0xAA], toyota),
            Err(Error::WrongAddress(0x41))
        );
        // Six payload bytes at most fit a single frame with extended addressing
        assert_eq!(
            Frame::parse(&[0x40, 0x07, 1, 2, 3, 4, 5, 6], toyota),
            Err(Error::BadLength)
        );
    }

    #[test]
    fn rejects_malformed_frames() {
        for bytes in [
            &[][..],
            &[0x00, 0x55],                   // single frame of length 0 (CAN FD escape)
            &[0x08, 1, 2, 3, 4, 5, 6, 7],    // single frame longer than 7
            &[0x05, 1, 2],                   // fewer bytes than the length says
            &[0x10, 0x00, 0, 0, 0, 0, 0, 0], // first frame escape (> 4095 bytes)
            &[0x10, 0x07, 1, 2, 3, 4, 5, 6], // first frame that would fit a single frame
            &[0x10, 0x14, 0x49, 0x02],       // first frame shorter than 8 bytes
            &[0x20],                         // consecutive frame with no data
            &[0x33, 0, 0],                   // reserved flow status
            &[0x30, 0],                      // flow control missing STmin
            &[0x40, 0, 0, 0, 0, 0, 0, 0],    // reserved frame type
            &[0xF0, 0, 0, 0, 0, 0, 0, 0],    // reserved frame type
            &[0x02, 1, 2, 0, 0, 0, 0, 0, 0], // more than 8 bytes
        ] {
            assert!(parse(bytes).is_err(), "{bytes:02X?}");
        }
    }
}

mod segment {
    use core::time::Duration;

    use obdcracker_core::isotp::{Addressing, Error, FlowControl, FlowStatus, Segmenter, Step};

    const CTS: FlowControl = FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size: 0,
        st_min: Duration::ZERO,
    };

    fn sent(step: Step) -> Vec<u8> {
        match step {
            Step::Send(frame) => frame.as_bytes().to_vec(),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    // 0x22 with four DIDs: F187, F189, F190, F191
    const FOUR_DIDS: [u8; 9] = [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90, 0xF1, 0x91];

    #[test]
    fn short_payload_is_one_single_frame() {
        let mut seg = Segmenter::new(&[0x09, 0x02], Addressing::Normal).unwrap();
        assert_eq!(sent(seg.step()), [0x02, 0x09, 0x02]);
        assert_eq!(seg.step(), Step::Done);
    }

    #[test]
    fn long_payload_waits_for_flow_control_after_the_first_frame() {
        let mut seg = Segmenter::new(&FOUR_DIDS, Addressing::Normal).unwrap();
        assert_eq!(
            sent(seg.step()),
            [0x10, 0x09, 0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1]
        );
        assert_eq!(seg.step(), Step::WaitForFlowControl);
        seg.flow_control(CTS).unwrap();
        assert_eq!(sent(seg.step()), [0x21, 0x90, 0xF1, 0x91]);
        assert_eq!(seg.step(), Step::Done);
    }

    #[test]
    fn block_size_makes_it_wait_again() {
        let payload: Vec<u8> = (0..6 + 7 * 3).collect();
        let mut seg = Segmenter::new(&payload, Addressing::Normal).unwrap();
        sent(seg.step());
        seg.flow_control(FlowControl {
            block_size: 2,
            ..CTS
        })
        .unwrap();
        assert_eq!(sent(seg.step())[0], 0x21);
        assert_eq!(sent(seg.step())[0], 0x22);
        assert_eq!(seg.step(), Step::WaitForFlowControl);
        seg.flow_control(CTS).unwrap();
        assert_eq!(sent(seg.step())[0], 0x23);
        assert_eq!(seg.step(), Step::Done);
    }

    #[test]
    fn wait_keeps_waiting_and_overflow_aborts() {
        let mut seg = Segmenter::new(&FOUR_DIDS, Addressing::Normal).unwrap();
        sent(seg.step());
        seg.flow_control(FlowControl {
            status: FlowStatus::Wait,
            ..CTS
        })
        .unwrap();
        assert_eq!(seg.step(), Step::WaitForFlowControl);
        assert_eq!(
            seg.flow_control(FlowControl {
                status: FlowStatus::Overflow,
                ..CTS
            }),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn flow_control_when_not_waiting_is_an_error() {
        let mut seg = Segmenter::new(&[0x09, 0x02], Addressing::Normal).unwrap();
        assert_eq!(seg.flow_control(CTS), Err(Error::UnexpectedFrame));
    }

    #[test]
    fn reports_the_separation_time_to_keep() {
        let mut seg = Segmenter::new(&FOUR_DIDS, Addressing::Normal).unwrap();
        sent(seg.step());
        seg.flow_control(FlowControl {
            st_min: Duration::from_millis(5),
            ..CTS
        })
        .unwrap();
        assert_eq!(seg.st_min(), Duration::from_millis(5));
    }

    #[test]
    fn sequence_number_wraps_after_fifteen() {
        let payload = vec![0xAB; 6 + 7 * 17];
        let mut seg = Segmenter::new(&payload, Addressing::Normal).unwrap();
        sent(seg.step());
        seg.flow_control(CTS).unwrap();
        let seqs: Vec<u8> = (0..17).map(|_| sent(seg.step())[0]).collect();
        assert_eq!(seqs[14], 0x2F);
        assert_eq!(seqs[15], 0x20);
        assert_eq!(seqs[16], 0x21);
        assert_eq!(seg.step(), Step::Done);
    }

    #[test]
    fn extended_addressing_prefixes_every_frame() {
        let toyota = Addressing::Extended(0x40);
        let mut seg = Segmenter::new(&[0x21, 0x01], toyota).unwrap();
        assert_eq!(sent(seg.step()), [0x40, 0x02, 0x21, 0x01]);

        let mut seg = Segmenter::new(&[1, 2, 3, 4, 5, 6, 7], toyota).unwrap();
        assert_eq!(sent(seg.step()), [0x40, 0x10, 0x07, 1, 2, 3, 4, 5]);
        seg.flow_control(CTS).unwrap();
        assert_eq!(sent(seg.step()), [0x40, 0x21, 6, 7]);
    }

    #[test]
    fn refuses_empty_and_oversized_payloads() {
        assert_eq!(
            Segmenter::new(&[], Addressing::Normal).err(),
            Some(Error::BadLength)
        );
        assert_eq!(
            Segmenter::new(&[0; 4096], Addressing::Normal).err(),
            Some(Error::BadLength)
        );
        assert!(Segmenter::new(&[0; 4095], Addressing::Normal).is_ok());
    }

    #[test]
    fn flow_control_encodes_back_to_its_frame() {
        let fc = FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size: 8,
            st_min: Duration::from_millis(20),
        };
        assert_eq!(fc.encode(Addressing::Normal).as_bytes(), [0x30, 0x08, 0x14]);
        let fc = FlowControl {
            status: FlowStatus::Overflow,
            block_size: 0,
            st_min: Duration::from_micros(300),
        };
        assert_eq!(
            fc.encode(Addressing::Extended(0xF1)).as_bytes(),
            [0xF1, 0x32, 0x00, 0xF3]
        );
    }
}

mod reassemble {
    use core::time::Duration;

    use obdcracker_core::isotp::{
        Addressing, Error, FlowControl, FlowStatus, Progress, Reassembler, Segmenter, Step,
    };

    const CTS: FlowControl = FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size: 0,
        st_min: Duration::ZERO,
    };

    // A mode 09 PID 02 reply from 7E8: 49 02 01 then the 17-character VIN, padded with 0x55
    const VIN_FRAMES: [[u8; 8]; 3] = [
        [0x10, 0x14, 0x49, 0x02, 0x01, 0x31, 0x44, 0x34],
        [0x21, 0x47, 0x50, 0x30, 0x30, 0x52, 0x35, 0x35],
        [0x22, 0x42, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
    ];

    #[test]
    fn reassembles_a_vin_reply() {
        let mut buf = [0; 64];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        assert_eq!(rx.feed(&VIN_FRAMES[0]), Ok(Progress::SendFlowControl(CTS)));
        assert_eq!(rx.feed(&VIN_FRAMES[1]), Ok(Progress::Pending));
        let Ok(Progress::Complete(payload)) = rx.feed(&VIN_FRAMES[2]) else {
            panic!("expected a complete payload");
        };
        assert_eq!(&payload[..3], [0x49, 0x02, 0x01]);
        assert_eq!(&payload[3..], b"1D4GP00R55B123456");
    }

    #[test]
    fn single_frame_completes_at_once() {
        let mut buf = [0; 8];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        assert_eq!(
            rx.feed(&[0x03, 0x41, 0x0D, 0x32, 0x55, 0x55, 0x55, 0x55]),
            Ok(Progress::Complete(&[0x41, 0x0D, 0x32]))
        );
    }

    #[test]
    fn drops_padding_after_the_last_consecutive_frame() {
        let mut buf = [0; 16];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        rx.feed(&[0x10, 0x08, 1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(
            rx.feed(&[0x21, 7, 8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
            Ok(Progress::Complete(&[1, 2, 3, 4, 5, 6, 7, 8]))
        );
    }

    #[test]
    fn asks_for_flow_control_after_each_block() {
        let fc = FlowControl {
            block_size: 2,
            st_min: Duration::from_millis(10),
            ..CTS
        };
        let mut buf = [0; 64];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal).with_flow_control(fc);
        assert_eq!(
            rx.feed(&[0x10, 0x1B, 0, 0, 0, 0, 0, 0]),
            Ok(Progress::SendFlowControl(fc))
        );
        assert_eq!(rx.feed(&[0x21, 0, 0, 0, 0, 0, 0, 0]), Ok(Progress::Pending));
        assert_eq!(
            rx.feed(&[0x22, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Progress::SendFlowControl(fc))
        );
        assert!(matches!(
            rx.feed(&[0x23, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Progress::Complete(p)) if p.len() == 27
        ));
    }

    #[test]
    fn wrong_sequence_number_aborts_and_a_new_first_frame_restarts() {
        let mut buf = [0; 64];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        rx.feed(&VIN_FRAMES[0]).unwrap();
        assert_eq!(rx.feed(&VIN_FRAMES[2]), Err(Error::WrongSequence));
        assert_eq!(rx.feed(&VIN_FRAMES[1]), Err(Error::UnexpectedFrame));
        rx.feed(&VIN_FRAMES[0]).unwrap();
        rx.feed(&VIN_FRAMES[1]).unwrap();
        assert!(matches!(rx.feed(&VIN_FRAMES[2]), Ok(Progress::Complete(_))));
    }

    #[test]
    fn refuses_a_transfer_longer_than_the_buffer() {
        let mut buf = [0; 16];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        assert_eq!(rx.feed(&VIN_FRAMES[0]), Err(Error::Overflow));
        assert_eq!(rx.feed(&VIN_FRAMES[1]), Err(Error::UnexpectedFrame));
    }

    #[test]
    fn flow_control_and_stray_consecutive_frames_are_unexpected() {
        let mut buf = [0; 16];
        let mut rx = Reassembler::new(&mut buf, Addressing::Normal);
        assert_eq!(rx.feed(&[0x30, 0, 0]), Err(Error::UnexpectedFrame));
        assert_eq!(rx.feed(&[0x21, 1, 2]), Err(Error::UnexpectedFrame));
    }

    #[test]
    fn round_trips_through_the_segmenter_with_extended_addressing() {
        let payload: Vec<u8> = (0..=255).collect();
        assert_eq!(round_trip(&payload, Addressing::Extended(0x40)), payload);
    }

    #[test]
    fn round_trips_the_longest_payload() {
        // 585 consecutive frames in one block of unlimited size
        let payload: Vec<u8> = (0..4095u16).map(|i| (i % 251).to_le_bytes()[0]).collect();
        assert_eq!(round_trip(&payload, Addressing::Normal), payload);
    }

    fn round_trip(payload: &[u8], addressing: Addressing) -> Vec<u8> {
        let mut seg = Segmenter::new(payload, addressing).unwrap();
        let mut buf = [0; 4095];
        let mut rx = Reassembler::new(&mut buf, addressing);
        let mut got = None;
        loop {
            match seg.step() {
                Step::Send(frame) => match rx.feed(frame.as_bytes()).unwrap() {
                    Progress::SendFlowControl(fc) => {
                        assert_eq!(seg.step(), Step::WaitForFlowControl);
                        seg.flow_control(fc).unwrap();
                    }
                    Progress::Complete(p) => got = Some(p.to_vec()),
                    Progress::Pending => {}
                },
                Step::WaitForFlowControl => panic!("receiver didn't send flow control"),
                Step::Done => break,
            }
        }
        got.expect("no complete payload")
    }
}
