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
