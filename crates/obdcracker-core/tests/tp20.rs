//! VW TP2.0 framing: channel setup and parameters, data frames, ACKs, keep-alive and disconnect.
//! The frames are from hobbyist traces of VAG modules; none is confirmed on the A7 yet (#124).

use core::time::Duration;

use obdcracker_core::tp20::{
    self, Channel, Error, Frame, Parameters, Progress, Reassembler, channel_parameters,
    channel_setup, data_frame, decode_channel_parameters, decode_channel_setup,
};

#[test]
fn builds_the_channel_setup_for_a_module() {
    // To 0x200: the module's address, setup request, the module's IDs left to it, the tester's
    // receive ID 0x300 proposed, KWP2000.
    assert_eq!(
        channel_setup(0x01),
        [0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]
    );
    assert_eq!(channel_setup(0x5F)[0], 0x5F);
    assert_eq!(tp20::SETUP_ID, 0x200);
    assert_eq!(tp20::setup_reply_id(0x01), 0x201);
    assert_eq!(tp20::setup_reply_id(0x5F), 0x25F);
}

#[test]
fn decodes_the_channel_a_module_gives() {
    // The module listens on 0x740 and sends on 0x300.
    assert_eq!(
        decode_channel_setup(&[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01]),
        Ok(Channel {
            send_id: 0x740,
            receive_id: 0x300,
        })
    );
    for (reply, error) in [
        // A refusal: application not supported, no resources.
        (
            &[0x00, 0xD6, 0x00, 0x03, 0x40, 0x07, 0x01][..],
            Error::Refused(0xD6),
        ),
        (
            &[0x00, 0xD7, 0x00, 0x03, 0x40, 0x07, 0x01],
            Error::Refused(0xD7),
        ),
        // Not for the tester, an unknown opcode, an ID marked invalid, another application.
        (
            &[0x01, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        (
            &[0x00, 0xC0, 0x00, 0x03, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        (
            &[0x00, 0xD0, 0x00, 0x13, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        (
            &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x17, 0x01],
            Error::Malformed,
        ),
        (
            &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x02],
            Error::Malformed,
        ),
        // IDs above 11 bits, or the setup range itself.
        (
            &[0x00, 0xD0, 0x00, 0x0B, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        (
            &[0x00, 0xD0, 0x01, 0x02, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        // One ID for both directions.
        (
            &[0x00, 0xD0, 0x40, 0x07, 0x40, 0x07, 0x01],
            Error::Malformed,
        ),
        // Lengths.
        (&[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07], Error::TooShort),
        (
            &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01, 0x00],
            Error::Malformed,
        ),
        (&[], Error::TooShort),
    ] {
        assert_eq!(decode_channel_setup(reply), Err(error), "{reply:02X?}");
    }
}

#[test]
fn builds_and_decodes_the_channel_parameters() {
    // Block size 15, T1 100 ms, T2 unused, T3 5 ms, T4 unused.
    assert_eq!(channel_parameters(), [0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]);
    // The module's: block size 15, T1 100 ms, T3 10 ms.
    assert_eq!(
        decode_channel_parameters(&[0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF]),
        Ok(Parameters {
            block_size: 15,
            t1: Duration::from_millis(100),
            t3: Duration::from_millis(10),
        })
    );
    // Each unit: 0.1 ms, 1 ms, 10 ms, 100 ms.
    assert_eq!(
        decode_channel_parameters(&[0xA1, 0x01, 0xC5, 0xFF, 0x05, 0xFF]).map(|p| (p.t1, p.t3)),
        Ok((Duration::from_millis(500), Duration::from_micros(500)))
    );
    for reply in [
        &[0xA1, 0x0F, 0x8A, 0xFF, 0x4A][..],
        &[0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF, 0x00],
        &[0xA0, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF],
        // A block size of 0, and T1 or T3 not given.
        &[0xA1, 0x00, 0x8A, 0xFF, 0x4A, 0xFF],
        &[0xA1, 0x0F, 0xFF, 0xFF, 0x4A, 0xFF],
        &[0xA1, 0x0F, 0x8A, 0xFF, 0xFF, 0xFF],
    ] {
        assert!(decode_channel_parameters(reply).is_err(), "{reply:02X?}");
    }
    assert_eq!(tp20::KEEP_ALIVE, [0xA3]);
    assert_eq!(tp20::DISCONNECT, [0xA8]);
}

#[test]
fn a_short_request_is_one_data_frame_that_asks_for_an_ack() {
    // Last packet, waiting for an ACK, sequence 0, then the length and the payload.
    let frame = data_frame(0, &[0x1A, 0x9B]).unwrap();
    assert_eq!(frame.data(), [0x10, 0x00, 0x02, 0x1A, 0x9B]);
    assert_eq!(
        data_frame(0x0F, &[0x21, 0x01, 0x02, 0x03, 0x04])
            .unwrap()
            .data(),
        [0x1F, 0x00, 0x05, 0x21, 0x01, 0x02, 0x03, 0x04]
    );
    // The sequence number wraps at 16; longer payloads and empty ones don't fit.
    assert_eq!(data_frame(0x10, &[0x3E]), Err(Error::Malformed));
    assert_eq!(data_frame(0, &[0; 6]), Err(Error::TooLong));
    assert_eq!(data_frame(0, &[]), Err(Error::Malformed));
    assert_eq!(tp20::ack(1), [0xB1]);
    assert_eq!(tp20::ack(0x10), [0xB0]);
}

#[test]
fn parses_each_kind_of_frame() {
    assert_eq!(
        Frame::parse(&[0x20, 0x00, 0x0C, 0x5A]),
        Ok(Frame::Data {
            sequence: 0,
            last: false,
            wants_ack: false,
            bytes: &[0x00, 0x0C, 0x5A],
        })
    );
    assert_eq!(
        Frame::parse(&[0x13, 0x01]),
        Ok(Frame::Data {
            sequence: 3,
            last: true,
            wants_ack: true,
            bytes: &[0x01],
        })
    );
    assert_eq!(
        Frame::parse(&[0x05, 0x01]).map(|f| matches!(
            f,
            Frame::Data {
                last: false,
                wants_ack: true,
                ..
            }
        )),
        Ok(true)
    );
    assert_eq!(
        Frame::parse(&[0x3F, 0x01]).map(|f| matches!(
            f,
            Frame::Data {
                last: true,
                wants_ack: false,
                ..
            }
        )),
        Ok(true)
    );
    assert_eq!(
        Frame::parse(&[0xB1]),
        Ok(Frame::Ack {
            next: 1,
            ready: true
        })
    );
    assert_eq!(
        Frame::parse(&[0x92]),
        Ok(Frame::Ack {
            next: 2,
            ready: false
        })
    );
    assert_eq!(
        Frame::parse(&[0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF])
            .map(|f| matches!(f, Frame::Parameters(_))),
        Ok(true)
    );
    assert_eq!(Frame::parse(&[0xA3]), Ok(Frame::Test));
    assert_eq!(Frame::parse(&[0xA8]), Ok(Frame::Disconnect));
    for frame in [
        &[][..],
        &[0x10],       // data with no data
        &[0xB1, 0x00], // an ACK is one byte
        &[0xA8, 0x00],
        &[0x40, 0x01], // reserved opcodes
        &[0xC0, 0x01],
        &[0x10, 1, 2, 3, 4, 5, 6, 7, 8],
    ] {
        assert!(Frame::parse(frame).is_err(), "{frame:02X?}");
    }
}

#[test]
fn reassembles_a_reply_and_acks_where_the_module_asks() {
    let mut buf = [0u8; 64];
    let mut reply = Reassembler::new(&mut buf[..]);
    // 12 bytes: 5A 9B 01 .. 0A, in a frame that needs no ACK and a last one that does.
    assert_eq!(
        reply.feed(&[0x20, 0x00, 0x0C, 0x5A, 0x9B, 0x01, 0x02, 0x03]),
        Ok(Progress::Pending)
    );
    assert_eq!(
        reply.feed(&[0x11, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]),
        Ok(Progress::Complete {
            payload: &[
                0x5A, 0x9B, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A
            ],
            ack: Some(2),
        })
    );
    // The module's sequence goes on across messages: a block that wants an ACK mid-message.
    assert_eq!(
        reply.feed(&[0x02, 0x00, 0x08, 0x61, 0x01, 0x00, 0x01, 0x02]),
        Ok(Progress::Ack(3))
    );
    assert_eq!(
        reply.feed(&[0x33, 0x03, 0x04, 0x05]),
        Ok(Progress::Complete {
            payload: &[0x61, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            ack: None,
        })
    );
}

#[test]
fn a_reply_that_breaks_the_framing_is_dropped_and_the_next_one_still_reads() {
    for frames in [
        // A sequence number out of order.
        &[
            &[0x20, 0x00, 0x0C, 1, 2, 3, 4, 5][..],
            &[0x12, 6, 7, 8, 9, 10, 11, 12],
        ][..],
        // "Last" before the length is reached, and more after it.
        &[&[0x30, 0x00, 0x0C, 1, 2, 3, 4, 5]],
        &[&[0x20, 0x00, 0x02, 1, 2, 3]],
        // A length of 0, and one longer than the buffer.
        &[&[0x30, 0x00, 0x00]],
        &[&[0x20, 0x01, 0x00, 1, 2, 3, 4, 5]],
        // A first frame too short for its length field.
        &[&[0x30, 0x00]],
    ] {
        let mut buf = [0u8; 64];
        let mut reply = Reassembler::new(&mut buf[..]);
        let results: Vec<_> = frames
            .iter()
            .map(|frame| reply.feed(frame).map(|_| ()))
            .collect();
        assert!(
            results.last().unwrap().is_err(),
            "{frames:02X?}: {results:?}"
        );
        // The module's next message starts over at its next sequence number.
        let next = (frames[0][0] & 0x0F) + u8::try_from(frames.len()).unwrap();
        let progress = reply.feed(&[0x30 | (next & 0x0F), 0x00, 0x01, 0x7E]);
        assert_eq!(
            progress,
            Ok(Progress::Complete {
                payload: &[0x7E],
                ack: None,
            }),
            "{frames:02X?}"
        );
    }
}
