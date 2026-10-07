//! ISO-TP properties for any input: CAN data from the bus is untrusted, and round trips are lossless.

use core::time::Duration;

use obdcracker_core::isotp::{
    Addressing, FlowControl, FlowStatus, Frame, Progress, Reassembler, Segmenter, Step,
};
use proptest::prelude::*;

fn any_addressing() -> impl Strategy<Value = Addressing> {
    prop_oneof![
        Just(Addressing::Normal),
        any::<u8>().prop_map(Addressing::Extended),
    ]
}

proptest! {
    #[test]
    fn parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..12), addressing in any_addressing()) {
        let _ = Frame::parse(&bytes, addressing);
    }

    #[test]
    fn reassembler_never_panics(
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..10), 0..40),
        buf_len in 0usize..64,
        addressing in any_addressing(),
    ) {
        let mut buf = vec![0; buf_len];
        let mut rx = Reassembler::new(&mut buf, addressing);
        for frame in &frames {
            let _ = rx.feed(frame);
        }
    }

    #[test]
    fn segment_then_reassemble_is_lossless(
        payload in prop::collection::vec(any::<u8>(), 1..=6000),
        block_size in any::<u8>(),
        addressing in any_addressing(),
    ) {
        let fc = FlowControl { status: FlowStatus::ContinueToSend, block_size, st_min: Duration::ZERO };
        let mut seg = Segmenter::new(&payload, addressing).unwrap();
        let mut buf = vec![0; 6000];
        let mut rx = Reassembler::new(&mut buf, addressing).with_flow_control(fc).unwrap();
        let mut got = None;
        loop {
            match seg.step() {
                Step::Send(frame) => match rx.feed(frame.as_bytes()).unwrap() {
                    Progress::SendFlowControl(fc) => seg.flow_control(fc).unwrap(),
                    Progress::Complete(p) => got = Some(p.to_vec()),
                    Progress::Pending => {}
                },
                Step::WaitForFlowControl => prop_assert!(false, "sender waits but receiver sent no flow control"),
                Step::Done => break,
            }
        }
        prop_assert_eq!(got, Some(payload));
    }

    #[test]
    fn flow_control_encodes_and_parses_back(block_size in any::<u8>(), st_min_byte in 0u8..=0x7F, addressing in any_addressing()) {
        let fc = FlowControl { status: FlowStatus::Wait, block_size, st_min: Duration::from_millis(u64::from(st_min_byte)) };
        let encoded = fc.encode(addressing).unwrap();
        prop_assert_eq!(Frame::parse(encoded.as_bytes(), addressing), Ok(Frame::FlowControl(fc)));
    }
}
