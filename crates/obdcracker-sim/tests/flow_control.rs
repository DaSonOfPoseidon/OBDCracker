//! A reply window driven by the sim's multi-frame replies: flow control exists only for the
//! request the sim answered.

use std::time::Duration;

use obdcracker_core::isotp::{Addressing, Frame, Segmenter, Step};
use obdcracker_core::obd;
use obdcracker_safety::{FeedOutcome, Policy, Protocol, ReplyWindow, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::{Response, Transport};

const TIMEOUT: Duration = Duration::from_millis(50);

fn request(target: Target, payload: &[u8]) -> obdcracker_safety::Approved {
    Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap()
}

fn answer(bus: &mut SimBus, request: &obdcracker_safety::Approved) -> Response {
    bus.send(request).unwrap();
    bus.recv(TIMEOUT).unwrap()
}

#[test]
fn the_sims_vin_reply_is_paced_by_a_token_for_the_request_that_asked() {
    let mut bus = SimBus::builtin("a7").unwrap();
    let approved = request(Target::ObdFunctional, &obd::vehicle_info(0x02));
    let reply = answer(&mut bus, &approved);
    assert_eq!(reply.source, 0x7E8);
    assert!(reply.payload.len() > 7, "the VIN reply is multi-frame");

    let mut window = ReplyWindow::open(&approved).unwrap();
    let mut tokens = Vec::new();
    let mut completed = None;
    // The sim answers with whole payloads, so the core segmenter plays the module: feed each frame the segmenter sends; hand back what the window mints.
    let mut segmenter = Segmenter::new(&reply.payload, Addressing::Normal).unwrap();
    loop {
        match segmenter.step() {
            Step::Send(frame) => match window.feed(reply.source, frame.as_bytes()).unwrap() {
                FeedOutcome::Complete { source, payload } => completed = Some((source, payload)),
                FeedOutcome::SendFlowControl(token) => {
                    assert!(tokens.is_empty(), "one first frame, one token");
                    assert_eq!(token.destination_id(), 0x7E0);
                    assert_eq!(token.data(), [0x30, 0x00, 0x00]);
                    tokens.push(token);
                }
                FeedOutcome::Pending => {}
                other => panic!("{other:?}"),
            },
            Step::WaitForFlowControl => {
                // The module continues only on a token the window issued.
                let token = tokens
                    .last()
                    .expect("no token, so the module keeps waiting");
                let Frame::FlowControl(fc) =
                    Frame::parse(token.data(), Addressing::Normal).unwrap()
                else {
                    panic!("not a flow control frame");
                };
                segmenter.flow_control(fc).unwrap();
            }
            Step::Done => break,
            Step::Aborted => panic!("aborted"),
        }
    }
    assert_eq!(tokens.len(), 1);
    assert_eq!(completed, Some((0x7E8, reply.payload.clone())));
    assert_eq!(
        obd::decode_vin(&reply.payload).unwrap(),
        "WAU2MBFC6EN093415"
    );
}

#[test]
fn a_window_for_one_module_mints_nothing_for_another_modules_reply() {
    let mut bus = SimBus::builtin("a7").unwrap();
    // The VIN comes from the engine at 0x7E0; a window for the transmission at 0x7E1 expects 0x7E9.
    let engine = request(Target::Physical(0x7E0), &obd::vehicle_info(0x02));
    let reply = answer(&mut bus, &engine);
    assert_eq!(reply.source, 0x7E8);
    let transmission = request(Target::Physical(0x7E1), &obd::vehicle_info(0x02));
    let mut window = ReplyWindow::open(&transmission).unwrap();
    let mut segmenter = Segmenter::new(&reply.payload, Addressing::Normal).unwrap();
    let Step::Send(first) = segmenter.step() else {
        panic!("a multi-frame reply starts with a frame");
    };
    assert_eq!(
        window.feed(reply.source, first.as_bytes()).unwrap(),
        FeedOutcome::Ignored
    );
    // And a window opened for the engine does mint one.
    let mut window = ReplyWindow::open(&engine).unwrap();
    assert!(matches!(
        window.feed(reply.source, first.as_bytes()).unwrap(),
        FeedOutcome::SendFlowControl(_)
    ));
}
