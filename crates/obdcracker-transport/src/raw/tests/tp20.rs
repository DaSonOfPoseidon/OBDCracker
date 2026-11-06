//! VW TP2.0 over the raw-CAN core (#259): the frames the policy builds go out as they are, and
//! the frames of the module's side come back unparsed, so `tp20::probe` and `ChannelSession`
//! run as they do over the ELM driver.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use obdcracker_core::tp20::Channel;
use obdcracker_safety::{Approved, OpenTp20Channel, Policy, Target};

use super::{Ecu, Fake, SHORT, ecus, frame, frame29, raw, read_did, rx};
use crate::raw::RawCan;
use crate::raw::port::{CanPort, Filter, PortEvent, TxFrame};
use crate::tp20::{self, Answer, ChannelError, ChannelSession, Disconnect};
use crate::{Error, Expect, LinkEvent, Response, Timing, Transport, exchange};

// The sim's frame-level module, as it is: it depends only on `obdcracker-core`, and
// `obdcracker-sim` depends on this crate, so it can't be a dev-dependency.
#[path = "../../../../obdcracker-sim/src/tp20_module.rs"]
mod sim_module;

use sim_module::Tp20Module;

// The passenger door's answer in session 6: the module sends on 0x300 and listens on 0x740.
pub(in crate::raw) const SETUP_REPLY: [u8; 7] = [0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01];
pub(in crate::raw) const SETUP_REQUEST: [u8; 7] = [0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01];
const SETUP_ANSWER_ID: u32 = 0x201;
const SEND_ID: u32 = 0x740;
const RECEIVE_ID: u32 = 0x300;
const PARAMETERS: [u8; 6] = [0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF];

pub(in crate::raw) fn policy() -> Policy {
    Policy::read_only().narrowed_to_tp20(&[0x01])
}

pub(in crate::raw) fn setup() -> Approved {
    policy().approve_tp20_setup(0x01).unwrap()
}

pub(in crate::raw) fn channel() -> OpenTp20Channel {
    policy()
        .tp20_channel(&setup(), SETUP_ANSWER_ID, &SETUP_REPLY)
        .unwrap()
}

// What went on the bus: the ID and exactly the bytes.
fn wire(can: &RawCan<Fake>) -> Vec<(u32, Vec<u8>)> {
    can.port
        .written()
        .iter()
        .map(|f| (f.id, f.bytes().to_vec()))
        .collect()
}

fn on_channel(frame: &[u8]) -> (u32, Vec<u8>) {
    (SEND_ID, frame.to_vec())
}

// ---- The simulated module, frame by frame

// The sim's module at address 1, as a car on any port: frames in, frames out.
pub(in crate::raw) struct Car {
    modules: Vec<Tp20Module>,
}

impl Car {
    // A module at address 1 that answers the KWP2000 reads in `answers`.
    pub(in crate::raw) fn with(answers: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let mut module = Tp20Module::new(
            0x01,
            Channel {
                send_id: SEND_ID,
                receive_id: RECEIVE_ID,
            },
        );
        module.answers = answers;
        Self {
            modules: vec![module],
        }
    }

    // What the car sends, as (CAN ID, data), when it hears `data` on `id`.
    pub(in crate::raw) fn hear_frame(&mut self, id: u32, data: &[u8]) -> Vec<(u32, Vec<u8>)> {
        if id == 0x200 {
            let Some(module) = self.modules.iter_mut().find(|m| m.address == data[0]) else {
                return Vec::new();
            };
            module.open();
            return vec![(0x200 + u32::from(module.address), SETUP_REPLY.to_vec())];
        }
        let Some(module) = self
            .modules
            .iter_mut()
            .find(|m| m.open && m.channel.send_id == id)
        else {
            return Vec::new();
        };
        let from = module.channel.receive_id;
        module
            .hear(data)
            .into_iter()
            .map(|payload| (from, payload))
            .collect()
    }

    fn hear(&mut self, sent: &TxFrame) -> Vec<PortEvent> {
        self.hear_frame(sent.id, sent.bytes())
            .into_iter()
            .map(|(id, payload)| frame(id, &payload))
            .collect()
    }

    fn port(mut self) -> Fake {
        Fake::answering(move |sent| self.hear(sent))
    }
}

pub(in crate::raw) const IDENTIFICATION: [u8; 2] = [0x1A, 0x9B];

fn identification() -> Vec<u8> {
    // 120 bytes: 18 data frames, which wraps the sequence numbers and makes the module wait for
    // an ACK in the middle of the answer.
    let mut answer = vec![0x5A, 0x9B];
    answer.extend((0..118).map(|i| u8::try_from(i % 200).unwrap()));
    answer
}

// ---- The frames that go out

#[test]
fn every_tp20_frame_goes_out_as_one_frame_of_its_own_length() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_ack(&channel, 3).unwrap())
        .unwrap();
    can.send(
        &policy
            .approve_tp20_request(&channel, 0, &IDENTIFICATION)
            .unwrap(),
    )
    .unwrap();
    can.send(&policy.approve_tp20_disconnect(&channel).unwrap())
        .unwrap();
    // One frame each: no ISO-TP segmentation, flow control or padding, at 11 bits.
    assert_eq!(
        wire(&can),
        [
            (0x200, SETUP_REQUEST.to_vec()),
            on_channel(&[0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]),
            on_channel(&[0xA3]),
            on_channel(&[0xB3]),
            on_channel(&[0x10, 0x00, 0x02, 0x1A, 0x9B]),
            on_channel(&[0xA8]),
        ]
    );
    assert!(can.port.written().iter().all(|f| !f.extended));
}

#[test]
fn a_frame_that_does_not_fit_a_classic_frame_is_refused_before_anything_is_touched() {
    // The policy never builds one, and `TxFrame` is where that is checked.
    assert!(TxFrame::exact(0x740, false, &[]).is_err());
    assert!(TxFrame::exact(0x740, false, &[0; 9]).is_err());
    let frame = TxFrame::exact(0x740, false, &[0xA3]).unwrap();
    assert_eq!(frame.bytes(), [0xA3]);
    assert_eq!(frame.data, [0xA3, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        TxFrame::exact(0x200, false, &[1; 8]).unwrap().bytes().len(),
        8
    );
}

#[test]
fn iso_tp_frames_are_still_padded_to_eight_bytes() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(can.port.written()[0].bytes().len(), 8);
}

// ---- Filters

#[test]
fn filters_follow_the_conversation_and_are_set_only_when_they_change() {
    let policy = policy();
    let channel = channel();
    let filter = |id| Filter {
        id,
        mask: 0x7FF,
        extended: false,
    };
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    assert_eq!(can.port.filters(), [vec![filter(SETUP_ANSWER_ID)]]);
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_ack(&channel, 1).unwrap())
        .unwrap();
    assert_eq!(
        can.port.filters(),
        [vec![filter(SETUP_ANSWER_ID)], vec![filter(RECEIVE_ID)]]
    );
    // An ISO-TP request puts its own back.
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(can.port.filters().last(), Some(&vec![filter(0x7E8)]));
    // And a new setup listens for its answer again.
    can.send(&setup()).unwrap();
    assert_eq!(
        can.port.filters().last(),
        Some(&vec![filter(SETUP_ANSWER_ID)])
    );
}

// ---- What comes back

#[test]
fn the_frames_of_the_module_come_back_unparsed() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.port
        .inbox
        .push_back(frame(SETUP_ANSWER_ID, &SETUP_REPLY));
    assert_eq!(
        can.recv(SHORT),
        Ok(Response::new(SETUP_ANSWER_ID, SETUP_REPLY.to_vec()))
    );
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    // As they are: an ACK, a parameters reply, a frame padded to 8 bytes, and an empty one are
    // all the session's to judge.
    for data in [
        vec![0xB1],
        PARAMETERS.to_vec(),
        vec![0x10, 0x00, 0x02, 0x5A, 0x9B, 0xAA, 0xAA, 0xAA],
        vec![],
    ] {
        can.port.inbox.push_back(frame(RECEIVE_ID, &data));
        assert_eq!(can.recv(SHORT), Ok(Response::new(RECEIVE_ID, data)));
    }
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

#[test]
fn a_reply_carries_the_bus_time_of_its_frame() {
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    let at = Instant::now();
    let mut heard = rx(SETUP_ANSWER_ID, false, &SETUP_REPLY);
    heard.time = Some(at);
    can.port.inbox.push_back(PortEvent::Frame(heard));
    assert_eq!(can.recv(SHORT).unwrap().bus_time, Some(at));
}

#[test]
fn only_the_conversations_source_is_heard() {
    let policy = policy();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    // Another module's setup answer, the channel's ID before there is a channel, the same
    // number at 29 bits, and an ISO-TP module.
    for other in [
        frame(0x202, &SETUP_REPLY),
        frame(RECEIVE_ID, &PARAMETERS),
        frame29(SETUP_ANSWER_ID, &SETUP_REPLY),
        frame(0x7E8, &[0x02, 0x50, 0x01]),
    ] {
        can.port.inbox.push_back(other);
    }
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    // Once the channel is open, its ID is the one: the setup answer's no longer is.
    can.send(&policy.approve_tp20_parameters(&channel()).unwrap())
        .unwrap();
    for other in [
        frame(SETUP_ANSWER_ID, &SETUP_REPLY),
        frame29(RECEIVE_ID, &PARAMETERS),
    ] {
        can.port.inbox.push_back(other);
    }
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    can.port.inbox.push_back(frame(RECEIVE_ID, &PARAMETERS));
    assert_eq!(can.recv(SHORT).unwrap().payload, PARAMETERS);
}

#[test]
fn a_flood_from_another_id_cannot_hold_recv_or_the_session_past_its_wait() {
    let mut can = raw(Fake {
        flood_after_write: Some(rx(0x123, false, &[1, 2, 3])),
        ..Fake::default()
    });
    let start = Instant::now();
    can.send(&setup()).unwrap();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    // Through the session: the open times out, it doesn't hang.
    let mut can = raw(Fake {
        flood_after_write: Some(rx(0x123, false, &[1, 2, 3])),
        ..Fake::default()
    });
    let policy = policy();
    let opened = ChannelSession::open(&mut can, &policy, 0x01, Timing::default());
    assert_eq!(opened.err(), Some(ChannelError::NoAnswer));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_flood_while_a_channel_frame_waits_to_be_sent_fails_the_send_and_writes_nothing() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    let written = can.port.written().len();
    for _ in 0..300 {
        can.port.inbox.push_back(frame(0x123, &[1]));
    }
    let err = can
        .send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap_err();
    assert!(err.to_string().contains("queued"), "{err}");
    assert_eq!(can.port.written().len(), written);
    // The frame that tripped the limit is in the log, not just gone (#264).
    let events = can.take_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LinkEvent::Unread { line, .. } if line.starts_with("123 "))),
        "{events:?}"
    );
    // 257 frames were read: 64 are kept, and the rest, the 257th included, are counted.
    assert!(events.contains(&LinkEvent::Lost(257 - 64)), "{events:?}");
}

// ---- Frames the session hasn't read yet

#[test]
fn a_channel_frame_does_not_drop_the_frames_the_session_has_not_read() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    // The module's ACK and its first data frame wait in the port while the tester sends.
    can.port.inbox.push_back(frame(RECEIVE_ID, &[0xB1]));
    can.port
        .inbox
        .push_back(frame(RECEIVE_ID, &[0x10, 0x00, 0x02, 0x5A, 0x9B]));
    can.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap();
    assert_eq!(can.recv(SHORT).unwrap().payload, [0xB1]);
    assert_eq!(
        can.recv(SHORT).unwrap().payload,
        [0x10, 0x00, 0x02, 0x5A, 0x9B]
    );
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    // Nothing was reported as unread: nothing was lost.
    assert_eq!(can.take_events(), []);
}

#[test]
fn a_late_repeat_of_the_setup_answer_is_logged_not_handed_to_the_session() {
    let policy = policy();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.port
        .inbox
        .push_back(frame(SETUP_ANSWER_ID, &SETUP_REPLY));
    assert_eq!(can.recv(SHORT).unwrap().payload, SETUP_REPLY);
    // The module repeats its answer before the tester's first frame on the channel goes out.
    can.port
        .inbox
        .push_back(frame(SETUP_ANSWER_ID, &SETUP_REPLY));
    can.send(&policy.approve_tp20_parameters(&channel()).unwrap())
        .unwrap();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    let events = can.take_events();
    assert!(
        matches!(&events[..], [LinkEvent::Unread { line, .. }] if line.starts_with("201 ")),
        "{events:?}"
    );
}

#[test]
fn a_new_setup_drops_what_the_last_channel_left() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_disconnect(&channel).unwrap())
        .unwrap();
    // A late data frame of the closed channel is on the same ID the next channel will use.
    can.port
        .inbox
        .push_back(frame(RECEIVE_ID, &[0x10, 0x00, 0x02, 0x5A, 0x9B]));
    can.send(&setup()).unwrap();
    can.port
        .inbox
        .push_back(frame(SETUP_ANSWER_ID, &SETUP_REPLY));
    assert_eq!(can.recv(SHORT).unwrap().payload, SETUP_REPLY);
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    let events = can.take_events();
    assert!(
        matches!(&events[..], [LinkEvent::Unread { line, .. }] if line.contains("5A 9B")),
        "{events:?}"
    );
}

#[test]
fn an_iso_tp_request_after_a_closed_channel_hears_only_its_own_module() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    can.send(&policy.approve_tp20_disconnect(&channel).unwrap())
        .unwrap();
    can.port.inbox.push_back(frame(RECEIVE_ID, &[0xA8]));
    assert_eq!(can.recv(SHORT).unwrap().payload, [0xA8]);
    // Late frames of the channel are still queued when the ISO-TP request starts.
    can.port
        .inbox
        .push_back(frame(RECEIVE_ID, &[0x10, 0x00, 0x02, 0x5A, 0x9B]));
    can.port.inbox.push_back(frame(RECEIVE_ID, &[0xB2]));
    let mut ecu = ecus(vec![Ecu::obd(0x7E0, &[0x62, 0xF1, 0x87, 0x11])]);
    can.port.responder = ecu.responder.take();
    let replies = exchange(
        &mut can,
        &read_did(Target::Physical(0x7E0)),
        Expect::Module(0x7E8),
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies[0].payload, [0x62, 0xF1, 0x87, 0x11]);
    // The filters are the ISO-TP ones again, and the old channel's frames were reported, not
    // delivered.
    assert_eq!(
        can.port.filters().last(),
        Some(&vec![Filter {
            id: 0x7E8,
            mask: 0x7FF,
            extended: false
        }])
    );
    let unread = can
        .take_events()
        .into_iter()
        .filter(|e| matches!(e, LinkEvent::Unread { .. }))
        .count();
    assert_eq!(unread, 2);
    // The channel's source is no longer listened to: a frame from it now is nobody's reply.
    can.port.inbox.push_back(frame(RECEIVE_ID, &[0xB2]));
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

// ---- Failures

#[test]
fn an_unconfirmed_frame_is_an_error_and_leaves_no_answer_to_be_read() {
    let policy = policy();
    let channel = channel();
    for failing in [0, 1] {
        let mut can = raw(Fake {
            fail_write: Some(failing),
            ..Fake::default()
        });
        let first = can.send(&setup());
        // The module's answer arrives anyway.
        can.port
            .inbox
            .push_back(frame(SETUP_ANSWER_ID, &SETUP_REPLY));
        if failing == 0 {
            assert_eq!(first, Err(Error::Adapter("no TX confirmation".to_owned())));
            assert_eq!(can.port.written().len(), 0);
        } else {
            first.unwrap();
            can.port.inbox.push_back(frame(RECEIVE_ID, &[0xB1]));
            let sent = can.send(&policy.approve_tp20_parameters(&channel).unwrap());
            assert_eq!(sent, Err(Error::Adapter("no TX confirmation".to_owned())));
        }
        // Whatever the unconfirmed frame was answered with is not for a later recv.
        assert_eq!(can.recv(SHORT), Err(Error::Timeout));
        // A failed frame doesn't latch; the port decides that.
        can.port.fail_write = None;
        can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    }
}

#[test]
fn a_bus_fault_queued_behind_other_frames_latches_before_a_channel_frame_is_written() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    let written = can.port.written().len();
    can.port.inbox.push_back(frame(RECEIVE_ID, &PARAMETERS));
    can.port.inbox.push_back(frame(0x123, &[1]));
    can.port.inbox.push_back(PortEvent::BusOff);
    let err = can
        .send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert_eq!(can.port.written().len(), written);
    // Latched: not the disconnect, not an ISO-TP request, not a new setup.
    assert!(
        can.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .is_err()
    );
    assert!(can.send(&setup()).is_err());
    assert!(can.send(&read_did(Target::Physical(0x7E0))).is_err());
    assert!(can.recv(SHORT).is_err());
    assert_eq!(can.port.written().len(), written);
}

#[test]
fn a_bus_fault_that_trips_the_poll_limit_still_latches() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    let written = can.port.written().len();
    // 256 foreign frames, then the fault as the 257th event: it is handled before the limit.
    for _ in 0..256 {
        can.port.inbox.push_back(frame(0x123, &[1]));
    }
    can.port.inbox.push_back(PortEvent::BusOff);
    let err = can
        .send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert_eq!(can.port.written().len(), written);
    assert!(can.send(&read_did(Target::Physical(0x7E0))).is_err());
}

#[test]
fn a_queue_of_exactly_the_poll_limit_still_sends() {
    let policy = policy();
    let channel = channel();
    let mut can = raw(Fake::default());
    can.send(&setup()).unwrap();
    can.send(&policy.approve_tp20_parameters(&channel).unwrap())
        .unwrap();
    for _ in 0..256 {
        can.port.inbox.push_back(frame(0x123, &[1]));
    }
    can.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
        .unwrap();
}

#[test]
fn a_bus_off_in_the_middle_of_a_session_ends_it_without_another_frame() {
    // The module ACKs, then the controller goes bus-off before the answer.
    let mut port = Car::with(vec![(IDENTIFICATION.to_vec(), identification())]).port();
    let mut car = std::mem::take(&mut port.responder).unwrap();
    port.responder = Some(Box::new(move |sent| {
        let mut events = car(sent);
        if sent.bytes().first() == Some(&0x10) {
            events.truncate(1);
            events.push(PortEvent::BusOff);
        }
        events
    }));
    let mut can = raw(port);
    let policy = policy();
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).unwrap();
    let err = session.request(&IDENTIFICATION).unwrap_err();
    assert!(
        matches!(&err, ChannelError::Transport(Error::Adapter(m)) if m.contains("bus-off")),
        "{err}"
    );
    drop(session);
    // Setup, parameters, the request: no `A8` after the fault, even from the session's drop.
    assert_eq!(wire(&can).len(), 3, "{:x?}", wire(&can));
    assert!(can.send(&read_did(Target::Physical(0x7E0))).is_err());
}

#[test]
fn a_receive_overrun_in_the_middle_of_a_session_ends_it_without_another_frame() {
    let mut port = Car::with(vec![(IDENTIFICATION.to_vec(), identification())]).port();
    let mut car = std::mem::take(&mut port.responder).unwrap();
    port.responder = Some(Box::new(move |sent| {
        let mut events = car(sent);
        if sent.bytes().first() == Some(&0x10) {
            events.insert(1, PortEvent::Overrun);
        }
        events
    }));
    let mut can = raw(port);
    let policy = policy();
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).unwrap();
    let err = session.request(&IDENTIFICATION).unwrap_err();
    assert!(
        matches!(&err, ChannelError::Transport(Error::Adapter(m)) if m.contains("overrun")),
        "{err}"
    );
    drop(session);
    assert_eq!(wire(&can).len(), 3, "{:x?}", wire(&can));
}

// ---- A whole session, against the sim's module

#[test]
fn a_channel_session_reads_a_long_answer_through_the_port() {
    let mut can = raw(Car::with(vec![(IDENTIFICATION.to_vec(), identification())]).port());
    let policy = policy();
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).unwrap();
    assert_eq!(session.request(&IDENTIFICATION).unwrap(), identification());
    assert_eq!(session.close(), Ok(Disconnect::Closed));
    // The whole conversation as the tester put it on the bus: the setup at its own length, the
    // tester's parameters, the request in one data frame, an ACK in the middle of the answer
    // (after its 15th frame, so the next is 15) and another after its last (18 frames, so 2),
    // and the disconnect.
    assert_eq!(
        wire(&can),
        [
            (0x200, SETUP_REQUEST.to_vec()),
            on_channel(&[0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]),
            on_channel(&[0x10, 0x00, 0x02, 0x1A, 0x9B]),
            on_channel(&[0xBF]),
            on_channel(&[0xB2]),
            on_channel(&[0xA8]),
        ]
    );
}

#[test]
fn a_session_keeps_a_channel_alive_and_survives_a_second_request() {
    let mut can = raw(Car::with(vec![(IDENTIFICATION.to_vec(), vec![0x5A, 0x9B, 1, 2])]).port());
    let policy = policy();
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).unwrap();
    assert_eq!(
        session.request(&IDENTIFICATION).unwrap(),
        [0x5A, 0x9B, 1, 2]
    );
    session.keep_alive().unwrap();
    assert_eq!(
        session.request(&IDENTIFICATION).unwrap(),
        [0x5A, 0x9B, 1, 2]
    );
    // A request the module doesn't know is a refusal, which is an answer.
    assert_eq!(session.request(&[0x1A, 0x80]).unwrap(), [0x7F, 0x1A, 0x31]);
    assert_eq!(session.close(), Ok(Disconnect::Closed));
    let sequence: Vec<_> = wire(&can).into_iter().map(|(_, bytes)| bytes).collect();
    assert_eq!(sequence[2], [0x10, 0x00, 0x02, 0x1A, 0x9B]);
    assert_eq!(sequence[4], [0xA3]);
    assert_eq!(sequence[5], [0x11, 0x00, 0x02, 0x1A, 0x9B]);
}

#[test]
fn probe_finds_the_module_that_answers_and_closes_its_channel() {
    let mut can = raw(Car::with(vec![]).port());
    let policy = Policy::read_only().narrowed_to_tp20(&[0x01, 0x02]);
    let found = tp20::probe(&mut can, &policy, &[0x01, 0x02], Timing::default()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].address, 0x01);
    assert!(matches!(found[0].answer, Answer::Channel(_)));
    assert_eq!(found[0].disconnect, Some(Disconnect::Closed));
    // Setup to 1, its disconnect, setup to 2 (nobody there), each at its own length.
    let sent = wire(&can);
    assert_eq!(sent[0], (0x200, SETUP_REQUEST.to_vec()));
    assert_eq!(sent[1], on_channel(&[0xA8]));
    assert_eq!(
        sent[2],
        (0x200, vec![0x02, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01])
    );
    assert_eq!(sent.len(), 3);
}

#[test]
fn a_refused_setup_is_a_refusal_not_a_channel() {
    let mut can = raw(Fake::answering(|_| {
        vec![frame(
            SETUP_ANSWER_ID,
            &[0x00, 0xD7, 0x00, 0x00, 0x00, 0x00, 0x00],
        )]
    }));
    let policy = policy();
    assert_eq!(
        ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).err(),
        Some(ChannelError::Refused(0xD7))
    );
}

// ---- What a module that pads its frames does

#[test]
fn a_setup_answer_padded_to_eight_bytes_is_undecodable_as_over_the_elm_driver() {
    let padded = [0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01, 0xAA];
    let mut can = raw(Fake::answering(move |_| {
        vec![frame(SETUP_ANSWER_ID, &padded)]
    }));
    let policy = policy();
    assert_eq!(
        ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).err(),
        Some(ChannelError::Undecodable(padded.to_vec()))
    );
    // The setup went out, and nothing else: no channel was assumed.
    assert_eq!(wire(&can), [(0x200, SETUP_REQUEST.to_vec())]);
}

#[test]
fn an_ack_padded_to_eight_bytes_breaks_the_framing_and_closes_the_channel() {
    let mut car = Car::with(vec![(IDENTIFICATION.to_vec(), vec![0x5A, 0x9B, 1, 2])]);
    let mut can = raw(Fake::answering(move |sent| {
        let mut events = car.hear(sent);
        if sent.bytes().first() == Some(&0x10) {
            events[0] = frame(
                RECEIVE_ID,
                &[0xB1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
            );
        }
        events
    }));
    let policy = policy();
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, Timing::default()).unwrap();
    let err = session.request(&IDENTIFICATION).unwrap_err();
    assert!(matches!(err, ChannelError::Framing(_)), "{err}");
    assert_eq!(session.request(&IDENTIFICATION), Err(ChannelError::Closed));
    drop(session);
    // The channel was closed with an `A8`, as for any broken framing.
    assert_eq!(wire(&can).last(), Some(&on_channel(&[0xA8])));
}

// ---- Timing, with a port that waits the way a real one does
type Script = Box<dyn FnMut(&TxFrame) -> Vec<(Duration, PortEvent)>>;

// A port that plays a script in real time: a frame arrives when its time comes, and `read` waits
// out its timeout when nothing does, as the real ports do.
struct Timed {
    written: Vec<(Instant, TxFrame)>,
    script: Script,
    due: VecDeque<(Instant, PortEvent)>,
}

impl std::fmt::Debug for Timed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Timed")
    }
}

impl Timed {
    fn new(script: impl FnMut(&TxFrame) -> Vec<(Duration, PortEvent)> + 'static) -> Self {
        Self {
            written: Vec::new(),
            script: Box::new(script),
            due: VecDeque::new(),
        }
    }

    fn bytes(&self) -> Vec<Vec<u8>> {
        self.written
            .iter()
            .map(|(_, f)| f.bytes().to_vec())
            .collect()
    }
}

impl CanPort for Timed {
    fn set_filters(&mut self, _: &[Filter]) -> Result<(), Error> {
        Ok(())
    }

    fn write(&mut self, frame: &TxFrame) -> Result<(), Error> {
        let now = Instant::now();
        self.written.push((now, *frame));
        for (delay, event) in (self.script)(frame) {
            self.due.push_back((now + delay, event));
        }
        self.due.make_contiguous().sort_by_key(|(at, _)| *at);
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> Result<PortEvent, Error> {
        let deadline = Instant::now() + timeout;
        match self.due.front() {
            Some((at, _)) if *at <= deadline => {
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                Ok(self.due.pop_front().unwrap().1)
            }
            _ => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                Err(Error::Timeout)
            }
        }
    }
}

const MS: fn(u64) -> Duration = Duration::from_millis;

// A module that opens a channel, takes the parameters, ACKs the request at once and then sends
// `after` (frames, each with the delay since the request).
fn slow_module(after: Vec<(Duration, Vec<u8>)>) -> Timed {
    Timed::new(move |sent| match sent.bytes() {
        [0x01, 0xC0, ..] => vec![(MS(1), frame(SETUP_ANSWER_ID, &SETUP_REPLY))],
        [0xA0, ..] | [0xA3] => vec![(MS(1), frame(RECEIVE_ID, &PARAMETERS))],
        [0xA8] => vec![(MS(1), frame(RECEIVE_ID, &[0xA8]))],
        [0x10, ..] => {
            let mut frames = vec![(MS(1), frame(RECEIVE_ID, &[0xB1]))];
            frames.extend(
                after
                    .iter()
                    .map(|(delay, data)| (*delay, frame(RECEIVE_ID, data))),
            );
            frames
        }
        _ => Vec::new(),
    })
}

#[test]
fn an_answer_that_takes_its_time_after_response_pending_needs_no_keep_alive() {
    // `recv` waits its whole timeout, so the session never sees the early timeout an ELM327's
    // prompt gives, and sends nothing to make the port listen again.
    let mut can = RawCan::new(slow_module(vec![
        (MS(5), vec![0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]),
        (MS(150), vec![0x11, 0x00, 0x04, 0x5A, 0x9B, 0x01, 0x02]),
    ]));
    let policy = policy();
    let timing = Timing {
        p2: MS(500),
        p2_star: Duration::from_secs(1),
        ..Timing::default()
    };
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, timing).unwrap();
    assert_eq!(
        session.request(&IDENTIFICATION).unwrap(),
        [0x5A, 0x9B, 0x01, 0x02]
    );
    drop(session);
    let sent = can.port.bytes();
    assert_eq!(
        sent[2..],
        [
            vec![0x10, 0x00, 0x02, 0x1A, 0x9B],
            vec![0xB1],
            vec![0xB2],
            vec![0xA8]
        ],
        "no A3 between the ACK and the answer"
    );
}

#[test]
fn an_answer_that_never_comes_after_response_pending_ends_after_the_whole_wait() {
    let mut can = RawCan::new(slow_module(vec![(
        MS(5),
        vec![0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78],
    )]));
    let policy = policy();
    let timing = Timing {
        p2: MS(500),
        p2_star: MS(120),
        max_pending: 3,
    };
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, timing).unwrap();
    let began = Instant::now();
    assert_eq!(
        session.request(&IDENTIFICATION),
        Err(ChannelError::StillPending)
    );
    // The port waited for the module the whole P2*, not less.
    assert!(began.elapsed() >= MS(120), "{:?}", began.elapsed());
    drop(session);
    // The one keep-alive the session sends when its pending wait runs out, then the disconnect.
    let sent = can.port.bytes();
    assert_eq!(sent[sent.len() - 2..], [vec![0xA3], vec![0xA8]]);
    assert_eq!(sent.iter().filter(|f| **f == [0xA3]).count(), 1);
}

#[test]
fn a_module_that_answers_within_the_sessions_wait_is_heard_however_late_it_is_in_it() {
    // The port waits the whole time it is asked to, so an answer at 80 ms of a 1 s wait is read.
    let mut can = RawCan::new(slow_module(vec![(
        MS(80),
        vec![0x10, 0x00, 0x04, 0x5A, 0x9B, 0x01, 0x02],
    )]));
    let policy = policy();
    let timing = Timing {
        p2: Duration::from_secs(1),
        ..Timing::default()
    };
    let mut session = ChannelSession::open(&mut can, &policy, 0x01, timing).unwrap();
    assert_eq!(
        session.request(&IDENTIFICATION).unwrap(),
        [0x5A, 0x9B, 0x01, 0x02]
    );
}
