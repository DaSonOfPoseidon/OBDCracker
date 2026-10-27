//! VW TP2.0: looking for modules (channel setups, what modules answer, closing their channels),
//! and KWP2000 reads on an open channel.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::tp20::{self as codec, Channel};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::FingerprintError;
use obdcracker_transport::tp20::{Answer, ChannelError, ChannelSession, Disconnect, Probed, probe};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};
use proptest::prelude::*;

type Answers = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

struct Car {
    answer: Answers,
    replies: VecDeque<Response>,
    sent: Vec<String>,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let id = request.target().can_id();
        self.sent
            .push(format!("{id:03X} {}", hex(request.payload())));
        self.replies.extend((self.answer)(id, request.payload()));
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

fn reply(source: u32, payload: &[u8]) -> Vec<Response> {
    vec![Response {
        source,
        payload: payload.to_vec(),
    }]
}

#[test]
fn the_policys_channel_frames_are_the_codecs() {
    for address in [0x01, 0x5F, 0xEF] {
        let setup = Policy::read_only().approve_tp20_setup(address).unwrap();
        assert_eq!(setup.payload(), codec::channel_setup(address));
        assert_eq!(setup.target().can_id(), codec::SETUP_ID);
        assert_eq!(setup.reply_id(), Some(codec::setup_reply_id(address)));
    }
    let policy = Policy::read_only();
    let setup = policy.approve_tp20_setup(0x5F).unwrap();
    let channel = policy
        .tp20_channel(&setup, 0x25F, &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])
        .unwrap();
    let disconnect = policy.approve_tp20_disconnect(&channel).unwrap();
    assert_eq!(disconnect.payload(), codec::DISCONNECT);
}

#[test]
fn finds_the_modules_that_answer_and_closes_their_channels() {
    // 0x5F opens 0x740/0x300 and closes it, 0x09 refuses (no resources), 0x16 sends nonsense,
    // 0x17 would answer on 0x301 rather than the 0x300 asked for, and 0x46 isn't there.
    let mut car = Car::new(|id, frame| match (id, frame) {
        (0x200, [0x5F, 0xC0, ..]) => reply(0x25F, &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01]),
        (0x200, [0x09, 0xC0, ..]) => reply(0x209, &[0x00, 0xD7, 0x00, 0x03, 0x40, 0x07, 0x01]),
        (0x200, [0x16, 0xC0, ..]) => reply(0x216, &[0x00, 0xD0, 0x00]),
        (0x200, [0x17, 0xC0, ..]) => reply(0x217, &[0x00, 0xD0, 0x01, 0x03, 0x40, 0x07, 0x01]),
        (0x740, [0xA8]) => reply(0x300, &[0xA8]),
        _ => Vec::new(),
    });
    let found = probe(
        &mut car,
        &Policy::read_only(),
        &[0x09, 0x16, 0x17, 0x46, 0x5F],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        found,
        [
            Probed {
                address: 0x09,
                answer: Answer::Refused(0xD7),
                disconnect: None,
            },
            Probed {
                address: 0x16,
                answer: Answer::Undecodable(vec![0x00, 0xD0, 0x00]),
                disconnect: None,
            },
            Probed {
                address: 0x17,
                answer: Answer::Undecodable(vec![0x00, 0xD0, 0x01, 0x03, 0x40, 0x07, 0x01]),
                disconnect: None,
            },
            Probed {
                address: 0x5F,
                answer: Answer::Channel(Channel {
                    send_id: 0x740,
                    receive_id: 0x300,
                }),
                disconnect: Some(Disconnect::Closed),
            },
        ]
    );
    assert_eq!(
        car.sent,
        [
            "200 09 C0 00 10 00 03 01",
            "200 16 C0 00 10 00 03 01",
            "200 17 C0 00 10 00 03 01",
            "200 46 C0 00 10 00 03 01",
            "200 5F C0 00 10 00 03 01",
            "740 A8",
        ]
    );
}

#[test]
fn a_disconnect_the_module_ignores_or_the_policy_refuses_is_reported() {
    // One module gives a channel on the gateway's own request ID, which a narrowed policy won't
    // send A8 on; another answers no disconnect.
    let mut car = Car::new(|id, frame| match (id, frame) {
        (0x200, [0x5F, 0xC0, ..]) => reply(0x25F, &[0x00, 0xD0, 0x00, 0x03, 0x10, 0x07, 0x01]),
        (0x200, [0x09, 0xC0, ..]) => reply(0x209, &[0x00, 0xD0, 0x00, 0x03, 0x41, 0x07, 0x01]),
        _ => Vec::new(),
    });
    let policy = Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x710,
            reply: 0x77A,
        }])
        .unwrap();
    let found = probe(&mut car, &policy, &[0x09, 0x5F], TIMING).unwrap();
    assert_eq!(found[0].disconnect, Some(Disconnect::NoReply));
    assert_eq!(
        found[1].disconnect,
        Some(Disconnect::NotSent(Rejection::WrongTarget))
    );
    assert!(!car.sent.iter().any(|sent| sent.starts_with("710")));
}

#[test]
fn every_setup_is_approved_before_anything_is_sent() {
    let mut car = Car::new(|_, _| Vec::new());
    let policy = Policy::read_only().narrowed_to_tp20(&[0x5F]);
    assert_eq!(
        probe(&mut car, &policy, &[0x5F, 0x09], TIMING),
        Err(FingerprintError::Rejected(Rejection::WrongTarget))
    );
    assert_eq!(car.sent, Vec::<String>::new());
}

#[test]
fn an_address_given_twice_is_refused_before_anything_is_sent() {
    let mut car = Car::new(|_, _| Vec::new());
    assert_eq!(
        probe(&mut car, &Policy::read_only(), &[0x5F, 0x09, 0x5F], TIMING),
        Err(FingerprintError::Rejected(Rejection::WrongTarget))
    );
    assert_eq!(car.sent, Vec::<String>::new());
}

const SETUP_REPLY: [u8; 7] = [0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01];
const MODULE_PARAMETERS: [u8; 6] = [0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF];

// Module 0x5F gives channel 0x740/0x300 and its parameters, closes it on A8, and answers data
// frames, ACKs and keep-alives with `data`.
fn channel_car(mut data: impl FnMut(&[u8]) -> Vec<Vec<u8>> + 'static) -> Car {
    Car::new(move |id, frame| match (id, frame) {
        (0x200, [0x5F, 0xC0, ..]) => reply(0x25F, &SETUP_REPLY),
        (0x740, [0xA0, ..]) => reply(0x300, &MODULE_PARAMETERS),
        (0x740, [0xA8]) => reply(0x300, &[0xA8]),
        (0x740, frame) => data(frame)
            .into_iter()
            .map(|payload| Response {
                source: 0x300,
                payload,
            })
            .collect(),
        _ => Vec::new(),
    })
}

fn frames(frames: &[&[u8]]) -> Vec<Vec<u8>> {
    frames.iter().map(|frame| frame.to_vec()).collect()
}

const OPENING: [&str; 2] = ["200 5F C0 00 10 00 03 01", "740 A0 0F 8A FF 32 FF"];

#[test]
fn reads_a_multi_frame_answer_acking_the_frames_that_ask() {
    // The module acks the request, then sends `5A 9B` and 12 bytes in three frames: the second
    // asks for an ACK, and the third comes only once it's had one.
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[
            &[0xB1],
            &[0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43],
            &[0x01, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A],
        ]),
        [0xB2] => frames(&[&[0x12, 0x4B, 0x4C]]),
        [0xB3] => Vec::new(),
        _ => frames(&[&[0xEE]]),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.channel().send_id(), 0x740);
    assert_eq!(session.parameters().block_size, 15);
    assert_eq!(session.parameters().t1, Duration::from_millis(100));
    assert_eq!(
        session.request(&[0x1A, 0x9B]).unwrap(),
        b"\x5A\x9BABCDEFGHIJKL"
    );
    assert_eq!(session.close(), Ok(Disconnect::Closed));
    assert_eq!(
        car.sent,
        [
            OPENING[0],
            OPENING[1],
            "740 10 00 02 1A 9B",
            "740 B2",
            "740 B3",
            "740 A8",
        ]
    );
}

#[test]
fn each_request_takes_the_next_sequence_number() {
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x21, 0x01] => frames(&[&[0xB1], &[0x30, 0x00, 0x02, 0x61, 0x01]]),
        [0x11, 0x00, 0x02, 0x21, 0x02] => frames(&[&[0xB2], &[0x31, 0x00, 0x02, 0x61, 0x02]]),
        _ => frames(&[&[0xEE]]),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x21, 0x01]).unwrap(), [0x61, 0x01]);
    assert_eq!(session.request(&[0x21, 0x02]).unwrap(), [0x61, 0x02]);
}

#[test]
fn a_refused_request_sends_nothing_and_leaves_the_channel_open() {
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[&[0xB1], &[0x30, 0x00, 0x02, 0x5A, 0x9B]]),
        _ => frames(&[&[0xEE]]),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    for (request, rejection) in [
        (&[0x31, 0x01][..], Rejection::Banned),
        (
            &[0x14, 0xFF, 0x00],
            Rejection::Locked(obdcracker_safety::Tier::ClearDtc),
        ),
        (&[0x22, 0xF1, 0x87], Rejection::NotAllowed),
        (&[0x18, 0x02, 0xFF, 0xFF, 0x00, 0x00], Rejection::NotAllowed),
    ] {
        assert_eq!(
            session.request(request),
            Err(ChannelError::Rejected(rejection)),
            "{request:02X?}"
        );
    }
    // Still on sequence number 0.
    assert_eq!(session.request(&[0x1A, 0x9B]).unwrap(), [0x5A, 0x9B]);
    drop(session);
    assert_eq!(car.sent[2..], ["740 10 00 02 1A 9B", "740 A8"]);
}

#[test]
fn a_refusal_is_the_answer() {
    let mut car = channel_car(|_| frames(&[&[0xB1], &[0x30, 0x00, 0x03, 0x7F, 0x1A, 0x31]]));
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x1A, 0x9B]).unwrap(), [0x7F, 0x1A, 0x31]);
}

#[test]
fn response_pending_is_waited_through() {
    // Pending first, acked; the answer comes once the ACK has arrived.
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xB1] => frames(&[&[0x31, 0x00, 0x02, 0x5A, 0x9B]]),
        _ => frames(&[&[0xEE]]),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x1A, 0x9B]).unwrap(), [0x5A, 0x9B]);
}

#[test]
fn an_adapter_that_stops_listening_while_pending_listens_again_after_a_keep_alive() {
    // As an ELM327 does after its prompt: nothing more arrives until the tester sends again.
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xB1] => Vec::new(),
        [0xA3] => frames(&[&MODULE_PARAMETERS, &[0x31, 0x00, 0x02, 0x5A, 0x9B]]),
        _ => frames(&[&[0xEE]]),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x1A, 0x9B]).unwrap(), [0x5A, 0x9B]);
    drop(session);
    assert_eq!(
        car.sent[2..],
        ["740 10 00 02 1A 9B", "740 B1", "740 A3", "740 A8"]
    );
}

#[test]
fn one_keep_alive_gets_one_answer() {
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xA3] => frames(&[&MODULE_PARAMETERS, &MODULE_PARAMETERS]),
        _ => Vec::new(),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert!(matches!(
        session.request(&[0x1A, 0x9B]),
        Err(ChannelError::Framing(_))
    ));
}

#[test]
fn a_keep_alive_s_late_answer_is_taken_by_the_next_request() {
    // The answer overtakes the keep-alive's A1, which arrives during the next request.
    let mut car = channel_car(|frame| match frame {
        [0x10, 0x00, 0x02, 0x1A, 0x9B] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xA3] => frames(&[&[0x31, 0x00, 0x02, 0x5A, 0x9B], &MODULE_PARAMETERS]),
        [0x11, 0x00, 0x02, 0x21, 0x01] => frames(&[&[0xB2], &[0x32, 0x00, 0x02, 0x61, 0x01]]),
        _ => Vec::new(),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x1A, 0x9B]).unwrap(), [0x5A, 0x9B]);
    assert_eq!(session.request(&[0x21, 0x01]).unwrap(), [0x61, 0x01]);
}

#[test]
fn a_module_pending_too_often_or_too_long_is_given_up_on() {
    // Pending on every ACK: over `max_pending` (2).
    let mut car = channel_car(|frame| match frame {
        [0x10, ..] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xB1] => frames(&[&[0x11, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xB2] => frames(&[&[0x12, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        _ => Vec::new(),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(
        session.request(&[0x1A, 0x9B]),
        Err(ChannelError::StillPending)
    );
    drop(session);
    assert_eq!(car.sent.last().map(String::as_str), Some("740 A8"));
    // Pending once, then nothing, even after keep-alives.
    let mut car = channel_car(|frame| match frame {
        [0x10, ..] => frames(&[&[0xB1], &[0x10, 0x00, 0x03, 0x7F, 0x1A, 0x78]]),
        [0xA3] => frames(&[&MODULE_PARAMETERS]),
        _ => Vec::new(),
    });
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(
        session.request(&[0x1A, 0x9B]),
        Err(ChannelError::StillPending)
    );
    drop(session);
    let keep_alives = car.sent.iter().filter(|sent| *sent == "740 A3").count();
    assert!(keep_alives <= 2, "{keep_alives}");
}

#[test]
fn a_frame_that_breaks_the_framing_closes_the_channel() {
    for (name, answer) in [
        ("an ACK of a frame not sent", frames(&[&[0xB5]])),
        ("a second ACK", frames(&[&[0xB1], &[0xB1]])),
        // The frame with sequence number 1 never arrived: the adapter lost it.
        (
            "a skipped sequence number",
            frames(&[
                &[0xB1],
                &[0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43],
                &[0x12, 0x4B, 0x4C],
            ]),
        ),
        (
            "a length the data doesn't keep",
            frames(&[&[0x30, 0x00, 0x03, 0x5A, 0x9B]]),
        ),
        ("an empty frame", frames(&[&[]])),
        ("a reserved opcode", frames(&[&[0x50, 0x00]])),
        ("a test from the module", frames(&[&[0xA3]])),
        ("parameters nobody asked for", frames(&[&MODULE_PARAMETERS])),
    ] {
        let mut car = channel_car(move |frame| match frame {
            [0x10, ..] => answer.clone(),
            _ => Vec::new(),
        });
        let policy = Policy::read_only();
        let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
        assert!(
            matches!(
                session.request(&[0x1A, 0x9B]),
                Err(ChannelError::Framing(_))
            ),
            "{name}"
        );
        assert_eq!(
            session.request(&[0x1A, 0x9B]),
            Err(ChannelError::Closed),
            "{name}"
        );
        drop(session);
        assert_eq!(
            car.sent.last().map(String::as_str),
            Some("740 A8"),
            "{name}"
        );
        assert_eq!(
            car.sent.iter().filter(|s| *s == "740 A8").count(),
            1,
            "{name}"
        );
    }
}

#[test]
fn an_answer_to_another_request_closes_the_channel() {
    // `61 02` answers a read of local ID 02, not 01: a late answer, so replies are out of step.
    let mut car = channel_car(|_| frames(&[&[0xB1], &[0x30, 0x00, 0x02, 0x61, 0x02]]));
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(
        session.request(&[0x21, 0x01]),
        Err(ChannelError::Unmatched(vec![0x61, 0x02]))
    );
    assert_eq!(session.request(&[0x21, 0x01]), Err(ChannelError::Closed));
    // Closing it again sends nothing.
    assert_eq!(session.close(), Err(ChannelError::Closed));
    assert_eq!(car.sent.iter().filter(|s| *s == "740 A8").count(), 1);
}

#[test]
fn a_module_that_closes_the_channel_isnt_sent_a_disconnect() {
    let mut car = channel_car(|_| frames(&[&[0xA8]]));
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(
        session.request(&[0x1A, 0x9B]),
        Err(ChannelError::ClosedByModule)
    );
    drop(session);
    assert_eq!(
        car.sent.last().map(String::as_str),
        Some("740 10 00 02 1A 9B")
    );
}

#[test]
fn no_answer_times_out_and_closes_the_channel() {
    let mut car = channel_car(|_| Vec::new());
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    assert_eq!(session.request(&[0x1A, 0x9B]), Err(ChannelError::Timeout));
    drop(session);
    assert_eq!(car.sent.last().map(String::as_str), Some("740 A8"));
}

#[test]
fn opening_fails_cleanly() {
    let policy = Policy::read_only();
    let mut silent = Car::new(|_, _| Vec::new());
    assert_eq!(
        ChannelSession::open(&mut silent, &policy, 0x5F, TIMING).err(),
        Some(ChannelError::NoAnswer)
    );
    let mut refusing = Car::new(|_, _| reply(0x25F, &[0x00, 0xD7, 0x00, 0x03, 0x40, 0x07, 0x01]));
    assert_eq!(
        ChannelSession::open(&mut refusing, &policy, 0x5F, TIMING).err(),
        Some(ChannelError::Refused(0xD7))
    );
    assert_eq!(
        ChannelSession::open(&mut Car::new(|_, _| Vec::new()), &policy, 0x00, TIMING).err(),
        Some(ChannelError::Rejected(Rejection::WrongTarget))
    );
    // A channel that gets no parameters is closed again.
    let mut no_parameters = Car::new(|id, frame| match (id, frame) {
        (0x200, _) => reply(0x25F, &SETUP_REPLY),
        (0x740, [0xA8]) => reply(0x300, &[0xA8]),
        _ => Vec::new(),
    });
    assert_eq!(
        ChannelSession::open(&mut no_parameters, &policy, 0x5F, TIMING).err(),
        Some(ChannelError::Timeout)
    );
    assert_eq!(
        no_parameters.sent.last().map(String::as_str),
        Some("740 A8")
    );
}

#[test]
fn keep_alive_reads_the_module_s_parameters() {
    let mut car = channel_car(|frame| match frame {
        [0xA3] => frames(&[&[0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF]]),
        _ => Vec::new(),
    });
    let policy = Policy::read_only();
    let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
    session.keep_alive().unwrap();
    assert_eq!(session.parameters().t3, Duration::from_millis(10));
}

// Opens like `channel_car`, then answers the request with `frame`, for ever.
struct Flood {
    car: Car,
    source: u32,
    frame: Vec<u8>,
    flooding: bool,
    handed_out: usize,
}

impl Transport for Flood {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.flooding |= request.payload().first() == Some(&0x10);
        self.car.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        if !self.flooding {
            return self.car.recv(timeout);
        }
        self.handed_out += 1;
        Ok(Response {
            source: self.source,
            payload: self.frame.clone(),
        })
    }
}

#[test]
fn a_module_that_never_stops_sending_cant_stall_a_request() {
    for frame in [
        // Not ready, for ever.
        vec![0x91],
        // The ready ACK, for ever.
        vec![0xB1],
        // Pending, each a new message, for ever.
        vec![0x30, 0x00, 0x03, 0x7F, 0x1A, 0x78],
        // The first frame of the longest message, which never goes on.
        vec![0x20, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05],
    ]
    .into_iter()
    .map(|frame| (0x300, frame))
    // Frames from another module: never the answer, but they keep coming.
    .chain([(0x301, vec![0x30, 0x00, 0x02, 0x5A, 0x9B])])
    {
        let (source, frame) = frame;
        let mut flood = Flood {
            car: channel_car(|_| Vec::new()),
            source,
            frame: frame.clone(),
            flooding: false,
            handed_out: 0,
        };
        let policy = Policy::read_only();
        let mut session = ChannelSession::open(&mut flood, &policy, 0x5F, TIMING).unwrap();
        let started = std::time::Instant::now();
        let result = session.request(&[0x1A, 0x9B]);
        drop(session);
        assert!(result.is_err(), "{frame:02X?}");
        // Bounded by time the frames can't extend, or by their count: well under a second.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{frame:02X?}: {:?}, {} frames",
            started.elapsed(),
            flood.handed_out
        );
    }
}

proptest! {
    #[test]
    fn whatever_the_module_sends_the_answer_answers_or_the_channel_closes(
        answer in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..9), 0..6),
    ) {
        let mut car = channel_car(move |frame| match frame {
            [0x10, ..] => answer.clone(),
            _ => Vec::new(),
        });
        let policy = Policy::read_only();
        let mut session = ChannelSession::open(&mut car, &policy, 0x5F, TIMING).unwrap();
        let result = session.request(&[0x21, 0x01]);
        drop(session);
        match result {
            Ok(message) => prop_assert!(obdcracker_core::response::kwp2000_answers(&[0x21, 0x01], &message)),
            Err(ChannelError::ClosedByModule) => {}
            Err(_) => prop_assert_eq!(car.sent.last().map(String::as_str), Some("740 A8")),
        }
    }
}
