//! Looking for VW TP2.0 modules: channel setups, what modules answer, and closing their channels.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::tp20::{self as codec, Channel};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::FingerprintError;
use obdcracker_transport::tp20::{Answer, Disconnect, Probed, probe};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

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
    // and 0x46 isn't there.
    let mut car = Car::new(|id, frame| match (id, frame) {
        (0x200, [0x5F, 0xC0, ..]) => reply(0x25F, &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01]),
        (0x200, [0x09, 0xC0, ..]) => reply(0x209, &[0x00, 0xD7, 0x00, 0x03, 0x40, 0x07, 0x01]),
        (0x200, [0x16, 0xC0, ..]) => reply(0x216, &[0x00, 0xD0, 0x00]),
        (0x740, [0xA8]) => reply(0x300, &[0xA8]),
        _ => Vec::new(),
    });
    let found = probe(
        &mut car,
        &Policy::read_only(),
        &[0x09, 0x16, 0x46, 0x5F],
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
