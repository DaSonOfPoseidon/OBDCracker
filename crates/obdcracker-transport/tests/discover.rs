//! Looking for modules a profile doesn't list: what's sent, and what counts as found.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::discover::{Found, PATIENT_P2, discover, discover_patiently};
use obdcracker_transport::fingerprint::{DidValue, FingerprintError, ReadError};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

// Answers each request as it's sent, and records what was sent.
struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
    fail_after: Option<usize>,
    // The shortest timeout each receive was given.
    shortest_wait: Option<Duration>,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
            fail_after: None,
            shortest_wait: None,
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        if self.fail_after == Some(self.sent.len()) {
            return Err(Error::Adapter("unplugged".to_owned()));
        }
        let id = request.target().can_id();
        self.sent
            .push(format!("{id:03X} {}", hex(request.payload())));
        self.replies.extend((self.answer)(id, request.payload()));
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.shortest_wait = Some(self.shortest_wait.map_or(timeout, |w| w.min(timeout)));
        self.replies.pop_front().ok_or(Error::Timeout)
    }

    fn patient(&mut self, on: bool) -> Result<(), Error> {
        self.sent.push(format!("patient {on}"));
        Ok(())
    }
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

fn reply(source: u32, payload: &[u8]) -> Response {
    Response {
        source,
        payload: payload.to_vec(),
    }
}

// 0x70E..=0x712, replies at +0x6A.
fn candidates() -> Vec<ModuleIds> {
    (0x70E..=0x712)
        .map(|request| ModuleIds {
            request,
            reply: request + 0x6A,
        })
        .collect()
}

fn policy() -> Policy {
    Policy::read_only().narrowed_to(&candidates()).unwrap()
}

// The gateway (0x710) answers with its part number, the steering (0x712) refuses F187, and
// another ID's module (0x7B9) talks out of turn.
fn car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x710, [0x22, 0xF1, 0x87]) => vec![reply(0x77A, b"\x62\xF1\x874G0907468AD")],
        (0x712, [0x22, 0xF1, 0x87]) => vec![reply(0x77C, &[0x7F, 0x22, 0x31])],
        (0x70F, _) => vec![reply(0x7B9, b"\x62\xF1\x874G0907561 ")],
        _ => Vec::new(),
    }
}

#[test]
fn reads_the_part_number_of_each_candidate_and_lists_those_that_answer() {
    let mut car = Car::new(car);
    let found = discover(&mut car, &policy(), &candidates(), TIMING).unwrap();
    assert_eq!(
        car.sent,
        [
            "70E 22 F1 87",
            "70F 22 F1 87",
            "710 22 F1 87",
            "711 22 F1 87",
            "712 22 F1 87"
        ]
    );
    assert_eq!(
        found,
        [
            Found {
                request_id: 0x710,
                response_id: 0x77A,
                part_number: Ok(DidValue::Text("4G0907468AD".into())),
            },
            // A refusal still means a module is there.
            Found {
                request_id: 0x712,
                response_id: 0x77C,
                part_number: Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
                    sid: 0x22,
                    nrc: Nrc::RequestOutOfRange,
                }))),
            },
        ]
    );
}

#[test]
fn every_request_is_approved_before_any_is_sent() {
    // The bare read-only policy doesn't know any candidate's reply ID, and a policy narrowed to
    // other modules refuses the candidates outright.
    let other = Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x714,
            reply: 0x77E,
        }])
        .unwrap();
    for (policy, rejection) in [
        (Policy::read_only(), Rejection::WrongTarget),
        (other, Rejection::WrongTarget),
    ] {
        let mut car = Car::new(car);
        assert_eq!(
            discover(&mut car, &policy, &candidates(), TIMING),
            Err(FingerprintError::Rejected(rejection))
        );
        assert_eq!(car.sent, Vec::<String>::new());
    }
}

#[test]
fn a_candidate_whose_reply_id_the_policy_disagrees_with_is_refused() {
    let mut wrong = candidates();
    wrong[2].reply = 0x7A0;
    let mut car = Car::new(car);
    assert_eq!(
        discover(&mut car, &policy(), &wrong, TIMING),
        Err(FingerprintError::Rejected(Rejection::WrongTarget))
    );
    assert_eq!(car.sent, Vec::<String>::new());
}

#[test]
fn an_adapter_failure_stops_discovery() {
    let mut car = Car::new(car);
    car.fail_after = Some(3);
    assert!(matches!(
        discover(&mut car, &policy(), &candidates(), TIMING),
        Err(FingerprintError::Transport(Error::Adapter(_)))
    ));
    assert_eq!(car.sent.len(), 3);
}

#[test]
fn nothing_answering_finds_nothing() {
    let mut car = Car::new(|_, _| Vec::new());
    assert_eq!(
        discover(&mut car, &policy(), &candidates(), TIMING).unwrap(),
        []
    );
    assert_eq!(car.sent.len(), 5);
}

#[test]
fn a_patient_pass_waits_longer_and_always_ends_patience() {
    let candidates = [
        ModuleIds {
            request: 0x709,
            reply: 0x773,
        },
        ModuleIds {
            request: 0x70A,
            reply: 0x774,
        },
    ];
    let policy = Policy::read_only().narrowed_to(&candidates).unwrap();
    let mut car = Car::new(|id, _| match id {
        0x70A => vec![reply(0x774, &[0x62, 0xF1, 0x87, b'X'])],
        _ => Vec::new(),
    });
    let found = discover_patiently(&mut car, &policy, &candidates, TIMING).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].request_id, 0x70A);
    assert_eq!(
        car.sent,
        [
            "patient true",
            "709 22 F1 87",
            "70A 22 F1 87",
            "patient false"
        ]
    );
    // Each receive gets what's left of P2.
    assert!(
        car.shortest_wait > PATIENT_P2.checked_sub(Duration::from_millis(100)),
        "{:?}",
        car.shortest_wait
    );
    // An adapter failure still ends patience, and is what's reported.
    let mut car = Car::new(|_, _| Vec::new());
    car.fail_after = Some(2);
    let error = discover_patiently(&mut car, &policy, &candidates, TIMING).unwrap_err();
    assert!(
        matches!(error, FingerprintError::Transport(Error::Adapter(_))),
        "{error:?}"
    );
    assert_eq!(car.sent.last().map(String::as_str), Some("patient false"));
}
