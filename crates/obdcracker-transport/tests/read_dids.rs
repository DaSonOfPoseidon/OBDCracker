//! One `22` request for several DIDs: what is sent, the bounds on the list, and a reply that is
//! checked exactly, never trusted.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::{ReadError, UdsModule};
use obdcracker_transport::read_dids::{DidsData, MAX_DIDS, ReadDidsError, read_dids};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};
use proptest::prelude::*;

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
    fail: bool,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
            fail: false,
        }
    }

    // A module that answers every request with `payload`.
    fn saying(payload: &[u8]) -> Self {
        let payload = payload.to_vec();
        Self::new(move |_, _| vec![Response::new(0x7E9, payload.clone())])
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Adapter("the adapter said BUFFER FULL".to_owned()));
        }
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

const FOUR: [u16; 4] = [0xF187, 0xF188, 0xF189, 0xF191];

fn transmission() -> UdsModule {
    UdsModule {
        name: "transmission".into(),
        request_id: 0x7E1,
        response_id: 0x7E9,
    }
}

// F187 is 2 bytes, F188 1, F189 3 and F191 1: the data of `REPLY`.
fn lengths(did: u16) -> Option<usize> {
    match did {
        0xF187 => Some(2),
        0xF188 | 0xF191 => Some(1),
        0xF189 => Some(3),
        _ => None,
    }
}

// The answer to the four-DID read, with the data `lengths` says.
fn reply() -> Vec<u8> {
    vec![
        0x62, 0xF1, 0x87, 0xAA, 0xBB, 0xF1, 0x88, 0xCC, 0xF1, 0x89, 0xDD, 0xEE, 0xFF, 0xF1, 0x91,
        0x11,
    ]
}

fn no_lengths(_: u16) -> Option<usize> {
    None
}

fn read(
    car: &mut Car,
    dids: &[u16],
    length_of: impl Fn(u16) -> Option<usize>,
) -> Result<Result<DidsData, ReadError>, ReadDidsError> {
    read_dids(
        car,
        &Policy::read_only(),
        &transmission(),
        dids,
        length_of,
        TIMING,
    )
}

fn data(split: &[(u16, &[u8])], unsplit: &[u8]) -> DidsData {
    DidsData {
        split: split.iter().map(|&(did, d)| (did, d.to_vec())).collect(),
        unsplit: unsplit.to_vec(),
    }
}

fn undecodable(got: Result<Result<DidsData, ReadError>, ReadDidsError>) -> (ReplyError, Vec<u8>) {
    match got {
        Ok(Err(ReadError::Undecodable { error, reply })) => (error, reply),
        other => panic!("expected an undecodable reply, got {other:?}"),
    }
}

// ---- what is sent ------------------------------------------------------------------------

#[test]
fn sends_one_request_with_every_did_in_order() {
    let mut car = Car::saying(&reply());
    read(&mut car, &FOUR, lengths).unwrap().unwrap();
    assert_eq!(car.sent, ["7E1 22 F1 87 F1 88 F1 89 F1 91"]);
}

#[test]
fn one_did_and_the_most_are_sent_and_one_more_isnt() {
    let mut car = Car::saying(&[0x62, 0xF1, 0x00, 0x01]);
    read(&mut car, &[0xF100], no_lengths).unwrap().unwrap();
    assert_eq!(car.sent, ["7E1 22 F1 00"]);

    let most: Vec<u16> = (0..21).map(|n| 0xF100 + n).collect();
    assert_eq!(most.len(), MAX_DIDS);
    let mut car = Car::saying(&[0x62]);
    let _ = read(&mut car, &most, no_lengths).unwrap();
    // 1 + 2 * 21 bytes
    assert_eq!(car.sent[0].split_whitespace().count(), 1 + 1 + 2 * 21);

    let too_many: Vec<u16> = (0..22).map(|n| 0xF100 + n).collect();
    let mut car = Car::saying(&[0x62]);
    assert_eq!(
        read(&mut car, &too_many, no_lengths),
        Err(ReadDidsError::TooMany(22))
    );
    assert_eq!(car.sent.len(), 0);
}

#[test]
fn refuses_no_dids_and_a_repeated_did_before_sending() {
    let mut car = Car::saying(&reply());
    assert_eq!(read(&mut car, &[], lengths), Err(ReadDidsError::NoDids));
    assert_eq!(
        read(&mut car, &[0xF187, 0xF188, 0xF187], lengths),
        Err(ReadDidsError::Duplicate(0xF187))
    );
    // A DID 0 is a DID like any other.
    assert_eq!(
        read(&mut car, &[0x0000, 0x0000], lengths),
        Err(ReadDidsError::Duplicate(0x0000))
    );
    assert_eq!(car.sent.len(), 0);
}

#[test]
fn the_policy_decides_and_nothing_is_sent_when_it_refuses() {
    // A module the policy was narrowed away from.
    let policy = Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x710,
            reply: 0x77A,
        }])
        .unwrap();
    let mut car = Car::saying(&reply());
    let got = read_dids(&mut car, &policy, &transmission(), &FOUR, lengths, TIMING);
    assert_eq!(got, Err(ReadDidsError::Rejected(Rejection::WrongTarget)));
    assert_eq!(car.sent.len(), 0);

    // The broadcast has no one module's reply to check, and the policy refuses it for `22`.
    let broadcast = UdsModule {
        name: "all".into(),
        request_id: 0x7DF,
        response_id: 0x7E8,
    };
    let got = read_dids(
        &mut car,
        &Policy::read_only(),
        &broadcast,
        &FOUR,
        lengths,
        TIMING,
    );
    assert!(matches!(got, Err(ReadDidsError::Rejected(_))), "{got:?}");
    assert_eq!(car.sent.len(), 0);
}

#[test]
fn an_adapter_failure_is_an_error() {
    let mut car = Car::saying(&reply());
    car.fail = true;
    assert!(matches!(
        read(&mut car, &FOUR, lengths),
        Err(ReadDidsError::Transport(Error::Adapter(_)))
    ));
}

// ---- the reply -----------------------------------------------------------------------------

#[test]
fn splits_a_reply_when_every_length_is_known() {
    let mut car = Car::saying(&reply());
    assert_eq!(
        read(&mut car, &FOUR, lengths).unwrap().unwrap(),
        data(
            &[
                (0xF187, &[0xAA, 0xBB]),
                (0xF188, &[0xCC]),
                (0xF189, &[0xDD, 0xEE, 0xFF]),
                (0xF191, &[0x11]),
            ],
            &[]
        )
    );
}

#[test]
fn the_last_did_takes_the_rest_when_its_length_isnt_known() {
    let mut car = Car::saying(&reply());
    let only_first_three = |did| lengths(did).filter(|_| did != 0xF191);
    assert_eq!(
        read(&mut car, &FOUR, only_first_three).unwrap().unwrap(),
        data(
            &[
                (0xF187, &[0xAA, 0xBB]),
                (0xF188, &[0xCC]),
                (0xF189, &[0xDD, 0xEE, 0xFF]),
                (0xF191, &[0x11]),
            ],
            &[]
        )
    );
    // A single DID of unknown length is the whole reply.
    let mut car = Car::saying(&[0x62, 0xF1, 0x87, 0x01, 0x02, 0x03]);
    assert_eq!(
        read(&mut car, &[0xF187], no_lengths).unwrap().unwrap(),
        data(&[(0xF187, &[0x01, 0x02, 0x03])], &[])
    );
}

#[test]
fn the_rest_stays_whole_from_the_first_did_whose_length_isnt_known() {
    // F188's length is unknown and it isn't last, so where it ends can't be told.
    let mut car = Car::saying(&reply());
    let got = read(&mut car, &FOUR, |did| {
        lengths(did).filter(|_| did != 0xF188)
    })
    .unwrap();
    assert_eq!(
        got.unwrap(),
        data(
            &[(0xF187, &[0xAA, 0xBB])],
            &[
                0xF1, 0x88, 0xCC, 0xF1, 0x89, 0xDD, 0xEE, 0xFF, 0xF1, 0x91, 0x11
            ]
        )
    );
    // Nothing known: the whole reply, from the first echo.
    let mut car = Car::saying(&reply());
    assert_eq!(
        read(&mut car, &FOUR, no_lengths).unwrap().unwrap(),
        data(&[], &reply()[1..])
    );
    // A length of 0 isn't a length.
    let mut car = Car::saying(&reply());
    assert_eq!(
        read(&mut car, &FOUR, |_| Some(0)).unwrap().unwrap(),
        data(&[], &reply()[1..])
    );
}

#[test]
fn a_negative_reply_is_the_refusal_and_silence_is_no_reply() {
    let mut car = Car::saying(&[0x7F, 0x22, 0x31]);
    assert_eq!(
        read(&mut car, &FOUR, lengths).unwrap(),
        Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
            sid: 0x22,
            nrc: Nrc::RequestOutOfRange,
        })))
    );
    let mut car = Car::new(|_, _| Vec::new());
    assert_eq!(
        read(&mut car, &FOUR, lengths).unwrap(),
        Err(ReadError::NoReply)
    );
}

#[test]
fn a_reply_that_doesnt_fit_is_reported_with_its_bytes_and_not_trusted() {
    // A DID the module left out (ISO 14229-1 allows it): F188 is missing.
    let missing = vec![
        0x62, 0xF1, 0x87, 0xAA, 0xBB, 0xF1, 0x89, 0xDD, 0xEE, 0xFF, 0xF1, 0x91, 0x11,
    ];
    let mut car = Car::saying(&missing);
    let (error, bytes) = undecodable(read(&mut car, &FOUR, lengths));
    assert_eq!((error, bytes), (ReplyError::Malformed, missing));

    // Bytes left over after the last DID.
    let mut extra = reply();
    extra.push(0x00);
    let mut car = Car::saying(&extra);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, lengths)),
        (ReplyError::Malformed, extra)
    );

    // Short: the last DID's data is cut off, or the reply stops after an echo.
    for cut in [15, 14, 13, 5, 3] {
        let short = reply()[..cut].to_vec();
        let mut car = Car::saying(&short);
        let (error, bytes) = undecodable(read(&mut car, &FOUR, lengths));
        assert!(
            matches!(error, ReplyError::TooShort | ReplyError::Malformed),
            "cut at {cut}: {error}"
        );
        assert_eq!(bytes, short);
    }

    // Echoes out of the requested order.
    let swapped = vec![
        0x62, 0xF1, 0x88, 0xCC, 0xF1, 0x87, 0xAA, 0xBB, 0xF1, 0x89, 0xDD, 0xEE, 0xFF, 0xF1, 0x91,
        0x11,
    ];
    let mut car = Car::saying(&swapped);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, lengths)).0,
        ReplyError::Malformed
    );
}

#[test]
fn a_reply_with_no_lengths_is_still_checked_as_far_as_it_can_be() {
    // It must begin with the first DID's echo, and have room for every DID's echo and a data byte.
    let mut car = Car::saying(&[0x62, 0xF1, 0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, no_lengths)).0,
        ReplyError::Malformed
    );
    // 4 DIDs need at least 12 bytes after the 62.
    let short = vec![
        0x62, 0xF1, 0x87, 1, 0xF1, 0x88, 2, 0xF1, 0x89, 3, 0xF1, 0x91,
    ];
    let mut car = Car::saying(&short);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, no_lengths)).0,
        ReplyError::TooShort
    );
    // An echo with no data.
    let mut car = Car::saying(&[0x62, 0xF1, 0x87]);
    assert_eq!(
        undecodable(read(&mut car, &[0xF187], no_lengths)).0,
        ReplyError::TooShort
    );
    // `62` alone doesn't echo a DID, so it isn't an answer to this request at all.
    let mut car = Car::saying(&[0x62]);
    assert_eq!(
        read(&mut car, &FOUR, no_lengths).unwrap(),
        Err(ReadError::NoReply)
    );
}

#[test]
fn a_reply_to_another_service_isnt_this_ones() {
    let mut car = Car::saying(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]);
    // `exchange` waits for a reply to `22`, so this is silence.
    assert_eq!(
        read(&mut car, &FOUR, lengths).unwrap(),
        Err(ReadError::NoReply)
    );
}

// ---- any reply -----------------------------------------------------------------------------

proptest! {
    // However the module's bytes are, nothing panics, and a reply that is accepted is exactly
    // the echoes and data it was split into: nothing dropped, nothing made up.
    #[test]
    fn an_accepted_reply_is_reassembled_exactly(
        body in proptest::collection::vec(any::<u8>(), 0..48),
        positive in 0u8..4,
        known in proptest::collection::vec(proptest::option::of(0usize..5), 4),
    ) {
        let mut payload = if positive > 0 { vec![0x62] } else { Vec::new() };
        // Often begin as a real reply does, so the checks past the first echo run.
        if positive > 1 {
            payload.extend([0xF1, 0x87]);
        }
        payload.extend(body);
        let length_of = |did: u16| {
            FOUR.iter().position(|&d| d == did).and_then(|i| known[i])
        };
        let mut car = Car::saying(&payload);
        if let Ok(Ok(got)) = read(&mut car, &FOUR, length_of) {
            let mut again = vec![0x62];
            for (did, bytes) in &got.split {
                again.extend(did.to_be_bytes());
                again.extend(bytes);
                if let Some(length) = length_of(*did).filter(|&l| l > 0) {
                    prop_assert_eq!(bytes.len(), length);
                }
                prop_assert!(!bytes.is_empty());
            }
            again.extend(&got.unsplit);
            prop_assert_eq!(again, payload);
            if !got.unsplit.is_empty() {
                prop_assert_eq!(&got.unsplit[..2], &FOUR[got.split.len()].to_be_bytes());
            }
            // In request order, from the first DID.
            for (index, (did, _)) in got.split.iter().enumerate() {
                prop_assert_eq!(*did, FOUR[index]);
            }
        }
    }
}
