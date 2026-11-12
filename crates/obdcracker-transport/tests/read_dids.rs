//! One `22` request for several DIDs: what is sent, the bounds on the list, and a reply that is
//! checked exactly, never trusted.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::{ReadError, UdsModule};
use obdcracker_transport::read_dids::{DidsData, MAX_DIDS, ReadDidsError, check_dids, read_dids};
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
    with_left_out(split, &[], unsplit)
}

fn with_left_out(split: &[(u16, &[u8])], left_out: &[u16], unsplit: &[u8]) -> DidsData {
    DidsData {
        split: split.iter().map(|&(did, d)| (did, d.to_vec())).collect(),
        left_out: left_out.to_vec(),
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
fn a_list_can_be_checked_without_a_transport() {
    assert_eq!(check_dids(&[]), Err(ReadDidsError::NoDids));
    assert_eq!(check_dids(&[0xF187]), Ok(()));
    let most: Vec<u16> = (0..21).map(|n| 0xF100 + n).collect();
    assert_eq!(check_dids(&most), Ok(()));
    let too_many: Vec<u16> = (0..22).map(|n| 0xF100 + n).collect();
    assert_eq!(check_dids(&too_many), Err(ReadDidsError::TooMany(22)));
    assert_eq!(
        check_dids(&[0xF187, 0xF188, 0xF188]),
        Err(ReadDidsError::Duplicate(0xF188))
    );
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
    // Bytes left over after the last DID.
    let mut extra = reply();
    extra.push(0x00);
    let mut car = Car::saying(&extra);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, lengths)),
        (ReplyError::Malformed, extra)
    );

    // Short: the last DID's data is cut off, or the reply stops inside an echo or a DID's data.
    for cut in [15, 14, 4, 3] {
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
    // A reply that begins with an echo of no DID asked for isn't an answer to this request.
    let mut car = Car::saying(&[0x62, 0xF1, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(
        read(&mut car, &FOUR, no_lengths).unwrap(),
        Err(ReadError::NoReply)
    );
    // The first DID with no known length needs a data byte after its echo.
    let mut car = Car::saying(&[0x62, 0xF1, 0x87]);
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

// ---- a module leaves out the DIDs it doesn't support (ISO 14229-1, #332) ----------------------

// The A7's engine, TCU and gateway each answered `22 F187 F188 F189 F191` without F188.
const ENGINE: [u8; 33] = [
    0x62, 0xF1, 0x87, 0x34, 0x47, 0x30, 0x39, 0x30, 0x37, 0x34, 0x30, 0x31, 0x4E, 0x20, 0xF1, 0x89,
    0x30, 0x30, 0x31, 0x36, 0xF1, 0x91, 0x34, 0x47, 0x30, 0x39, 0x30, 0x37, 0x34, 0x30, 0x31, 0x45,
    0x20,
];
const TCU: [u8; 33] = [
    0x62, 0xF1, 0x87, 0x34, 0x47, 0x30, 0x39, 0x32, 0x37, 0x31, 0x35, 0x38, 0x51, 0x20, 0xF1, 0x89,
    0x31, 0x30, 0x30, 0x38, 0xF1, 0x91, 0x30, 0x42, 0x4B, 0x39, 0x32, 0x37, 0x31, 0x35, 0x36, 0x41,
    0x4D,
];
const GATEWAY: [u8; 33] = [
    0x62, 0xF1, 0x87, 0x34, 0x47, 0x30, 0x39, 0x30, 0x37, 0x34, 0x36, 0x38, 0x41, 0x44, 0xF1, 0x89,
    0x30, 0x30, 0x35, 0x30, 0xF1, 0x91, 0x34, 0x47, 0x30, 0x39, 0x30, 0x37, 0x34, 0x36, 0x38, 0x41,
    0x43,
];

// The profile's lengths on the A7: no F188, which is the DID every module left out.
fn a7_lengths(did: u16) -> Option<usize> {
    match did {
        0xF187 | 0xF191 => Some(11),
        0xF189 => Some(4),
        _ => None,
    }
}

#[test]
fn a_did_the_module_leaves_out_is_reported_not_malformed() {
    for (reply, f187, f189, f191) in [
        (&ENGINE, &ENGINE[3..14], &ENGINE[16..20], &ENGINE[22..]),
        (&TCU, &TCU[3..14], &TCU[16..20], &TCU[22..]),
        (&GATEWAY, &GATEWAY[3..14], &GATEWAY[16..20], &GATEWAY[22..]),
    ] {
        let mut car = Car::saying(reply);
        assert_eq!(
            read(&mut car, &FOUR, a7_lengths).unwrap().unwrap(),
            with_left_out(
                &[(0xF187, f187), (0xF189, f189), (0xF191, f191)],
                &[0xF188],
                &[]
            )
        );
    }
    // The same when the profile does give F188 a length: it is left out all the same.
    let mut car = Car::saying(&ENGINE);
    let with_f188 = |did| a7_lengths(did).or(if did == 0xF188 { Some(20) } else { None });
    assert_eq!(
        read(&mut car, &FOUR, with_f188).unwrap().unwrap().left_out,
        [0xF188]
    );
}

#[test]
fn a_did_with_no_length_matters_only_when_the_reply_has_it() {
    // F188 is the unknown one and isn't in the reply, so the rest splits.
    let mut car = Car::saying(&TCU);
    let got = read(&mut car, &FOUR, a7_lengths).unwrap().unwrap();
    assert_eq!(got.split.len(), 3);
    assert_eq!(got.unsplit, Vec::<u8>::new());
    // F189 is the unknown one and is in the reply, not last: from it on, nothing is split.
    let mut car = Car::saying(&TCU);
    let no_f189 = |did| a7_lengths(did).filter(|_| did != 0xF189);
    assert_eq!(
        read(&mut car, &FOUR, no_f189).unwrap().unwrap(),
        with_left_out(&[(0xF187, &TCU[3..14])], &[0xF188], &TCU[14..])
    );
}

// The DIDs a reply holds (echo and data), what they split into, and the DIDs it leaves out.
type Case<'a> = (&'a [&'a [u8]], &'a [(u16, &'a [u8])], &'a [u16]);

#[test]
fn any_dids_but_not_all_can_be_left_out() {
    let f187 = [0xF1, 0x87, 0xAA, 0xBB];
    let f188 = [0xF1, 0x88, 0xCC];
    let f189 = [0xF1, 0x89, 0xDD, 0xEE, 0xFF];
    let f191 = [0xF1, 0x91, 0x11];
    let cases: [Case; 6] = [
        // The first, the last, several in a row, and all but one.
        (
            &[&f188, &f189, &f191],
            &[
                (0xF188, &[0xCC]),
                (0xF189, &[0xDD, 0xEE, 0xFF]),
                (0xF191, &[0x11]),
            ],
            &[0xF187],
        ),
        (
            &[&f187, &f188, &f189],
            &[
                (0xF187, &[0xAA, 0xBB]),
                (0xF188, &[0xCC]),
                (0xF189, &[0xDD, 0xEE, 0xFF]),
            ],
            &[0xF191],
        ),
        (
            &[&f187, &f191],
            &[(0xF187, &[0xAA, 0xBB]), (0xF191, &[0x11])],
            &[0xF188, 0xF189],
        ),
        (
            &[&f187],
            &[(0xF187, &[0xAA, 0xBB])],
            &[0xF188, 0xF189, 0xF191],
        ),
        (&[&f191], &[(0xF191, &[0x11])], &[0xF187, 0xF188, 0xF189]),
        (
            &[&f189, &f191],
            &[(0xF189, &[0xDD, 0xEE, 0xFF]), (0xF191, &[0x11])],
            &[0xF187, 0xF188],
        ),
    ];
    for (present, split, left_out) in cases {
        let mut payload = vec![0x62];
        payload.extend(present.iter().flat_map(|did| did.iter().copied()));
        let mut car = Car::saying(&payload);
        assert_eq!(
            read(&mut car, &FOUR, lengths).unwrap().unwrap(),
            with_left_out(split, left_out, &[]),
            "{payload:02X?}"
        );
    }
}

#[test]
fn a_last_did_of_unknown_length_takes_the_rest_even_after_left_out_dids() {
    let mut car = Car::saying(&[0x62, 0xF1, 0x87, 0xAA, 0xBB, 0xF1, 0x91, 0x11, 0x22]);
    let last_unknown = |did| lengths(did).filter(|_| did != 0xF191);
    assert_eq!(
        read(&mut car, &FOUR, last_unknown).unwrap().unwrap(),
        with_left_out(
            &[(0xF187, &[0xAA, 0xBB]), (0xF191, &[0x11, 0x22])],
            &[0xF188, 0xF189],
            &[]
        )
    );
}

#[test]
fn the_unsplit_bytes_start_at_the_first_unknown_did_after_the_left_out_ones() {
    // F187 is left out and F188 has no length: F188's echo opens the unsplit bytes, and F189 and
    // F191 aren't claimed as left out because the bytes after F188's can't be read.
    let mut car = Car::saying(&[0x62, 0xF1, 0x88, 0xCC, 0xF1, 0x91, 0x11]);
    assert_eq!(
        read(&mut car, &FOUR, no_lengths).unwrap().unwrap(),
        with_left_out(&[], &[0xF187], &[0xF1, 0x88, 0xCC, 0xF1, 0x91, 0x11])
    );
    // The same after a split DID, and a DID that is last takes the rest.
    let only_f187 = |did| lengths(did).filter(|_| did == 0xF187);
    let mut car = Car::saying(&[
        0x62, 0xF1, 0x87, 0xAA, 0xBB, 0xF1, 0x89, 0xDD, 0xF1, 0x91, 0x11,
    ]);
    assert_eq!(
        read(&mut car, &FOUR, only_f187).unwrap().unwrap(),
        with_left_out(
            &[(0xF187, &[0xAA, 0xBB])],
            &[0xF188],
            &[0xF1, 0x89, 0xDD, 0xF1, 0x91, 0x11]
        )
    );
    // An unknown-length DID still needs a data byte after its echo.
    let mut car = Car::saying(&[0x62, 0xF1, 0x88]);
    assert_eq!(
        undecodable(read(&mut car, &FOUR, no_lengths)).0,
        ReplyError::TooShort
    );
}

#[test]
fn a_reply_that_leaves_out_every_did_is_not_an_answer() {
    // A module with none of the DIDs says `7F 22 31`, so `62` alone, or cut inside an echo, is
    // never a success.
    for payload in [&[0x62][..], &[0x62, 0xF1][..]] {
        let mut car = Car::saying(payload);
        let got = read(&mut car, &FOUR, lengths).unwrap();
        assert!(got.is_err(), "{payload:02X?}: {got:?}");
    }
}

#[test]
fn left_out_dids_dont_loosen_the_echo_the_order_or_the_end() {
    let f187 = [0xF1, 0x87, 0xAA, 0xBB];
    let f189 = [0xF1, 0x89, 0xDD, 0xEE, 0xFF];
    let cases: [(&str, Vec<u8>); 5] = [
        ("out of order", [&[0x62][..], &f189, &f187].concat()),
        ("repeated", [&[0x62][..], &f187, &f187].concat()),
        (
            "not asked for",
            [&[0x62][..], &f187, &[0xF1, 0x00, 0x01]].concat(),
        ),
        (
            "leftover after the last DID",
            [&[0x62][..], &f187, &f189, &[0xF1, 0x91, 0x11, 0x00]].concat(),
        ),
        (
            "leftover after an early end",
            [&[0x62][..], &f187, &[0x00]].concat(),
        ),
    ];
    for (what, payload) in cases {
        let mut car = Car::saying(&payload);
        let got = read(&mut car, &FOUR, lengths).unwrap();
        assert!(
            matches!(got, Err(ReadError::Undecodable { .. })),
            "{what}: {got:?}"
        );
    }
    // A leftover byte after an early end is a 1-byte echo, which is short; the others are wrong.
    let mut car = Car::saying(&[&[0x62][..], &f187, &[0x00]].concat());
    assert_eq!(
        undecodable(read(&mut car, &FOUR, lengths)).0,
        ReplyError::TooShort
    );
    let mut car = Car::saying(&[&[0x62][..], &f189, &f187].concat());
    assert_eq!(
        undecodable(read(&mut car, &FOUR, lengths)).0,
        ReplyError::Malformed
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

// A DID's place in the request.
fn place(did: u16) -> usize {
    FOUR.iter().position(|&d| d == did).unwrap()
}

proptest! {
    // However the module's bytes are, nothing panics, and a reply that is accepted is exactly
    // the echoes and data it was split into: nothing dropped, nothing made up. Every DID asked
    // for is split, left out, or in the unsplit bytes, once, in request order.
    #[test]
    fn an_accepted_reply_is_reassembled_exactly(
        body in proptest::collection::vec(any::<u8>(), 0..48),
        positive in 0u8..4,
        first in 0usize..4,
        known in proptest::collection::vec(proptest::option::of(0usize..5), 4),
    ) {
        let mut payload = if positive > 0 { vec![0x62] } else { Vec::new() };
        // Often begin as a real reply does, so the checks past the first echo run.
        if positive > 1 {
            payload.extend(FOUR[first].to_be_bytes());
        }
        payload.extend(body);
        let length_of = |did: u16| known[place(did)];
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

            let split: Vec<u16> = got.split.iter().map(|(did, _)| *did).collect();
            prop_assert!(split.windows(2).all(|w| place(w[0]) < place(w[1])));
            prop_assert!(got.left_out.windows(2).all(|w| place(w[0]) < place(w[1])));
            let mut named = [split, got.left_out.clone()].concat();
            named.sort_by_key(|&did| place(did));
            // Nothing is both, and what's named is the DIDs from the first one on, with no gap.
            prop_assert_eq!(&named[..], &FOUR[..named.len()]);
            if got.unsplit.is_empty() {
                prop_assert_eq!(named.len(), FOUR.len());
                prop_assert!(!got.split.is_empty());
            } else {
                // The unsplit bytes open with the echo of the first DID not named, whose length
                // isn't known, and a data byte.
                let next = FOUR[named.len()];
                prop_assert_eq!(&got.unsplit[..2], &next.to_be_bytes());
                prop_assert!(got.unsplit.len() >= 3);
                prop_assert!(length_of(next).is_none_or(|l| l == 0));
            }
        }
    }

    // A reply that holds any non-empty subset of the DIDs, in order, with every length known,
    // splits into exactly those DIDs, and the others are left out.
    #[test]
    fn any_subset_of_the_dids_can_be_left_out(
        mask in 1u8..16,
        data in proptest::collection::vec(any::<u8>(), 4 * 4),
    ) {
        let length = |did: u16| 1 + place(did);
        let mut payload = vec![0x62];
        let mut split = Vec::new();
        let mut left_out = Vec::new();
        for (index, &did) in FOUR.iter().enumerate() {
            if mask >> index & 1 == 1 {
                let bytes = data[index * 4..index * 4 + length(did)].to_vec();
                payload.extend(did.to_be_bytes());
                payload.extend(&bytes);
                split.push((did, bytes));
            } else {
                left_out.push(did);
            }
        }
        let mut car = Car::saying(&payload);
        let got = read(&mut car, &FOUR, |did| Some(length(did))).unwrap().unwrap();
        prop_assert_eq!(got, DidsData { split, left_out, unsplit: Vec::new() });
    }
}
