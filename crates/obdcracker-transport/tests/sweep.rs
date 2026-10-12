//! A read-only DID sweep: which DIDs a module answers, in which session, and how it stops.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, Policy};
use obdcracker_transport::fingerprint::{FingerprintError, ReadError, UdsModule};
use obdcracker_transport::sweep::{Stop, SweepOptions, Why, sweep_dids, sweep_dids_reporting};
use obdcracker_transport::{Error, Response, S3, SessionError, Timing, Transport, hex};
use proptest::prelude::*;

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

// Answers each request as it's sent, and records what was sent.
struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
    fail_at: Option<usize>,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
            fail_at: None,
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        if self.fail_at == Some(self.sent.len()) {
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

fn engine() -> UdsModule {
    UdsModule::obd_engine()
}

fn reply(payload: &[u8]) -> Vec<Response> {
    vec![Response {
        source: 0x7E8,
        payload: payload.to_vec(),
    }]
}

// An engine with 0600 (any session), 0601 (extended only) and 0602 (security access needed);
// everything else is out of range.
fn car() -> Car {
    let mut extended = false;
    Car::new(move |id, request| {
        if id != 0x7E0 {
            return Vec::new();
        }
        match request {
            [0x10, 0x03] => {
                extended = true;
                reply(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4])
            }
            [0x10, 0x01] => {
                extended = false;
                reply(&[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4])
            }
            [0x3E, 0x00] => reply(&[0x7E, 0x00]),
            [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
            [0x22, 0x06, 0x01] if extended => reply(&[0x62, 0x06, 0x01, 0x34, 0x56]),
            [0x22, 0x06, 0x02] => reply(&[0x7F, 0x22, 0x33]),
            [0x22, ..] => reply(&[0x7F, 0x22, 0x31]),
            _ => Vec::new(),
        }
    })
}

fn extended() -> SweepOptions {
    let mut options = SweepOptions::default();
    options.extended = Some(S3::default());
    options
}

#[test]
fn finds_what_answers_and_skips_what_is_out_of_range() {
    let mut car = car();
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x05FE..=0x0603,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(
        got.found,
        [
            (0x0600, Ok(vec![0x12])),
            // Refused for another reason than "out of range": it's there.
            (
                0x0602,
                Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
                    sid: 0x22,
                    nrc: Nrc::SecurityAccessDenied,
                })))
            ),
        ]
    );
    assert_eq!(got.stop, None);
    assert_eq!(
        car.sent,
        [
            "7E0 22 05 FE",
            "7E0 22 05 FF",
            "7E0 22 06 00",
            "7E0 22 06 01",
            "7E0 22 06 02",
            "7E0 22 06 03"
        ]
    );
}

#[test]
fn an_extended_sweep_reads_in_the_extended_session_and_leaves_it() {
    let mut car = car();
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0601,
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(
        got.found,
        [(0x0600, Ok(vec![0x12])), (0x0601, Ok(vec![0x34, 0x56]))]
    );
    assert_eq!(
        car.sent,
        ["7E0 10 03", "7E0 22 06 00", "7E0 22 06 01", "7E0 10 01"]
    );
}

#[test]
fn a_refused_session_stops_the_sweep_before_any_read() {
    let mut car = Car::new(|_, request| match request {
        [0x10, 0x03] => reply(&[0x7F, 0x10, 0x22]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0601,
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(got.found, []);
    assert!(
        matches!(
            got.stop,
            Some(Stop {
                at: 0x0600,
                why: Why::Module(ReadError::SessionRefused(_))
            })
        ),
        "{:?}",
        got.stop
    );
    assert_eq!(car.sent, ["7E0 10 03"]);
}

#[test]
fn a_module_that_goes_quiet_stops_the_sweep_where_it_can_resume() {
    // It answers up to 0x0602, then nothing: after 3 unanswered reads the sweep stops at the
    // first of them.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, low] if *low <= 0x02 => reply(&[0x7F, 0x22, 0x31]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x06FF,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0603,
            why: Why::Module(ReadError::NoReply)
        })
    );
    assert_eq!(car.sent.len(), 6);
}

#[test]
fn an_adapter_error_stops_the_sweep_but_keeps_what_it_found() {
    let mut car = car();
    car.fail_at = Some(3);
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0610,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found[0], (0x0600, Ok(vec![0x12])));
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0603,
            why: Why::Adapter(Error::Adapter("the adapter said BUFFER FULL".into()))
        })
    );
}

#[test]
fn reports_progress_after_each_did() {
    let mut car = car();
    let mut seen = Vec::new();
    sweep_dids_reporting(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0603,
        TIMING,
        &SweepOptions::default(),
        |did| seen.push(did),
    )
    .unwrap();
    assert_eq!(seen, [0x0600, 0x0601, 0x0602, 0x0603]);
}

#[test]
fn the_extended_session_needs_the_reply_id_before_anything_is_sent() {
    let mut car = car();
    let module = UdsModule {
        name: "instruments".into(),
        request_id: 0x714,
        response_id: 0x77E,
    };
    let err = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &module,
        0x0600..=0x0601,
        TIMING,
        &extended(),
    )
    .unwrap_err();
    assert_eq!(err, FingerprintError::Session(SessionError::UnknownReplyId));
    assert_eq!(car.sent, Vec::<String>::new());
}

proptest! {
    // Every DID in the range is asked for once, in order, and nothing past its end: no wrap at
    // 0xFFFF.
    #[test]
    fn asks_for_each_did_in_the_range_once(start in 0xFFC0u16..=0xFFFF, len in 0u16..64) {
        let end = start.saturating_add(len);
        let mut car = Car::new(|_, _| reply(&[0x7F, 0x22, 0x31]));
        sweep_dids(
            &mut car,
            &Policy::read_only(),
            &engine(),
            start..=end,
            TIMING,
            &SweepOptions::default(),
        )
        .unwrap();
        let want: Vec<String> = (start..=end)
            .map(|did| format!("7E0 22 {:02X} {:02X}", did >> 8, did & 0xFF))
            .collect();
        prop_assert_eq!(car.sent, want);
    }
}
