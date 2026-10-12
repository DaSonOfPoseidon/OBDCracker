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

#[test]
fn a_refusal_of_the_service_stops_the_sweep() {
    // Refusing `22` itself, not one DID, means nothing more will read in this session.
    for nrc in [0x11, 0x12, 0x13, 0x7F] {
        let mut car = Car::new(move |_, request| match request {
            [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
            [0x22, ..] => reply(&[0x7F, 0x22, nrc]),
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
        assert_eq!(got.found, [(0x0600, Ok(vec![0x12]))], "{nrc:02X}");
        assert_eq!(
            got.stop,
            Some(Stop {
                at: 0x0601,
                why: Why::Module(ReadError::Reply(ReplyError::Negative(NegativeResponse {
                    sid: 0x22,
                    nrc: Nrc::from(nrc),
                })))
            }),
            "{nrc:02X}"
        );
        assert_eq!(car.sent.len(), 2, "{nrc:02X}");
    }
}

#[test]
fn unanswered_dids_before_a_refusal_are_listed() {
    // 0x0601 goes unanswered once, then 0x0602 is refused as out of range: the module is still
    // there, so 0x0601 may be worth reading again. The refusal may be 0x0601's, so the sweep
    // stops at 0x0602.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, 0x01] => Vec::new(),
        [0x22, ..] => reply(&[0x7F, 0x22, 0x31]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0603,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0601, Err(ReadError::NoReply))]);
    assert_eq!(got.stop.map(|stop| stop.at), Some(0x0602));
}

#[test]
fn unanswered_dids_are_listed_or_resumed_never_lost() {
    // 0x0601 goes unanswered, then the adapter fails at 0x0602: resuming must read 0x0601 again.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
        _ => Vec::new(),
    });
    car.fail_at = Some(2);
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0610,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0600, Ok(vec![0x12]))]);
    assert_eq!(got.stop.map(|stop| stop.at), Some(0x0601));
    // Unanswered DIDs at the end of the range, fewer than QUIET_LIMIT, are listed.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0602,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(
        got.found,
        [
            (0x0600, Ok(vec![0x12])),
            (0x0601, Err(ReadError::NoReply)),
            (0x0602, Err(ReadError::NoReply)),
        ]
    );
    assert_eq!(got.stop, None);
    // Only 0x0600 answered.
    assert_eq!(got.answered(), 1);
}

#[test]
fn an_adapter_failure_leaving_the_session_outranks_a_module_stop() {
    // The module refuses `22` in the extended session, then `10 01` fails at the adapter: its
    // state is unknown, so that's the stop to report, at the same DID.
    let mut car = Car::new(|_, request| match request {
        [0x10, 0x03] => reply(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]),
        [0x22, ..] => reply(&[0x7F, 0x22, 0x7F]),
        _ => Vec::new(),
    });
    car.fail_at = Some(2);
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x06FF,
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0600,
            why: Why::Adapter(Error::Adapter("the adapter said BUFFER FULL".into()))
        })
    );
}

#[test]
fn a_refusal_right_after_an_unanswered_read_stops_the_sweep_there() {
    // 0x0600's late `7F 22 31` may arrive as 0x0601's answer, and a refusal doesn't name its
    // DID. Asking again could leave a reply queued for 0x0602, so the sweep stops at 0x0601:
    // resumed on a fresh connection, 0x0601 is asked first.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, 0x00] => Vec::new(),
        _ => reply(&[0x7F, 0x22, 0x31]),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0602,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0600, Err(ReadError::NoReply))]);
    let stop = got.stop.unwrap();
    assert_eq!(stop.at, 0x0601);
    assert!(matches!(stop.why, Why::Unmatched(ReadError::Reply(_))));
    assert_eq!(car.sent.len(), 2, "0x0602 isn't asked");
}

#[test]
fn a_module_stuck_on_response_pending_stops_the_sweep() {
    // Response-pending past the limit for every DID: as good as no answer.
    let mut car = Car::new(|_, request| match request {
        [0x22, ..] => std::iter::repeat_n(
            reply(&[0x7F, 0x22, 0x78]),
            usize::from(TIMING.max_pending) + 1,
        )
        .flatten()
        .collect(),
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
            at: 0x0600,
            why: Why::Module(ReadError::StillPending)
        })
    );
    assert_eq!(got.answered(), 0);
    assert_eq!(car.sent.len(), 3);
}

#[test]
fn a_busy_module_stops_the_sweep_at_that_did() {
    // `7F 22 21` asks to repeat the request later: not an answer, and asking the next DID at
    // once only keeps a busy module busy.
    let mut car = Car::new(|_, request| match request {
        [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
        [0x22, ..] => reply(&[0x7F, 0x22, 0x21]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0603,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0600, Ok(vec![0x12]))]);
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0601,
            why: Why::Module(ReadError::Reply(ReplyError::Negative(NegativeResponse {
                sid: 0x22,
                nrc: Nrc::BusyRepeatRequest,
            })))
        })
    );
    assert_eq!(car.sent.len(), 2);
}

#[test]
fn a_module_that_refuses_to_leave_the_extended_session_is_reported() {
    let mut car = Car::new(|_, request| match request {
        [0x10, 0x03] => reply(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]),
        [0x10, 0x01] => reply(&[0x7F, 0x10, 0x22]),
        [0x22, 0x06, 0x00] => reply(&[0x62, 0x06, 0x00, 0x12]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0600,
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0600, Ok(vec![0x12]))]);
    assert_eq!(got.stop, None);
    assert!(
        matches!(got.still_extended, Some(ReadError::SessionRefused(_))),
        "{:?}",
        got.still_extended
    );
}

#[test]
fn a_module_that_leaves_the_extended_session_is_not_still_in_it() {
    let got = sweep_dids(
        &mut car(),
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0601,
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(got.still_extended, None);
}

#[test]
fn an_unconfirmed_entry_and_leave_say_the_module_may_still_be_extended() {
    let mut car = Car::new(|_, request| match request {
        [0x10, 0x03] => reply(&[0x7F, 0x10, 0x22, 0x00]),
        [0x10, 0x01] => reply(&[0x7F, 0x10, 0x22]),
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
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0600,
            why: Why::Module(ReadError::NoReply)
        })
    );
    assert!(
        matches!(got.still_extended, Some(ReadError::SessionRefused(_))),
        "{:?}",
        got.still_extended
    );
}

#[test]
fn a_general_reject_is_listed_and_stops_the_sweep_after_it() {
    // `7F 22 10` gives no reason, so it may be every DID's answer: listing each would fill the
    // sweep with false finds. The DID is listed, and the sweep stops at the next one.
    let mut car = Car::new(|_, request| match request {
        [0x22, ..] => reply(&[0x7F, 0x22, 0x10]),
        _ => Vec::new(),
    });
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0600..=0x0603,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    let reject = ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x22,
        nrc: Nrc::GeneralReject,
    }));
    assert_eq!(got.found, [(0x0600, Err(reject))]);
    assert_eq!(
        got.stop,
        Some(Stop {
            at: 0x0601,
            why: Why::Module(reject)
        })
    );
    // At the end of the range there's nothing left to stop before.
    let got = sweep_dids(
        &mut car,
        &Policy::read_only(),
        &engine(),
        0x0603..=0x0603,
        TIMING,
        &SweepOptions::default(),
    )
    .unwrap();
    assert_eq!(got.found, [(0x0603, Err(reject))]);
    assert_eq!(got.stop, None);
}
