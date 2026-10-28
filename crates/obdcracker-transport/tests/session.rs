//! `ExtendedSession` against a module that refuses or answers oddly. The simulated A7's tests
//! (`obdcracker-sim/tests/session.rs`) cover S3 itself.

use std::thread::sleep;
use std::time::Duration;

use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_transport::{ExtendedSession, Mock, Response, S3, SessionError, Timing};

const ENGINE: Target = Target::Physical(0x7E0);
const FAST: Timing = Timing {
    p2: Duration::from_millis(20),
    p2_star: Duration::from_millis(40),
    max_pending: 3,
};
const GUARD: S3 = S3 {
    keepalive: Duration::from_millis(50),
    timeout: Duration::from_secs(5),
};

fn mock(replies: &[&[u8]]) -> Mock {
    let mut mock = Mock::default();
    for payload in replies {
        mock.queue(Response {
            source: 0x7E8,
            payload: payload.to_vec(),
        });
    }
    mock
}

fn timeout() -> SessionError {
    SessionError::Transport(obdcracker_transport::Error::Timeout)
}

// `entry`, then no answer to `10 01`.
fn unconfirmed(entry: SessionError) -> SessionError {
    SessionError::Unconfirmed {
        entry: Box::new(entry),
        leave: Box::new(timeout()),
    }
}

fn sent(mock: &Mock) -> Vec<Vec<u8>> {
    mock.sent().iter().map(|r| r.payload().to_vec()).collect()
}

#[test]
fn a_refused_session_change_is_reported_and_not_left() {
    let mut adapter = mock(&[&[0x7F, 0x10, 0x22]]);
    let error = ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD)
        .unwrap_err();
    assert_eq!(error, SessionError::Refused(vec![0x7F, 0x10, 0x22]));
    // The module never left the default session, so nothing returns it there.
    assert_eq!(sent(&adapter), [vec![0x10, 0x03]]);
}

#[test]
fn a_refused_tester_present_is_reported() {
    let mut adapter = mock(&[&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4], &[0x7F, 0x3E, 0x22]]);
    let mut guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    sleep(Duration::from_millis(80));
    assert_eq!(
        guard.keep_alive(),
        Err(SessionError::Refused(vec![0x7F, 0x3E, 0x22]))
    );
}

#[test]
fn a_session_change_to_another_session_is_refused() {
    // `50 01` answers `10 01`, not `10 03`, so exchange drops it as a reply to something else.
    let mut adapter = mock(&[&[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4]]);
    let error = ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD)
        .unwrap_err();
    // Nor does anything answer `10 01`, so the module may be in the extended session.
    assert_eq!(error, unconfirmed(timeout()));
}

#[test]
fn the_end_reports_a_refused_return_to_the_default_session() {
    let mut adapter = mock(&[&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4], &[0x7F, 0x10, 0x22]]);
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    assert_eq!(
        guard.end(),
        Err(SessionError::Refused(vec![0x7F, 0x10, 0x22]))
    );
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn a_refused_reentry_is_tried_again_rather_than_kept_alive() {
    let short = S3 {
        keepalive: Duration::from_millis(30),
        timeout: Duration::from_millis(60),
    };
    let mut adapter = mock(&[
        &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
        &[0x7F, 0x10, 0x22],
        &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
    ]);
    let mut guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, short).unwrap();
    sleep(Duration::from_millis(100));
    assert_eq!(
        guard.keep_alive(),
        Err(SessionError::Refused(vec![0x7F, 0x10, 0x22]))
    );
    // The module is still in the default session: TesterPresent would keep it there.
    guard.keep_alive().unwrap();
    drop(guard);
    assert_eq!(
        sent(&adapter),
        [
            vec![0x10, 0x03],
            vec![0x10, 0x03],
            vec![0x10, 0x03],
            vec![0x10, 0x01]
        ]
    );
}

#[test]
fn a_malformed_refusal_counts_as_no_answer_and_is_left() {
    // `exchange` drops a refusal with a trailing byte, so the module may have switched: leave.
    let mut adapter = mock(&[&[0x7F, 0x10, 0x22, 0x00]]);
    let error = ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD)
        .unwrap_err();
    // Nor does anything answer `10 01`, so the module may be in the extended session.
    assert_eq!(error, unconfirmed(timeout()));
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

struct Slow {
    inner: Mock,
    delays: std::collections::VecDeque<Duration>,
}

fn slow(replies: &[(u64, &[u8])]) -> Slow {
    Slow {
        inner: mock(&replies.iter().map(|&(_, r)| r).collect::<Vec<_>>()),
        delays: replies
            .iter()
            .map(|&(ms, _)| Duration::from_millis(ms))
            .collect(),
    }
}

impl obdcracker_transport::Transport for Slow {
    fn send(
        &mut self,
        request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        self.inner.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        sleep(self.delays.pop_front().unwrap_or_default());
        self.inner.recv(timeout)
    }
}

const PATIENT: Timing = Timing {
    p2: Duration::from_millis(500),
    p2_star: Duration::from_millis(500),
    max_pending: 3,
};

#[test]
fn a_wait_longer_than_the_margin_is_followed_by_a_new_10_03() {
    // The module restarted S3 somewhere between the request and the answer reaching us: an ELM
    // can spend seconds printing a long answer. Only the request's time is safe, so after a
    // slow answer the guard enters the session again before the next request.
    let short = S3 {
        keepalive: Duration::from_millis(40),
        timeout: Duration::from_millis(120),
    };
    let positive_entry: &[u8] = &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4];
    let mut adapter = slow(&[
        (0, positive_entry),
        (60, &[0x7F, 0x22, 0x78]),
        (60, &[0x7F, 0x22, 0x78]),
        (60, &[0x62, 0xF1, 0x87, 0x41]),
        (0, positive_entry),
        (0, &[0x62, 0xF1, 0x87, 0x41]),
    ]);
    let read = Policy::read_only()
        .approve(Protocol::Uds, ENGINE, &[0x22, 0xF1, 0x87])
        .unwrap();
    let mut guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, PATIENT, short).unwrap();
    // About 180 ms from the request to the answer, longer than S3.
    guard.exchange(&read).unwrap();
    guard.exchange(&read).unwrap();
    drop(guard);
    assert_eq!(
        sent(&adapter.inner),
        [
            vec![0x10, 0x03],
            vec![0x22, 0xF1, 0x87],
            vec![0x10, 0x03],
            vec![0x22, 0xF1, 0x87],
            vec![0x10, 0x01]
        ]
    );
}

#[test]
fn the_timing_the_module_gives_is_used() {
    // The module says P2 is 200 ms in the extended session; the caller's P2 assumed 50 ms.
    let base = Timing {
        p2: Duration::from_millis(50),
        p2_star: Duration::from_millis(500),
        max_pending: 3,
    };
    let mut adapter = slow(&[
        (0, &[0x50, 0x03, 0x00, 0xC8, 0x01, 0xF4]),
        (120, &[0x62, 0xF1, 0x87, 0x41]),
    ]);
    let read = Policy::read_only()
        .approve(Protocol::Uds, ENGINE, &[0x22, 0xF1, 0x87])
        .unwrap();
    let mut guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, base, GUARD).unwrap();
    assert_eq!(
        guard.exchange(&read).unwrap().payload,
        [0x62, 0xF1, 0x87, 0x41]
    );
}

#[test]
fn an_unanswered_end_is_tried_once_more() {
    // `end` consumes the guard, so the caller can't retry; `end` tries `10 01` once more itself.
    let mut adapter = mock(&[&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]]);
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    assert_eq!(guard.end(), Err(SessionError::Retried(Box::new(timeout()))));
    assert_eq!(
        sent(&adapter),
        [vec![0x10, 0x03], vec![0x10, 0x01], vec![0x10, 0x01]]
    );
}

// Confirms `10 03`, and every `10 01` but the first, which it answers only after the tester has
// given up on it: the late `50 01` then answers the retry, and the retry's own stays queued.
#[derive(Debug, Default)]
struct LateLeave {
    sent: Vec<Vec<u8>>,
    replies: std::collections::VecDeque<Response>,
}

impl obdcracker_transport::Transport for LateLeave {
    fn send(
        &mut self,
        request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        self.sent.push(request.payload().to_vec());
        let answers = match request.payload() {
            [0x10, 0x03] => vec![vec![0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]],
            [0x10, 0x01] if self.sent.len() == 2 => Vec::new(),
            _ => vec![vec![0x50, 0x01, 0x00, 0x32, 0x01, 0xF4]; 2],
        };
        self.replies
            .extend(answers.into_iter().map(|payload| Response {
                source: 0x7E8,
                payload,
            }));
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        self.replies
            .pop_front()
            .ok_or(obdcracker_transport::Error::Timeout)
    }
}

#[test]
fn a_retried_end_says_replies_may_be_out_of_step() {
    let mut adapter = LateLeave::default();
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    assert!(guard.end().unwrap().out_of_step);
    assert_eq!(
        adapter.sent,
        [vec![0x10, 0x03], vec![0x10, 0x01], vec![0x10, 0x01]]
    );
}

#[test]
fn an_end_answered_at_once_is_in_step() {
    let mut adapter = mock(&[
        &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
        &[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4],
    ]);
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    assert!(!guard.end().unwrap().out_of_step);
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn a_bare_positive_entry_is_accepted() {
    // Older servers answer `50 03` without the timing; the caller's timing is kept.
    let mut adapter = mock(&[&[0x50, 0x03]]);
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    drop(guard);
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn a_malformed_positive_entry_is_refused_and_left() {
    let mut adapter = mock(&[&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4, 0x00]]);
    let error = ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD)
        .unwrap_err();
    assert_eq!(
        error,
        unconfirmed(SessionError::Refused(vec![
            0x50, 0x03, 0x00, 0x32, 0x01, 0xF4, 0x00
        ]))
    );
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[derive(Debug, Default)]
struct FailsAfterOne {
    sent: usize,
}

impl obdcracker_transport::Transport for FailsAfterOne {
    fn send(
        &mut self,
        _request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        self.sent += 1;
        if self.sent > 1 {
            return Err(obdcracker_transport::Error::Adapter(
                "the adapter said BUFFER FULL".to_owned(),
            ));
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        Err(obdcracker_transport::Error::Timeout)
    }
}

#[test]
fn an_adapter_failure_leaving_after_an_unanswered_entry_is_reported() {
    // `10 03` goes unanswered, so the module may have switched; `10 01` then fails in the
    // adapter, whose state is now unknown. That matters more than the missing answer.
    let mut adapter = FailsAfterOne::default();
    let error = ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD)
        .unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Transport(obdcracker_transport::Error::Adapter(_))
        ),
        "{error:?}"
    );
    assert_eq!(adapter.sent, 2);
}

// Confirms `10 03`, answers nothing else, and fails as an adapter does from the third request on.
#[derive(Debug, Default)]
struct FailsOnRetry {
    sent: Vec<Vec<u8>>,
    replies: Vec<Response>,
}

impl obdcracker_transport::Transport for FailsOnRetry {
    fn send(
        &mut self,
        request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        if self.sent.len() == 2 {
            return Err(obdcracker_transport::Error::Adapter(
                "the adapter said BUFFER FULL".to_owned(),
            ));
        }
        self.sent.push(request.payload().to_vec());
        if request.payload() == [0x10, 0x03] {
            self.replies.push(Response {
                source: 0x7E8,
                payload: vec![0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
            });
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        self.replies
            .pop()
            .ok_or(obdcracker_transport::Error::Timeout)
    }
}

#[test]
fn an_adapter_failure_retrying_the_end_is_reported() {
    // `10 01` goes unanswered, and trying it again fails in the adapter, whose state is now
    // unknown: `end` reports that, and nothing is left for dropping the guard to send.
    let mut adapter = FailsOnRetry::default();
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    let error = guard.end().unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Transport(obdcracker_transport::Error::Adapter(_))
        ),
        "{error:?}"
    );
    assert_eq!(adapter.sent, [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

// Confirms every session request, but fails as an adapter does on the second one sent.
#[derive(Debug, Default)]
struct FailsOnce {
    sent: Vec<Vec<u8>>,
    replies: Vec<Response>,
}

impl obdcracker_transport::Transport for FailsOnce {
    fn send(
        &mut self,
        request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        self.sent.push(request.payload().to_vec());
        if self.sent.len() == 2 {
            return Err(obdcracker_transport::Error::Adapter(
                "the adapter said BUFFER FULL".to_owned(),
            ));
        }
        let mut payload = vec![0x50, request.payload()[1]];
        payload.extend([0x00, 0x32, 0x01, 0xF4]);
        self.replies.push(Response {
            source: 0x7E8,
            payload,
        });
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        self.replies
            .pop()
            .ok_or(obdcracker_transport::Error::Timeout)
    }
}

#[test]
fn an_adapter_failure_leaving_is_reported_even_if_the_retry_works() {
    // The adapter failed, so its state is unknown, however the retry went.
    let mut adapter = FailsOnce::default();
    let guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, FAST, GUARD).unwrap();
    let error = guard.end().unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Transport(obdcracker_transport::Error::Adapter(_))
        ),
        "{error:?}"
    );
    assert_eq!(
        adapter.sent,
        [vec![0x10, 0x03], vec![0x10, 0x01], vec![0x10, 0x01]]
    );
}
