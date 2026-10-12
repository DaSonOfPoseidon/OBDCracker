//! `ExtendedSession` against a module that refuses or answers oddly. The simulated A7's tests
//! (`obdcracker-sim/tests/session.rs`) cover S3 itself.

use std::thread::sleep;
use std::time::Duration;

use obdcracker_safety::{Policy, Target};
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
    assert_eq!(
        error,
        SessionError::Transport(obdcracker_transport::Error::Timeout)
    );
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
    assert_eq!(
        error,
        SessionError::Transport(obdcracker_transport::Error::Timeout)
    );
    assert_eq!(sent(&adapter), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

// A module whose every reply takes `delay` to arrive.
struct Slow {
    inner: Mock,
    delay: Duration,
}

impl obdcracker_transport::Transport for Slow {
    fn send(
        &mut self,
        request: &obdcracker_safety::Approved,
    ) -> Result<(), obdcracker_transport::Error> {
        self.inner.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, obdcracker_transport::Error> {
        sleep(self.delay);
        self.inner.recv(timeout)
    }
}

#[test]
fn a_long_response_pending_wait_does_not_lapse_the_session() {
    // Response-pending replies keep the module's session alive (ISO 14229-2), so a read that
    // takes longer than S3 to answer needs no new `10 03` afterwards.
    let short = S3 {
        keepalive: Duration::from_millis(40),
        timeout: Duration::from_millis(120),
    };
    let patient = Timing {
        p2: Duration::from_millis(500),
        p2_star: Duration::from_millis(500),
        max_pending: 3,
    };
    let mut adapter = Slow {
        inner: mock(&[
            &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
            &[0x7F, 0x22, 0x78],
            &[0x7F, 0x22, 0x78],
            &[0x62, 0xF1, 0x87, 0x41],
            &[0x62, 0xF1, 0x87, 0x41],
        ]),
        delay: Duration::from_millis(60),
    };
    let read = Policy::read_only()
        .approve(ENGINE, &[0x22, 0xF1, 0x87])
        .unwrap();
    let mut guard =
        ExtendedSession::enter(&mut adapter, &Policy::read_only(), ENGINE, patient, short).unwrap();
    // About 180 ms from the request to the answer, longer than S3.
    guard.exchange(&read).unwrap();
    guard.exchange(&read).unwrap();
    drop(guard);
    let sent: Vec<Vec<u8>> = adapter
        .inner
        .sent()
        .iter()
        .map(|r| r.payload().to_vec())
        .collect();
    assert_eq!(
        sent,
        [
            vec![0x10, 0x03],
            vec![0x22, 0xF1, 0x87],
            vec![0x22, 0xF1, 0x87],
            vec![0x10, 0x01]
        ]
    );
}
