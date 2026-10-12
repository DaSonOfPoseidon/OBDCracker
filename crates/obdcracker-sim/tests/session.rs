//! The extended diagnostic session on the simulated A7: S3 lapses it, and `ExtendedSession` keeps
//! it alive and returns the module to the default session.

use std::thread::sleep;
use std::time::Duration;

use obdcracker_core::response::Nrc;
use obdcracker_core::uds;
use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Target};
use obdcracker_sim::{Session, SimBus};
use obdcracker_transport::{Error, Expect, ExtendedSession, S3, SessionError, Timing, exchange};

const ENGINE: Target = Target::Physical(0x7E0);
const CODING: u16 = 0x0600;
// Short enough for tests, with margins of tens of milliseconds either side of each deadline.
const SIM_S3: Duration = Duration::from_millis(300);
const GUARD: S3 = S3 {
    keepalive: Duration::from_millis(100),
    timeout: SIM_S3,
};

// The engine with a coding DID that only the extended session can read.
fn car() -> SimBus {
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0x0600\n\
                   hex = \"01 02 03 04 05 06 07 08 09 0A\"\nsession = \"extended\"\n";
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap();
    bus.ecu_mut("engine").unwrap().set_s3(SIM_S3);
    bus
}

fn ask(bus: &mut SimBus, payload: &[u8]) -> Vec<u8> {
    let request = Policy::read_only().approve(ENGINE, payload).unwrap();
    exchange(bus, &request, Expect::Module(0x7E8), Timing::default())
        .unwrap()
        .remove(0)
        .payload
}

fn session(bus: &SimBus) -> Session {
    bus.ecu("engine").unwrap().session()
}

// Every request sent to the engine so far, as bytes.
fn sent(bus: &SimBus) -> Vec<Vec<u8>> {
    bus.sent().iter().map(|r| r.payload().to_vec()).collect()
}

#[test]
fn extended_session_lapses_after_s3_without_a_request() {
    let mut bus = car();
    ask(&mut bus, &[0x10, 0x03]);
    sleep(SIM_S3 + Duration::from_millis(100));
    assert_eq!(session(&bus), Session::Default);
    let reply = ask(&mut bus, &uds::read_did(CODING));
    assert_eq!(reply, [0x7F, 0x22, Nrc::RequestOutOfRange.code()]);
}

#[test]
fn each_request_restarts_s3() {
    let mut bus = car();
    ask(&mut bus, &[0x10, 0x03]);
    for _ in 0..3 {
        sleep(Duration::from_millis(150));
        assert_eq!(ask(&mut bus, &[0x3E, 0x00]), [0x7E, 0x00]);
    }
    // 450 ms after entering, longer than S3, but never 300 ms without a request.
    assert_eq!(session(&bus), Session::Extended);
    assert!(uds::decode_did(&ask(&mut bus, &uds::read_did(CODING)), CODING).is_ok());
}

#[test]
fn guard_enters_the_extended_session() {
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    let read = Policy::read_only()
        .approve(ENGINE, &uds::read_did(CODING))
        .unwrap();
    let reply = guard.exchange(&read).unwrap();
    assert!(uds::decode_did(&reply.payload, CODING).is_ok());
    drop(guard);
    assert_eq!(sent(&bus)[0], [0x10, 0x03]);
}

#[test]
fn guard_keeps_the_session_alive_with_tester_present() {
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    for _ in 0..3 {
        sleep(Duration::from_millis(150));
        guard.keep_alive().unwrap();
    }
    let read = Policy::read_only()
        .approve(ENGINE, &uds::read_did(CODING))
        .unwrap();
    assert!(uds::decode_did(&guard.exchange(&read).unwrap().payload, CODING).is_ok());
    drop(guard);
    // `3E 00`, not `3E 80`: an ELM waits out its whole timeout for a suppressed reply.
    assert_eq!(
        sent(&bus)[..5],
        [
            vec![0x10, 0x03],
            vec![0x3E, 0x00],
            vec![0x3E, 0x00],
            vec![0x3E, 0x00],
            uds::read_did(CODING).to_vec(),
        ]
    );
}

#[test]
fn keep_alive_sends_nothing_until_it_is_due() {
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    guard.keep_alive().unwrap();
    guard.keep_alive().unwrap();
    drop(guard);
    assert_eq!(sent(&bus), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn guard_reenters_a_session_that_lapsed() {
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    sleep(SIM_S3 + Duration::from_millis(100));
    let read = Policy::read_only()
        .approve(ENGINE, &uds::read_did(CODING))
        .unwrap();
    assert!(uds::decode_did(&guard.exchange(&read).unwrap().payload, CODING).is_ok());

    // keep_alive re-enters too, rather than sending TesterPresent to a module in the default
    // session, which would answer it and stay there.
    sleep(SIM_S3 + Duration::from_millis(100));
    guard.keep_alive().unwrap();
    drop(guard);
    assert_eq!(
        sent(&bus),
        [
            vec![0x10, 0x03],
            vec![0x10, 0x03],
            uds::read_did(CODING).to_vec(),
            vec![0x10, 0x03],
            vec![0x10, 0x01],
        ]
    );
}

#[test]
fn dropping_the_guard_returns_to_the_default_session() {
    let mut bus = car();
    let guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    drop(guard);
    assert_eq!(session(&bus), Session::Default);
    assert_eq!(sent(&bus).last().unwrap(), &[0x10, 0x01]);
}

#[test]
fn ending_the_guard_returns_to_the_default_session_once() {
    let mut bus = car();
    let guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    guard.end().unwrap();
    assert_eq!(session(&bus), Session::Default);
    assert_eq!(sent(&bus), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn guard_refuses_requests_for_another_module() {
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    let other = Policy::read_only()
        .approve(Target::Physical(0x7E1), &uds::read_did(0xF190))
        .unwrap();
    assert_eq!(guard.exchange(&other), Err(SessionError::WrongTarget));
    drop(guard);
    assert!(!sent(&bus).contains(&uds::read_did(0xF190).to_vec()));
}

#[test]
fn guard_needs_the_modules_reply_id() {
    // The gateway's reply ID is only known once the policy is narrowed to the A7's modules.
    let mut bus = car();
    let gateway = Target::Physical(0x710);
    let error = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        gateway,
        Timing::default(),
        GUARD,
    )
    .unwrap_err();
    assert_eq!(error, SessionError::UnknownReplyId);
    assert_eq!(bus.sent(), []);
}

#[test]
fn guard_reports_a_module_that_does_not_answer() {
    let mut bus = car();
    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(obdcracker_sim::Fault::Silent));
    let error = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap_err();
    assert_eq!(error, SessionError::Transport(Error::Timeout));
}

#[test]
fn guard_refuses_session_changes_it_does_not_make() {
    // The guard tracks the session itself; a `10 01` sent through it would leave a keepalive
    // holding the module in the default session.
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    for payload in [[0x10, 0x01], [0x10, 0x03], [0x10, 0x81]] {
        let request = Policy::read_only().approve(ENGINE, &payload).unwrap();
        assert_eq!(guard.exchange(&request), Err(SessionError::SessionChange));
    }
    drop(guard);
    assert_eq!(sent(&bus), [vec![0x10, 0x03], vec![0x10, 0x01]]);
}

#[test]
fn a_longer_s3_does_not_revive_a_lapsed_session() {
    let mut bus = car();
    ask(&mut bus, &[0x10, 0x03]);
    sleep(SIM_S3 + Duration::from_millis(100));
    bus.ecu_mut("engine")
        .unwrap()
        .set_s3(Duration::from_secs(60));
    assert_eq!(session(&bus), Session::Default);
}

#[test]
fn guard_leaves_a_session_whose_entry_went_unanswered() {
    // The silent module still switches session; only its reply is lost, so `10 03` may have
    // taken effect and the guard sends `10 01` anyway.
    let mut bus = car();
    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(obdcracker_sim::Fault::Silent));
    let error = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap_err();
    assert_eq!(error, SessionError::Transport(Error::Timeout));
    assert_eq!(sent(&bus), [vec![0x10, 0x03], vec![0x10, 0x01]]);
    assert_eq!(session(&bus), Session::Default);
}

#[test]
fn guard_leaves_a_session_whose_entry_got_a_reply_to_something_else() {
    // `Fault::WrongSid` switches session, then answers for another service.
    let mut bus = car();
    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(obdcracker_sim::Fault::WrongSid));
    assert!(
        ExtendedSession::enter(
            &mut bus,
            &Policy::read_only(),
            ENGINE,
            Timing::default(),
            GUARD
        )
        .is_err()
    );
    assert_eq!(sent(&bus).last().unwrap(), &[0x10, 0x01]);
    assert_eq!(session(&bus), Session::Default);
}

#[test]
fn keep_alive_close_to_s3_reenters_instead() {
    // 250 ms idle is under S3 (300 ms), but a `3E 00` could arrive after it, and a module in the
    // default session answers TesterPresent too. Past the margin, the guard enters again.
    let mut bus = car();
    let mut guard = ExtendedSession::enter(
        &mut bus,
        &Policy::read_only(),
        ENGINE,
        Timing::default(),
        GUARD,
    )
    .unwrap();
    sleep(Duration::from_millis(250));
    guard.keep_alive().unwrap();
    drop(guard);
    assert_eq!(
        sent(&bus),
        [vec![0x10, 0x03], vec![0x10, 0x03], vec![0x10, 0x01]]
    );
}
