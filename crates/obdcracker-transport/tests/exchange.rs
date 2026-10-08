//! Sending one request and collecting its replies.

use std::time::{Duration, Instant};

use obdcracker_safety::{Approved, Policy, Target};
use obdcracker_transport::{Error, Expect, Mock, Response, Timing, Transport, exchange};

const FAST: Timing = Timing {
    p2: Duration::from_millis(20),
    p2_star: Duration::from_millis(40),
    max_pending: 3,
};

fn approve(target: Target, payload: &[u8]) -> Approved {
    Policy::read_only().approve(target, payload).unwrap()
}

fn reply(source: u32, payload: &[u8]) -> Response {
    Response {
        source,
        payload: payload.to_vec(),
    }
}

fn mock(replies: &[Response]) -> Mock {
    let mut mock = Mock::default();
    for r in replies {
        mock.queue(r.clone());
    }
    mock
}

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";
const PENDING: &[u8] = &[0x7F, 0x22, 0x78];
const F190: &[u8] = b"\x62\xF1\x90WAUZZZ4G1EN000000";

#[test]
fn default_timing_is_iso_14229_2() {
    let timing = Timing::default();
    assert_eq!(timing.p2, Duration::from_millis(50));
    assert_eq!(timing.p2_star, Duration::from_secs(5));
}

#[test]
fn sends_the_request_once() {
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let mut adapter = mock(&[]);
    exchange(&mut adapter, &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(adapter.sent(), [vin]);
}

#[test]
fn functional_request_collects_every_ecu_until_quiet() {
    let replies = [reply(0x7E8, VIN), reply(0x7E9, VIN)];
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, replies);
}

#[test]
fn functional_request_with_no_reply_is_empty_not_an_error() {
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    assert_eq!(
        exchange(&mut mock(&[]), &vin, Expect::ObdEcus, FAST),
        Ok(vec![])
    );
}

#[test]
fn functional_request_ignores_ids_outside_the_obd_responses() {
    let replies = [
        reply(0x77A, VIN),
        reply(0x7E7, VIN),
        reply(0x7F0, VIN),
        reply(0x7EF, VIN),
    ];
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7EF, VIN)]);
}

#[test]
fn functional_request_waits_through_one_ecus_pending() {
    let replies = [
        reply(0x7E8, &[0x7F, 0x09, 0x78]),
        reply(0x7E9, VIN),
        reply(0x7E8, VIN),
    ];
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN), reply(0x7E8, VIN)]);
}

#[test]
fn physical_request_returns_the_modules_reply() {
    let read = approve(Target::Physical(0x710), &[0x22, 0xF1, 0x90]);
    let replies = [reply(0x7E8, VIN), reply(0x77A, F190)];
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x77A), FAST).unwrap();
    assert_eq!(got, [reply(0x77A, F190)]);
}

#[test]
fn physical_request_without_a_reply_times_out() {
    let read = approve(Target::Physical(0x710), &[0x22, 0xF1, 0x90]);
    let replies = [reply(0x7E8, F190)];
    assert_eq!(
        exchange(&mut mock(&replies), &read, Expect::Module(0x77A), FAST),
        Err(Error::Timeout)
    );
}

#[test]
fn physical_request_waits_through_response_pending() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let replies = [
        reply(0x7E8, PENDING),
        reply(0x7E8, PENDING),
        reply(0x7E8, F190),
    ];
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, F190)]);
}

#[test]
fn a_refusal_is_a_reply_not_pending() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let refusal = reply(0x7E8, &[0x7F, 0x22, 0x31]);
    let got = exchange(
        &mut mock(&[refusal.clone()]),
        &read,
        Expect::Module(0x7E8),
        FAST,
    );
    assert_eq!(got, Ok(vec![refusal]));
}

#[test]
fn pending_for_another_service_is_a_reply() {
    // `7F 19 78` doesn't answer a 0x22 request, so it isn't a reason to keep waiting.
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let other = reply(0x7E8, &[0x7F, 0x19, 0x78]);
    let got = exchange(
        &mut mock(&[other.clone()]),
        &read,
        Expect::Module(0x7E8),
        FAST,
    );
    assert_eq!(got, Ok(vec![other]));
}

#[test]
fn too_many_pending_replies_time_out() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let mut replies = vec![reply(0x7E8, PENDING); 4];
    replies.push(reply(0x7E8, F190));
    assert_eq!(
        exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST),
        Err(Error::Timeout)
    );
}

// A module that sends response-pending once, then nothing.
#[derive(Debug, Default)]
struct PendingThenSilent {
    sent: bool,
    asked_for: Vec<Duration>,
}

impl Transport for PendingThenSilent {
    fn send(&mut self, _request: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.asked_for.push(timeout);
        if self.sent {
            std::thread::sleep(timeout);
            return Err(Error::Timeout);
        }
        self.sent = true;
        Ok(reply(0x7E8, PENDING))
    }
}

#[test]
fn pending_extends_the_wait_to_p2_star_then_times_out() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let mut adapter = PendingThenSilent::default();
    let start = Instant::now();
    let got = exchange(&mut adapter, &read, Expect::Module(0x7E8), FAST);
    assert_eq!(got, Err(Error::Timeout));
    assert!(start.elapsed() >= FAST.p2_star);
    assert!(adapter.asked_for[0] <= FAST.p2);
    assert!(adapter.asked_for[1] > FAST.p2 && adapter.asked_for[1] <= FAST.p2_star);
}

#[test]
fn adapter_errors_are_returned() {
    #[derive(Debug)]
    struct Broken;
    impl Transport for Broken {
        fn send(&mut self, _request: &Approved) -> Result<(), Error> {
            Ok(())
        }
        fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
            Err(Error::Adapter("unplugged".into()))
        }
    }
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    assert_eq!(
        exchange(&mut Broken, &vin, Expect::ObdEcus, FAST),
        Err(Error::Adapter("unplugged".into()))
    );
}
