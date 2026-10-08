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
fn functional_request_collects_every_ecu() {
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
fn a_suppressed_request_gets_its_answer_after_response_pending() {
    // ISO 14229-1: response-pending obliges the final positive reply despite the suppress bit.
    let read = approve(Target::Physical(0x7E0), &[0x19, 0x82, 0x08]);
    let answer = reply(0x7E8, &[0x59, 0x02, 0xFF]);
    let replies = [reply(0x7E8, &[0x7F, 0x19, 0x78]), answer.clone()];
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST);
    assert_eq!(got, Ok(vec![answer.clone()]));
    // Without response-pending first, a positive reply is a late answer to an earlier request.
    assert_eq!(
        exchange(
            &mut mock(std::slice::from_ref(&answer)),
            &read,
            Expect::Module(0x7E8),
            FAST
        ),
        Err(Error::Timeout)
    );
}

#[test]
fn a_refusal_is_a_reply_not_pending() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let refusal = reply(0x7E8, &[0x7F, 0x22, 0x31]);
    let got = exchange(
        &mut mock(std::slice::from_ref(&refusal)),
        &read,
        Expect::Module(0x7E8),
        FAST,
    );
    assert_eq!(got, Ok(vec![refusal]));
}

#[test]
fn replies_to_another_service_are_ignored() {
    // A late answer to an earlier request (or its response-pending) isn't this request's reply.
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let stale = [
        reply(0x7E8, &[0x7F, 0x19, 0x78]),
        reply(0x7E8, &[0x59, 0x02, 0xFF]),
        reply(0x7E8, &[]),
    ];
    assert_eq!(
        exchange(&mut mock(&stale), &read, Expect::Module(0x7E8), FAST),
        Err(Error::Timeout)
    );
    let mut replies = stale.to_vec();
    replies.push(reply(0x7E8, F190));
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, F190)]);
}

#[test]
fn functional_request_ignores_replies_to_another_service() {
    let replies = [reply(0x7E8, &[0x41, 0x0C, 0x0C, 0x80]), reply(0x7E9, VIN)];
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN)]);
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

#[test]
fn an_ecu_over_the_pending_limit_does_not_lose_the_others_answers() {
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let mut replies = vec![reply(0x7E9, VIN)];
    replies.extend(vec![reply(0x7E8, &[0x7F, 0x09, 0x78]); 4]);
    replies.push(reply(0x7E8, VIN));
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN)]);
}

#[test]
fn the_pending_limit_is_per_ecu() {
    // Each ECU goes pending 3 times (the limit), 6 in all, then both answer.
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let mut replies = Vec::new();
    for _ in 0..3 {
        replies.push(reply(0x7E8, &[0x7F, 0x09, 0x78]));
        replies.push(reply(0x7E9, &[0x7F, 0x09, 0x78]));
    }
    replies.push(reply(0x7E8, VIN));
    replies.push(reply(0x7E9, VIN));
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, VIN), reply(0x7E9, VIN)]);
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

#[test]
fn a_late_reply_for_another_pid_is_ignored() {
    // A reply to an earlier mode 09 PID 04 request has the same service byte as the VIN's.
    let stale = reply(0x7E8, &[0x49, 0x04, 0x01, 0x41, 0x42]);
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let replies = [stale.clone(), reply(0x7E9, VIN)];
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN)]);

    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let replies = [reply(0x7E8, &[0x62, 0xF1, 0x87, 0x30]), reply(0x7E8, F190)];
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, F190)]);
}

// Plays back replies, then sleeps through each wait it's given and times out.
#[derive(Debug)]
struct Script {
    replies: Vec<Response>,
    asked_for: Vec<Duration>,
}

impl Transport for Script {
    fn send(&mut self, _request: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.asked_for.push(timeout);
        if self.replies.is_empty() {
            std::thread::sleep(timeout);
            return Err(Error::Timeout);
        }
        Ok(self.replies.remove(0))
    }
}

#[test]
fn broadcast_ends_once_the_pending_ecu_answers() {
    let timing = Timing {
        p2: Duration::from_millis(10),
        p2_star: Duration::from_secs(5),
        max_pending: 3,
    };
    let mut adapter = Script {
        replies: vec![reply(0x7E8, &[0x7F, 0x09, 0x78]), reply(0x7E8, VIN)],
        asked_for: Vec::new(),
    };
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let start = Instant::now();
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, timing).unwrap();
    assert_eq!(got, [reply(0x7E8, VIN)]);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn broadcast_keeps_waiting_for_an_ecu_still_pending() {
    let timing = Timing {
        p2: Duration::from_millis(10),
        p2_star: Duration::from_millis(200),
        max_pending: 3,
    };
    let mut adapter = Script {
        replies: vec![reply(0x7E8, &[0x7F, 0x09, 0x78]), reply(0x7E9, VIN)],
        asked_for: Vec::new(),
    };
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let start = Instant::now();
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, timing).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN)]);
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn the_largest_pending_limit_still_ends_the_wait() {
    let timing = Timing {
        max_pending: u16::MAX,
        ..FAST
    };
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let replies = vec![reply(0x7E8, PENDING); usize::from(u16::MAX) + 1];
    assert_eq!(
        exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), timing),
        Err(Error::Timeout)
    );
}

#[test]
fn exactly_max_pending_replies_are_waited_through() {
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let mut replies = vec![reply(0x7E8, PENDING); usize::from(FAST.max_pending)];
    replies.push(reply(0x7E8, F190));
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, F190)]);
}

#[test]
fn huge_timings_do_not_overflow_the_clock() {
    let timing = Timing {
        p2: Duration::MAX,
        p2_star: Duration::MAX,
        max_pending: 1,
    };
    let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x90]);
    let replies = [reply(0x7E8, PENDING), reply(0x7E8, F190)];
    let got = exchange(&mut mock(&replies), &read, Expect::Module(0x7E8), timing).unwrap();
    assert_eq!(got, [reply(0x7E8, F190)]);
}

// An ECU stuck repeating the same answer.
#[derive(Debug)]
struct Repeating(Response);

impl Transport for Repeating {
    fn send(&mut self, _request: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        Ok(self.0.clone())
    }
}

#[test]
fn a_repeating_ecu_cannot_keep_a_broadcast_open() {
    // J1979: each ECU answers a broadcast once, so repeats are dropped and don't extend the wait.
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let mut adapter = Repeating(reply(0x7E8, VIN));
    let start = Instant::now();
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, FAST).unwrap();
    assert_eq!(got, [reply(0x7E8, VIN)]);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}

// Replies that arrive after a delay, then silence until the wait ends.
#[derive(Debug)]
struct Timed(Vec<(Duration, Response)>);

impl Transport for Timed {
    fn send(&mut self, _request: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        if self.0.is_empty() {
            std::thread::sleep(timeout);
            return Err(Error::Timeout);
        }
        let (delay, reply) = self.0.remove(0);
        std::thread::sleep(delay);
        Ok(reply)
    }
}

#[test]
fn each_pending_ecu_gets_only_its_own_p2_star() {
    let timing = Timing {
        p2: Duration::from_millis(10),
        p2_star: Duration::from_millis(100),
        max_pending: 5,
    };
    let ms = Duration::from_millis;
    let mut adapter = Timed(vec![
        (ms(0), reply(0x7E8, &[0x7F, 0x09, 0x78])),
        // Both go pending within P2; 0x7E9 renews its P2* at about 90 ms.
        (ms(5), reply(0x7E9, &[0x7F, 0x09, 0x78])),
        (ms(85), reply(0x7E9, &[0x7F, 0x09, 0x78])),
        // 0x7E8's P2* ended at about 100 ms, so its answer at about 140 ms is too late.
        (ms(50), reply(0x7E8, VIN)),
        (ms(10), reply(0x7E9, VIN)),
    ]);
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, timing).unwrap();
    assert_eq!(got, [reply(0x7E9, VIN)]);
}

#[test]
fn an_ecu_that_answered_cannot_reopen_the_wait_with_pending() {
    let timing = Timing {
        max_pending: 1,
        ..FAST
    };
    let pending = reply(0x7E8, &[0x7F, 0x09, 0x78]);
    let replies = [reply(0x7E8, VIN), pending.clone(), pending.clone(), pending];
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut mock(&replies), &vin, Expect::ObdEcus, timing);
    assert_eq!(got, Ok(vec![reply(0x7E8, VIN)]));
}

#[test]
fn another_ecus_pending_does_not_extend_p2_for_the_rest() {
    let timing = Timing {
        p2: Duration::from_millis(20),
        p2_star: Duration::from_millis(300),
        max_pending: 5,
    };
    let ms = Duration::from_millis;
    let mut adapter = Timed(vec![
        (ms(0), reply(0x7E8, &[0x7F, 0x09, 0x78])),
        // 0x7E9 never went pending, and P2 ended long before this.
        (ms(100), reply(0x7E9, VIN)),
        (ms(10), reply(0x7E8, VIN)),
    ]);
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, timing).unwrap();
    assert_eq!(got, [reply(0x7E8, VIN)]);
}

#[test]
fn a_pending_ecus_answer_does_not_reopen_p2_for_the_rest() {
    let timing = Timing {
        p2: Duration::from_millis(20),
        p2_star: Duration::from_millis(300),
        max_pending: 5,
    };
    let ms = Duration::from_millis;
    let mut adapter = Timed(vec![
        (ms(0), reply(0x7E8, &[0x7F, 0x09, 0x78])),
        // 0x7E8 answers after P2, which it may: it went pending.
        (ms(60), reply(0x7E8, VIN)),
        // 0x7E9 never went pending, so its answer is late.
        (ms(5), reply(0x7E9, VIN)),
    ]);
    let vin = approve(Target::ObdFunctional, &[0x09, 0x02]);
    let got = exchange(&mut adapter, &vin, Expect::ObdEcus, timing).unwrap();
    assert_eq!(got, [reply(0x7E8, VIN)]);
}
