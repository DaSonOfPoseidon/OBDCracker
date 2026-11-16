//! A mode 01 PID whose value changes on each request: `Ecu::set_pid_sequence`.

use std::time::Duration;

use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_sim::{FixtureError, SimBus};
use obdcracker_transport::{Error, Transport};

const PROFILE: &str = r#"
name = "Two modules"
bitrate = 500000

[[module]]
name = "engine"
request_id = 0x7E0
response_id = 0x7E8
protocol = "uds"

[[module]]
name = "abs"
request_id = 0x713
response_id = 0x77D
protocol = "uds"
"#;

const FIXTURE: &str = r#"
[[ecu]]
module = "engine"

[ecu.obd.pids]
"0D" = "32"

[[ecu]]
module = "abs"
"#;

fn bus() -> SimBus {
    SimBus::new(&Profile::from_toml(PROFILE).unwrap(), FIXTURE).unwrap()
}

// What the engine answers to a broadcast request for `pids`.
fn ask(bus: &mut SimBus, pids: &[u8]) -> Option<Vec<u8>> {
    let mut payload = vec![0x01];
    payload.extend(pids);
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::ObdFunctional, &payload)
        .unwrap();
    bus.send(&request).unwrap();
    match bus.recv(Duration::from_millis(5)) {
        Ok(reply) => Some(reply.payload),
        Err(Error::Timeout) => None,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn the_value_advances_on_each_request_and_the_last_one_repeats() {
    let mut bus = bus();
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x0C, vec![vec![0x0C, 0x80], vec![0x1A, 0xF8], vec![0, 0]])
        .unwrap();
    let answers: Vec<_> = (0..5).map(|_| ask(&mut bus, &[0x0C])).collect();
    assert_eq!(
        answers,
        [
            Some(vec![0x41, 0x0C, 0x0C, 0x80]),
            Some(vec![0x41, 0x0C, 0x1A, 0xF8]),
            Some(vec![0x41, 0x0C, 0, 0]),
            Some(vec![0x41, 0x0C, 0, 0]),
            Some(vec![0x41, 0x0C, 0, 0]),
        ]
    );
}

#[test]
fn a_request_for_other_pids_does_not_advance_it_and_a_batch_does() {
    let mut bus = bus();
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x0C, vec![vec![0x0C, 0x80], vec![0x1A, 0xF8]])
        .unwrap();
    assert_eq!(ask(&mut bus, &[0x0D]), Some(vec![0x41, 0x0D, 0x32]));
    assert_eq!(
        ask(&mut bus, &[0x0D, 0x0C]),
        Some(vec![0x41, 0x0D, 0x32, 0x0C, 0x0C, 0x80])
    );
    assert_eq!(
        ask(&mut bus, &[0x0C, 0x0D]),
        Some(vec![0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32])
    );
}

#[test]
fn a_pid_named_twice_in_one_request_advances_once() {
    let mut bus = bus();
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x0C, vec![vec![0, 1], vec![0, 2], vec![0, 3]])
        .unwrap();
    assert_eq!(
        ask(&mut bus, &[0x0C, 0x0C]),
        Some(vec![0x41, 0x0C, 0, 1, 0x0C, 0, 1])
    );
    assert_eq!(ask(&mut bus, &[0x0C]), Some(vec![0x41, 0x0C, 0, 2]));
}

#[test]
fn the_pid_is_in_the_bitmap_and_replaces_a_fixed_value() {
    let mut bus = bus();
    let engine = bus.ecu_mut("engine").unwrap();
    engine
        .set_pid_sequence(0x0D, vec![vec![0x10], vec![0x20]])
        .unwrap();
    engine.set_pid_sequence(0x0C, vec![vec![0, 0]]).unwrap();
    assert_eq!(ask(&mut bus, &[0x0D]), Some(vec![0x41, 0x0D, 0x10]));
    assert_eq!(ask(&mut bus, &[0x0D]), Some(vec![0x41, 0x0D, 0x20]));
    // PID 0x0C is bit 20 and 0x0D is bit 19 of the first page, and nothing above 0x20 follows.
    assert_eq!(
        ask(&mut bus, &[0x00]),
        Some(vec![0x41, 0x00, 0x00, 0x18, 0x00, 0x00])
    );
}

#[test]
fn a_second_call_starts_the_new_sequence_over() {
    let mut bus = bus();
    let engine = bus.ecu_mut("engine").unwrap();
    engine
        .set_pid_sequence(0x0C, vec![vec![0, 1], vec![0, 2]])
        .unwrap();
    assert_eq!(ask(&mut bus, &[0x0C]), Some(vec![0x41, 0x0C, 0, 1]));
    assert_eq!(ask(&mut bus, &[0x0C]), Some(vec![0x41, 0x0C, 0, 2]));
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x0C, vec![vec![0, 9], vec![0, 8]])
        .unwrap();
    assert_eq!(ask(&mut bus, &[0x0C]), Some(vec![0x41, 0x0C, 0, 9]));
}

#[test]
fn refuses_what_a_fixture_would() {
    let mut bus = bus();
    let engine = bus.ecu_mut("engine").unwrap();
    // No values.
    assert!(matches!(
        engine.set_pid_sequence(0x0C, vec![]),
        Err(FixtureError::Value(_))
    ));
    // A value of the wrong length for the PID, in any position.
    for values in [
        vec![vec![0x0C]],
        vec![vec![0x0C, 0x80], vec![0x0C, 0x80, 0x00]],
        vec![vec![]],
    ] {
        assert!(
            matches!(
                engine.set_pid_sequence(0x0C, values.clone()),
                Err(FixtureError::Value(_))
            ),
            "{values:02X?}"
        );
    }
    // A bitmap PID is computed.
    for pid in [0x00, 0x20, 0xE0] {
        assert!(
            matches!(
                engine.set_pid_sequence(pid, vec![vec![0; 4]]),
                Err(FixtureError::Value(_))
            ),
            "{pid:02X}"
        );
    }
    // Nothing was set by any of them.
    assert_eq!(ask(&mut bus, &[0x0C]), None);
    // A module with no OBD-II data.
    let abs = bus.ecu_mut("abs").unwrap();
    assert!(matches!(
        abs.set_pid_sequence(0x0C, vec![vec![0, 0]]),
        Err(FixtureError::NotObd(name)) if name == "abs"
    ));
}

#[test]
fn a_pid_the_decoder_does_not_know_takes_any_length() {
    let mut bus = bus();
    // 0x1B is reserved in SAE J1979, so the decoder doesn't know its length.
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x1B, vec![vec![1], vec![2, 3]])
        .unwrap();
    assert_eq!(ask(&mut bus, &[0x1B]), Some(vec![0x41, 0x1B, 1]));
    assert_eq!(ask(&mut bus, &[0x1B]), Some(vec![0x41, 0x1B, 2, 3]));
}
