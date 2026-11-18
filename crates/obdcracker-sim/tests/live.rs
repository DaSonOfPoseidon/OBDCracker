//! The live-data poller on the simulated car: values that change from one poll to the next, how
//! many requests a poll sends, and a module that misbehaves. Every expected value is worked out by
//! hand from SAE J1979.

use std::time::Duration;

use obdcracker_core::obd::Unit;
use obdcracker_core::response::Error as ReplyError;
use obdcracker_profile::Profile;
use obdcracker_safety::Policy;
use obdcracker_sim::{Fault, SimBus};
use obdcracker_transport::fingerprint::{ReadError, UdsModule};
use obdcracker_transport::live::{DidPoll, Poller, next_due};
use obdcracker_transport::scan::PidValue;
use obdcracker_transport::{Timing, hex};

const PROFILE: &str = r#"
name = "Two OBD-II modules"
bitrate = 500000

[[module]]
name = "engine"
request_id = 0x7E0
response_id = 0x7E8
protocol = "uds"

[[module]]
name = "transmission"
request_id = 0x7E1
response_id = 0x7E9
protocol = "uds"
"#;

const FIXTURE: &str = r#"
[[ecu]]
module = "engine"

[ecu.obd.pids]
"04" = "FF"
"05" = "7B"
"0B" = "62"
"0D" = "32"
"0F" = "00"
"11" = "00"

[[ecu.did]]
id = 0xF187
text = "4G0907401N "

[[ecu.did]]
id = 0xF189
text = "0016"

[[ecu]]
module = "transmission"

[ecu.obd.pids]
"0C" = "00 04"
"0D" = "00"
"#;

const ENGINE: u32 = 0x7E8;
const TRANSMISSION: u32 = 0x7E9;

const TIMING: Timing = Timing {
    p2: Duration::from_millis(20),
    p2_star: Duration::from_millis(20),
    max_pending: 2,
};

fn bus() -> SimBus {
    SimBus::new(&Profile::from_toml(PROFILE).unwrap(), FIXTURE).unwrap()
}

#[expect(clippy::unnecessary_wraps, reason = "a reading is a result")]
fn rpm(value: f32) -> Result<PidValue, ReadError> {
    Ok(PidValue::Quantity {
        value,
        unit: Unit::Rpm,
    })
}

fn sent(bus: &SimBus) -> Vec<String> {
    bus.sent()
        .iter()
        .map(|request| {
            format!(
                "{:03X} {}",
                request.target().can_id(),
                hex(request.payload())
            )
        })
        .collect()
}

#[test]
fn the_values_change_from_one_poll_to_the_next() {
    let mut bus = bus();
    // 0x0C80 / 4 = 800 rpm, 0x1AF8 / 4 = 1726, 0.
    bus.ecu_mut("engine")
        .unwrap()
        .set_pid_sequence(0x0C, vec![vec![0x0C, 0x80], vec![0x1A, 0xF8], vec![0, 0]])
        .unwrap();
    let mut poller = Poller::new(&Policy::read_only(), &[0x0C, 0x0D, 0x05], Vec::new()).unwrap();
    let samples: Vec<_> = (0..4)
        .map(|_| poller.poll(&mut bus, TIMING).unwrap())
        .collect();
    let engine_rpm: Vec<_> = samples
        .iter()
        .map(|sample| sample.pids[&ENGINE][0].1.clone())
        .collect();
    assert_eq!(
        engine_rpm,
        [rpm(800.0), rpm(1726.0), rpm(0.0), rpm(0.0)],
        "the last value repeats"
    );
    // The others don't change, and the transmission's rpm is 1.
    for sample in &samples {
        assert_eq!(
            sample.pids[&ENGINE][1..],
            [
                (
                    0x0D,
                    Ok(PidValue::Quantity {
                        value: 50.0,
                        unit: Unit::KilometresPerHour
                    })
                ),
                (
                    0x05,
                    Ok(PidValue::Quantity {
                        value: 83.0,
                        unit: Unit::Celsius
                    })
                ),
            ]
        );
        assert_eq!(sample.pids[&TRANSMISSION][0].1, rpm(1.0));
        // The transmission has no coolant temperature.
        assert_eq!(
            sample.pids[&TRANSMISSION][2],
            (0x05, Err(ReadError::NoReply))
        );
        assert_eq!(sample.dids, vec![]);
    }
    // The bitmaps once, then one request a poll, however many PIDs and ECUs.
    let mut want = vec!["7DF 01 00"];
    want.extend(["7DF 01 0C 0D 05"; 4]);
    assert_eq!(sent(&bus), want);
    assert!(samples.iter().all(|sample| !sample.out_of_step));
}

#[test]
fn a_poll_starts_after_the_one_before_and_the_next_is_due_an_interval_later() {
    let mut bus = bus();
    let mut poller = Poller::new(&Policy::read_only(), &[0x0D], Vec::new()).unwrap();
    let first = poller.poll(&mut bus, TIMING).unwrap();
    let second = poller.poll(&mut bus, TIMING).unwrap();
    assert!(first.started <= first.finished);
    assert!(first.finished <= second.started);
    // The sim answers within a poll, so the next is due an interval after the first began.
    let interval = Duration::from_secs(1);
    assert_eq!(
        next_due(first.started, interval, first.finished),
        first.started + interval
    );
}

#[test]
fn seven_known_pids_are_two_requests_and_each_is_read() {
    let mut bus = bus();
    let pids = [0x04, 0x05, 0x0B, 0x0D, 0x0F, 0x11, 0x0C];
    let mut poller = Poller::new(&Policy::read_only(), &pids, Vec::new()).unwrap();
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    assert_eq!(
        sent(&bus),
        ["7DF 01 00", "7DF 01 04 05 0B 0D 0F 11", "7DF 01 0C"]
    );
    // The engine lists no rpm, so it owed no answer to the request for it.
    assert!(!sample.out_of_step);
    let engine = &sample.pids[&ENGINE];
    assert_eq!(engine.iter().map(|(pid, _)| *pid).collect::<Vec<_>>(), pids);
    // Everything but the rpm, which the engine doesn't have in this fixture.
    for (pid, value) in engine {
        assert_eq!(value.is_ok(), *pid != 0x0C, "{pid:02X}");
    }
    assert_eq!(engine[6].1, Err(ReadError::NoReply));
    assert_eq!(sample.pids[&TRANSMISSION][6].1, rpm(1.0));
}

#[test]
fn the_pid_requests_are_the_broadcasts_a_poll_sends_once_every_pid_is_listed() {
    // Seven known PIDs go six to a request, and an unknown one (0x13, which this crate doesn't
    // decode) alone. Nothing is sent to find them out.
    let pids = [0x04, 0x05, 0x0B, 0x0D, 0x0F, 0x11, 0x0C, 0x13];
    let poller = Poller::new(&Policy::read_only(), &pids, Vec::new()).unwrap();
    let requests: Vec<String> = poller
        .pid_requests()
        .map(|request| {
            format!(
                "{:03X} {}",
                request.target().can_id(),
                hex(request.payload())
            )
        })
        .collect();
    assert_eq!(
        requests,
        ["7DF 01 04 05 0B 0D 0F 11", "7DF 01 0C", "7DF 01 13"]
    );
    let only_dids = Poller::new(
        &Policy::read_only(),
        &[],
        vec![DidPoll {
            module: UdsModule::obd_engine(),
            dids: vec![(0xF187, None)],
        }],
    )
    .unwrap();
    assert_eq!(only_dids.pid_requests().count(), 0);
}

#[test]
fn reads_a_modules_dids_with_each_poll() {
    let mut bus = bus();
    let engine = UdsModule {
        name: "engine".to_owned(),
        request_id: 0x7E0,
        response_id: 0x7E8,
    };
    let dids = vec![DidPoll {
        module: engine.clone(),
        dids: vec![(0xF187, Some(11)), (0xF189, Some(4))],
    }];
    let mut poller = Poller::new(&Policy::read_only(), &[0x0D], dids).unwrap();
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    poller.poll(&mut bus, TIMING).unwrap();
    let mut want = vec!["7DF 01 00".to_owned()];
    want.extend(
        ["7DF 01 0D", "7E0 22 F1 87 F1 89"]
            .repeat(2)
            .into_iter()
            .map(str::to_owned),
    );
    assert_eq!(sent(&bus), want);
    assert_eq!(sample.dids.len(), 1);
    assert_eq!(sample.dids[0].module, engine);
    let data = sample.dids[0].result.as_ref().unwrap();
    assert_eq!(
        data.split,
        [
            (0xF187, b"4G0907401N ".to_vec()),
            (0xF189, b"0016".to_vec())
        ]
    );
    assert!(data.left_out.is_empty() && data.unsplit.is_empty());
}

#[test]
fn a_cut_off_reply_costs_that_ecu_its_values_and_no_other() {
    let mut bus = bus();
    let mut poller = Poller::new(&Policy::read_only(), &[0x0C, 0x0D], Vec::new()).unwrap();
    poller.poll(&mut bus, TIMING).unwrap();
    // Cut to five bytes, the transmission's `41 0C 00 04 0D 00` ends with the second PID's ID and
    // none of its data.
    bus.ecu_mut("transmission")
        .unwrap()
        .set_fault(Some(Fault::Truncate(5)));
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    let cut = [0x41, 0x0C, 0x00, 0x04, 0x0D];
    for (_, reading) in &sample.pids[&TRANSMISSION] {
        assert_eq!(
            reading,
            &Err(ReadError::Undecodable {
                error: ReplyError::TooShort,
                reply: cut.to_vec()
            })
        );
    }
    // The engine has no rpm in this fixture, but its speed is read.
    assert_eq!(sample.pids[&ENGINE][0], (0x0C, Err(ReadError::NoReply)));
    assert!(sample.pids[&ENGINE][1].1.is_ok());
}

#[test]
fn a_silent_ecu_is_missing_from_the_sample_and_the_other_is_read() {
    let mut bus = bus();
    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(Fault::Silent));
    let mut poller = Poller::new(&Policy::read_only(), &[0x0D], Vec::new()).unwrap();
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    assert_eq!(
        sample.pids.keys().copied().collect::<Vec<_>>(),
        [TRANSMISSION]
    );
}

#[test]
fn an_ecu_whose_bitmap_is_cut_off_is_left_out_with_its_error() {
    let mut bus = bus();
    // `41 00 .. .. .. ..` cut to five bytes is a bitmap short of its last byte.
    bus.ecu_mut("transmission")
        .unwrap()
        .set_fault(Some(Fault::Truncate(5)));
    let mut poller = Poller::new(&Policy::read_only(), &[0x0D], Vec::new()).unwrap();
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    assert_eq!(sample.pids.keys().copied().collect::<Vec<_>>(), [ENGINE]);
    assert!(matches!(
        sample.bitmap_errors[&TRANSMISSION],
        ReadError::Undecodable {
            error: ReplyError::TooShort,
            ..
        }
    ));
    assert!(!sample.out_of_step);
}

#[test]
fn a_pid_no_module_has_is_not_sent() {
    let mut bus = bus();
    // 0x10 (air flow) is in neither module.
    let mut poller = Poller::new(&Policy::read_only(), &[0x0D, 0x10], Vec::new()).unwrap();
    let sample = poller.poll(&mut bus, TIMING).unwrap();
    assert_eq!(sent(&bus), ["7DF 01 00", "7DF 01 0D"]);
    assert_eq!(sample.unsupported_pids, [0x10]);
    assert_eq!(sample.pids[&ENGINE][1], (0x10, Err(ReadError::NoReply)));
}
