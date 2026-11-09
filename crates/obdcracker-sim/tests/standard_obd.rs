//! Mode 01, 03 and 09 replies at the edges of the standard (issue #12): the synthetic
//! `standard-obd.toml`, plus the largest lists the formats can carry. Every expected value is worked
//! out by hand from SAE J1979, not read back from the decoders.

use std::fmt::Write as _;
use std::time::Duration;

use obdcracker_core::obd::{self, Unit, Value};
use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_sim::{FixtureError, SimBus};
use obdcracker_transport::{Error, Transport};

const ENGINE: Target = Target::Physical(0x7E0);
const TRANSMISSION: Target = Target::Physical(0x7E1);
const FIXTURE: &str = include_str!("../fixtures/standard-obd.toml");

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

fn bus_with(fixture: &str) -> Result<SimBus, FixtureError> {
    SimBus::new(&Profile::from_toml(PROFILE).unwrap(), fixture)
}

fn bus() -> SimBus {
    bus_with(FIXTURE).unwrap()
}

fn ask(bus: &mut SimBus, target: Target, payload: &[u8]) -> Vec<u8> {
    let request = Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap();
    bus.send(&request).unwrap();
    let reply = bus.recv(Duration::from_millis(50)).unwrap();
    assert_eq!(bus.recv(Duration::from_millis(5)), Err(Error::Timeout));
    reply.payload
}

fn ask_or_silent(bus: &mut SimBus, target: Target, payload: &[u8]) -> Option<Vec<u8>> {
    let request = Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap();
    bus.send(&request).unwrap();
    bus.recv(Duration::from_millis(5))
        .ok()
        .map(|reply| reply.payload)
}

fn quantity(bus: &mut SimBus, target: Target, pid: u8) -> (f32, Unit) {
    let reply = ask(bus, target, &obd::current_data(pid));
    let mut readings = obd::decode_current_data(&reply).unwrap();
    let reading = readings.next().unwrap().unwrap();
    assert_eq!(reading.pid, pid);
    assert!(readings.next().is_none());
    let Value::Quantity { value, unit } = reading.value else {
        panic!("{reading:?}");
    };
    (value, unit)
}

// Per PID: the engine's value and unit, then the transmission's. Each is the formula of SAE J1979
// at 0x00 or 0xFF in every data byte.
#[test]
fn mode_01_formulas_hold_at_both_ends_of_their_range() {
    use Unit::{
        Celsius, Count, Degrees, GramsPerSecond, Kilometres, KilometresPerHour, Kilopascals,
        LitresPerHour, NewtonMetres, Percent, Rpm, Seconds, Volts,
    };
    #[rustfmt::skip]
    let expected = [
        (0x04, (0.0, Percent), (100.0, Percent)),
        (0x05, (-40.0, Celsius), (215.0, Celsius)),
        (0x0C, (16383.75, Rpm), (0.0, Rpm)),
        (0x0D, (255.0, KilometresPerHour), (0.0, KilometresPerHour)),
        (0x0F, (215.0, Celsius), (-40.0, Celsius)),
        (0x10, (655.35, GramsPerSecond), (0.0, GramsPerSecond)),
        (0x11, (100.0, Percent), (0.0, Percent)),
        (0x1F, (65535.0, Seconds), (0.0, Seconds)),
        (0x21, (65535.0, Kilometres), (0.0, Kilometres)),
        (0x30, (255.0, Count), (0.0, Count)),
        (0x33, (255.0, Kilopascals), (0.0, Kilopascals)),
        (0x3C, (6513.5, Celsius), (-40.0, Celsius)),
        (0x42, (65.535, Volts), (0.0, Volts)),
        (0x5D, (-210.0, Degrees), (65535.0 / 128.0 - 210.0, Degrees)),
        (0x5E, (3276.75, LitresPerHour), (0.0, LitresPerHour)),
        (0x61, (-125.0, Percent), (130.0, Percent)),
        (0x63, (65535.0, NewtonMetres), (0.0, NewtonMetres)),
    ];
    let mut bus = bus();
    for (pid, engine, transmission) in expected {
        assert_eq!(quantity(&mut bus, ENGINE, pid), engine, "engine {pid:02X}");
        assert_eq!(
            quantity(&mut bus, TRANSMISSION, pid),
            transmission,
            "transmission {pid:02X}"
        );
    }
}

#[test]
fn mode_01_every_pid_has_0x00_in_one_module_and_0xff_in_the_other() {
    let mut bus = bus();
    let mut checked = 0;
    // 0xFF is only in the engine, and the bitmap PIDs are computed.
    for pid in (0x01..0xFFu8).filter(|pid| !pid.is_multiple_of(0x20)) {
        let engine = ask_or_silent(&mut bus, ENGINE, &obd::current_data(pid));
        let transmission = ask_or_silent(&mut bus, TRANSMISSION, &obd::current_data(pid));
        let (engine, transmission) = match (engine, transmission) {
            (None, None) => continue,
            (Some(engine), Some(transmission)) => (engine, transmission),
            other => panic!("PID {pid:02X} is in only one module: {other:02X?}"),
        };
        let end = |reply: &[u8]| match reply[2..] {
            [first @ (0x00 | 0xFF), ref rest @ ..] if rest.iter().all(|&b| b == first) => first,
            ref data => panic!("PID {pid:02X}: {data:02X?} isn't all 0x00 or all 0xFF"),
        };
        assert_eq!(engine.len(), transmission.len(), "PID {pid:02X}");
        assert_eq!(end(&engine), !end(&transmission), "PID {pid:02X}");
        checked += 1;
    }
    assert_eq!(checked, 17);
}

#[test]
fn mode_01_highest_pid_is_raw_and_reachable_through_the_last_bitmap() {
    let mut bus = bus();
    let reply = ask(&mut bus, ENGINE, &obd::current_data(0xFF));
    let reading = obd::decode_current_data(&reply)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(reading.pid, 0xFF);
    assert_eq!(reading.value, Value::Raw(&[0xAB]));

    // 0xE0 is the last bitmap PID: its 32nd bit would be PID 0x100, so it says nothing is next.
    let reply = ask(&mut bus, ENGINE, &obd::current_data(0xE0));
    let mut readings = obd::decode_current_data(&reply).unwrap();
    let Value::Supported(bitmap) = readings.next().unwrap().unwrap().value else {
        panic!("{reply:02X?}");
    };
    assert_eq!(bitmap.iter().collect::<Vec<_>>(), [0xFF]);
    assert!(!bitmap.contains(0x00));
}

#[test]
fn mode_01_bitmaps_chain_to_exactly_the_listed_pids() {
    let mut bus = bus();
    let mut supported = Vec::new();
    let mut base = Some(0x00u8);
    while let Some(b) = base {
        let reply = ask(&mut bus, ENGINE, &obd::current_data(b));
        let mut readings = obd::decode_current_data(&reply).unwrap();
        let Value::Supported(bitmap) = readings.next().unwrap().unwrap().value else {
            panic!("{reply:02X?}");
        };
        supported.extend(bitmap.iter().filter(|pid| !pid.is_multiple_of(0x20)));
        base = b.checked_add(0x20).filter(|&next| bitmap.contains(next));
    }
    assert_eq!(
        supported,
        [
            0x04, 0x05, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x1F, 0x21, 0x30, 0x33, 0x3C, 0x42, 0x5D,
            0x5E, 0x61, 0x63, 0xFF
        ]
    );
}

#[test]
fn mode_03_lists_the_edge_code_of_every_system() {
    let reply = ask(&mut bus(), ENGINE, &obd::stored_dtcs());
    assert_eq!(reply[..2], [0x43, 9]);
    // Two bytes per code: the top two bits choose the system, the other 14 are the number.
    assert_eq!(
        reply[2..],
        [
            0x00, 0x01, 0x0A, 0x7F, 0x3F, 0xFF, 0x40, 0x00, 0x7F, 0xFF, 0x80, 0x00, 0xBF, 0xFF,
            0xC0, 0x00, 0xFF, 0xFF
        ]
    );
    let codes: Vec<_> = obd::decode_stored_dtcs(&reply)
        .unwrap()
        .map(|dtc| dtc.to_string())
        .collect();
    assert_eq!(
        codes,
        [
            "P0001", "P0A7F", "P3FFF", "C0000", "C3FFF", "B0000", "B3FFF", "U0000", "U3FFF"
        ]
    );
}

#[test]
fn mode_03_with_no_codes_is_a_count_of_zero() {
    let reply = ask(&mut bus(), TRANSMISSION, &obd::stored_dtcs());
    assert_eq!(reply, [0x43, 0x00]);
    assert_eq!(obd::decode_stored_dtcs(&reply).unwrap().count(), 0);
}

fn dtc_fixture(count: u16) -> String {
    // P0001 up: the codes below it, P0000, are padding.
    let codes: Vec<_> = (1..=count).map(|n| format!("\"P{n:04X}\"")).collect();
    format!(
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ndtcs = [{}]\n",
        codes.join(", ")
    )
}

#[test]
fn mode_03_carries_255_codes_and_the_fixture_refuses_a_256th() {
    let mut bus = bus_with(&dtc_fixture(255)).unwrap();
    let reply = ask(&mut bus, ENGINE, &obd::stored_dtcs());
    assert_eq!(reply.len(), 2 + 255 * 2);
    assert_eq!(reply[1], 0xFF);
    let codes: Vec<_> = obd::decode_stored_dtcs(&reply).unwrap().collect();
    assert_eq!(codes.len(), 255);
    assert_eq!(codes[254].to_string(), "P00FF");
    assert!(matches!(
        bus_with(&dtc_fixture(256)),
        Err(FixtureError::Value(_))
    ));
}

#[test]
fn mode_09_vin_uses_the_letters_either_side_of_the_excluded_ones() {
    let mut bus = bus();
    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x02));
    assert_eq!(obd::decode_vin(&reply).unwrap(), "0123456789ABCDEFG");
    let reply = ask(&mut bus, TRANSMISSION, &obd::vehicle_info(0x02));
    assert_eq!(obd::decode_vin(&reply).unwrap(), "HJKLMNPRSTUVWXYZ9");
    // The excluded letters are the three that look like digits.
    for excluded in ["I", "O", "Q"] {
        let fixture = format!(
            "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"0123456789ABCDEF{excluded}\"\n"
        );
        assert!(bus_with(&fixture).is_err(), "{excluded}");
    }
}

#[test]
fn mode_09_calibration_ids_fill_their_slot_or_leave_it_empty() {
    let mut bus = bus();
    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x04));
    assert_eq!(reply.len(), 3 + 4 * 16);
    let calids: Vec<_> = obd::decode_calids(&reply)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // 16 characters leave no padding, 1 leaves 15 bytes of it, and an empty slot is all padding.
    assert_eq!(
        calids,
        [
            Some("ABCDEFGHJKLMNPRS"),
            Some("A"),
            None,
            Some("0123456789ABCDEF")
        ]
    );

    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x06));
    let cvns: Vec<_> = obd::decode_cvns(&reply)
        .unwrap()
        .map(|cvn| cvn.to_string())
        .collect();
    assert_eq!(cvns, ["FFFFFFFF", "00000001", "00000000", "80000000"]);

    let reply = ask(&mut bus, TRANSMISSION, &obd::vehicle_info(0x04));
    let calids: Vec<_> = obd::decode_calids(&reply)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(calids, [Some("Z")]);
}

fn calid_fixture(count: usize) -> String {
    let mut fixture = String::from("[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\n");
    let calids: Vec<_> = (0..count).map(|n| format!("\"CAL{n:013}\"")).collect();
    let cvns = vec!["\"00 00 00 01\""; count];
    writeln!(fixture, "calids = [{}]", calids.join(", ")).unwrap();
    writeln!(fixture, "cvns = [{}]", cvns.join(", ")).unwrap();
    fixture
}

#[test]
fn mode_09_carries_255_calibration_ids_and_the_fixture_refuses_a_256th() {
    let mut bus = bus_with(&calid_fixture(255)).unwrap();
    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x04));
    assert_eq!(reply.len(), 3 + 255 * 16);
    assert_eq!(reply[2], 0xFF);
    let calids: Vec<_> = obd::decode_calids(&reply)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(calids.len(), 255);
    assert_eq!(calids[254], Some("CAL0000000000254"));
    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x06));
    assert_eq!(obd::decode_cvns(&reply).unwrap().count(), 255);
    assert!(matches!(
        bus_with(&calid_fixture(256)),
        Err(FixtureError::Value(_))
    ));
}

#[test]
fn mode_09_names_at_full_width_and_the_supported_pids_that_hold_them() {
    let mut bus = bus();
    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x0A));
    let name = obd::decode_ecu_name(&reply).unwrap();
    assert_eq!((name.acronym, name.name), ("ABCD", "ABCDEFGHIJKLMNO"));
    let reply = ask(&mut bus, TRANSMISSION, &obd::vehicle_info(0x0A));
    let name = obd::decode_ecu_name(&reply).unwrap();
    assert_eq!((name.acronym, name.name), ("T", "T"));

    let reply = ask(&mut bus, ENGINE, &obd::vehicle_info(0x00));
    let supported = obd::decode_supported_info(&reply).unwrap();
    assert_eq!(
        supported.iter().collect::<Vec<_>>(),
        [0x02, 0x04, 0x06, 0x0A]
    );
}
