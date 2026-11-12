//! Modes 02, 06, 07 and 0A: what the synthetic `obd-modes.toml` answers, and what a fixture may say
//! about them. Every expected reply is worked out by hand from SAE J1979, not read back from the
//! decoders.

use std::time::Duration;

use obdcracker_core::obd;
use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_sim::{FixtureError, SimBus};
use obdcracker_transport::{Error, Transport};

const ENGINE: Target = Target::Physical(0x7E0);
const TRANSMISSION: Target = Target::Physical(0x7E1);
const FIXTURE: &str = include_str!("../fixtures/obd-modes.toml");

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

// Every reply to the request, by the ID it came from.
fn ask_all(bus: &mut SimBus, target: Target, payload: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let request = Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap();
    bus.send(&request).unwrap();
    let mut replies = Vec::new();
    loop {
        match bus.recv(Duration::from_millis(5)) {
            Ok(reply) => replies.push((reply.source, reply.payload)),
            Err(Error::Timeout) => return replies,
            Err(e) => panic!("{e}"),
        }
    }
}

// The one reply, or none.
fn ask(bus: &mut SimBus, target: Target, payload: &[u8]) -> Option<Vec<u8>> {
    let mut replies = ask_all(bus, target, payload);
    assert!(replies.len() <= 1, "{replies:02X?}");
    replies.pop().map(|(_, payload)| payload)
}

#[test]
fn mode_07_lists_the_pending_codes_and_an_empty_list_has_a_count_of_0() {
    let mut bus = bus();
    // P0299 is 0x0299 and U3FFF is 0xFFFF.
    assert_eq!(
        ask(&mut bus, ENGINE, &obd::pending_dtcs()),
        Some(vec![0x47, 2, 0x02, 0x99, 0xFF, 0xFF])
    );
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::pending_dtcs()),
        Some(vec![0x47, 0])
    );
}

#[test]
fn mode_0a_answers_only_where_the_fixture_lists_permanent_codes() {
    let mut bus = bus();
    assert_eq!(
        ask(&mut bus, ENGINE, &obd::permanent_dtcs()),
        Some(vec![0x4A, 0])
    );
    // A physical request to a module without the mode is refused as not supported; broadcast, the
    // module stays silent (ISO 14229-1), so only the engine answers.
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::permanent_dtcs()),
        Some(vec![0x7F, 0x0A, 0x11])
    );
    assert_eq!(
        ask_all(&mut bus, Target::ObdFunctional, &obd::permanent_dtcs()),
        [(0x7E8, vec![0x4A, 0])]
    );
}

#[test]
fn mode_02_answers_the_cause_the_bitmap_and_each_pid_of_frame_0() {
    let mut bus = bus();
    let frame = |bus: &mut SimBus, pid| ask(bus, ENGINE, &obd::freeze_frame(pid, 0));
    assert_eq!(
        frame(&mut bus, 0x02),
        Some(vec![0x42, 0x02, 0x00, 0x02, 0x99])
    );
    // PIDs 02, 04, 05 and 0C: bits 6, 4 and 3 of the first byte, and bit 4 of the second. No PID
    // above 0x20, so no next bitmap.
    assert_eq!(
        frame(&mut bus, 0x00),
        Some(vec![0x42, 0x00, 0x00, 0x58, 0x10, 0x00, 0x00])
    );
    assert_eq!(frame(&mut bus, 0x04), Some(vec![0x42, 0x04, 0x00, 0x80]));
    assert_eq!(frame(&mut bus, 0x05), Some(vec![0x42, 0x05, 0x00, 0x82]));
    assert_eq!(
        frame(&mut bus, 0x0C),
        Some(vec![0x42, 0x0C, 0x00, 0x0C, 0x80])
    );
    // A PID the frame doesn't hold, and a frame the module doesn't have, get no answer.
    assert_eq!(frame(&mut bus, 0x06), None);
    assert_eq!(ask(&mut bus, ENGINE, &obd::freeze_frame(0x04, 1)), None);
    assert_eq!(ask(&mut bus, ENGINE, &obd::freeze_frame(0x02, 1)), None);
}

#[test]
fn a_frame_with_no_dtc_stored_answers_cause_p0000() {
    let mut bus = bus();
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::freeze_frame(0x02, 0)),
        Some(vec![0x42, 0x02, 0x00, 0x00, 0x00])
    );
    // Only PID 02 is in it.
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::freeze_frame(0x00, 0)),
        Some(vec![0x42, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00])
    );
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::freeze_frame(0x04, 0)),
        None
    );
}

#[test]
fn mode_06_bitmaps_chain_through_every_range_up_to_the_highest_monitor_id() {
    let mut bus = bus();
    let bitmap = |bus: &mut SimBus, base| ask(bus, ENGINE, &obd::monitor_results(base));
    // 01 and 02 are bits 31 and 30; 21 and FF are above, so a next range follows.
    assert_eq!(
        bitmap(&mut bus, 0x00),
        Some(vec![0x46, 0x00, 0xC0, 0x00, 0x00, 0x01])
    );
    // 21 is the first ID of the second range.
    assert_eq!(
        bitmap(&mut bus, 0x20),
        Some(vec![0x46, 0x20, 0x80, 0x00, 0x00, 0x01])
    );
    for base in [0x40, 0x60, 0x80, 0xA0, 0xC0] {
        assert_eq!(
            bitmap(&mut bus, base),
            Some(vec![0x46, base, 0x00, 0x00, 0x00, 0x01]),
            "{base:02X}"
        );
    }
    // FF is the last ID of the last range (bit 1), and says nothing is next.
    assert_eq!(
        bitmap(&mut bus, 0xE0),
        Some(vec![0x46, 0xE0, 0x00, 0x00, 0x00, 0x02])
    );
}

#[test]
fn mode_06_test_records_are_not_modelled() {
    assert_eq!(ask(&mut bus(), ENGINE, &obd::monitor_results(0x01)), None);
}

#[test]
fn a_mode_the_module_doesnt_list_is_not_supported_when_asked_alone_and_silent_to_everyone() {
    let mut bus = bus();
    assert_eq!(
        ask(&mut bus, TRANSMISSION, &obd::monitor_results(0x00)),
        Some(vec![0x7F, 0x06, 0x11])
    );
    assert_eq!(
        ask_all(&mut bus, Target::ObdFunctional, &obd::monitor_results(0x00)),
        [(0x7E8, vec![0x46, 0x00, 0xC0, 0x00, 0x00, 0x01])]
    );
}

#[test]
fn the_new_modes_are_refused_from_a_module_without_an_obd_table() {
    let mut bus = bus_with("[[ecu]]\nmodule = \"engine\"\n").unwrap();
    for payload in [
        obd::pending_dtcs().to_vec(),
        obd::permanent_dtcs().to_vec(),
        obd::freeze_frame(0x02, 0).to_vec(),
        obd::monitor_results(0x00).to_vec(),
    ] {
        assert_eq!(
            ask(&mut bus, ENGINE, &payload),
            Some(vec![0x7F, payload[0], 0x11])
        );
        assert_eq!(ask_all(&mut bus, Target::ObdFunctional, &payload).len(), 0);
    }
}

fn with_obd(body: &str) -> Result<SimBus, FixtureError> {
    bus_with(&format!(
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\n{body}\n"
    ))
}

fn dtcs(count: usize) -> String {
    let codes: Vec<String> = (1..=count).map(|n| format!("\"P{n:04X}\"")).collect();
    format!("[{}]", codes.join(", "))
}

#[test]
fn a_dtc_list_takes_up_to_255_codes_and_refuses_padding_and_repeats() {
    for key in ["pending_dtcs", "permanent_dtcs"] {
        assert!(with_obd(&format!("{key} = {}", dtcs(255))).is_ok(), "{key}");
        for bad in [
            dtcs(256),
            "[\"P0000\"]".to_owned(),
            "[\"P0299\", \"P0299\"]".to_owned(),
            "[\"p0299\"]".to_owned(),
            "[\"P029\"]".to_owned(),
            "[\"X0299\"]".to_owned(),
        ] {
            assert!(with_obd(&format!("{key} = {bad}")).is_err(), "{key} {bad}");
        }
    }
}

#[test]
fn a_freeze_frame_needs_a_cause_for_its_pids_and_checks_them_like_mode_01() {
    assert!(with_obd("[ecu.obd.freeze_frame]\ncause = \"P0299\"").is_ok());
    assert!(with_obd("freeze_frame = {}").is_ok());
    for bad in [
        // PIDs but no cause
        "[ecu.obd.freeze_frame.pids]\n\"04\" = \"80\"",
        "[ecu.obd.freeze_frame]\ncause = \"P0000\"",
        // Bitmap PIDs are computed, and PID 02 is the cause
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"00\" = \"00 00 00 00\"",
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"20\" = \"00 00 00 00\"",
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"02\" = \"02 99\"",
        // 04 is one byte
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"04\" = \"80 80\"",
        // The same PID spelled twice
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"0C\" = \"0C 80\"\n\"0c\" = \"0C 80\"",
        "[ecu.obd.freeze_frame]\ncause = \"P0299\"\n[ecu.obd.freeze_frame.pids]\n\"+4\" = \"80\"",
    ] {
        assert!(with_obd(bad).is_err(), "{bad}");
    }
}

#[test]
fn monitor_ids_are_two_hex_digits_other_than_a_bitmap_id_and_listed_once() {
    assert!(with_obd("monitor_ids = []").is_ok());
    assert!(with_obd("monitor_ids = [\"01\", \"FF\", \"1F\", \"21\"]").is_ok());
    for bad in [
        "[\"00\"]",
        "[\"20\"]",
        "[\"E0\"]",
        "[\"1\"]",
        "[\"001\"]",
        "[\"+1\"]",
        "[\"G1\"]",
        "[\"0A\", \"0a\"]",
        "[\"01\", \"01\"]",
    ] {
        assert!(with_obd(&format!("monitor_ids = {bad}")).is_err(), "{bad}");
    }
}

#[test]
fn an_empty_monitor_id_list_answers_the_first_bitmap_with_no_ids() {
    let mut bus = with_obd("monitor_ids = []").unwrap();
    assert_eq!(
        ask(&mut bus, ENGINE, &obd::monitor_results(0x00)),
        Some(vec![0x46, 0x00, 0x00, 0x00, 0x00, 0x00])
    );
    assert_eq!(ask(&mut bus, ENGINE, &obd::monitor_results(0x20)), None);
}
