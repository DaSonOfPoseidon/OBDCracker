//! The simulated A7 answering through the `Transport` trait, decoded with the M1 codecs.

use std::fmt::Write as _;
use std::time::Duration;

use obdcracker_core::obd::{self, Unit, Value};
use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::{self, DtcFormat, DtcStatus};
use obdcracker_profile::{DidSession, Profile, ProfileError};
use obdcracker_safety::{Approved, Policy, Target};
use obdcracker_sim::{Fault, FixtureError, Session, SimBus};
use obdcracker_transport::{Error, Expect, Response, Timing, Transport, exchange};
use proptest::prelude::*;

const ENGINE: Target = Target::Physical(0x7E0);
const TRANSMISSION: Target = Target::Physical(0x7E1);
const GATEWAY: Target = Target::Physical(0x710);
const INSTRUMENTS: Target = Target::Physical(0x714);
const TIMEOUT: Duration = Duration::from_millis(50);

fn a7() -> SimBus {
    SimBus::builtin("a7").unwrap()
}

// Behaviour the real A7 doesn't show, on the A7's addresses: a stored mode 03 code, a coding DID
// that needs the extended session, and the DTC count report.
const FEATURES: &str = r#"
[[ecu]]
module = "engine"
dtc_format = 0x00

[[ecu.dtc]]
code = 0x029900
status = 0x08

# No status bits set, so only 0x19 0x0A lists it.
[[ecu.dtc]]
code = 0x011300
status = 0x00

[ecu.obd]
dtcs = ["P0299"]

[[ecu.did]]
id = 0x0600
hex = "01 23 45 67 89 AB CD EF 01 23"
session = "extended"

[[ecu]]
module = "transmission"

[ecu.obd]
dtcs = []
"#;

fn features() -> SimBus {
    SimBus::new(&Profile::builtin("a7").unwrap(), FEATURES).unwrap()
}

// Sends one read and returns every reply it produced.
fn ask(bus: &mut SimBus, target: Target, payload: &[u8]) -> Vec<Response> {
    let request = Policy::read_only().approve(target, payload).unwrap();
    bus.send(&request).unwrap();
    let mut replies = Vec::new();
    loop {
        match bus.recv(TIMEOUT) {
            Ok(reply) => replies.push(reply),
            Err(Error::Timeout) => return replies,
            Err(e) => panic!("{e}"),
        }
    }
}

fn assert_silent(bus: &mut SimBus, target: Target, payload: &[u8]) {
    let replies = ask(bus, target, payload);
    assert!(replies.is_empty(), "{replies:?}");
}

fn ask_one(bus: &mut SimBus, target: Target, payload: &[u8]) -> Vec<u8> {
    let mut replies = ask(bus, target, payload);
    assert_eq!(replies.len(), 1, "{replies:?}");
    replies.remove(0).payload
}

fn nrc(reply: &[u8], sid: u8) -> Nrc {
    match obdcracker_core::response::positive(sid, reply) {
        Err(ReplyError::Negative(negative)) => negative.nrc,
        other => panic!("expected a negative reply, got {other:?}"),
    }
}

#[test]
fn nothing_to_receive_times_out() {
    assert_eq!(a7().recv(TIMEOUT), Err(Error::Timeout));
}

#[test]
fn functional_vin_is_answered_by_the_engine_only() {
    // As on the real A7 (#46): the transmission doesn't answer mode 09 PID 02.
    let replies = ask(&mut a7(), Target::ObdFunctional, &obd::vehicle_info(0x02));
    let sources: Vec<_> = replies.iter().map(|r| r.source).collect();
    assert_eq!(sources, [0x7E8]);
    assert_eq!(
        obd::decode_vin(&replies[0].payload).unwrap(),
        "WAU2MBFC6EN093415"
    );
}

#[test]
fn physical_obd_request_reaches_only_that_module() {
    let replies = ask(&mut a7(), ENGINE, &obd::vehicle_info(0x02));
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].source, 0x7E8);
}

#[test]
fn unknown_target_is_silent() {
    assert_silent(&mut a7(), Target::Physical(0x7A0), &uds::read_did(0xF190));
}

#[test]
fn records_what_was_sent() {
    let mut bus = a7();
    ask(&mut bus, ENGINE, &uds::read_did(0xF190));
    assert_eq!(bus.sent().len(), 1);
    assert_eq!(bus.sent()[0].payload(), [0x22, 0xF1, 0x90]);
}

#[test]
fn mode_01_supported_pid_bitmaps_chain_to_every_listed_pid() {
    let mut bus = a7();
    let mut supported = Vec::new();
    let mut base = Some(0x00u8);
    while let Some(b) = base {
        let reply = ask_one(&mut bus, ENGINE, &obd::current_data(b));
        let mut readings = obd::decode_current_data(&reply).unwrap();
        let reading = readings.next().unwrap().unwrap();
        let Value::Supported(bitmap) = reading.value else {
            panic!("{reading:?}");
        };
        supported.extend(bitmap.iter().filter(|pid| !pid.is_multiple_of(0x20)));
        base = b.checked_add(0x20).filter(|&next| bitmap.contains(next));
    }
    // The engine's real list (#49).
    assert_eq!(
        supported,
        [
            0x01, 0x04, 0x05, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x13, 0x1C, 0x1F, 0x21, 0x24, 0x30,
            0x31, 0x33, 0x3C, 0x3E, 0x41, 0x42, 0x45, 0x46, 0x49, 0x4A, 0x4C, 0x4F, 0x51, 0x5C,
            0x5D, 0x5E, 0x61, 0x62, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x70, 0x71, 0x78, 0x7A,
            0x7F, 0x81, 0x82, 0x83, 0x85, 0x88, 0x8B, 0x8F
        ]
    );
}

#[test]
fn mode_01_answers_several_pids_at_once() {
    let reply = ask_one(&mut a7(), ENGINE, &[0x01, 0x0C, 0x0D]);
    let readings: Vec<_> = obd::decode_current_data(&reply)
        .unwrap()
        .map(Result::unwrap)
        .map(|r| (r.pid, r.value))
        .collect();
    assert_eq!(
        readings,
        [
            (
                0x0C,
                Value::Quantity {
                    value: 0.0,
                    unit: Unit::Rpm
                }
            ),
            (
                0x0D,
                Value::Quantity {
                    value: 0.0,
                    unit: Unit::KilometresPerHour
                }
            ),
        ]
    );
}

#[test]
fn unsupported_obd_pid_gets_no_reply() {
    // Neither the engine nor the transmission supports PID 0A (fuel pressure).
    assert_silent(&mut a7(), Target::ObdFunctional, &obd::current_data(0x0A));
    assert_silent(&mut a7(), Target::ObdFunctional, &obd::vehicle_info(0x08));
}

#[test]
fn mode_03_lists_stored_dtcs_per_module() {
    let replies = ask(&mut features(), Target::ObdFunctional, &obd::stored_dtcs());
    let dtcs: Vec<(u32, Vec<String>)> = replies
        .iter()
        .map(|r| {
            let codes = obd::decode_stored_dtcs(&r.payload).unwrap();
            (r.source, codes.map(|dtc| dtc.to_string()).collect())
        })
        .collect();
    assert_eq!(dtcs, [(0x7E8, vec!["P0299".into()]), (0x7E9, vec![])]);
    // The real A7 has none stored (#49).
    let replies = ask(&mut a7(), Target::ObdFunctional, &obd::stored_dtcs());
    assert_eq!(replies.len(), 2);
    for reply in replies {
        assert_eq!(obd::decode_stored_dtcs(&reply.payload).unwrap().count(), 0);
    }
}

#[test]
fn mode_09_reports_calids_cvns_and_name() {
    let mut bus = a7();
    let calids = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x04));
    let calids: Vec<_> = obd::decode_calids(&calids)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // The engine's real reply (#46): five slots, the second one empty.
    assert_eq!(calids.len(), 5);
    assert_eq!(calids[..2], [Some("4G0401N 0016BVAB"), None]);
    let cvns = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x06));
    assert_eq!(obd::decode_cvns(&cvns).unwrap().count(), 5);
    let name = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x0A));
    let name = obd::decode_ecu_name(&name).unwrap();
    assert_eq!((name.acronym, name.name), ("ECM", "EngineControl"));
    let supported = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x00));
    let supported = obd::decode_supported_info(&supported).unwrap();
    assert_eq!(
        supported.iter().collect::<Vec<_>>(),
        [0x02, 0x04, 0x06, 0x0A]
    );
}

#[test]
fn module_without_obd_refuses_obd_services() {
    let reply = ask_one(&mut a7(), GATEWAY, &obd::vehicle_info(0x02));
    assert_eq!(nrc(&reply, 0x09), Nrc::ServiceNotSupported);
}

#[test]
fn reads_one_did() {
    let reply = ask_one(
        &mut a7(),
        GATEWAY,
        &uds::read_did(uds::did::SPARE_PART_NUMBER),
    );
    let data = uds::decode_did(&reply, uds::did::SPARE_PART_NUMBER).unwrap();
    assert_eq!(uds::decode_text(data).unwrap(), "4G0907468AD");
    // The gateway and instruments refuse F190 (#49).
    for target in [GATEWAY, INSTRUMENTS] {
        let reply = ask(&mut a7(), target, &uds::read_did(uds::did::VIN))
            .pop()
            .unwrap()
            .payload;
        assert_eq!(nrc(&reply, 0x22), Nrc::RequestOutOfRange);
    }
}

#[test]
fn reads_several_dids_in_request_order() {
    let reply = ask_one(&mut a7(), ENGINE, &[0x22, 0xF1, 0x89, 0xF1, 0x87]);
    let values: Vec<_> = uds::decode_dids(&reply, &[(0xF189, 4), (0xF187, 11)])
        .unwrap()
        .map(|value| {
            let (did, data) = value.unwrap();
            (did, uds::decode_text(data).unwrap().to_owned())
        })
        .collect();
    assert_eq!(
        values,
        [(0xF189, "0016".into()), (0xF187, "4G0907401N".into())]
    );
}

#[test]
fn unknown_dids_are_dropped_or_refused() {
    let mut bus = a7();
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0x1234));
    assert_eq!(nrc(&reply, 0x22), Nrc::RequestOutOfRange);
    let reply = ask_one(&mut bus, ENGINE, &[0x22, 0x12, 0x34, 0xF1, 0x90]);
    assert_eq!(uds::decode_did(&reply, 0xF190).unwrap().len(), 17);
}

#[test]
fn coding_did_needs_the_extended_session() {
    let mut bus = features();
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0x0600));
    assert_eq!(nrc(&reply, 0x22), Nrc::RequestOutOfRange);

    let reply = ask_one(&mut bus, ENGINE, &[0x10, 0x03]);
    assert_eq!(reply, [0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]);
    assert_eq!(bus.ecu("engine").unwrap().session(), Session::Extended);
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0x0600));
    assert!(uds::decode_did(&reply, 0x0600).is_ok());

    ask_one(&mut bus, ENGINE, &[0x10, 0x01]);
    assert_eq!(bus.ecu("engine").unwrap().session(), Session::Default);
}

#[test]
fn a7_coding_reads_in_the_default_session() {
    // Every A7 module that has a coding answered 0600 without a session change (#49, #86). The
    // instruments send response-pending first, so the answer is the last reply.
    let profile = Profile::builtin("a7").unwrap();
    let mut bus = a7();
    let mut read = 0;
    for module in &profile.modules {
        let target = Target::Physical(module.request_id);
        let reply = ask(&mut bus, target, &uds::read_did(0x0600))
            .pop()
            .unwrap()
            .payload;
        if module.dids.iter().any(|did| did.id == 0x0600) {
            assert!(uds::decode_did(&reply, 0x0600).is_ok(), "{}", module.name);
            read += 1;
        } else {
            // The transmission, and the three modules that refused it in #86.
            assert_eq!(nrc(&reply, 0x22), Nrc::RequestOutOfRange, "{}", module.name);
        }
    }
    assert_eq!(read, 20);
}

#[test]
fn a7_answers_every_profile_did_with_its_length() {
    // A DID the profile gives a length for is one the car answered, so the sim must answer it too,
    // or `--sim a7 scan` shows a refusal the car never sent (PR #127, Codex).
    let profile = Profile::builtin("a7").unwrap();
    let mut bus = a7();
    for module in &profile.modules {
        for did in &module.dids {
            let (Some(length), DidSession::Default) = (did.length, did.session) else {
                continue;
            };
            let target = Target::Physical(module.request_id);
            let reply = ask(&mut bus, target, &uds::read_did(did.id))
                .pop()
                .unwrap()
                .payload;
            let [high, low] = did.id.to_be_bytes();
            assert_eq!(
                reply[..3],
                [0x62, high, low],
                "{} {:04X}",
                module.name,
                did.id
            );
            assert_eq!(
                reply.len() - 3,
                usize::from(length),
                "{} {:04X}",
                module.name,
                did.id
            );
        }
    }
}

#[test]
fn a7_hud_answers_as_its_sweeps_did() {
    // #86: 0100 answered only in the extended session, refused as out of range in the default one;
    // 028D was refused for want of security access in both.
    let hud = Target::Physical(0x71B);
    let mut bus = a7();
    let reply = ask_one(&mut bus, hud, &uds::read_did(0x0100));
    assert_eq!(nrc(&reply, 0x22), Nrc::RequestOutOfRange);
    let reply = ask_one(&mut bus, hud, &uds::read_did(0x028D));
    assert_eq!(nrc(&reply, 0x22), Nrc::SecurityAccessDenied);
    assert_eq!(
        ask_one(&mut bus, hud, &uds::read_did(0x0502)),
        [
            0x62, 0x05, 0x02, 0x1E, 0x82, 0x14, 0x02, 0x02, 0x32, 0x32, 0x40, 0x00, 0x3B, 0x00
        ]
    );
    ask_one(&mut bus, hud, &[0x10, 0x03]);
    assert_eq!(
        ask_one(&mut bus, hud, &uds::read_did(0x0100)),
        [0x62, 0x01, 0x00, 0x00]
    );
    let reply = ask_one(&mut bus, hud, &uds::read_did(0x028D));
    assert_eq!(nrc(&reply, 0x22), Nrc::SecurityAccessDenied);
}

#[test]
fn suppress_bit_silences_positive_replies_only() {
    let mut bus = a7();
    assert_silent(&mut bus, ENGINE, &[0x10, 0x83]);
    assert_eq!(bus.ecu("engine").unwrap().session(), Session::Extended);
    assert_silent(&mut bus, ENGINE, &[0x3E, 0x80]);
    assert_silent(&mut bus, ENGINE, &[0x19, 0x82, 0x08]);
    // A refusal is sent even with the bit set.
    let reply = ask_one(&mut bus, ENGINE, &[0x19, 0x84, 0x08]);
    assert_eq!(nrc(&reply, 0x19), Nrc::SubFunctionNotSupported);
    assert_eq!(ask_one(&mut bus, ENGINE, &[0x3E, 0x00]), [0x7E, 0x00]);
}

#[test]
fn reads_uds_dtcs() {
    let mut bus = features();
    let reply = ask_one(&mut bus, ENGINE, &uds::dtc_count_by_status_mask(0x08));
    let count = uds::decode_dtc_count(&reply).unwrap();
    assert_eq!((count.format, count.count), (DtcFormat::SaeJ2012Da00, 1));

    let reply = ask_one(&mut bus, ENGINE, &uds::dtcs_by_status_mask(0x08));
    let (_, records) = uds::decode_dtcs_by_status_mask(&reply).unwrap();
    let records: Vec<_> = records.collect();
    assert_eq!(records.len(), 1);
    let j2012 = records[0].dtc.j2012(DtcFormat::SaeJ2012Da00).unwrap();
    assert_eq!(j2012.to_string(), "P0299-00");

    let reply = ask_one(&mut bus, ENGINE, &uds::supported_dtcs());
    assert_eq!(uds::decode_supported_dtcs(&reply).unwrap().1.count(), 2);
}

// A module that, like every A7 module (#49), only reports DTCs by status mask, and supports only
// some status bits.
const DTC_REPORTS: &str = r#"
[[ecu]]
module = "engine"
status_availability = 0x09
dtc_reports = [0x02]

[[ecu.dtc]]
code = 0x029900
status = 0x08

[[ecu.dtc]]
code = 0x011300
status = 0x01
"#;

#[test]
fn a_module_answers_only_the_dtc_reports_it_supports() {
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), DTC_REPORTS).unwrap();
    for request in [
        &uds::dtc_count_by_status_mask(0xFF)[..],
        &uds::supported_dtcs(),
    ] {
        let reply = ask_one(&mut bus, ENGINE, request);
        assert_eq!(
            nrc(&reply, 0x19),
            Nrc::SubFunctionNotSupported,
            "{request:02X?}"
        );
    }
    let reply = ask_one(&mut bus, ENGINE, &uds::dtcs_by_status_mask(0x08));
    let (availability, records) = uds::decode_dtcs_by_status_mask(&reply).unwrap();
    assert_eq!(availability, DtcStatus(0x09));
    let records: Vec<_> = records.map(|r| (r.dtc.code(), r.status)).collect();
    assert_eq!(records, [(0x02_9900, DtcStatus(0x08))]);
}

#[test]
fn dtc_report_settings_are_checked() {
    let a7 = Profile::builtin("a7").unwrap();
    let engine = "[[ecu]]\nmodule = \"engine\"\n";
    for bad in [
        // Not a report the sim implements, or listed twice.
        "dtc_reports = [0x04]\n",
        "dtc_reports = [0x02, 0x02]\n",
        // A module that reports no DTCs at all doesn't support the service; leave it out.
        "dtc_reports = []\n",
        // The format is only sent in the count report (0x01).
        "dtc_reports = [0x02]\ndtc_format = 0x00\n",
        // A status may only use bits the module says it supports.
        "status_availability = 0x09\n[[ecu.dtc]]\ncode = 0x029900\nstatus = 0x10\n",
    ] {
        assert!(
            matches!(
                SimBus::new(&a7, &format!("{engine}{bad}")),
                Err(FixtureError::Value(_))
            ),
            "{bad}"
        );
    }
}

#[test]
fn a7_modules_report_dtcs_as_the_car_did() {
    // Session 2 (#49): every module refuses the count report and lists its DTC table by status
    // mask, but no DTC is failed, pending or confirmed. The transmission says it's busy first.
    let mut bus = a7();
    for (target, availability, pending) in [
        (ENGINE, 0xFF, 0),
        (TRANSMISSION, 0xFF, 1),
        (GATEWAY, 0x19, 0),
        (INSTRUMENTS, 0x19, 0),
    ] {
        let reply = ask_one(&mut bus, target, &uds::dtc_count_by_status_mask(0xFF));
        assert_eq!(nrc(&reply, 0x19), Nrc::SubFunctionNotSupported);
        let mut replies = payloads(&ask(&mut bus, target, &uds::dtcs_by_status_mask(0xFF)));
        let reply = replies.pop().unwrap();
        assert_eq!(replies.len(), pending, "{target:?}");
        assert!(replies.iter().all(|r| nrc(r, 0x19).is_pending()));
        let (status, records) = uds::decode_dtcs_by_status_mask(&reply).unwrap();
        assert_eq!(status, DtcStatus(availability), "{target:?}");
        assert!(records.count() > 0, "{target:?}");
        let reply = ask(&mut bus, target, &uds::dtcs_by_status_mask(0x0F))
            .pop()
            .unwrap();
        let (_, records) = uds::decode_dtcs_by_status_mask(&reply.payload).unwrap();
        assert_eq!(records.count(), 0, "{target:?}");
    }
}

#[test]
fn bad_dtc_requests_are_refused() {
    let mut bus = a7();
    let reply = ask_one(&mut bus, ENGINE, &[0x19, 0x04, 0x00, 0x00, 0x00, 0xFF]);
    assert_eq!(nrc(&reply, 0x19), Nrc::SubFunctionNotSupported);
    let reply = ask_one(&mut bus, ENGINE, &[0x19, 0x02]);
    assert_eq!(nrc(&reply, 0x19), Nrc::IncorrectMessageLength);
}

const PENDING: &str = r#"
[[ecu]]
module = "engine"

[[ecu.did]]
id = 0xF190
text = "WAUZZZ4G1EN000000"
pending = 2
"#;

#[test]
fn slow_did_sends_response_pending_first() {
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), PENDING).unwrap();
    let replies = ask(&mut bus, ENGINE, &uds::read_did(0xF190));
    let payloads: Vec<_> = replies.iter().map(|r| r.payload.as_slice()).collect();
    assert_eq!(payloads.len(), 3);
    assert!(nrc(payloads[0], 0x22).is_pending());
    assert!(nrc(payloads[1], 0x22).is_pending());
    assert!(uds::decode_did(payloads[2], 0xF190).is_ok());
}

#[test]
fn exchange_collects_the_calids_from_every_obd_ecu() {
    let calids = Policy::read_only()
        .approve(Target::ObdFunctional, &obd::vehicle_info(0x04))
        .unwrap();
    let replies = exchange(&mut a7(), &calids, Expect::ObdEcus, Timing::default()).unwrap();
    let counts: Vec<_> = replies
        .iter()
        .map(|r| (r.source, obd::decode_calids(&r.payload).unwrap().count()))
        .collect();
    assert_eq!(counts, [(0x7E8, 5), (0x7E9, 1)]);
}

#[test]
fn exchange_waits_through_a_slow_did() {
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), PENDING).unwrap();
    let read = Policy::read_only()
        .approve(ENGINE, &uds::read_did(0xF190))
        .unwrap();
    let replies = exchange(&mut bus, &read, Expect::Module(0x7E8), Timing::default()).unwrap();
    assert_eq!(replies.len(), 1);
    assert!(uds::decode_did(&replies[0].payload, 0xF190).is_ok());
}

#[test]
fn faults_corrupt_or_drop_replies() {
    let mut bus = a7();
    let vin = uds::read_did(0xF190);

    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(Fault::Silent));
    assert_silent(&mut bus, ENGINE, &vin);

    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(Fault::Truncate(4)));
    let reply = ask_one(&mut bus, ENGINE, &vin);
    assert_eq!(uds::decode_did(&reply, 0xF190), Ok(&reply[3..4]));
    assert_eq!(reply.len(), 4);

    bus.ecu_mut("engine")
        .unwrap()
        .set_fault(Some(Fault::WrongSid));
    let reply = ask_one(&mut bus, ENGINE, &vin);
    assert!(matches!(
        uds::decode_did(&reply, 0xF190),
        Err(ReplyError::WrongService(_))
    ));

    bus.ecu_mut("engine").unwrap().set_fault(None);
    assert!(uds::decode_did(&ask_one(&mut bus, ENGINE, &vin), 0xF190).is_ok());
}

#[test]
fn fixture_errors_are_reported() {
    let a7 = Profile::builtin("a7").unwrap();
    assert!(matches!(
        SimBus::new(&a7, "[[ecu]]\nmodule = \"radio\"\n"),
        Err(FixtureError::UnknownModule(name)) if name == "radio"
    ));
    assert!(matches!(
        SimBus::new(&a7, "[[ecu]]\nmodul = \"engine\"\n"),
        Err(FixtureError::Toml(_))
    ));
    assert!(matches!(
        SimBus::new(
            &a7,
            "[[ecu]]\nmodule = \"engine\"\n[[ecu]]\nmodule = \"engine\"\n"
        ),
        Err(FixtureError::DuplicateModule(_))
    ));
    let bad_hex = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\nhex = \"0G\"\n";
    assert!(matches!(
        SimBus::new(&a7, bad_hex),
        Err(FixtureError::Value(_))
    ));
    for bad in [
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\nhex = \"+F\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\ntext = \"a\\u0001\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ndtcs = [\"P+299\"]\n",
        // 0000 is mode 03's padding (SAE J1979), not a code.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ndtcs = [\"P0000\"]\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"+5\" = \"00\"\n",
        // I, O and Q aren't VIN characters, and neither are lower case letters.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"WAUZZZ4G1EN00000O\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"wauzzz4g1en000000\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\nhex = \"00\"\n[[ecu.did]]\nid = 1\nhex = \"01\"\n",
        // The same code twice, in mode 03 or UDS, would be reported twice.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ndtcs = [\"P0299\", \"P0299\"]\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.dtc]]\ncode = 0x029900\nstatus = 0x08\n[[ecu.dtc]]\ncode = 0x029900\nstatus = 0x00\n",
        // 0x000000 is no code, and 0xFFFFFF means every group (ISO 14229-1), not one DTC.
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.dtc]]\ncode = 0\nstatus = 0x08\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.dtc]]\ncode = 0xFFFFFF\nstatus = 0x08\n",
        // Values that are only spaces or padding are empty.
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\ntext = \"   \"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF187\nhex = \"20 20\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF197\nhex = \"00\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ncalids = [\"   \"]\ncvns = [\"00 00 00 00\"]\n",
        // PID keys that differ only in case name the same PID.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"0c\" = \"0C 80\"\n\"0C\" = \"0C 80\"\n",
        // PID 0C is two bytes (SAE J1979), not one or three.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"0C\" = \"00\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"0C\" = \"0C 80 00\"\n",
    ] {
        assert!(
            matches!(SimBus::new(&a7, bad), Err(FixtureError::Value(_))),
            "{bad}"
        );
    }
    assert!(matches!(
        SimBus::builtin("delorean"),
        Err(FixtureError::Profile(_))
    ));
}

#[test]
fn pids_the_decoder_doesnt_know_take_any_length() {
    // SAE J1979 doesn't define PID 0xE1.
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"E1\" = \"01 02 03\"\n";
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap();
    assert_eq!(
        ask_one(&mut bus, ENGINE, &obd::current_data(0xE1)),
        [0x41, 0xE1, 0x01, 0x02, 0x03]
    );
}

#[test]
fn fixture_dids_must_be_standard_or_in_the_profile() {
    let a7 = Profile::builtin("a7").unwrap();
    // 0x0601 is a typo for the profile's 0x0600 coding DID.
    let typo = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0x0601\nhex = \"00\"\n";
    assert_eq!(
        SimBus::new(&a7, typo).unwrap_err(),
        FixtureError::UnknownDid {
            module: "engine".into(),
            did: 0x0601
        }
    );
    // Standard identification DIDs (0xF180..=0xF19F) need no profile entry.
    let standard = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF18C\ntext = \"123\"\n";
    assert!(SimBus::new(&a7, standard).is_ok());
}

#[test]
fn replies_longer_than_the_short_isotp_length_are_sent_whole() {
    let value = vec!["AB"; 5000].join(" ");
    let fixture =
        format!("[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0x0600\nhex = \"{value}\"\n");
    // Without the A7's 10-byte coding length, so any length goes.
    let mut a7 = Profile::builtin("a7").unwrap();
    for did in &mut a7.modules[0].dids {
        did.length = None;
    }
    let mut bus = SimBus::new(&a7, &fixture).unwrap();
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0x0600));
    assert_eq!(uds::decode_did(&reply, 0x0600).unwrap().len(), 5000);
}

#[test]
fn only_obd_ids_can_have_obd_data() {
    // The gateway answers on 0x77A, outside 0x7E8..=0x7EF, so it can't be an OBD-II ECU.
    let fixture = "[[ecu]]\nmodule = \"gateway\"\n[ecu.obd]\nvin = \"WAUZZZ4G1EN000000\"\n";
    assert_eq!(
        SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap_err(),
        FixtureError::NotObd("gateway".into())
    );
}

#[test]
fn profiles_built_by_hand_are_validated() {
    let mut a7 = Profile::builtin("a7").unwrap();
    // Two modules on one request ID would both answer it.
    a7.modules[1].request_id = 0x7E0;
    assert!(matches!(
        SimBus::new(&a7, "[[ecu]]\nmodule = \"engine\"\n"),
        Err(FixtureError::Profile(ProfileError::DuplicateId(0x7E0)))
    ));
}

#[test]
fn fixture_values_must_have_the_profile_length() {
    // The A7 profile gives the engine's coding (0600) as 10 bytes.
    let a7 = Profile::builtin("a7").unwrap();
    let coding = |hex: &str| {
        format!("[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0x0600\nhex = \"{hex}\"\n")
    };
    for wrong in [
        "1A 2A 40 12 05 66 01 05 00",
        "1A 2A 40 12 05 66 01 05 00 00 00",
    ] {
        assert!(
            matches!(
                SimBus::new(&a7, &coding(wrong)),
                Err(FixtureError::Value(_))
            ),
            "{wrong}"
        );
    }
    assert!(SimBus::new(&a7, &coding("1A 2A 40 12 05 66 01 05 00 00")).is_ok());
}

#[test]
fn fixture_values_must_suit_the_profile_decoder() {
    // The A7 profile declares 0xF197 (system name) as text.
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF197\nhex = \"FF 00 01\"\n";
    assert!(matches!(
        SimBus::new(&Profile::builtin("a7").unwrap(), fixture),
        Err(FixtureError::Value(_))
    ));
}

#[test]
fn uds_dtcs_must_fit_the_16_bit_count() {
    let mut fixture = String::from("[[ecu]]\nmodule = \"engine\"\n");
    for code in 1..=u32::from(u16::MAX) + 1 {
        writeln!(fixture, "[[ecu.dtc]]\ncode = {code}\nstatus = 0x08").unwrap();
    }
    assert!(matches!(
        SimBus::new(&Profile::builtin("a7").unwrap(), &fixture),
        Err(FixtureError::Value(_))
    ));
}

#[test]
fn standard_dids_must_have_their_iso_format() {
    let a7 = Profile::builtin("a7").unwrap();
    for (did, value) in [
        (0xF190, "hex = \"FF\""),
        (0xF190, "text = \"WAUZZZ4G1EN00000O\""),
        (0xF187, "hex = \"FF 00\""),
        (0xF19E, "hex = \"01\""),
    ] {
        let fixture = format!("[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = {did}\n{value}\n");
        assert!(
            matches!(SimBus::new(&a7, &fixture), Err(FixtureError::Value(_))),
            "0x{did:04X} {value}"
        );
    }
    // A profile entry for a standard DID doesn't replace its ISO format.
    let listed = Profile::from_toml(
        "name = \"x\"\nbitrate = 500000\n[[module]]\nname = \"engine\"\nrequest_id = 0x7E0\n\
         response_id = 0x7E8\nprotocol = \"uds\"\n[[module.did]]\nid = 0xF190\nname = \"VIN\"\n\
         decode = \"text\"\n",
    )
    .unwrap();
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\ntext = \"abc\"\n";
    assert!(matches!(
        SimBus::new(&listed, fixture),
        Err(FixtureError::Value(_))
    ));
    let fixture =
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\ntext = \"WAUZZZ4G1EN000000\"\n";
    assert!(SimBus::new(&listed, fixture).is_ok());
    // A module with no VIN stored sends 17 of one filler byte, as the A7's rear lid does (#63).
    for (value, ok) in [
        ("text = \"-----------------\"", true),
        (
            "hex = \"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\"",
            true,
        ),
        ("text = \"----------------\"", false),
    ] {
        let fixture = format!("[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\n{value}\n");
        assert_eq!(SimBus::new(&listed, &fixture).is_ok(), ok, "{value}");
    }
    // Identification DIDs without a fixed text format, such as 0xF18B (manufacturing date), take any bytes.
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF18B\nhex = \"26 10 08\"\n";
    assert!(SimBus::new(&a7, fixture).is_ok());
}

#[test]
fn modules_the_sim_cannot_address_are_refused() {
    let profile = Profile::from_toml(
        "name = \"x\"\nbitrate = 500000\n[[module]]\nname = \"body\"\nrequest_id = 0x750\n\
         response_id = 0x758\nprotocol = \"uds\"\nextended_address = 0x40\n",
    )
    .unwrap();
    assert_eq!(
        SimBus::new(&profile, "[[ecu]]\nmodule = \"body\"\n").unwrap_err(),
        FixtureError::UnsupportedModule("body".into())
    );
    let kwp = profile_with_protocol("kwp2000");
    assert_eq!(
        SimBus::new(&kwp, "[[ecu]]\nmodule = \"body\"\n").unwrap_err(),
        FixtureError::UnsupportedModule("body".into())
    );
}

fn profile_with_protocol(protocol: &str) -> Profile {
    Profile::from_toml(&format!(
        "name = \"x\"\nbitrate = 500000\n[[module]]\nname = \"body\"\nrequest_id = 0x750\n\
         response_id = 0x758\nprotocol = \"{protocol}\"\n"
    ))
    .unwrap()
}

const READ_SIDS: [u8; 6] = [0x01, 0x03, 0x09, 0x19, 0x22, 0x3E];

proptest! {
    // ECU replies are untrusted input for the code above the sim, but the sim itself must never
    // panic, and every reply must be a well-formed positive or negative answer to the request.
    #[test]
    fn every_approved_request_gets_well_formed_replies(
        sid in prop::sample::select(READ_SIDS.to_vec()),
        data in prop::collection::vec(any::<u8>(), 0..8),
        id in prop::sample::select(vec![0x7DFu32, 0x7E0, 0x7E1, 0x710, 0x714, 0x7A0]),
    ) {
        let target = if id == 0x7DF { Target::ObdFunctional } else { Target::Physical(id) };
        let mut payload = vec![sid];
        payload.extend(data);
        let Ok(request) = Policy::read_only().approve(target, &payload) else {
            return Ok(());
        };
        check_replies(&request).map_err(TestCaseError::fail)?;
    }
}

// Every reply the simulated A7 sends to `request` is well formed and answers it: after
// response-pending, the final reply comes even to a suppressed request.
fn check_replies(request: &Approved) -> Result<(), String> {
    let payload = request.payload();
    let sid = payload[0];
    let mut bus = a7();
    bus.send(request).unwrap();
    let mut pending = false;
    while let Ok(reply) = bus.recv(TIMEOUT) {
        let reply = reply.payload;
        let shape = match reply[0] {
            0x7F => reply.len() == 3 && reply[1] == sid,
            first => first == sid + 0x40,
        };
        let answers = if pending {
            obdcracker_core::response::answers_after_pending(payload, &reply)
        } else {
            obdcracker_core::response::answers(payload, &reply)
        };
        if !shape || !answers {
            return Err(format!("{reply:02X?} doesn't answer {payload:02X?}"));
        }
        pending |= reply.len() == 3 && reply[0] == 0x7F && reply[2] == 0x78;
    }
    Ok(())
}

#[test]
fn a_suppressed_dtc_request_gets_its_report_after_response_pending() {
    // The transmission sends response-pending before each DTC report (session 3).
    let request = Policy::read_only()
        .approve(TRANSMISSION, &[0x19, 0x82, 0xAF])
        .unwrap();
    check_replies(&request).unwrap();
}

// What session 3 (#54) showed that a plain fixture couldn't say: response-pending before a DTC
// report, a reply the car sent that isn't well formed, and a DID refused with an NRC of its own.
const QUIRKS: &str = r#"
[[ecu]]
module = "engine"
dtc_pending = 2
dtc_reports = [0x02]

[[ecu.dtc]]
code = 0x029900
status = 0x08

[[ecu.did]]
id = 0xF187
text = "4G0907589F "

[[ecu.did]]
id = 0xF190
nrc = 0x22

[[ecu.raw]]
request = "19 01 AF"
reply = "59 01 00 00"
pending = 1
"#;

fn quirks() -> SimBus {
    SimBus::new(&Profile::builtin("a7").unwrap(), QUIRKS).unwrap()
}

fn payloads(replies: &[Response]) -> Vec<Vec<u8>> {
    replies.iter().map(|r| r.payload.clone()).collect()
}

#[test]
fn a_dtc_report_can_send_response_pending_first() {
    let mut bus = quirks();
    let replies = payloads(&ask(&mut bus, ENGINE, &uds::dtcs_by_status_mask(0xAF)));
    assert_eq!(replies.len(), 3, "{replies:02X?}");
    assert!(nrc(&replies[0], 0x19).is_pending());
    assert!(nrc(&replies[1], 0x19).is_pending());
    assert!(uds::decode_dtcs_by_status_mask(&replies[2]).is_ok());
    // A refusal comes at once (session 3: `7F 19 12` with no pending first).
    let replies = payloads(&ask(&mut bus, ENGINE, &uds::dtc_count_by_status_mask(0xFF)));
    assert_eq!(replies, [[0x7F, 0x19, 0x12]]);
}

#[test]
fn a_raw_reply_is_sent_as_the_car_sent_it() {
    // The airbag answered `19 01 AF` with `59 01 00 00`, too short to decode.
    let mut bus = quirks();
    let replies = payloads(&ask(&mut bus, ENGINE, &uds::dtc_count_by_status_mask(0xAF)));
    assert_eq!(replies.len(), 2, "{replies:02X?}");
    assert!(nrc(&replies[0], 0x19).is_pending());
    assert_eq!(replies[1], [0x59, 0x01, 0x00, 0x00]);
    assert!(uds::decode_dtc_count(&replies[1]).is_err());
}

#[test]
fn a_did_can_be_refused_with_its_own_nrc() {
    // Night vision refused F190 with 0x22 (conditions not correct), not 0x31.
    let mut bus = quirks();
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0xF190));
    assert_eq!(nrc(&reply, 0x22), Nrc::ConditionsNotCorrect);
    // ISO 14229-1 checks conditions for the whole request, so a read that includes it is refused.
    let reply = ask_one(&mut bus, ENGINE, &[0x22, 0xF1, 0x87, 0xF1, 0x90]);
    assert_eq!(nrc(&reply, 0x22), Nrc::ConditionsNotCorrect);
    let reply = ask_one(&mut bus, ENGINE, &uds::read_did(0xF187));
    assert!(uds::decode_did(&reply, 0xF187).is_ok());
}

#[test]
fn quirk_settings_are_checked() {
    let a7 = Profile::builtin("a7").unwrap();
    for bad in [
        // A refusal has no value, and 0x00 and 0x78 (response-pending) aren't refusals.
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\nnrc = 0x22\ntext = \"WAUZZZ4G1EN000000\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\nnrc = 0x00\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\nnrc = 0x78\n",
        // A raw reply must answer its request, and each request has one.
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"19 01 AF\"\nreply = \"62 F1 90\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"19 01 AF\"\nreply = \"59 02 00\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"19 01 AF\"\nreply = \"59 01 00 00\"\n[[ecu.raw]]\nrequest = \"19 01 AF\"\nreply = \"59 01 00 01\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"\"\nreply = \"59 01 00 00\"\n",
        // Session control changes the module's state, which a raw reply would skip.
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"10 03\"\nreply = \"50 03 00 32 01 F4\"\n",
    ] {
        assert!(
            matches!(SimBus::new(&a7, bad), Err(FixtureError::Value(_))),
            "{bad}"
        );
    }
}

#[test]
fn a_refused_did_can_send_response_pending_first() {
    let fixture =
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0xF190\nnrc = 0x22\npending = 2\n";
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap();
    let replies = payloads(&ask(&mut bus, ENGINE, &uds::read_did(0xF190)));
    assert_eq!(replies.len(), 3, "{replies:02X?}");
    assert!(nrc(&replies[0], 0x22).is_pending());
    assert!(nrc(&replies[1], 0x22).is_pending());
    assert_eq!(nrc(&replies[2], 0x22), Nrc::ConditionsNotCorrect);
}

#[test]
fn a_raw_reply_after_response_pending_answers_a_suppressed_request() {
    // After response-pending, the final positive reply is sent even with bit 7 set.
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[[ecu.raw]]\nrequest = \"19 81 AF\"\n\
                   reply = \"59 01 00 00\"\npending = 1\n";
    assert!(SimBus::new(&Profile::builtin("a7").unwrap(), fixture).is_ok());
}

// Wide discovery finds a module past the first pass's range, here at VW's MQB MMI IDs, without
// sending on a reply ID of a module that answers.
#[test]
fn wide_discovery_finds_a_module_past_the_first_range() {
    use obdcracker_safety::ModuleIds;
    use obdcracker_transport::discover::discover;

    let profile = Profile::from_toml(
        "name = \"x\"\nbitrate = 500000\n\
         [[module]]\nname = \"gateway\"\nrequest_id = 0x710\nresponse_id = 0x77A\nprotocol = \"uds\"\n\
         [[module]]\nname = \"mmi\"\nrequest_id = 0x773\nresponse_id = 0x7DD\nprotocol = \"uds\"\n\
         [discovery]\nfirst_request_id = 0x700\nlast_request_id = 0x769\nreply_offset = 0x6A\n\
         wide_last_request_id = 0x795\n",
    )
    .unwrap();
    let fixture = "[[ecu]]\nmodule = \"gateway\"\n[[ecu.did]]\nid = 0xF187\ntext = \"4G0907468AD\"\n\
                   [[ecu]]\nmodule = \"mmi\"\n[[ecu.did]]\nid = 0xF187\ntext = \"4G0035000\"\n";
    let mut bus = SimBus::new(&profile, fixture).unwrap();
    let timing = Timing::default();
    let first = profile.narrow_for_discovery(Policy::read_only()).unwrap();
    let found = discover(&mut bus, &first, &profile.candidates(), timing).unwrap();
    let ids = |found: &[obdcracker_transport::discover::Found]| -> Vec<ModuleIds> {
        found
            .iter()
            .map(|f| ModuleIds {
                request: f.request_id,
                reply: f.response_id,
            })
            .collect()
    };
    assert_eq!(
        ids(&found),
        [ModuleIds {
            request: 0x710,
            reply: 0x77A
        }]
    );
    let known = ids(&found);
    let wide = profile.wide_candidates(&known);
    let policy = profile
        .narrow_with(Policy::read_only(), &[known.as_slice(), &wide].concat())
        .unwrap();
    let more = discover(&mut bus, &policy, &wide, timing).unwrap();
    assert_eq!(
        ids(&more),
        [ModuleIds {
            request: 0x773,
            reply: 0x7DD
        }]
    );
    let sent: Vec<u32> = bus
        .sent()
        .iter()
        .map(|r| match r.target() {
            Target::Physical(id) => id,
            Target::ObdFunctional => 0x7DF,
        })
        .collect();
    // Not 0x709, whose reply ID is the MMI's request ID, nor the gateway's reply ID.
    for never in [0x709, 0x77A, 0x7DD] {
        assert!(!sent.contains(&never), "{never:03X}");
    }
}
