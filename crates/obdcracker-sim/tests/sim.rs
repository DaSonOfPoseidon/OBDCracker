//! The simulated A7 answering through the `Transport` trait, decoded with the M1 codecs.

use std::fmt::Write as _;
use std::time::Duration;

use obdcracker_core::obd::{self, Unit, Value};
use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::{self, DtcFormat};
use obdcracker_profile::{Profile, ProfileError};
use obdcracker_safety::{Policy, Target};
use obdcracker_sim::{Fault, FixtureError, Session, SimBus};
use obdcracker_transport::{Error, Expect, Response, Timing, Transport, exchange};
use proptest::prelude::*;

const ENGINE: Target = Target::Physical(0x7E0);
const GATEWAY: Target = Target::Physical(0x710);
const TIMEOUT: Duration = Duration::from_millis(50);

fn a7() -> SimBus {
    SimBus::builtin("a7").unwrap()
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
fn functional_vin_is_answered_by_engine_and_transmission() {
    let replies = ask(&mut a7(), Target::ObdFunctional, &obd::vehicle_info(0x02));
    let sources: Vec<_> = replies.iter().map(|r| r.source).collect();
    assert_eq!(sources, [0x7E8, 0x7E9]);
    for reply in &replies {
        assert_eq!(
            obd::decode_vin(&reply.payload).unwrap(),
            "WAUZZZ4G1EN000000"
        );
    }
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
    assert_eq!(supported, [0x05, 0x0C, 0x0D, 0x42]);
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
                    value: 800.0,
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
    assert_silent(&mut a7(), Target::ObdFunctional, &obd::current_data(0x10));
    assert_silent(&mut a7(), Target::ObdFunctional, &obd::vehicle_info(0x08));
}

#[test]
fn mode_03_lists_stored_dtcs_per_module() {
    let replies = ask(&mut a7(), Target::ObdFunctional, &obd::stored_dtcs());
    let dtcs: Vec<(u32, Vec<String>)> = replies
        .iter()
        .map(|r| {
            let codes = obd::decode_stored_dtcs(&r.payload).unwrap();
            (r.source, codes.map(|dtc| dtc.to_string()).collect())
        })
        .collect();
    assert_eq!(dtcs, [(0x7E8, vec!["P0299".into()]), (0x7E9, vec![])]);
}

#[test]
fn mode_09_reports_calids_cvns_and_name() {
    let mut bus = a7();
    let calids = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x04));
    let calids: Vec<_> = obd::decode_calids(&calids)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(calids.len(), 1);
    let cvns = ask_one(&mut bus, ENGINE, &obd::vehicle_info(0x06));
    assert_eq!(obd::decode_cvns(&cvns).unwrap().count(), 1);
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
    let reply = ask_one(&mut a7(), GATEWAY, &uds::read_did(uds::did::VIN));
    let data = uds::decode_did(&reply, uds::did::VIN).unwrap();
    assert_eq!(uds::decode_text(data).unwrap(), "WAUZZZ4G1EN000000");
}

#[test]
fn reads_several_dids_in_request_order() {
    let reply = ask_one(&mut a7(), ENGINE, &[0x22, 0xF1, 0x89, 0xF1, 0x87]);
    let values: Vec<_> = uds::decode_dids(&reply, &[(0xF189, 4), (0xF187, 10)])
        .unwrap()
        .map(|value| {
            let (did, data) = value.unwrap();
            (did, uds::decode_text(data).unwrap().to_owned())
        })
        .collect();
    assert_eq!(
        values,
        [(0xF189, "0010".into()), (0xF187, "4G0907401A".into())]
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
    let mut bus = a7();
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
fn suppress_bit_silences_positive_replies_only() {
    let mut bus = a7();
    assert_silent(&mut bus, ENGINE, &[0x10, 0x83]);
    assert_eq!(bus.ecu("engine").unwrap().session(), Session::Extended);
    assert_silent(&mut bus, ENGINE, &[0x3E, 0x80]);
    assert_eq!(ask_one(&mut bus, ENGINE, &[0x3E, 0x00]), [0x7E, 0x00]);
}

#[test]
fn reads_uds_dtcs() {
    let mut bus = a7();
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
fn exchange_collects_the_vin_from_every_obd_ecu() {
    let vin = Policy::read_only()
        .approve(Target::ObdFunctional, &obd::vehicle_info(0x02))
        .unwrap();
    let replies = exchange(&mut a7(), &vin, Expect::ObdEcus, Timing::default()).unwrap();
    let vins: Vec<_> = replies
        .iter()
        .map(|r| (r.source, obd::decode_vin(&r.payload).unwrap()))
        .collect();
    assert_eq!(
        vins,
        [(0x7E8, "WAUZZZ4G1EN000000"), (0x7E9, "WAUZZZ4G1EN000000")]
    );
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
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"+5\" = \"00\"\n",
        // I, O and Q aren't VIN characters, and neither are lower case letters.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"WAUZZZ4G1EN00000O\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"wauzzz4g1en000000\"\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 1\nhex = \"00\"\n[[ecu.did]]\nid = 1\nhex = \"01\"\n",
        // The same code twice, in mode 03 or UDS, would be reported twice.
        "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\ndtcs = [\"P0299\", \"P0299\"]\n",
        "[[ecu]]\nmodule = \"engine\"\n[[ecu.dtc]]\ncode = 0x029900\nstatus = 0x08\n[[ecu.dtc]]\ncode = 0x029900\nstatus = 0x00\n",
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
    let fixture = "[[ecu]]\nmodule = \"engine\"\n[ecu.obd.pids]\n\"10\" = \"01 02 03\"\n";
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap();
    assert_eq!(
        ask_one(&mut bus, ENGINE, &obd::current_data(0x10)),
        [0x41, 0x10, 0x01, 0x02, 0x03]
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
    let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), &fixture).unwrap();
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
    for code in 0..=u32::from(u16::MAX) {
        writeln!(fixture, "[[ecu.dtc]]\ncode = {code}\nstatus = 0x08").unwrap();
    }
    assert!(matches!(
        SimBus::new(&Profile::builtin("a7").unwrap(), &fixture),
        Err(FixtureError::Value(_))
    ));
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
        let mut bus = a7();
        bus.send(&request).unwrap();
        while let Ok(reply) = bus.recv(TIMEOUT) {
            let first = reply.payload[0];
            if first == 0x7F {
                prop_assert_eq!(reply.payload.len(), 3);
                prop_assert_eq!(reply.payload[1], sid);
            } else {
                prop_assert_eq!(first, sid + 0x40);
            }
        }
    }
}
