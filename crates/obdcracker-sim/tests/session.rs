//! The extended diagnostic session on the simulated A7: S3 lapses it.

use std::thread::sleep;
use std::time::Duration;

use obdcracker_core::response::Nrc;
use obdcracker_core::uds;
use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Target};
use obdcracker_sim::{Session, SimBus};
use obdcracker_transport::{Expect, Timing, exchange};

const ENGINE: Target = Target::Physical(0x7E0);
const CODING: u16 = 0x0600;
// Short enough for tests, with margins of tens of milliseconds either side of each deadline.
const SIM_S3: Duration = Duration::from_millis(300);

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
