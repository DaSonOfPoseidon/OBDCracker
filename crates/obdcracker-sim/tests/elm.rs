//! The simulated A7 behind a fake ELM327: every read gives the same replies through the ELM
//! driver as straight from the simulator.

#[path = "../../obdcracker-transport/tests/support/fake_elm.rs"]
mod fake_elm;

use obdcracker_safety::{Policy, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::elm::Elm;
use obdcracker_transport::{Error, Expect, Response, Transport, exchange};

use fake_elm::{FakeElm, FakeLink};

fn target(id: u32) -> Target {
    if id == 0x7DF {
        Target::ObdFunctional
    } else {
        Target::Physical(id)
    }
}

// A fake adapter whose bus is a simulated A7. The adapter has only bytes, so it re-approves
// each request before handing it to the simulator, as a real car would just receive it.
fn a7_behind_an_elm() -> Elm<FakeLink> {
    let mut car = SimBus::builtin("a7").unwrap();
    let elm = FakeElm::new(Box::new(move |header, request| {
        let request = Policy::read_only()
            .approve(target(header), request)
            .unwrap();
        car.send(&request).unwrap();
        let mut replies = Vec::new();
        while let Ok(Response { source, payload }) = car.recv(std::time::Duration::ZERO) {
            replies.push((source, payload));
        }
        replies
    }));
    let mut link = FakeLink::new(elm);
    // Small reads, so frames and lines arrive split.
    link.chunk = 5;
    Elm::connect(link).unwrap()
}

const READS: &[(u32, &[u8], Expect)] = &[
    // OBD-II broadcasts: VIN, CALID, CVN, ECU name, stored DTCs, current data
    (0x7DF, &[0x09, 0x02], Expect::ObdEcus),
    (0x7DF, &[0x09, 0x04], Expect::ObdEcus),
    (0x7DF, &[0x09, 0x06], Expect::ObdEcus),
    (0x7DF, &[0x09, 0x0A], Expect::ObdEcus),
    (0x7DF, &[0x03], Expect::ObdEcus),
    (0x7DF, &[0x01, 0x0C], Expect::ObdEcus),
    (0x7DF, &[0x01, 0x0D], Expect::ObdEcus),
    // UDS on the engine (OBD-II IDs) and the gateway (a VAG module ID)
    (0x7E0, &[0x22, 0xF1, 0x90], Expect::Module(0x7E8)),
    (
        0x7E0,
        &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x9E],
        Expect::Module(0x7E8),
    ),
    (0x7E0, &[0x19, 0x0A], Expect::Module(0x7E8)),
    (0x7E0, &[0x22, 0x06, 0x00], Expect::Module(0x7E8)),
    (0x7E1, &[0x22, 0xF1, 0x87], Expect::Module(0x7E9)),
    (0x710, &[0x22, 0xF1, 0x87], Expect::Module(0x77A)),
    (0x710, &[0x22, 0xF1, 0x9E], Expect::Module(0x77A)),
    // A DID nobody has: a refusal
    (0x710, &[0x22, 0x12, 0x34], Expect::Module(0x77A)),
];

#[test]
fn every_read_matches_the_simulator() {
    let mut direct = SimBus::builtin("a7").unwrap();
    let mut elm = a7_behind_an_elm();
    for &(id, payload, expect) in READS {
        let request = Policy::read_only().approve(target(id), payload).unwrap();
        let want = exchange(&mut direct, &request, expect, Elm::<FakeLink>::timing());
        let got = exchange(&mut elm, &request, expect, Elm::<FakeLink>::timing());
        assert_eq!(got, want, "{id:03X} {payload:02X?}");
        assert!(
            want.as_ref().is_ok_and(|replies| !replies.is_empty()),
            "{id:03X} {payload:02X?} got no reply, so it proves nothing: {want:?}"
        );
    }
}

// Each is one flipped bit on the serial line from a reset or a session change, so the driver
// refuses it before it reaches the car.
#[test]
fn reads_a_flipped_bit_could_make_dangerous_never_reach_the_car() {
    let mut elm = a7_behind_an_elm();
    for (id, payload) in [
        (0x7DF, &[0x01, 0x05, 0x0C, 0x0D, 0x42][..]),
        (0x7E0, &[0x19, 0x02, 0xFF]),
        (0x7E0, &[0x10, 0x03]),
    ] {
        let request = Policy::read_only().approve(target(id), payload).unwrap();
        let got = exchange(
            &mut elm,
            &request,
            Expect::ObdEcus,
            Elm::<FakeLink>::timing(),
        );
        assert!(
            matches!(&got, Err(Error::Adapter(e)) if e.starts_with("refused")),
            "{id:03X} {payload:02X?}: {got:?}"
        );
    }
    assert_eq!(elm.link().elm.sent, []);
}

#[test]
fn a_module_that_isnt_there_times_out() {
    let mut elm = a7_behind_an_elm();
    let request = Policy::read_only()
        .approve(Target::Physical(0x7E5), &[0x22, 0xF1, 0x90])
        .unwrap();
    assert_eq!(
        exchange(
            &mut elm,
            &request,
            Expect::Module(0x7ED),
            Elm::<FakeLink>::timing()
        ),
        Err(Error::Timeout)
    );
}
