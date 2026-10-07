//! The dry-run backend.

use std::time::Duration;

use obdcracker_safety::{Policy, Target};
use obdcracker_transport::{DryRun, Error, Transport};

#[test]
fn writes_the_can_frame_instead_of_sending_it() {
    let vin = Policy::read_only()
        .approve(Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    let mut dry = DryRun::new(Vec::new());
    dry.send(&vin).unwrap();
    assert_eq!(dry.recv(Duration::from_millis(10)), Err(Error::Timeout));
    assert_eq!(
        String::from_utf8(dry.into_inner()).unwrap(),
        "7DF 02 09 02\n"
    );
}

#[test]
fn prints_first_and_consecutive_frames_of_a_long_request() {
    // Four DIDs need two frames. With no ECU to send flow control, the dry run assumes
    // continue-to-send.
    let long = Policy::read_only()
        .approve(
            Target::Physical(0x7E0),
            &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90, 0xF1, 0x91],
        )
        .unwrap();
    let mut dry = DryRun::new(Vec::new());
    dry.send(&long).unwrap();
    assert_eq!(
        String::from_utf8(dry.into_inner()).unwrap(),
        "7E0 10 09 22 F1 87 F1 89 F1\n7E0 21 90 F1 91\n"
    );
}
