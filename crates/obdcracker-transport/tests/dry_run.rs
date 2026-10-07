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
fn refuses_requests_that_need_multiple_frames() {
    let long = Policy::read_only()
        .approve(
            Target::Physical(0x7E0),
            &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90, 0xF1, 0x91],
        )
        .unwrap();
    assert!(DryRun::new(Vec::new()).send(&long).is_err());
}
