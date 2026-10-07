//! The audit log wrapper.

use std::path::PathBuf;
use std::time::Duration;

use obdcracker_safety::{Policy, Target};
use obdcracker_transport::{Audited, Mock, Response, Transport};

fn temp_log(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "obdcracker-transport-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn logs_requests_and_replies_with_the_link() {
    let log = temp_log("roundtrip");
    let mut mock = Mock::default();
    mock.queue(Response {
        source: 0x7E8,
        payload: vec![0x41, 0x0C, 0x1A, 0xF8],
    });
    let mut audited = Audited::open(&log, mock, "mock").unwrap();
    let rpm = Policy::read_only()
        .approve(Target::ObdFunctional, &[0x01, 0x0C])
        .unwrap();
    audited.send(&rpm).unwrap();
    audited.recv(Duration::from_millis(10)).unwrap();

    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].ends_with(r#""dir":"tx","id":"7DF","payload":"01 0C","link":"mock"}"#),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].ends_with(r#""dir":"rx","id":"7E8","payload":"41 0C 1A F8","link":"mock"}"#),
        "{}",
        lines[1]
    );
}

#[test]
fn appends_to_an_existing_log() {
    let log = temp_log("append");
    let vin = Policy::read_only()
        .approve(Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    for _ in 0..2 {
        Audited::open(&log, Mock::default(), "mock")
            .unwrap()
            .send(&vin)
            .unwrap();
    }
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
}
