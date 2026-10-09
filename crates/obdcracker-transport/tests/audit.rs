//! The audit log wrapper.

use std::path::PathBuf;
use std::time::Duration;

use obdcracker_safety::Approved;
use obdcracker_safety::{Policy, Target};
use obdcracker_transport::{Audited, Error, Mock, Response, Transport};

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

#[test]
fn every_line_is_valid_json_whatever_the_link_name() {
    let names = [
        r#"tcp "wifi""#,
        r"\\.\COM10",
        "tab\there",
        "line\nbreak",
        "nul\0and\u{1f}and\u{7f}",
        "ünïcode ✓",
        "",
    ];
    let vin = Policy::read_only()
        .approve(Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    for (i, link) in names.iter().enumerate() {
        let log = temp_log(&format!("escape-{i}"));
        let mut mock = Mock::default();
        mock.queue(Response {
            source: 0x7E8,
            payload: vec![0x49, 0x02, 0x01],
        });
        let mut audited = Audited::open(&log, mock, *link).unwrap();
        audited.send(&vin).unwrap();
        audited.recv(Duration::from_millis(10)).unwrap();

        let audit = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<_> = audit.lines().collect();
        assert_eq!(lines.len(), 2, "{link:?}: {audit:?}");
        for line in lines {
            let entry: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{link:?}: {line:?} isn't JSON: {e}"));
            assert_eq!(entry["link"], *link, "{line}");
        }
    }
}

// Fails every send and receive with the error it was built with.
struct Failing(Error);

impl Transport for Failing {
    fn send(&mut self, _: &Approved) -> Result<(), Error> {
        Err(self.0.clone())
    }

    fn recv(&mut self, _: Duration) -> Result<Response, Error> {
        Err(self.0.clone())
    }
}

#[test]
fn logs_adapter_errors_as_valid_json() {
    let log = temp_log("errors");
    let error = Error::Adapter("the adapter echoed \"09 12\"\r\n\\ instead".to_string());
    let mut audited = Audited::open(&log, Failing(error.clone()), "mock").unwrap();
    let vin = Policy::read_only()
        .approve(Target::Physical(0x7E0), &[0x09, 0x02])
        .unwrap();
    assert_eq!(audited.send(&vin), Err(error.clone()));
    assert_eq!(audited.recv(Duration::from_millis(10)).unwrap_err(), error);

    let audit = std::fs::read_to_string(&log).unwrap();
    let entries: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line:?}: {e}")))
        .collect();
    // The request is logged before it's sent, then the error that sending it gave.
    assert_eq!(entries.len(), 3, "{audit}");
    assert_eq!(entries[0]["dir"], "tx");
    for (entry, op) in entries[1..].iter().zip(["send", "recv"]) {
        assert_eq!(entry["dir"], "err", "{audit}");
        assert_eq!(entry["op"], op, "{audit}");
        assert_eq!(entry["error"], error.to_string(), "{audit}");
        assert_eq!(entry["link"], "mock", "{audit}");
    }
    assert_eq!(entries[1]["id"], "7E0", "{audit}");
}

#[test]
fn a_timeout_isnt_an_error_worth_logging() {
    // Every exchange ends by waiting for replies that don't come.
    let log = temp_log("timeout");
    let mut audited = Audited::open(&log, Mock::default(), "mock").unwrap();
    assert_eq!(
        audited.recv(Duration::from_millis(10)).unwrap_err(),
        Error::Timeout
    );
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "");
}
