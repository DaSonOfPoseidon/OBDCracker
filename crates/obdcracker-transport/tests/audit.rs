//! The audit log wrapper.

use std::path::PathBuf;
use std::time::Duration;

use obdcracker_safety::Approved;
use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_transport::{Audited, Error, LinkEvent, Mock, Response, Transport, log_failure};

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
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x01, 0x0C])
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
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x09, 0x02])
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
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x09, 0x02])
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
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x09, 0x02])
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

// Reports adapter commands and an unread reply line with every send, and can fail the send.
struct Chatty {
    events: Vec<LinkEvent>,
    fail: bool,
}

impl Transport for Chatty {
    fn send(&mut self, _: &Approved) -> Result<(), Error> {
        let at = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        self.events.push(LinkEvent::Unread {
            at,
            line: "7E9 03 41 0C 00".to_owned(),
        });
        self.events.push(LinkEvent::Command {
            at,
            command: "ATSH7E0".to_owned(),
            answer: vec!["OK".to_owned(), "say \"hi\"".to_owned()],
        });
        self.events.push(LinkEvent::Lost(3));
        if self.fail {
            return Err(Error::Adapter("BUFFER FULL".to_owned()));
        }
        Ok(())
    }

    fn recv(&mut self, _: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        std::mem::take(&mut self.events)
    }

    fn settle(&mut self) -> Result<(), Error> {
        self.events.push(LinkEvent::Unread {
            at: std::time::UNIX_EPOCH,
            line: "7E9 03 7F 22 31".to_owned(),
        });
        Ok(())
    }
}

#[test]
fn what_is_left_when_the_session_ends_is_logged() {
    let log = temp_log("settle");
    let chatty = Chatty {
        events: Vec::new(),
        fail: false,
    };
    drop(Audited::open(&log, chatty, "mock").unwrap());
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""dir":"unread","line":"7E9 03 7F 22 31""#),
        "{audit}"
    );
}

#[test]
fn logs_adapter_commands_and_unread_reply_lines() {
    for fail in [false, true] {
        let log = temp_log(&format!("events-{fail}"));
        let chatty = Chatty {
            events: Vec::new(),
            fail,
        };
        let mut audited = Audited::open(&log, chatty, "mock").unwrap();
        let rpm = Policy::read_only()
            .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x01, 0x0C])
            .unwrap();
        assert_eq!(audited.send(&rpm).is_err(), fail);
        let audit = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<_> = audit.lines().collect();
        assert!(lines[0].contains(r#""dir":"tx""#), "{audit}");
        // When it happened, not when it was logged.
        assert!(
            lines[1].starts_with(
                r#"{"ts_ms":1700000000000,"dir":"unread","line":"7E9 03 41 0C 00","link":"mock"}"#
            ),
            "{audit}"
        );
        assert!(
            lines[2].starts_with(
                r#"{"ts_ms":1700000000000,"dir":"cmd","cmd":"ATSH7E0","answer":"OK / say \"hi\"","link":"mock"}"#
            ),
            "{audit}"
        );
        assert!(
            lines[3].ends_with(r#""dir":"lost","count":3,"link":"mock"}"#),
            "{audit}"
        );
        if fail {
            assert!(lines[4].contains(r#""dir":"err""#), "{audit}");
        }
        assert_eq!(lines.len(), if fail { 5 } else { 4 }, "{audit}");
    }
}

#[test]
fn a_transport_that_failed_before_it_could_be_wrapped_is_logged() {
    let log = temp_log("failure");
    let events = vec![LinkEvent::Command {
        at: std::time::UNIX_EPOCH,
        command: "ATSP6".to_owned(),
        answer: vec!["?".to_owned()],
    }];
    let error = Error::Adapter("the adapter doesn't support ATSP6".to_owned());
    log_failure(&log, "usb-serial", events, "connect", &error).unwrap();
    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 2, "{audit}");
    assert!(
        lines[0].contains(r#""dir":"cmd","cmd":"ATSP6","answer":"?","link":"usb-serial""#),
        "{audit}"
    );
    assert!(
        lines[1].contains(r#""dir":"err","op":"connect","error":"adapter error: the adapter doesn't support ATSP6""#),
        "{audit}"
    );
}

// Fails while finishing its last request.
struct FailsToSettle;

impl Transport for FailsToSettle {
    fn send(&mut self, _: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, _: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }

    fn settle(&mut self) -> Result<(), Error> {
        Err(Error::Adapter("the link closed".to_owned()))
    }
}

#[test]
fn a_failure_finishing_the_last_request_is_logged() {
    let log = temp_log("settle-fails");
    drop(Audited::open(&log, FailsToSettle, "mock").unwrap());
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""dir":"err","op":"settle","error":"adapter error: the link closed""#),
        "{audit}"
    );
}

#[test]
fn a_status_line_is_logged_as_a_status() {
    let log = temp_log("status");
    let events = vec![LinkEvent::Status {
        at: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        line: "NO DATA".to_owned(),
    }];
    let error = Error::Adapter("the link closed".to_owned());
    log_failure(&log, "mock", events, "recv", &error).unwrap();
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.starts_with(
            r#"{"ts_ms":1700000000000,"dir":"status","line":"NO DATA","link":"mock"}"#
        ),
        "{audit}"
    );
}

#[test]
fn a_session_settled_already_is_not_settled_again_when_dropped() {
    // #83: the explicit settle's failure is logged once, not again by the drop.
    let settle_errors = |audit: &str| audit.matches(r#""op":"settle""#).count();
    let log = temp_log("settle-once");
    let mut audited = Audited::open(&log, FailsToSettle, "mock").unwrap();
    assert!(audited.settle().is_err());
    drop(audited);
    assert_eq!(settle_errors(&std::fs::read_to_string(&log).unwrap()), 1);

    // A request after the settle leaves something to settle again.
    let log = temp_log("settle-again");
    let mut audited = Audited::open(&log, FailsToSettle, "mock").unwrap();
    assert!(audited.settle().is_err());
    let rpm = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x01, 0x0C])
        .unwrap();
    audited.send(&rpm).unwrap();
    drop(audited);
    assert_eq!(settle_errors(&std::fs::read_to_string(&log).unwrap()), 2);
}
