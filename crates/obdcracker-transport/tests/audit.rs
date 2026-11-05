//! The audit log wrapper.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use obdcracker_safety::Approved;
use obdcracker_safety::{ApprovedFlowControl, FeedOutcome, Policy, Protocol, ReplyWindow, Target};
use obdcracker_transport::{
    Audited, Error, LinkEvent, Mock, Response, Transport, log_events, log_failure,
};

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
    mock.queue(Response::new(0x7E8, vec![0x41, 0x0C, 0x1A, 0xF8]));
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
fn a_reply_keeps_its_bus_time() {
    let log = temp_log("bus-time");
    let left = std::time::Instant::now();
    let mut mock = Mock::default();
    mock.queue(Response::new(0x7E8, vec![0x41, 0x0C, 0x1A, 0xF8]).at_bus_time(Some(left)));
    let mut audited = Audited::open(&log, mock, "mock").unwrap();
    let rpm = Policy::read_only()
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x01, 0x0C])
        .unwrap();
    audited.send(&rpm).unwrap();
    assert_eq!(
        audited.recv(Duration::from_millis(10)).unwrap().bus_time,
        Some(left)
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
        mock.queue(Response::new(0x7E8, vec![0x49, 0x02, 0x01]));
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

#[test]
fn events_left_after_the_wrapper_is_gone_can_be_logged_alone() {
    let log = temp_log("events-only");
    let events = vec![LinkEvent::Command {
        at: std::time::UNIX_EPOCH,
        command: "MODE RESET".to_owned(),
        answer: vec!["ok".to_owned()],
    }];
    log_events(&log, "gsusb:active:500000", events).unwrap();
    let audit = std::fs::read_to_string(&log).unwrap();
    assert_eq!(audit.lines().count(), 1, "{audit}");
    assert!(
        audit.contains(
            r#""dir":"cmd","cmd":"MODE RESET","answer":"ok","link":"gsusb:active:500000""#
        ),
        "{audit}"
    );
}

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

// A first frame, which calls for flow control.
const FIRST_FRAME: [u8; 8] = [0x10, 0x14, 0x62, 0xF1, 0x87, 1, 2, 3];

// One flow control token for each of `sources`, as a raw backend would get them.
fn flow_controls(sources: &[u32]) -> Vec<ApprovedFlowControl> {
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    let mut window = ReplyWindow::open(&request).unwrap();
    sources
        .iter()
        .map(|&source| match window.feed(source, &FIRST_FRAME).unwrap() {
            FeedOutcome::SendFlowControl(token) => token,
            other => panic!("expected a token, got {other:?}"),
        })
        .collect()
}

type Sent = Rc<RefCell<Vec<(u32, Vec<u8>)>>>;
type AtSend = Rc<RefCell<Vec<String>>>;

// What a raw backend does under `recv`: reports each token, and sends it only if that succeeds.
// `at_send` holds the audit log's content at the moment each frame went out.
struct SendsFlowControl {
    log: PathBuf,
    tokens: Vec<ApprovedFlowControl>,
    at_send: AtSend,
    sent: Sent,
}

impl Transport for SendsFlowControl {
    fn send(&mut self, _: &Approved) -> Result<(), Error> {
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.recv_logged(timeout, &mut |_| Ok(()))
    }

    fn recv_logged(
        &mut self,
        _: Duration,
        before_send: &mut dyn FnMut(&ApprovedFlowControl) -> Result<(), Error>,
    ) -> Result<Response, Error> {
        for token in std::mem::take(&mut self.tokens) {
            before_send(&token)?;
            let content = std::fs::read_to_string(&self.log).unwrap_or_default();
            self.at_send.borrow_mut().push(content);
            self.sent
                .borrow_mut()
                .push((token.destination_id(), token.data().to_vec()));
        }
        Ok(Response::new(0x7E8, vec![0x49, 0x02]))
    }
}

fn sends_flow_control(log: &std::path::Path, sources: &[u32]) -> (SendsFlowControl, AtSend, Sent) {
    let at_send = AtSend::default();
    let sent = Sent::default();
    let transport = SendsFlowControl {
        log: log.to_owned(),
        tokens: flow_controls(sources),
        at_send: Rc::clone(&at_send),
        sent: Rc::clone(&sent),
    };
    (transport, at_send, sent)
}

#[test]
fn flow_control_is_on_disk_before_it_is_sent() {
    let log = temp_log("fc-before-send");
    let (transport, at_send, sent) = sends_flow_control(&log, &[0x7E8]);
    let mut audited = Audited::open(&log, transport, "mock").unwrap();
    audited.recv(Duration::from_millis(10)).unwrap();

    assert_eq!(*sent.borrow(), [(0x7E0, vec![0x30, 0x00, 0x00])]);
    let seen = at_send.borrow();
    assert_eq!(seen.len(), 1);
    // Only the flow control: the reply it leads to hasn't arrived yet.
    assert_eq!(seen[0].lines().count(), 1, "{}", seen[0]);
    assert!(
        seen[0].ends_with(
            "\"dir\":\"tx\",\"id\":\"7E0\",\"payload\":\"30 00 00\",\"link\":\"mock\"}\n"
        ),
        "{}",
        seen[0]
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    assert_eq!(audit.lines().count(), 2);
    assert!(
        audit
            .lines()
            .nth(1)
            .unwrap()
            .contains(r#""dir":"rx","id":"7E8""#),
        "{audit}"
    );
}

#[test]
fn every_flow_control_in_one_receive_is_logged_before_its_own_send() {
    let log = temp_log("fc-several");
    let (transport, at_send, sent) = sends_flow_control(&log, &[0x7E8, 0x7E9]);
    let mut audited = Audited::open(&log, transport, "mock").unwrap();
    audited.recv(Duration::from_millis(10)).unwrap();

    assert_eq!(sent.borrow().len(), 2);
    let seen = at_send.borrow();
    assert_eq!(seen[0].lines().count(), 1, "{}", seen[0]);
    assert_eq!(seen[1].lines().count(), 2, "{}", seen[1]);
    assert!(seen[1].lines().nth(1).unwrap().contains(r#""id":"7E1""#));
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 3);
}

#[test]
fn a_receive_that_sends_no_flow_control_logs_only_the_reply() {
    let log = temp_log("fc-none");
    let mut mock = Mock::default();
    mock.queue(Response::new(0x7E8, vec![0x41, 0x0C, 0x1A, 0xF8]));
    let mut audited = Audited::open(&log, mock, "mock").unwrap();
    audited.recv(Duration::from_millis(10)).unwrap();
    let audit = std::fs::read_to_string(&log).unwrap();
    assert_eq!(audit.lines().count(), 1, "{audit}");
    assert!(audit.contains(r#""dir":"rx""#), "{audit}");
}

// Writing to /dev/full always fails, so the log can't take the record.
#[cfg(target_os = "linux")]
#[test]
fn flow_control_is_not_sent_when_the_log_cannot_take_it() {
    let log = temp_log("fc-unwritable");
    let (transport, at_send, sent) = sends_flow_control(&log, &[0x7E8]);
    let mut audited = Audited::open(std::path::Path::new("/dev/full"), transport, "mock").unwrap();
    match audited.recv(Duration::from_millis(10)) {
        Err(Error::Adapter(message)) => assert!(message.contains("audit log"), "{message}"),
        other => panic!("expected the log's failure, got {other:?}"),
    }
    assert!(sent.borrow().is_empty());
    assert!(at_send.borrow().is_empty());
}

#[test]
fn flow_control_through_two_audited_wrappers_is_logged_by_both() {
    let inner_log = temp_log("fc-nested-inner");
    let outer_log = temp_log("fc-nested-outer");
    let (transport, _, sent) = sends_flow_control(&inner_log, &[0x7E8]);
    let inner = Audited::open(&inner_log, transport, "inner").unwrap();
    let mut outer = Audited::open(&outer_log, inner, "outer").unwrap();
    outer.recv(Duration::from_millis(10)).unwrap();
    assert_eq!(sent.borrow().len(), 1);
    for log in [&inner_log, &outer_log] {
        let audit = std::fs::read_to_string(log).unwrap();
        assert!(
            audit.contains(r#""dir":"tx","id":"7E0","payload":"30 00 00""#),
            "{audit}"
        );
    }
}
