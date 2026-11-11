//! The supply voltage through the ELM327 driver (`ATRV`), and through the audit log.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use obdcracker_safety::{Policy, Protocol, SupplyVoltage, Target};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::{Audited, Error, Mock, Transport};
use support::fake_elm::{FakeElm, FakeLink};

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";

fn known(millivolts: u32) -> SupplyVoltage {
    SupplyVoltage::Known { millivolts }
}

fn connect(elm: FakeElm) -> Elm<FakeLink> {
    Elm::connect(FakeLink::new(elm)).unwrap()
}

fn reading(lines: &[&str]) -> FakeElm {
    let mut elm = FakeElm::silent();
    elm.voltage = lines.iter().map(|&line| line.to_owned()).collect();
    elm
}

fn commands(elm: &Elm<FakeLink>) -> &[String] {
    &elm.link().elm.commands
}

fn temp_log(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "obdcracker-transport-voltage-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn asks_the_adapter_with_atrv_and_reads_its_answer() {
    let mut elm = connect(FakeElm::silent());
    assert_eq!(elm.supply_voltage().unwrap(), known(12_600));
    assert_eq!(commands(&elm).last().map(String::as_str), Some("ATRV"));
    assert_eq!(elm.link().elm.sent, [], "ATRV put a frame on the bus");
}

#[test]
fn reads_what_an_adapter_prints() {
    for (answer, expected) in [
        ("11.5V", known(11_500)),
        ("12V", known(12_000)),
        (" 9.8V", known(9_800)),
        ("0.0V", known(0)),
        ("12.63V", known(12_630)),
    ] {
        let mut elm = connect(reading(&[answer]));
        assert_eq!(elm.supply_voltage().unwrap(), expected, "{answer:?}");
    }
}

#[test]
fn an_answer_that_isnt_one_voltage_is_unknown() {
    let answers: [&[&str]; 6] = [
        &["?"],
        &[],
        &["NO DATA"],
        &["12.6V", "12.6V"],
        &["12.6V junk"],
        &["-12.6V"],
    ];
    for lines in answers {
        let mut elm = connect(reading(lines));
        assert_eq!(
            elm.supply_voltage().unwrap(),
            SupplyVoltage::Unknown,
            "{lines:?}"
        );
        // Not a failure: the adapter is still usable.
        assert_eq!(elm.supply_voltage().unwrap(), SupplyVoltage::Unknown);
    }
}

#[test]
fn an_adapter_that_refuses_atrv_reports_unknown() {
    let mut adapter = FakeElm::silent();
    adapter.unsupported.push("ATRV".to_owned());
    let mut elm = connect(adapter);
    assert_eq!(elm.supply_voltage().unwrap(), SupplyVoltage::Unknown);
}

#[test]
fn an_adapter_that_never_answers_atrv_is_an_error_and_then_closed() {
    let mut adapter = FakeElm::silent();
    adapter.mute.push("ATRV".to_owned());
    let mut elm = connect(adapter);
    assert!(elm.supply_voltage().is_err());
    let written = elm.link().written.len();
    assert!(elm.supply_voltage().is_err());
    assert_eq!(
        elm.link().written.len(),
        written,
        "wrote to a broken adapter"
    );
}

#[test]
fn a_request_still_printing_is_finished_before_the_command_is_written() {
    let mut adapter = FakeElm::new(Box::new(|header, request| {
        if header == 0x7E0 && request == [0x09, 0x02] {
            vec![(0x7E8, VIN.to_vec())]
        } else {
            Vec::new()
        }
    }));
    adapter.voltage = vec!["12.1V".to_owned()];
    let mut elm = connect(adapter);
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x09, 0x02])
        .unwrap();
    elm.send(&request).unwrap();
    elm.recv(Duration::from_secs(1)).unwrap();
    assert_eq!(elm.supply_voltage().unwrap(), known(12_100));
    // And the adapter still takes requests.
    elm.send(&request).unwrap();
    elm.recv(Duration::from_secs(1)).unwrap();
}

#[test]
fn nothing_is_written_while_a_tp20_channel_is_open() {
    // An AT command would stop the adapter's listening and could make the module drop the channel
    // (docs/tp20.md), so the voltage is unknown there.
    let mut adapter = FakeElm::new(Box::new(|header, request| match (header, request) {
        (0x200, [0x5F, 0xC0, ..]) => {
            vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
        }
        (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
        _ => Vec::new(),
    }));
    adapter.voltage = vec!["12.6V".to_owned()];
    let mut elm = connect(adapter);
    let read = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x09, 0x02])
        .unwrap();
    // An ISO-TP request first shows the adapter echoes each character as it reads it.
    elm.send(&read).unwrap();
    while elm.recv(Duration::from_secs(1)).is_ok() {}
    let setup = Policy::read_only().approve_tp20_setup(0x5F).unwrap();
    elm.send(&setup).unwrap();
    elm.recv(Duration::from_secs(1)).unwrap();
    let written = elm.link().written.len();
    assert_eq!(elm.supply_voltage().unwrap(), SupplyVoltage::Unknown);
    assert_eq!(elm.link().written.len(), written, "wrote during a channel");
    // Back in ISO-TP mode it reads again.
    elm.send(&read).unwrap();
    while elm.recv(Duration::from_secs(1)).is_ok() {}
    assert_eq!(elm.supply_voltage().unwrap(), known(12_600));
}

#[test]
fn the_audit_log_records_the_command_and_the_voltage() {
    let log = temp_log("elm");
    let mut audited = Audited::open(&log, connect(reading(&["11.9V"])), "usb-serial").unwrap();
    assert_eq!(audited.supply_voltage().unwrap(), known(11_900));
    let audit = std::fs::read_to_string(&log).unwrap();
    let command = audit
        .lines()
        .find(|line| line.contains(r#""cmd":"ATRV""#))
        .expect("no ATRV entry");
    assert!(command.contains(r#""dir":"cmd""#), "{command}");
    assert!(command.contains(r#""answer":"11.9V""#), "{command}");
    let voltage = audit
        .lines()
        .find(|line| line.contains(r#""dir":"voltage""#))
        .expect("no voltage entry");
    assert!(voltage.contains(r#""millivolts":11900"#), "{voltage}");
    assert!(voltage.ends_with(r#""link":"usb-serial"}"#), "{voltage}");
    // The reading came after the command that made it.
    let at = |needle: &str| audit.lines().position(|l| l.contains(needle)).unwrap();
    assert!(at(r#""cmd":"ATRV""#) < at(r#""dir":"voltage""#), "{audit}");
}

// A transport that reports a supply voltage, which Mock leaves unknown.
struct Powered(Mock, Result<SupplyVoltage, Error>);

impl Transport for Powered {
    fn send(&mut self, request: &obdcracker_safety::Approved) -> Result<(), Error> {
        self.0.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<obdcracker_transport::Response, Error> {
        self.0.recv(timeout)
    }

    fn supply_voltage(&mut self) -> Result<SupplyVoltage, Error> {
        self.1.clone()
    }
}

#[test]
fn a_transport_with_no_voltage_is_unknown_and_the_audit_wrapper_passes_one_through() {
    assert_eq!(
        Mock::default().supply_voltage().unwrap(),
        SupplyVoltage::Unknown
    );
    let log = temp_log("wrapper");
    let mut audited =
        Audited::open(&log, Powered(Mock::default(), Ok(known(12_345))), "x").unwrap();
    assert_eq!(audited.supply_voltage().unwrap(), known(12_345));
    let mut plain = Audited::open(&log, Mock::default(), "x").unwrap();
    assert_eq!(plain.supply_voltage().unwrap(), SupplyVoltage::Unknown);
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""dir":"voltage","millivolts":12345"#),
        "{audit}"
    );
    assert!(
        audit.contains(r#""dir":"voltage","millivolts":null"#),
        "{audit}"
    );
}

#[test]
fn a_voltage_the_adapter_failed_to_give_is_logged_as_an_error() {
    let log = temp_log("error");
    let failing = Powered(Mock::default(), Err(Error::Adapter("gone".to_owned())));
    let mut audited = Audited::open(&log, failing, "x").unwrap();
    assert_eq!(
        audited.supply_voltage(),
        Err(Error::Adapter("gone".to_owned()))
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""dir":"err","op":"supply_voltage""#),
        "{audit}"
    );
    assert!(!audit.contains(r#""dir":"voltage""#), "{audit}");
}
