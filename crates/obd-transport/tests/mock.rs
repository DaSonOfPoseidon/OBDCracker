use std::time::Duration;

use obd_safety::{Policy, Target};
use obd_transport::{Error, Mock, Response, Transport};

const WAIT: Duration = Duration::from_millis(100);

#[test]
fn records_each_sent_request() {
    let policy = Policy::read_only();
    let vin = policy
        .approve(Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    let rpm = policy
        .approve(Target::ObdFunctional, &[0x01, 0x0C])
        .unwrap();
    let mut mock = Mock::default();
    mock.send(&vin).unwrap();
    mock.send(&rpm).unwrap();
    assert_eq!(mock.sent(), [vin, rpm]);
}

#[test]
fn returns_queued_responses_in_order_then_times_out() {
    let mut mock = Mock::default();
    let first = Response {
        source: 0x7E8,
        payload: vec![0x41, 0x0C, 0x1A, 0xF8],
    };
    let second = Response {
        source: 0x7E9,
        payload: vec![0x41, 0x0C, 0x00, 0x00],
    };
    mock.queue(first.clone());
    mock.queue(second.clone());
    assert_eq!(mock.recv(WAIT), Ok(first));
    assert_eq!(mock.recv(WAIT), Ok(second));
    assert_eq!(mock.recv(WAIT), Err(Error::Timeout));
}
