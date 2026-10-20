//! One DTC's snapshots and extended data: what's read, in which order, and when the second read
//! is left out.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_core::uds::{DtcStatus, UdsDtc};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::dtc::{DtcDetail, RecordData, read_dtc_detail};
use obdcracker_transport::fingerprint::{FingerprintError, ReadError, UdsModule};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

// Answers each request as it's sent, and records what was sent.
struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let id = request.target().can_id();
        self.sent
            .push(format!("{id:03X} {}", hex(request.payload())));
        self.replies.extend((self.answer)(id, request.payload()));
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

// The A7's gateway and the DTC session 5 saw on it (#92).
const DTC: u32 = 0x00_16A0;

fn gateway() -> UdsModule {
    UdsModule {
        name: "gateway".into(),
        request_id: 0x710,
        response_id: 0x77A,
    }
}

fn policy() -> Policy {
    Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x710,
            reply: 0x77A,
        }])
        .unwrap()
}

fn reply(payload: &[u8]) -> Vec<Response> {
    vec![Response {
        source: 0x77A,
        payload: payload.to_vec(),
    }]
}

fn read(car: &mut Car) -> DtcDetail {
    read_dtc_detail(car, &policy(), &gateway(), UdsDtc::new(DTC), TIMING).unwrap()
}

#[test]
fn reads_every_snapshot_then_every_extended_data_record() {
    let mut car = Car::new(|_, request| match request {
        [0x19, 0x04, ..] => reply(&[0x59, 0x04, 0x00, 0x16, 0xA0, 0x01, 0x01, 0x01, 0x02]),
        // Busy first, as the A7's transmission is before DTC reads.
        [0x19, 0x06, ..] => [
            reply(&[0x7F, 0x19, 0x78]),
            reply(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01, 0x01, 0x05]),
        ]
        .concat(),
        _ => Vec::new(),
    });
    let got = read(&mut car);
    assert_eq!(
        got,
        DtcDetail {
            snapshots: Ok(RecordData {
                status: DtcStatus(0x01),
                records: vec![0x01, 0x01, 0x02],
            }),
            extended_data: Some(Ok(RecordData {
                status: DtcStatus(0x01),
                records: vec![0x01, 0x05],
            })),
            out_of_step: false,
        }
    );
    assert_eq!(car.sent, ["710 19 04 00 16 A0 FF", "710 19 06 00 16 A0 FF"]);
}

#[test]
fn a_refusal_of_one_read_doesnt_stop_the_other() {
    let mut car = Car::new(|_, request| match request {
        [0x19, 0x04, ..] => reply(&[0x7F, 0x19, 0x12]),
        [0x19, 0x06, ..] => reply(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01]),
        _ => Vec::new(),
    });
    let got = read(&mut car);
    assert_eq!(
        got.snapshots,
        Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
            sid: 0x19,
            nrc: Nrc::SubFunctionNotSupported,
        })))
    );
    assert_eq!(
        got.extended_data,
        Some(Ok(RecordData {
            status: DtcStatus(0x01),
            records: Vec::new(),
        }))
    );
    assert!(!got.out_of_step);
}

#[test]
fn after_an_unanswered_snapshot_read_the_extended_data_isnt_asked() {
    // Its late refusal could pass for the extended data's answer: refusals don't name the DTC.
    let mut car = Car::new(|_, _| Vec::new());
    let got = read(&mut car);
    assert_eq!(
        got,
        DtcDetail {
            snapshots: Err(ReadError::NoReply),
            extended_data: None,
            out_of_step: true,
        }
    );
    assert_eq!(car.sent, ["710 19 04 00 16 A0 FF"]);
}

#[test]
fn an_unanswered_extended_data_read_says_replies_may_be_out_of_step() {
    let mut car = Car::new(|_, request| match request {
        [0x19, 0x04, ..] => reply(&[0x59, 0x04, 0x00, 0x16, 0xA0, 0x01]),
        _ => Vec::new(),
    });
    let got = read(&mut car);
    assert_eq!(got.extended_data, Some(Err(ReadError::NoReply)));
    assert!(got.out_of_step);
}

#[test]
fn another_dtcs_answer_is_kept_as_undecodable() {
    let mut car = Car::new(|_, request| match request {
        [0x19, 0x04, ..] => reply(&[0x59, 0x04, 0x00, 0x16, 0xA1, 0x01]),
        [0x19, 0x06, ..] => reply(&[0x59, 0x06, 0x00, 0x16, 0xA0, 0x01]),
        _ => Vec::new(),
    });
    let got = read(&mut car);
    assert_eq!(
        got.snapshots,
        Err(ReadError::Undecodable {
            error: ReplyError::Malformed,
            reply: vec![0x59, 0x04, 0x00, 0x16, 0xA1, 0x01],
        })
    );
}

#[test]
fn both_reads_are_approved_before_anything_is_sent() {
    // A module the narrowed policy doesn't know: refused, and nothing reaches the bus.
    let mut car = Car::new(|_, _| Vec::new());
    let other = UdsModule {
        name: "other".into(),
        request_id: 0x711,
        response_id: 0x77B,
    };
    let got = read_dtc_detail(&mut car, &policy(), &other, UdsDtc::new(DTC), TIMING);
    assert_eq!(got, Err(FingerprintError::Rejected(Rejection::WrongTarget)));
    assert_eq!(car.sent, Vec::<String>::new());
}
