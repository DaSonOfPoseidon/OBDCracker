//! Reading a car's fingerprint: what's sent, in what order, and how missing values are reported.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::obd::Cvn;
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, Policy, Rejection};
use obdcracker_transport::fingerprint::{
    Calibration, DidValue, FingerprintError, IDENTIFICATION_DIDS, ReadError, UdsModule, fingerprint,
};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

// Answers each request as it's sent, and records what was sent.
struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
    fail_after: Option<usize>,
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
            fail_after: None,
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        if self.fail_after == Some(self.sent.len()) {
            return Err(Error::Adapter("unplugged".to_owned()));
        }
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

fn reply(source: u32, payload: &[u8]) -> Response {
    Response {
        source,
        payload: payload.to_vec(),
    }
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(50),
    max_pending: 20,
};

fn calid(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(16, 0);
    bytes
}

// The engine (7E8) answers everything; the transmission (7E9) answers mode 09 PID 04 only, and
// refuses every DID but F187.
fn a7(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x09, 0x04]) => {
            let mut engine = vec![0x49, 0x04, 0x01];
            engine.extend(calid("4G0907401A  0010"));
            let mut tcu = vec![0x49, 0x04, 0x01];
            tcu.extend(calid("4G0927158   1100"));
            vec![reply(0x7E8, &engine), reply(0x7E9, &tcu)]
        }
        (0x7DF, [0x09, 0x06]) => vec![reply(0x7E8, &[0x49, 0x06, 0x01, 0x1A, 0x2B, 0x3C, 0x4D])],
        (0x7E0, [0x22, high, low]) => {
            let mut payload = vec![0x62, *high, *low];
            payload.extend(b"4G0907401A ");
            vec![reply(0x7E8, &payload)]
        }
        (0x7E1, [0x22, 0xF1, 0x87]) => vec![reply(0x7E9, b"\x62\xF1\x874G0927158  ")],
        (0x7E1, [0x22, ..]) => vec![reply(0x7E9, &[0x7F, 0x22, 0x31])],
        _ => Vec::new(),
    }
}

fn modules() -> [UdsModule; 2] {
    [UdsModule::obd_engine(), UdsModule::obd_transmission()]
}

#[test]
fn reads_calibrations_then_each_modules_dids() {
    let mut car = Car::new(a7);
    let got = fingerprint(&mut car, &Policy::read_only(), &modules(), TIMING).unwrap();

    let mut expected = vec!["7DF 09 04".to_owned(), "7DF 09 06".to_owned()];
    for id in ["7E0", "7E1"] {
        for did in IDENTIFICATION_DIDS {
            expected.push(format!("{id} 22 {:02X} {:02X}", did >> 8, did & 0xFF));
        }
    }
    assert_eq!(car.sent, expected);

    assert_eq!(
        got.ecus,
        [
            Calibration {
                source: 0x7E8,
                calids: Ok(vec!["4G0907401A  0010".to_owned()]),
                cvns: Ok(vec![Cvn([0x1A, 0x2B, 0x3C, 0x4D])]),
            },
            Calibration {
                source: 0x7E9,
                calids: Ok(vec!["4G0927158   1100".to_owned()]),
                cvns: Err(ReadError::NoReply),
            },
        ]
    );

    let [engine, tcu] = &got.modules[..] else {
        panic!("{:?}", got.modules);
    };
    assert_eq!(
        (engine.name.as_str(), engine.response_id),
        ("engine", 0x7E8)
    );
    for (did, value) in &engine.dids {
        assert_eq!(value, &Ok(DidValue::Text("4G0907401A".into())), "{did:04X}");
    }
    assert_eq!(
        tcu.dids[0],
        (0xF187, Ok(DidValue::Text("4G0927158".into())))
    );
    let refused = Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x22,
        nrc: Nrc::RequestOutOfRange,
    })));
    for (did, value) in &tcu.dids[1..] {
        assert_eq!(value, &refused, "{did:04X}");
    }
}

#[test]
fn a_silent_module_and_a_silent_car_lose_only_their_values() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = fingerprint(&mut car, &Policy::read_only(), &modules(), TIMING).unwrap();
    assert_eq!(got.ecus, []);
    for module in &got.modules {
        assert_eq!(module.dids.len(), IDENTIFICATION_DIDS.len());
        assert!(
            module
                .dids
                .iter()
                .all(|(_, v)| *v == Err(ReadError::NoReply))
        );
    }
    assert_eq!(car.sent.len(), 2 + 2 * IDENTIFICATION_DIDS.len());
}

#[test]
fn a_bad_reply_is_reported_not_trusted() {
    // CALIDs of nothing but padding, and DIDs echoed with no data
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x09, 0x04]) => {
            let mut payload = vec![0x49, 0x04, 0x01];
            payload.extend([0; 16]);
            vec![reply(0x7E8, &payload)]
        }
        (0x7E0, [0x22, high, low]) => vec![reply(0x7E8, &[0x62, *high, *low])],
        _ => Vec::new(),
    });
    let got = fingerprint(
        &mut car,
        &Policy::read_only(),
        &[UdsModule::obd_engine()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        got.ecus[0].calids,
        Err(ReadError::Reply(ReplyError::Malformed))
    );
    assert!(
        got.modules[0]
            .dids
            .iter()
            .all(|(_, v)| *v == Err(ReadError::Reply(ReplyError::TooShort)))
    );
}

#[test]
fn a_did_that_isnt_text_keeps_its_bytes() {
    // Some modules answer F188 or F19E with binary data: it's kept, shown as hex, not dropped.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, high, low]) => vec![reply(0x7E8, &[0x62, *high, *low, b'4', 0x1B, 0xFF])],
        _ => Vec::new(),
    });
    let got = fingerprint(
        &mut car,
        &Policy::read_only(),
        &[UdsModule::obd_engine()],
        TIMING,
    )
    .unwrap();
    for (did, value) in &got.modules[0].dids {
        assert_eq!(
            value,
            &Ok(DidValue::Bytes(vec![b'4', 0x1B, 0xFF])),
            "{did:04X}"
        );
        assert_eq!(value.as_ref().unwrap().to_string(), "34 1B FF");
    }
    assert_eq!(
        DidValue::Text("4G0907401A".into()).to_string(),
        "4G0907401A"
    );
}

#[test]
fn a_refused_request_stops_it_before_anything_is_sent() {
    // 0x7E8 is a reply ID, which the policy refuses as a target (#26).
    let wrong = UdsModule {
        name: "backwards".to_owned(),
        request_id: 0x7E8,
        response_id: 0x7E0,
    };
    let mut car = Car::new(a7);
    let err = fingerprint(
        &mut car,
        &Policy::read_only(),
        &[UdsModule::obd_engine(), wrong],
        TIMING,
    )
    .unwrap_err();
    assert_eq!(err, FingerprintError::Rejected(Rejection::WrongTarget));
    assert_eq!(car.sent, Vec::<String>::new());
}

#[test]
fn an_adapter_error_stops_it() {
    for fail_after in [0, 1, 2, 6] {
        let mut car = Car::new(a7);
        car.fail_after = Some(fail_after);
        assert_eq!(
            fingerprint(&mut car, &Policy::read_only(), &modules(), TIMING),
            Err(FingerprintError::Transport(Error::Adapter(
                "unplugged".to_owned()
            ))),
            "after {fail_after}"
        );
        assert_eq!(car.sent.len(), fail_after);
    }
}

#[test]
fn cvns_that_dont_pair_with_the_calids_are_an_error() {
    // Two calibration IDs but one CVN: J1979 gives one CVN per calibration ID.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x09, 0x04]) => {
            let mut payload = vec![0x49, 0x04, 0x02];
            payload.extend(calid("4G0907401A  0010"));
            payload.extend(calid("4G0907401B  0020"));
            vec![reply(0x7E8, &payload)]
        }
        (0x7DF, [0x09, 0x06]) => vec![reply(0x7E8, &[0x49, 0x06, 0x01, 0x1A, 0x2B, 0x3C, 0x4D])],
        _ => Vec::new(),
    });
    let got = fingerprint(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    assert_eq!(got.ecus[0].calids.as_ref().map(Vec::len), Ok(2));
    assert_eq!(
        got.ecus[0].cvns,
        Err(ReadError::CountMismatch { calids: 2, cvns: 1 })
    );
}
