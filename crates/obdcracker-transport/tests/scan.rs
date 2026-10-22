//! A read-only scan: what's sent, in what order, and how missing values are reported.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::obd::{Dtc, Unit};
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_core::uds::{DiagnosticSession, DtcCount, DtcFormat, DtcRecord, DtcStatus, UdsDtc};
use obdcracker_safety::{Approved, Policy};
use obdcracker_transport::fingerprint::{DidValue, FingerprintError, ReadError, UdsModule};
use obdcracker_transport::scan::{
    DidFormat, ExtraDid, ObdEcu, PidValue, SCAN_DIDS, Scan, ScanModule, ScanOptions, scan,
    scan_with,
};
use obdcracker_transport::{Error, Response, S3, SessionError, Timing, Transport, hex};

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

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
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

const REFUSED: Nrc = Nrc::RequestOutOfRange;

fn engine(extra_dids: &[u16]) -> ScanModule {
    ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: extra_dids
            .iter()
            .map(|&id| ExtraDid {
                id,
                format: DidFormat::Text,
                length: None,
                session: DiagnosticSession::Default,
            })
            .collect(),
    }
}

// The engine with the lengths of F187, F189, F191 (11, 4 and 11 bytes) and its 2-byte coding
// (0600), so those can be read several at a time.
fn engine_with_lengths() -> ScanModule {
    let did = |id, format, length| ExtraDid {
        id,
        format,
        length: Some(length),
        session: DiagnosticSession::Default,
    };
    ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![
            did(0xF187, DidFormat::Text, 11),
            did(0xF189, DidFormat::Text, 4),
            did(0xF191, DidFormat::Text, 11),
            did(0x0600, DidFormat::Hex, 2),
        ],
    }
}

const F187: &[u8] = b"\xF1\x874G0907401N ";
const F189: &[u8] = b"\xF1\x890016";
const F191: &[u8] = b"\xF1\x914G0907401E ";

fn undecodable(error: ReplyError, reply: &[u8]) -> ReadError {
    ReadError::Undecodable {
        error,
        reply: reply.to_vec(),
    }
}

fn dids_reply(values: &[&[u8]]) -> Vec<Response> {
    let mut payload = vec![0x62];
    for value in values {
        payload.extend_from_slice(value);
    }
    vec![reply(0x7E8, &payload)]
}

fn did_requests(car: &Car) -> Vec<&str> {
    car.sent
        .iter()
        .map(String::as_str)
        .filter(|sent| sent.starts_with("7E0 22"))
        .collect()
}

fn texts(scan: &Scan) -> Vec<(u16, String)> {
    scan.modules[0]
        .dids
        .iter()
        .filter_map(|(did, value)| match value {
            Ok(DidValue::Text(text)) => Some((*did, text.clone())),
            Ok(DidValue::Bytes(bytes)) => Some((*did, hex(bytes))),
            Ok(DidValue::NotSet) => Some((*did, "not set".into())),
            Err(_) => None,
        })
        .collect()
}

const READ: [(u16, &str); 4] = [
    (0xF187, "4G0907401N"),
    (0xF189, "0016"),
    (0xF191, "4G0907401E"),
    (0x0600, "01 02"),
];

#[test]
fn reads_dids_with_known_lengths_three_at_a_time() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91]) => dids_reply(&[F187, F189, F191]),
        (0x7E0, [0x22, 0x06, 0x00]) => dids_reply(&[&[0x06, 0x00, 0x01, 0x02]]),
        (0x7E0, [0x22, _, _]) => vec![reply(0x7E8, &[0x7F, 0x22, 0x31])],
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    // The three with lengths in one request where the first of them comes, the rest alone. A
    // group of one is an ordinary read.
    let mut expected = vec!["7E0 22 F1 87 F1 89 F1 91".to_owned()];
    for did in SCAN_DIDS.iter().chain(&[0x0600]) {
        if ![0xF187, 0xF189, 0xF191].contains(did) {
            expected.push(format!("7E0 22 {:02X} {:02X}", did >> 8, did & 0xFF));
        }
    }
    assert_eq!(did_requests(&car), expected);
    assert_eq!(texts(&got), READ.map(|(did, text)| (did, text.to_owned())));
    let order: Vec<u16> = got.modules[0].dids.iter().map(|(did, _)| *did).collect();
    let mut want = SCAN_DIDS.to_vec();
    want.push(0x0600);
    assert_eq!(order, want);
}

#[test]
fn a_batch_never_asks_for_a_reply_longer_than_iso_tp_carries() {
    // Two 2046-byte values need a 4097-byte reply (1 + 2 + 2046 + 2 + 2046), over ISO-TP's
    // 4095, so they're read in separate requests; a small one still joins the second.
    let mut car = Car::new(|_, _| Vec::new());
    let did = |id, length| ExtraDid {
        id,
        format: DidFormat::Hex,
        length: Some(length),
        session: DiagnosticSession::Default,
    };
    let module = ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![did(0x0600, 2046), did(0x0601, 2046), did(0x0602, 1)],
    };
    scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    let requests = did_requests(&car);
    assert!(requests.contains(&"7E0 22 06 01 06 02"), "{requests:?}");
    assert!(
        !requests
            .iter()
            .any(|sent| sent.starts_with("7E0 22 06 00 06")),
        "{requests:?}"
    );
    // Exactly 4095 bytes fits: 1 + 2 + 2045 + 2 + 2045.
    let mut car = Car::new(|_, _| Vec::new());
    let module = ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![did(0x0600, 2045), did(0x0601, 2045)],
    };
    scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    assert!(did_requests(&car).contains(&"7E0 22 06 00 06 01"));
    // A value too long for any batch is read alone, and the ones around it still batch.
    let mut car = Car::new(|_, _| Vec::new());
    let module = ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![
            did(0x0600, 1),
            did(0x0601, 5000),
            did(0x0602, 1),
            did(0x0603, 1),
        ],
    };
    scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    let requests = did_requests(&car);
    assert!(requests.contains(&"7E0 22 06 01"), "{requests:?}");
    assert!(requests.contains(&"7E0 22 06 02 06 03"), "{requests:?}");
    assert!(
        !requests.iter().any(|sent| sent.contains("06 01 06")),
        "{requests:?}"
    );
}

#[test]
fn a_late_batched_reply_isnt_taken_for_one_did() {
    // The multi-DID read times out, and its reply arrives during the first read alone. It starts
    // with F187, but the rest is F189 and F191, not more of F187's value.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87]) => dids_reply(&[F187, F189, F191]),
        (0x7E0, [0x22, 0xF1, 0x89]) => dids_reply(&[F189]),
        (0x7E0, [0x22, 0xF1, 0x91]) => dids_reply(&[F191]),
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        did_value(&got, 0xF187),
        Some(Err(undecodable(
            ReplyError::Malformed,
            &[&[0x62][..], F187, F189, F191].concat()
        )))
    );
    assert_eq!(
        did_value(&got, 0xF189),
        Some(Ok(DidValue::Text("0016".into())))
    );
    assert_eq!(
        did_value(&got, 0xF191),
        Some(Ok(DidValue::Text("4G0907401E".into())))
    );
    // Nor when it doesn't fit the lengths either: F187 a byte short.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87]) => dids_reply(&[b"\xF1\x874G0907401N", F189, F191]),
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        did_value(&got, 0xF187),
        Some(Err(undecodable(
            ReplyError::Malformed,
            &[&b"\x62\xF1\x874G0907401N"[..], F189, F191].concat()
        )))
    );
    // A reply to a read alone may still carry just that DID at its length.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87]) => dids_reply(&[F187]),
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        did_value(&got, 0xF187),
        Some(Ok(DidValue::Text("4G0907401N".into())))
    );
}

#[test]
fn after_any_failed_batch_a_did_must_have_its_length() {
    // A late refusal can pass for the multi-DID answer, so a lone read must be the profile's length.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91]) => {
            vec![reply(0x7E8, &[0x7F, 0x22, 0x13])]
        }
        (0x7E0, [0x22, 0xF1, 0x87]) => dids_reply(&[b"\xF1\x874G0907401ABC"]),
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        did_value(&got, 0xF187),
        Some(Err(undecodable(
            ReplyError::Malformed,
            b"\x62\xF1\x874G0907401ABC"
        )))
    );
}

#[test]
fn a_refused_batch_counts_as_an_answer() {
    // The module refuses the multi-DID read, then goes quiet: every later read times out.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91]) => {
            vec![reply(0x7E8, &[0x7F, 0x22, 0x13])]
        }
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert!(
        got.modules[0]
            .dids
            .iter()
            .all(|(_, value)| *value == Err(ReadError::NoReply))
    );
    assert!(got.modules[0].answered);
    assert!(got.anything_answered());
}

#[test]
fn a_did_with_length_0_is_read_alone() {
    let mut car = Car::new(|_, _| Vec::new());
    let mut module = engine_with_lengths();
    module.extra_dids[1].length = Some(0);
    scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    // Nothing answers, so the three in the batch are read alone after it.
    assert_eq!(
        &did_requests(&car)[..4],
        [
            "7E0 22 F1 87 F1 91 06 00",
            "7E0 22 F1 87",
            "7E0 22 F1 91",
            "7E0 22 06 00"
        ]
    );
    assert!(did_requests(&car).contains(&"7E0 22 F1 89"));
}

#[test]
fn a_did_missing_from_a_batched_reply_is_read_alone() {
    // ISO 14229-1: a module leaves out the DIDs it doesn't support. Here it leaves out F189,
    // which it then answers alone, as a module might under a different condition.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91]) => dids_reply(&[F187, F191]),
        (0x7E0, [0x22, 0xF1, 0x89]) => dids_reply(&[F189]),
        (0x7E0, [0x22, 0x06, 0x00]) => dids_reply(&[&[0x06, 0x00, 0x01, 0x02]]),
        (0x7E0, [0x22, _, _]) => vec![reply(0x7E8, &[0x7F, 0x22, 0x31])],
        _ => Vec::new(),
    });
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_lengths()],
        TIMING,
    )
    .unwrap();
    assert_eq!(
        &did_requests(&car)[..2],
        ["7E0 22 F1 87 F1 89 F1 91", "7E0 22 F1 89"]
    );
    assert_eq!(
        did_requests(&car)
            .iter()
            .filter(|sent| sent.contains("F1 87") || sent.contains("F1 91"))
            .count(),
        1
    );
    assert_eq!(texts(&got), READ.map(|(did, text)| (did, text.to_owned())));
}

#[test]
fn a_batched_read_that_fails_is_read_again_one_at_a_time() {
    let wrong_length: &[u8] = b"\xF1\x874G0907401N";
    for batch in [
        // A refusal, such as a module that takes one DID per request
        vec![reply(0x7E8, &[0x7F, 0x22, 0x13])],
        // F187 a byte shorter than the profile says, so F189 doesn't start where expected
        dids_reply(&[wrong_length, F189, F191]),
        // A byte left over
        dids_reply(&[F187, F189, F191, &[0x00]]),
        // DIDs out of the order asked for
        dids_reply(&[F189, F187, F191]),
        // A DID that wasn't asked for
        dids_reply(&[F187, &[0xF1, 0x88, 0x30, 0x30]]),
        // Nothing at all
        Vec::new(),
    ] {
        let mut car = Car::new(move |id, request| match (id, request) {
            (0x7E0, [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91]) => batch.clone(),
            (0x7E0, [0x22, 0xF1, 0x87]) => dids_reply(&[F187]),
            (0x7E0, [0x22, 0xF1, 0x89]) => dids_reply(&[F189]),
            (0x7E0, [0x22, 0xF1, 0x91]) => dids_reply(&[F191]),
            (0x7E0, [0x22, 0x06, 0x00]) => dids_reply(&[&[0x06, 0x00, 0x01, 0x02]]),
            (0x7E0, [0x22, _, _]) => vec![reply(0x7E8, &[0x7F, 0x22, 0x31])],
            _ => Vec::new(),
        });
        let got = scan(
            &mut car,
            &Policy::read_only(),
            &[engine_with_lengths()],
            TIMING,
        )
        .unwrap();
        assert_eq!(
            &did_requests(&car)[..4],
            [
                "7E0 22 F1 87 F1 89 F1 91",
                "7E0 22 F1 87",
                "7E0 22 F1 89",
                "7E0 22 F1 91"
            ]
        );
        assert_eq!(texts(&got), READ.map(|(did, text)| (did, text.to_owned())));
    }
}

// The engine (7E8) supports PIDs 05, 0C, 1C (not decoded here) and, through bitmaps 20 and 40,
// 42.
// The transmission (7E9) supports only 05. Only the engine answers UDS reads.
fn car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![
            // 05, 0C, 1C and 20
            reply(0x7E8, &[0x41, 0x00, 0x08, 0x10, 0x00, 0x11]),
            // 05
            reply(0x7E9, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x00]),
        ],
        // Only the next bitmap
        (0x7DF, [0x01, 0x20]) => vec![reply(0x7E8, &[0x41, 0x20, 0x00, 0x00, 0x00, 0x01])],
        // 42, and no next bitmap
        (0x7DF, [0x01, 0x40]) => vec![reply(0x7E8, &[0x41, 0x40, 0x40, 0x00, 0x00, 0x00])],
        (0x7DF, [0x01, 0x05]) => vec![
            reply(0x7E8, &[0x41, 0x05, 0x82]),
            reply(0x7E9, &[0x41, 0x05, 0x7D]),
        ],
        (0x7DF, [0x01, 0x0C]) => vec![reply(0x7E8, &[0x41, 0x0C, 0x0C, 0x80])],
        (0x7DF, [0x01, 0x1C]) => vec![reply(0x7E8, &[0x41, 0x1C, 0x06])],
        (0x7DF, [0x01, 0x42]) => vec![reply(0x7E8, &[0x41, 0x42, 0x36, 0xB0])],
        // 02, 04, 06 and 0A
        (0x7DF, [0x09, 0x00]) => vec![reply(0x7E8, &[0x49, 0x00, 0x54, 0x40, 0x00, 0x00])],
        (0x7DF, [0x09, 0x0A]) => {
            let mut payload = vec![0x49, 0x0A, 0x01];
            payload.extend(b"ECM\0-EngineControl\0\0");
            vec![reply(0x7E8, &payload)]
        }
        (0x7DF, [0x03]) => vec![
            reply(0x7E8, &[0x43, 0x01, 0x02, 0x99]),
            reply(0x7E9, &[0x43, 0x00]),
        ],
        (0x7E0, [0x22, 0xF1, 0x87]) => vec![reply(0x7E8, b"\x62\xF1\x874G0907401N ")],
        (0x7E0, [0x22, 0x06, 0x00]) => vec![reply(0x7E8, &[0x62, 0x06, 0x00, 0x01, 0x02])],
        (0x7E0, [0x22, _, _]) => vec![reply(0x7E8, &[0x7F, 0x22, 0x31])],
        (0x7E0, [0x19, 0x01, 0xAF]) => {
            vec![reply(0x7E8, &[0x59, 0x01, 0xFF, 0x00, 0x00, 0x01])]
        }
        (0x7E0, [0x19, 0x02, 0xAF]) => {
            vec![reply(0x7E8, &[0x59, 0x02, 0xFF, 0x02, 0x99, 0x00, 0x08])]
        }
        _ => Vec::new(),
    }
}

#[test]
fn reads_obd_data_then_each_modules_dids_and_dtcs() {
    let mut car = Car::new(car);
    let got = scan(&mut car, &Policy::read_only(), &[engine(&[0x0600])], TIMING).unwrap();

    let mut expected: Vec<String> = [
        "7DF 01 00",
        "7DF 01 20",
        "7DF 01 40",
        "7DF 01 05",
        "7DF 01 0C",
        "7DF 01 1C",
        "7DF 01 42",
        "7DF 09 00",
        "7DF 09 0A",
        "7DF 03",
    ]
    .map(str::to_owned)
    .to_vec();
    for did in SCAN_DIDS.iter().chain(&[0x0600]) {
        expected.push(format!("7E0 22 {:02X} {:02X}", did >> 8, did & 0xFF));
    }
    expected.extend(["7E0 19 01 AF".to_owned(), "7E0 19 02 AF".to_owned()]);
    assert_eq!(car.sent, expected);

    let quantity = |value, unit| Ok(PidValue::Quantity { value, unit });
    assert_eq!(
        got.ecus,
        [
            ObdEcu {
                source: 0x7E8,
                pids: Ok(vec![
                    (0x05, quantity(90.0, Unit::Celsius)),
                    (0x0C, quantity(800.0, Unit::Rpm)),
                    (0x1C, Ok(PidValue::Raw(vec![0x06]))),
                    (0x42, quantity(14.0, Unit::Volts)),
                ]),
                pids_cut_short: None,
                supported_info: Ok(vec![0x02, 0x04, 0x06, 0x0A]),
                ecu_name: Ok("ECM-EngineControl".to_owned()),
                stored_dtcs: Ok(vec![Dtc::new(0x0299)]),
            },
            ObdEcu {
                source: 0x7E9,
                pids: Ok(vec![(0x05, quantity(85.0, Unit::Celsius))]),
                pids_cut_short: None,
                supported_info: Err(ReadError::NoReply),
                ecu_name: Err(ReadError::NoReply),
                stored_dtcs: Ok(vec![]),
            },
        ]
    );

    let [module] = &got.modules[..] else {
        panic!("{:?}", got.modules);
    };
    assert_eq!(
        (module.name.as_str(), module.response_id),
        ("engine", 0x7E8)
    );
    let refused = Err(ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x22,
        nrc: REFUSED,
    })));
    for (did, value) in &module.dids {
        let want = match did {
            0xF187 => Ok(DidValue::Text("4G0907401N".into())),
            0x0600 => Ok(DidValue::Bytes(vec![0x01, 0x02])),
            _ => refused.clone(),
        };
        assert_eq!(value, &want, "{did:04X}");
    }
    assert_eq!(
        module.dtc_count,
        Ok(DtcCount {
            availability: DtcStatus(0xFF),
            format: DtcFormat::SaeJ2012Da00,
            count: 1,
        })
    );
    assert_eq!(
        module.dtcs,
        Ok(vec![DtcRecord {
            dtc: UdsDtc::new(0x02_9900),
            status: DtcStatus(0x08),
        }])
    );
}

#[test]
fn lists_only_dtcs_with_a_fault_bit_the_module_supports() {
    // A module that ignores the mask and sends its whole DTC table, as every A7 module's table
    // looks with mask 0xFF (#49), and supports only status bits 0, 3, 4 and 5 (availability
    // 0x39).
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x19, 0x02, 0xAF]) => vec![reply(
            0x7E8,
            &[
                0x59, 0x02, 0x39, //
                0x00, 0x12, 0x57, 0x50, // not tested: no fault bit
                0x00, 0x13, 0x01, 0x04, // pending, but the module says it has no such bit
                0x02, 0x99, 0x00, 0x09, // failed, confirmed
                0x00, 0x13, 0x02, 0x11, // failed, not tested since clear
                0x00, 0x14, 0x00, 0x20, // failed since the last clear, passing now
            ],
        )],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING).unwrap();
    assert_eq!(
        got.modules[0].dtcs,
        Ok(vec![
            DtcRecord {
                dtc: UdsDtc::new(0x02_9900),
                status: DtcStatus(0x09),
            },
            DtcRecord {
                dtc: UdsDtc::new(0x00_1302),
                status: DtcStatus(0x11),
            },
            DtcRecord {
                dtc: UdsDtc::new(0x00_1400),
                status: DtcStatus(0x20),
            },
        ])
    );
}

#[test]
fn reads_each_did_once_in_standard_then_profile_order() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine(&[0x0600, 0xF187, 0xF1AA, 0x0600])],
        TIMING,
    )
    .unwrap();
    let dids: Vec<u16> = got.modules[0].dids.iter().map(|(did, _)| *did).collect();
    let mut expected = SCAN_DIDS.to_vec();
    expected.extend([0x0600, 0xF1AA]);
    assert_eq!(dids, expected);
}

#[test]
fn a_hex_did_keeps_its_bytes_even_when_they_look_like_text() {
    // A VAG coding value whose bytes happen to be printable ("01").
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0x06, 0x00]) => vec![reply(0x7E8, &[0x62, 0x06, 0x00, 0x30, 0x31])],
        (0x7E0, [0x22, 0xF1, 0x87]) => vec![reply(0x7E8, b"\x62\xF1\x87ab")],
        _ => Vec::new(),
    });
    let module = ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![
            ExtraDid {
                id: 0x0600,
                format: DidFormat::Hex,
                length: None,
                session: DiagnosticSession::Default,
            },
            // A standard DID stays text, whatever a later entry says.
            ExtraDid {
                id: 0xF187,
                format: DidFormat::Hex,
                length: None,
                session: DiagnosticSession::Default,
            },
        ],
    };
    let got = scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    let value = |want: u16| {
        got.modules[0]
            .dids
            .iter()
            .find(|(did, _)| *did == want)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value(0x0600), Some(Ok(DidValue::Bytes(vec![0x30, 0x31]))));
    assert_eq!(value(0xF187), Some(Ok(DidValue::Text("ab".into()))));
}

fn did_value(got: &Scan, want: u16) -> Option<Result<DidValue, ReadError>> {
    got.modules[0]
        .dids
        .iter()
        .find(|(did, _)| *did == want)
        .map(|(_, value)| value.clone())
}

#[test]
fn a_profile_format_replaces_the_default_for_a_standard_did_with_no_fixed_format() {
    // A manufacture date (F18B) whose BCD bytes happen to be printable ("13 11 19" isn't, but
    // "20 31 39" is), and an unset date of zeros, which as text would show as empty.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x8B]) => vec![reply(0x7E8, &[0x62, 0xF1, 0x8B, 0x20, 0x31, 0x39])],
        (0x7E0, [0x22, 0xF1, 0x8C]) => vec![reply(0x7E8, &[0x62, 0xF1, 0x8C, 0x00, 0x00, 0x00])],
        _ => Vec::new(),
    });
    let hex = |id| ExtraDid {
        id,
        format: DidFormat::Hex,
        length: None,
        session: DiagnosticSession::Default,
    };
    let module = ScanModule {
        module: UdsModule::obd_engine(),
        // The first entry for a DID wins, as for any other extra DID.
        extra_dids: vec![
            hex(0xF18B),
            hex(0xF18C),
            ExtraDid {
                id: 0xF18B,
                format: DidFormat::Text,
                length: None,
                session: DiagnosticSession::Default,
            },
        ],
    };
    let got = scan(&mut car, &Policy::read_only(), &[module], TIMING).unwrap();
    assert_eq!(
        did_value(&got, 0xF18B),
        Some(Ok(DidValue::Bytes(vec![0x20, 0x31, 0x39])))
    );
    assert_eq!(
        did_value(&got, 0xF18C),
        Some(Ok(DidValue::Bytes(vec![0x00, 0x00, 0x00])))
    );
    let dids: Vec<u16> = got.modules[0].dids.iter().map(|(did, _)| *did).collect();
    assert_eq!(dids, SCAN_DIDS);
}

#[test]
fn f190_must_be_a_vin() {
    for (data, want) in [
        (
            &b"WAU2MBFC6EN093415"[..],
            Ok::<_, ReplyError>(DidValue::Text("WAU2MBFC6EN093415".into())),
        ),
        (b"abc", Err(ReplyError::Malformed)),
        (b"WAU2MBFC6EN09341 ", Err(ReplyError::Malformed)),
        // A module with no VIN stored sends 17 of one filler byte: dashes on the A7's rear lid,
        // parking brake and top view camera (#54, #63).
        (b"-----------------", Ok(DidValue::NotSet)),
        (&[0x00; 17], Ok(DidValue::NotSet)),
        (&[0xFF; 17], Ok(DidValue::NotSet)),
        (&[b' '; 17], Ok(DidValue::NotSet)),
        // Only a whole VIN's worth of one filler.
        (b"----------------", Err(ReplyError::Malformed)),
        (b"------------------", Err(ReplyError::Malformed)),
        (b"----------------\0", Err(ReplyError::Malformed)),
        (&[0x2E; 17], Err(ReplyError::Malformed)),
    ] {
        let payload = [&[0x62, 0xF1, 0x90][..], data].concat();
        let want = want.map_err(|error| undecodable(error, &payload));
        let mut car = Car::new(move |id, request| match (id, request) {
            (0x7E0, [0x22, 0xF1, 0x90]) => vec![reply(0x7E8, &payload)],
            _ => Vec::new(),
        });
        let got = scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING).unwrap();
        assert_eq!(
            did_value(&got, 0xF190),
            Some(want),
            "{}",
            String::from_utf8_lossy(data)
        );
    }
}

#[test]
fn a_silent_car_loses_only_its_values() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING).unwrap();
    assert_eq!(got.ecus, []);
    assert!(!got.anything_answered());
    let module = &got.modules[0];
    assert!(!module.answered);
    assert!(
        module
            .dids
            .iter()
            .all(|(_, v)| *v == Err(ReadError::NoReply))
    );
    assert_eq!(module.dtc_count, Err(ReadError::NoReply));
    assert_eq!(module.dtcs, Err(ReadError::NoReply));
    // No bitmap answered, so no PIDs and no later bitmaps are asked for.
    assert_eq!(
        car.sent[..4],
        ["7DF 01 00", "7DF 09 00", "7DF 09 0A", "7DF 03"]
    );
    assert_eq!(car.sent.len(), 4 + SCAN_DIDS.len() + 2);
}

#[test]
fn a_garbled_later_bitmap_ends_that_ecus_chain() {
    // 7E8's bitmap 20 is truncated while 7E9's keeps the chain going to 40; 7E8 answers 40 too.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![
            // 05 and 20
            reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x01]),
            reply(0x7E9, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x01]),
        ],
        (0x7DF, [0x01, 0x20]) => vec![
            reply(0x7E8, &[0x41, 0x20, 0x00]),
            // 40
            reply(0x7E9, &[0x41, 0x20, 0x00, 0x00, 0x00, 0x01]),
        ],
        // 42
        (0x7DF, [0x01, 0x40]) => vec![
            reply(0x7E8, &[0x41, 0x40, 0x40, 0x00, 0x00, 0x00]),
            reply(0x7E9, &[0x41, 0x40, 0x40, 0x00, 0x00, 0x00]),
        ],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    let pids = |ecu: &ObdEcu| -> Vec<u8> {
        ecu.pids
            .as_ref()
            .unwrap()
            .iter()
            .map(|(pid, _)| *pid)
            .collect()
    };
    assert_eq!(pids(&got.ecus[0]), [0x05]);
    assert_eq!(pids(&got.ecus[1]), [0x05, 0x42]);
}

#[test]
fn a_bitmap_an_ecu_didnt_advertise_is_ignored() {
    // Only 7E8 says bitmap 20 is supported, but 7E9 answers it too.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![
            // 05 and 20
            reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x01]),
            // 05
            reply(0x7E9, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x00]),
        ],
        // 21
        (0x7DF, [0x01, 0x20]) => vec![
            reply(0x7E8, &[0x41, 0x20, 0x80, 0x00, 0x00, 0x00]),
            reply(0x7E9, &[0x41, 0x20, 0x80, 0x00, 0x00, 0x00]),
        ],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    let pids = |ecu: &ObdEcu| -> Vec<u8> {
        ecu.pids
            .as_ref()
            .unwrap()
            .iter()
            .map(|(pid, _)| *pid)
            .collect()
    };
    assert_eq!(pids(&got.ecus[0]), [0x05, 0x21]);
    assert_eq!(pids(&got.ecus[1]), [0x05]);
}

#[test]
fn the_bitmap_chain_stops_after_pid_e0() {
    // Every bitmap says the next one is supported, and nothing else.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, base]) => vec![reply(0x7E8, &[0x41, *base, 0x00, 0x00, 0x00, 0x01])],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    let bitmaps: Vec<_> = car
        .sent
        .iter()
        .filter(|s| s.starts_with("7DF 01"))
        .collect();
    assert_eq!(
        bitmaps,
        [
            "7DF 01 00",
            "7DF 01 20",
            "7DF 01 40",
            "7DF 01 60",
            "7DF 01 80",
            "7DF 01 A0",
            "7DF 01 C0",
            "7DF 01 E0",
        ]
    );
    assert_eq!(got.ecus[0].pids, Ok(vec![]));
}

#[test]
fn a_pid_reply_with_extra_bytes_is_malformed() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x00])],
        (0x7DF, [0x01, 0x05]) => vec![reply(0x7E8, &[0x41, 0x05, 0x82, 0x0C])],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    assert_eq!(
        got.ecus[0].pids,
        Ok(vec![(
            0x05,
            Err(undecodable(
                ReplyError::Malformed,
                &[0x41, 0x05, 0x82, 0x0C]
            ))
        )])
    );
}

#[test]
fn a_garbled_first_bitmap_is_an_error_not_an_empty_list() {
    // A truncated 01 00 reply, then a stored-DTC answer so the ECU is still listed.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x08])],
        (0x7DF, [0x03]) => vec![reply(0x7E8, &[0x43, 0x00])],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    assert_eq!(
        got.ecus[0].pids,
        Err(undecodable(ReplyError::TooShort, &[0x41, 0x00, 0x08]))
    );
    assert_eq!(got.ecus[0].stored_dtcs, Ok(vec![]));
}

#[test]
fn a_later_bitmap_that_is_garbled_or_missing_says_where_the_list_was_cut_short() {
    // PID 00 lists PID 05 and the next page (20), whose reply is truncated or never comes. Page
    // 00's PIDs are still read, and the list says it stops at 20 and why.
    for (page_20, why) in [
        (
            vec![reply(0x7E8, &[0x41, 0x20, 0x08])],
            undecodable(ReplyError::TooShort, &[0x41, 0x20, 0x08]),
        ),
        (Vec::new(), ReadError::NoReply),
    ] {
        let mut car = Car::new(move |id, request| match (id, request) {
            (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x01])],
            (0x7DF, [0x01, 0x20]) => page_20.clone(),
            (0x7DF, [0x01, 0x05]) => vec![reply(0x7E8, &[0x41, 0x05, 0x82])],
            _ => Vec::new(),
        });
        let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
        assert_eq!(
            got.ecus[0].pids,
            Ok(vec![(
                0x05,
                Ok(PidValue::Quantity {
                    value: 90.0,
                    unit: Unit::Celsius
                })
            )])
        );
        assert_eq!(got.ecus[0].pids_cut_short, Some((0x20, why)));
    }
    // A chain that ends where the ECU said it does isn't cut short.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x00])],
        (0x7DF, [0x01, 0x05]) => vec![reply(0x7E8, &[0x41, 0x05, 0x82])],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    assert_eq!(got.ecus[0].pids_cut_short, None);
}

#[test]
fn an_ecu_missing_from_the_bitmap_has_no_pid_list() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x03]) => vec![reply(0x7E8, &[0x43, 0x00])],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap();
    assert_eq!(got.ecus[0].pids, Err(ReadError::NoReply));
}

#[test]
fn an_adapter_failure_stops_the_scan() {
    for fail_after in [0, 1, 9, 12] {
        let mut car = Car::new(car);
        car.fail_after = Some(fail_after);
        assert_eq!(
            scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING),
            Err(FingerprintError::Transport(Error::Adapter(
                "unplugged".to_owned()
            ))),
            "after {fail_after}"
        );
        assert_eq!(car.sent.len(), fail_after);
    }
}

#[test]
fn a_module_that_stays_busy_loses_only_that_value() {
    // F187 gets response-pending and never its answer (#17): that value says so, and the scan
    // goes on to the rest.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7E0, [0x22, 0xF1, 0x87]) => vec![reply(0x7E8, &[0x7F, 0x22, 0x78])],
        (0x7E0, [0x22, 0xF1, 0x89]) => vec![reply(0x7E8, b"\x62\xF1\x890016")],
        _ => Vec::new(),
    });
    let got = scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING).unwrap();
    assert_eq!(did_value(&got, 0xF187), Some(Err(ReadError::StillPending)));
    assert_eq!(
        did_value(&got, 0xF189),
        Some(Ok(DidValue::Text("0016".into())))
    );
    assert_eq!(
        ReadError::StillPending.to_string(),
        "the module said it was busy (response-pending) but didn't answer in time"
    );
}

// The engine with DIDs only the extended session reads: its coding (0600) and two values with
// lengths, which can be read in one request.
fn engine_with_extended() -> ScanModule {
    let did = |id, length| ExtraDid {
        id,
        format: DidFormat::Hex,
        length,
        session: DiagnosticSession::Extended,
    };
    ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: vec![
            did(0x0600, None),
            did(0x0601, Some(1)),
            did(0x0602, Some(2)),
        ],
    }
}

// An engine that reads 0600..=0602 only in the extended session, and refuses the identification
// DIDs. `enter` is its answer to 10 03.
fn session_car(enter: &'static [u8]) -> Car {
    let mut extended = false;
    Car::new(move |id, request| {
        if id != 0x7E0 {
            return Vec::new();
        }
        match request {
            [0x10, 0x03] => {
                extended = enter[0] == 0x50;
                vec![reply(0x7E8, enter)]
            }
            [0x10, 0x01] => {
                extended = false;
                vec![reply(0x7E8, &[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4])]
            }
            [0x3E, 0x00] => vec![reply(0x7E8, &[0x7E, 0x00])],
            [0x22, 0x06, 0x00] if extended => dids_reply(&[&[0x06, 0x00, 0xAA, 0xBB]]),
            [0x22, 0x06, 0x01, 0x06, 0x02] if extended => {
                dids_reply(&[&[0x06, 0x01, 0x01], &[0x06, 0x02, 0x02, 0x03]])
            }
            [0x22, ..] => vec![reply(0x7E8, &[0x7F, 0x22, 0x31])],
            [0x19, ..] => vec![reply(0x7E8, &[0x7F, 0x19, 0x12])],
            _ => Vec::new(),
        }
    })
}

const ENTERED: &[u8] = &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4];

fn extended() -> ScanOptions {
    let mut options = ScanOptions::default();
    options.extended = Some(S3::default());
    options
}

fn value(scan: &Scan, did: u16) -> Result<DidValue, ReadError> {
    scan.modules[0]
        .dids
        .iter()
        .find(|(id, _)| *id == did)
        .unwrap_or_else(|| panic!("{did:04X} wasn't read"))
        .1
        .clone()
}

#[test]
fn extended_dids_are_only_read_when_asked() {
    let mut car = session_car(ENTERED);
    let got = scan(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
    )
    .unwrap();
    for did in [0x0600, 0x0601, 0x0602] {
        assert_eq!(value(&got, did), Err(ReadError::NeedsExtendedSession));
    }
    assert!(
        !car.sent.iter().any(|sent| sent.starts_with("7E0 10")),
        "{:?}",
        car.sent
    );
    // Only the module's own answers count: refusals of the identification DIDs here.
    assert!(got.modules[0].answered);
}

#[test]
fn extended_dids_are_read_in_the_extended_session_after_everything_else() {
    let mut car = session_car(ENTERED);
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(value(&got, 0x0600), Ok(DidValue::Bytes(vec![0xAA, 0xBB])));
    assert_eq!(value(&got, 0x0601), Ok(DidValue::Bytes(vec![0x01])));
    assert_eq!(value(&got, 0x0602), Ok(DidValue::Bytes(vec![0x02, 0x03])));
    let engine: Vec<&str> = car
        .sent
        .iter()
        .map(String::as_str)
        .filter(|sent| sent.starts_with("7E0"))
        .collect();
    let enter = engine.iter().position(|s| *s == "7E0 10 03").unwrap();
    assert_eq!(
        engine[enter..],
        [
            "7E0 10 03",
            "7E0 22 06 00",
            "7E0 22 06 01 06 02",
            "7E0 10 01"
        ]
    );
    assert!(engine[..enter].iter().any(|s| s.starts_with("7E0 19")));
}

#[test]
fn a_module_that_refuses_the_extended_session_doesnt_stop_the_scan() {
    let mut car = session_car(&[0x7F, 0x10, 0x22]);
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended(), engine(&[])],
        TIMING,
        &extended(),
    )
    .unwrap();
    for did in [0x0600, 0x0601, 0x0602] {
        assert_eq!(
            value(&got, did),
            Err(ReadError::SessionRefused {
                error: ReplyError::Negative(NegativeResponse {
                    sid: 0x10,
                    nrc: Nrc::ConditionsNotCorrect,
                }),
                reply: vec![0x7F, 0x10, 0x22],
            })
        );
    }
    // A plain refusal leaves the module in the default session: nothing to leave.
    assert!(!car.sent.iter().any(|sent| sent == "7E0 10 01"));
    assert_eq!(got.modules.len(), 2);
}

#[test]
fn an_undecodable_answer_to_10_03_is_kept_with_its_bytes() {
    // A positive answer cut short of its timing.
    let mut car = session_car(&[0x50, 0x03, 0x00]);
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &extended(),
    )
    .unwrap();
    let want = ReadError::SessionRefused {
        error: ReplyError::Malformed,
        reply: vec![0x50, 0x03, 0x00],
    };
    assert_eq!(
        want.to_string(),
        "not read: extended session: reply is malformed: 50 03 00"
    );
    for did in [0x0600, 0x0601, 0x0602] {
        assert_eq!(value(&got, did), Err(want.clone()));
    }
}

#[test]
fn an_empty_reply_says_so() {
    let refused = ReadError::SessionRefused {
        error: ReplyError::Malformed,
        reply: vec![],
    };
    assert_eq!(
        refused.to_string(),
        "not read: extended session: reply is malformed: (empty)"
    );
    let undecodable = ReadError::Undecodable {
        error: ReplyError::Malformed,
        reply: vec![],
    };
    assert_eq!(undecodable.to_string(), "reply is malformed: (empty)");
}

#[test]
fn a_module_that_doesnt_answer_10_03_is_returned_to_the_default_session() {
    // No answer doesn't mean the module didn't switch.
    let mut car = session_car(ENTERED);
    let mut answer = std::mem::replace(&mut car.answer, Box::new(|_, _| Vec::new()));
    car.answer = Box::new(move |id, request| {
        if request == [0x10, 0x03] {
            Vec::new()
        } else {
            answer(id, request)
        }
    });
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(value(&got, 0x0600), Err(ReadError::NoReply));
    assert_eq!(car.sent.last().map(String::as_str), Some("7E0 10 01"));
}

#[test]
fn a_module_without_extended_dids_isnt_switched() {
    let mut car = session_car(ENTERED);
    scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine(&[0x0600])],
        TIMING,
        &extended(),
    )
    .unwrap();
    assert!(!car.sent.iter().any(|sent| sent.starts_with("7E0 10")));
}

#[test]
fn the_extended_session_needs_the_modules_reply_id_before_anything_is_sent() {
    // Without a profile, the policy doesn't know which ID 0x714 answers on.
    let mut module = engine_with_extended();
    module.module = UdsModule {
        name: "instruments".into(),
        request_id: 0x714,
        response_id: 0x77E,
    };
    let mut car = session_car(ENTERED);
    let err = scan_with(
        &mut car,
        &Policy::read_only(),
        &[module],
        TIMING,
        &extended(),
    )
    .unwrap_err();
    assert_eq!(err, FingerprintError::Session(SessionError::UnknownReplyId));
    assert!(car.sent.is_empty(), "{:?}", car.sent);
}

#[test]
fn a_slow_module_is_kept_in_the_extended_session_with_tester_present() {
    // A keepalive due at every read, as if each read took longer than S3client.
    let mut options = ScanOptions::default();
    options.extended = Some(S3 {
        keepalive: Duration::ZERO,
        timeout: Duration::from_secs(3600),
    });
    let mut car = session_car(ENTERED);
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &options,
    )
    .unwrap();
    assert_eq!(value(&got, 0x0600), Ok(DidValue::Bytes(vec![0xAA, 0xBB])));
    let enter = car.sent.iter().position(|s| s == "7E0 10 03").unwrap();
    assert_eq!(
        car.sent[enter..],
        [
            "7E0 10 03",
            "7E0 3E 00",
            "7E0 22 06 00",
            "7E0 3E 00",
            "7E0 22 06 01 06 02",
            "7E0 10 01"
        ]
    );
}

#[test]
fn a_module_that_answered_nothing_isnt_switched() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &extended(),
    )
    .unwrap();
    assert_eq!(value(&got, 0x0600), Err(ReadError::NoReply));
    assert!(!car.sent.iter().any(|sent| sent.starts_with("7E0 10")));
    assert!(!got.modules[0].answered);
}

#[test]
fn values_keep_their_order_whatever_session_reads_them() {
    // An extended DID listed before a default one.
    let mut module = engine_with_extended();
    module.extra_dids.push(ExtraDid {
        id: 0x0700,
        format: DidFormat::Hex,
        length: None,
        session: DiagnosticSession::Default,
    });
    let expected: Vec<u16> = SCAN_DIDS
        .iter()
        .copied()
        .chain([0x0600, 0x0601, 0x0602, 0x0700])
        .collect();
    for options in [ScanOptions::default(), extended()] {
        let mut car = session_car(ENTERED);
        let got = scan_with(
            &mut car,
            &Policy::read_only(),
            std::slice::from_ref(&module),
            TIMING,
            &options,
        )
        .unwrap();
        let order: Vec<u16> = got.modules[0].dids.iter().map(|(id, _)| *id).collect();
        assert_eq!(order, expected, "{options:?}");
    }
}

#[test]
fn a_refused_tester_present_is_reported_as_its_own_refusal() {
    let mut car = session_car(ENTERED);
    let mut answer = std::mem::replace(&mut car.answer, Box::new(|_, _| Vec::new()));
    car.answer = Box::new(move |id, request| {
        if request == [0x3E, 0x00] {
            vec![reply(0x7E8, &[0x7F, 0x3E, 0x22])]
        } else {
            answer(id, request)
        }
    });
    let mut options = ScanOptions::default();
    options.extended = Some(S3 {
        keepalive: Duration::ZERO,
        timeout: Duration::from_secs(3600),
    });
    let got = scan_with(
        &mut car,
        &Policy::read_only(),
        &[engine_with_extended()],
        TIMING,
        &options,
    )
    .unwrap();
    assert_eq!(
        value(&got, 0x0600),
        Err(ReadError::SessionRefused {
            error: ReplyError::Negative(NegativeResponse {
                sid: 0x3E,
                nrc: Nrc::ConditionsNotCorrect,
            }),
            reply: vec![0x7F, 0x3E, 0x22],
        })
    );
}
