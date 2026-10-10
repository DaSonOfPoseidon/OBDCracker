//! A read-only scan: what's sent, in what order, and how missing values are reported.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::obd::{Dtc, Unit};
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_core::uds::{DtcCount, DtcFormat, DtcRecord, DtcStatus, UdsDtc};
use obdcracker_safety::{Approved, Policy};
use obdcracker_transport::fingerprint::{DidValue, FingerprintError, ReadError, UdsModule};
use obdcracker_transport::scan::{ObdEcu, PidValue, SCAN_DIDS, ScanModule, scan};
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
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

const REFUSED: Nrc = Nrc::RequestOutOfRange;

fn engine(extra_dids: &[u16]) -> ScanModule {
    ScanModule {
        module: UdsModule::obd_engine(),
        extra_dids: extra_dids.to_vec(),
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
        (0x7E0, [0x19, 0x01, 0xFF]) => {
            vec![reply(0x7E8, &[0x59, 0x01, 0xFF, 0x00, 0x00, 0x01])]
        }
        (0x7E0, [0x19, 0x02, 0xFF]) => {
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
    expected.extend(["7E0 19 01 FF".to_owned(), "7E0 19 02 FF".to_owned()]);
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
                supported_info: Ok(vec![0x02, 0x04, 0x06, 0x0A]),
                ecu_name: Ok("ECM-EngineControl".to_owned()),
                stored_dtcs: Ok(vec![Dtc::new(0x0299)]),
            },
            ObdEcu {
                source: 0x7E9,
                pids: Ok(vec![(0x05, quantity(85.0, Unit::Celsius))]),
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
fn a_silent_car_loses_only_its_values() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = scan(&mut car, &Policy::read_only(), &[engine(&[])], TIMING).unwrap();
    assert_eq!(got.ecus, []);
    assert!(!got.anything_answered());
    let module = &got.modules[0];
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
        Ok(vec![(0x05, Err(ReadError::Reply(ReplyError::Malformed)))])
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
        Err(ReadError::Reply(ReplyError::TooShort))
    );
    assert_eq!(got.ecus[0].stored_dtcs, Ok(vec![]));
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
