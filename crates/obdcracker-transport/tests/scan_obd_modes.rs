//! What a scan reads past modes 01, 03 and 09: each ECU's readiness monitors, pending and permanent
//! DTCs, freeze frame and supported mode 06 monitor IDs.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::obd::{Dtc, Unit, decode_monitor_status};
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, Policy};
use obdcracker_transport::fingerprint::{FingerprintError, ReadError};
use obdcracker_transport::scan::{FreezeFrame, ObdEcu, PidValue, Scan, scan};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

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
    Response::new(source, payload.to_vec())
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

fn undecodable(error: ReplyError, reply: &[u8]) -> ReadError {
    ReadError::Undecodable {
        error,
        reply: reply.to_vec(),
    }
}

fn obd_only(car: &mut Car) -> Scan {
    scan(car, &Policy::read_only(), &[], TIMING).unwrap()
}

fn ecu(scan: &Scan, source: u32) -> &ObdEcu {
    scan.ecus.iter().find(|e| e.source == source).unwrap()
}

fn sent_with<'a>(car: &'a Car, prefix: &str) -> Vec<&'a str> {
    car.sent
        .iter()
        .map(String::as_str)
        .filter(|sent| sent.starts_with(prefix))
        .collect()
}

// Session 11's replies from the A7's engine (7E8) and transmission (7E9), which support PID 01.
const ENGINE_STATUS: [u8; 6] = [0x41, 0x01, 0x00, 0x2F, 0x28, 0x20];
const TCU_STATUS: [u8; 6] = [0x41, 0x01, 0x00, 0x04, 0x00, 0x00];

fn status_car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![
            reply(0x7E8, &[0x41, 0x00, 0x80, 0x00, 0x00, 0x00]),
            reply(0x7E9, &[0x41, 0x00, 0x80, 0x00, 0x00, 0x00]),
        ],
        (0x7DF, [0x01, 0x01]) => vec![reply(0x7E8, &ENGINE_STATUS), reply(0x7E9, &TCU_STATUS)],
        (0x7DF, [0x03]) => vec![reply(0x7E8, &[0x43, 0x00]), reply(0x7E9, &[0x43, 0x00])],
        _ => Vec::new(),
    }
}

#[test]
fn decodes_each_ecus_monitor_status_from_the_pid_01_read_the_scan_already_makes() {
    let mut car = Car::new(status_car);
    let got = obd_only(&mut car);
    assert_eq!(
        ecu(&got, 0x7E8).monitor_status,
        Some(Ok(decode_monitor_status(&ENGINE_STATUS).unwrap()))
    );
    assert_eq!(
        ecu(&got, 0x7E9).monitor_status,
        Some(Ok(decode_monitor_status(&TCU_STATUS).unwrap()))
    );
    // The status doesn't replace the PID's raw bytes, and costs no request of its own.
    assert_eq!(
        ecu(&got, 0x7E8).pids,
        Ok(vec![(
            0x01,
            Ok(PidValue::Raw(vec![0x00, 0x2F, 0x28, 0x20]))
        )])
    );
    assert_eq!(sent_with(&car, "7DF 01 01").len(), 1);
}

#[test]
fn a_status_reply_of_the_wrong_length_is_that_ecus_error_and_the_scan_goes_on() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x01]) => vec![reply(0x7E8, &[0x41, 0x01, 0x00]), reply(0x7E9, &TCU_STATUS)],
        _ => status_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(
        ecu(&got, 0x7E8).monitor_status,
        Some(Err(undecodable(ReplyError::Malformed, &[0x41, 0x01, 0x00])))
    );
    assert_eq!(
        ecu(&got, 0x7E9).monitor_status,
        Some(Ok(decode_monitor_status(&TCU_STATUS).unwrap()))
    );
    assert_eq!(ecu(&got, 0x7E8).stored_dtcs, Ok(vec![]));
}

#[test]
fn an_ecu_that_doesnt_support_pid_01_has_no_status() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x08, 0x00, 0x00, 0x00])],
        (0x7DF, [0x01, 0x05]) => vec![reply(0x7E8, &[0x41, 0x05, 0x82])],
        _ => Vec::new(),
    });
    let got = obd_only(&mut car);
    assert_eq!(ecu(&got, 0x7E8).monitor_status, None);
    assert_eq!(sent_with(&car, "7DF 01 01").len(), 0);
}

fn dtc_car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x03]) => vec![reply(0x7E8, &[0x43, 0x00]), reply(0x7E9, &[0x43, 0x00])],
        // 7E8 has a pending DTC; 7E9 none.
        (0x7DF, [0x07]) => vec![
            reply(0x7E8, &[0x47, 0x01, 0x02, 0x99]),
            reply(0x7E9, &[0x47, 0x00]),
        ],
        // 7E8 doesn't support mode 0A; 7E9 has one permanent DTC, and a P0000 pad.
        (0x7DF, [0x0A]) => vec![
            reply(0x7E8, &[0x7F, 0x0A, 0x11]),
            reply(0x7E9, &[0x4A, 0x02, 0x04, 0x20, 0x00, 0x00]),
        ],
        _ => Vec::new(),
    }
}

#[test]
fn reads_pending_then_permanent_dtcs_after_the_stored_ones() {
    let mut car = Car::new(dtc_car);
    let got = obd_only(&mut car);
    assert_eq!(
        car.sent,
        [
            "7DF 01 00",
            "7DF 09 00",
            "7DF 09 0A",
            "7DF 03",
            "7DF 07",
            "7DF 0A",
            "7DF 02 02 00",
            "7DF 06 00"
        ]
    );
    assert_eq!(
        ecu(&got, 0x7E8).pending_dtcs,
        Some(Ok(vec![Dtc::new(0x0299)]))
    );
    assert_eq!(ecu(&got, 0x7E9).pending_dtcs, Some(Ok(vec![])));
    assert_eq!(
        ecu(&got, 0x7E9).permanent_dtcs,
        Some(Ok(vec![Dtc::new(0x0420)]))
    );
}

#[test]
fn a_mode_that_isnt_supported_is_told_apart_from_a_failed_read() {
    let mut car = Car::new(dtc_car);
    let got = obd_only(&mut car);
    let Some(Err(not_supported)) = &ecu(&got, 0x7E8).permanent_dtcs else {
        panic!("{:?}", ecu(&got, 0x7E8).permanent_dtcs);
    };
    assert!(not_supported.is_not_supported());
    assert!(!ReadError::NoReply.is_not_supported());
    let other = ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x0A,
        nrc: Nrc::ConditionsNotCorrect,
    }));
    assert!(!other.is_not_supported());
}

#[test]
fn a_failed_new_read_hides_neither_the_other_new_reads_nor_the_old_ones() {
    // Nothing answers mode 07; mode 0A and 03 do.
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x07]) => Vec::new(),
        _ => dtc_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(ecu(&got, 0x7E8).pending_dtcs, Some(Err(ReadError::NoReply)));
    assert_eq!(
        ecu(&got, 0x7E9).permanent_dtcs,
        Some(Ok(vec![Dtc::new(0x0420)]))
    );
    assert_eq!(ecu(&got, 0x7E8).stored_dtcs, Ok(vec![]));
}

#[test]
fn a_pending_count_that_doesnt_match_the_bytes_is_an_error() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x07]) => vec![reply(0x7E8, &[0x47, 0x02, 0x02, 0x99])],
        _ => dtc_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(
        ecu(&got, 0x7E8).pending_dtcs,
        Some(Err(undecodable(
            ReplyError::Malformed,
            &[0x47, 0x02, 0x02, 0x99]
        )))
    );
}

// The engine's frame 0 was stored by P0299 and has PIDs 04 and 05 (bitmap 58: 02, 04, 05); the
// transmission's frame is empty (P0000).
fn freeze_car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![
            reply(0x7E8, &[0x41, 0x00, 0x00, 0x00, 0x00, 0x00]),
            reply(0x7E9, &[0x41, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ],
        (0x7DF, [0x02, 0x02, 0x00]) => vec![
            reply(0x7E8, &[0x42, 0x02, 0x00, 0x02, 0x99]),
            reply(0x7E9, &[0x42, 0x02, 0x00, 0x00, 0x00]),
        ],
        (0x7DF, [0x02, 0x00, 0x00]) => vec![
            reply(0x7E8, &[0x42, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00]),
            reply(0x7E9, &[0x42, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]),
        ],
        (0x7DF, [0x02, 0x04, 0x00]) => vec![reply(0x7E8, &[0x42, 0x04, 0x00, 0x80])],
        (0x7DF, [0x02, 0x05, 0x00]) => vec![reply(0x7E8, &[0x42, 0x05, 0x00, 0x82])],
        _ => Vec::new(),
    }
}

fn empty_frame() -> FreezeFrame {
    FreezeFrame {
        cause: None,
        pids: Ok(vec![]),
        pids_cut_short: None,
    }
}

#[test]
fn reads_the_freeze_frames_cause_then_its_pids_without_reading_the_cause_twice() {
    let mut car = Car::new(freeze_car);
    let got = obd_only(&mut car);
    assert_eq!(
        sent_with(&car, "7DF 02"),
        [
            "7DF 02 02 00",
            "7DF 02 00 00",
            "7DF 02 04 00",
            "7DF 02 05 00"
        ]
    );
    assert_eq!(
        ecu(&got, 0x7E8).freeze_frame,
        Some(Ok(FreezeFrame {
            cause: Some(Dtc::new(0x0299)),
            pids: Ok(vec![
                (
                    0x04,
                    Ok(PidValue::Quantity {
                        value: f32::from(0x80_u8) * 100.0 / 255.0,
                        unit: Unit::Percent,
                    })
                ),
                (
                    0x05,
                    Ok(PidValue::Quantity {
                        value: 90.0,
                        unit: Unit::Celsius,
                    })
                ),
            ]),
            pids_cut_short: None,
        }))
    );
}

#[test]
fn a_frame_stored_by_no_dtc_is_empty_and_its_ecus_bitmap_is_ignored() {
    let mut car = Car::new(freeze_car);
    let got = obd_only(&mut car);
    assert_eq!(ecu(&got, 0x7E9).freeze_frame, Some(Ok(empty_frame())));
    // The transmission's bitmap says every PID, but only the engine's are read.
    assert!(!sent_with(&car, "7DF 02").contains(&"7DF 02 06 00"));
}

#[test]
fn nobody_with_a_frame_means_no_requests_past_the_cause() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x02, 0x02, 0x00]) => vec![reply(0x7E8, &[0x42, 0x02, 0x00, 0x00, 0x00])],
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(sent_with(&car, "7DF 02"), ["7DF 02 02 00"]);
    assert_eq!(ecu(&got, 0x7E8).freeze_frame, Some(Ok(empty_frame())));
}

#[test]
fn a_frame_pid_answered_with_another_frame_or_pid_is_its_own_error() {
    let mut car = Car::new(|id, request| match (id, request) {
        // Frame 1's value for PID 04, and PID 06's for a request for PID 05
        (0x7DF, [0x02, 0x04, 0x00]) => vec![reply(0x7E8, &[0x42, 0x04, 0x01, 0x80])],
        (0x7DF, [0x02, 0x05, 0x00]) => vec![reply(0x7E8, &[0x42, 0x06, 0x00, 0x82])],
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Ok(frame)) = &ecu(&got, 0x7E8).freeze_frame else {
        panic!("{:?}", ecu(&got, 0x7E8).freeze_frame);
    };
    let Ok(pids) = &frame.pids else {
        panic!("{frame:?}");
    };
    // Frame 1 isn't the frame asked for, so the reply doesn't pass for PID 04's answer at all.
    assert_eq!(pids[0], (0x04, Err(ReadError::NoReply)));
    assert_eq!(pids[1], (0x05, Err(ReadError::NoReply)));
}

#[test]
fn a_frame_value_that_fits_its_request_but_is_the_wrong_length_is_an_error_and_the_others_read() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x02, 0x04, 0x00]) => vec![reply(0x7E8, &[0x42, 0x04, 0x00])],
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Ok(frame)) = &ecu(&got, 0x7E8).freeze_frame else {
        panic!("{:?}", ecu(&got, 0x7E8).freeze_frame);
    };
    let Ok(pids) = &frame.pids else {
        panic!("{frame:?}");
    };
    assert_eq!(
        pids[0],
        (
            0x04,
            Err(undecodable(ReplyError::TooShort, &[0x42, 0x04, 0x00]))
        )
    );
    assert!(matches!(pids[1], (0x05, Ok(PidValue::Quantity { .. }))));
}

#[test]
fn a_frame_bitmap_that_says_another_page_follows_but_isnt_answered_cuts_the_list_short() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x02, 0x00, 0x00]) => {
            vec![reply(0x7E8, &[0x42, 0x00, 0x00, 0x58, 0x00, 0x00, 0x01])]
        }
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Ok(frame)) = &ecu(&got, 0x7E8).freeze_frame else {
        panic!("{:?}", ecu(&got, 0x7E8).freeze_frame);
    };
    assert_eq!(frame.pids_cut_short, Some((0x20, ReadError::NoReply)));
    assert_eq!(frame.pids.as_ref().map(Vec::len), Ok(2));
    assert!(sent_with(&car, "7DF 02").contains(&"7DF 02 20 00"));
}

#[test]
fn a_frame_that_has_no_bitmap_answer_is_an_error_but_keeps_its_cause() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x02, 0x00, 0x00]) => Vec::new(),
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Ok(frame)) = &ecu(&got, 0x7E8).freeze_frame else {
        panic!("{:?}", ecu(&got, 0x7E8).freeze_frame);
    };
    assert_eq!(frame.cause, Some(Dtc::new(0x0299)));
    assert_eq!(frame.pids, Err(ReadError::NoReply));
}

#[test]
fn a_car_without_mode_02_has_no_freeze_frame_and_the_refusal_says_so() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x02, ..]) => vec![reply(0x7E8, &[0x7F, 0x02, 0x11])],
        _ => freeze_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Err(error)) = &ecu(&got, 0x7E8).freeze_frame else {
        panic!("{:?}", ecu(&got, 0x7E8).freeze_frame);
    };
    assert!(error.is_not_supported());
    assert_eq!(sent_with(&car, "7DF 02"), ["7DF 02 02 00"]);
}

// The engine supports monitor IDs 01 and 02 and, through the next range, 21. The transmission
// answers nothing.
fn monitor_id_car(id: u32, request: &[u8]) -> Vec<Response> {
    match (id, request) {
        (0x7DF, [0x01, 0x00]) => vec![reply(0x7E8, &[0x41, 0x00, 0x00, 0x00, 0x00, 0x00])],
        (0x7DF, [0x06, 0x00]) => vec![reply(0x7E8, &[0x46, 0x00, 0xC0, 0x00, 0x00, 0x01])],
        (0x7DF, [0x06, 0x20]) => vec![reply(0x7E8, &[0x46, 0x20, 0x80, 0x00, 0x00, 0x00])],
        _ => Vec::new(),
    }
}

#[test]
fn reads_the_supported_monitor_ids_over_each_range_the_bits_say() {
    let mut car = Car::new(monitor_id_car);
    let got = obd_only(&mut car);
    assert_eq!(sent_with(&car, "7DF 06"), ["7DF 06 00", "7DF 06 20"]);
    assert_eq!(
        ecu(&got, 0x7E8).monitor_ids,
        Some(Ok(vec![0x01, 0x02, 0x21]))
    );
    assert_eq!(ecu(&got, 0x7E8).monitor_ids_cut_short, None);
}

#[test]
fn a_monitor_id_range_that_isnt_answered_stops_with_what_there_is() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x06, 0x20]) => Vec::new(),
        _ => monitor_id_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(ecu(&got, 0x7E8).monitor_ids, Some(Ok(vec![0x01, 0x02])));
    assert_eq!(
        ecu(&got, 0x7E8).monitor_ids_cut_short,
        Some((0x20, ReadError::NoReply))
    );
}

#[test]
fn an_ecu_that_gives_no_monitor_ids_is_no_reply_and_no_other_range_is_asked() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x06, _]) => Vec::new(),
        _ => monitor_id_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(sent_with(&car, "7DF 06"), ["7DF 06 00"]);
    assert_eq!(ecu(&got, 0x7E8).monitor_ids, Some(Err(ReadError::NoReply)));
}

#[test]
fn a_monitor_id_bitmap_for_another_range_doesnt_answer_the_request() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x06, 0x00]) => vec![reply(0x7E8, &[0x46, 0x20, 0x80, 0x00, 0x00, 0x00])],
        _ => monitor_id_car(id, request),
    });
    let got = obd_only(&mut car);
    assert_eq!(ecu(&got, 0x7E8).monitor_ids, Some(Err(ReadError::NoReply)));
}

#[test]
fn a_refused_mode_06_is_that_ecus_error() {
    let mut car = Car::new(|id, request| match (id, request) {
        (0x7DF, [0x06, 0x00]) => vec![reply(0x7E8, &[0x7F, 0x06, 0x11])],
        _ => monitor_id_car(id, request),
    });
    let got = obd_only(&mut car);
    let Some(Err(error)) = &ecu(&got, 0x7E8).monitor_ids else {
        panic!("{:?}", ecu(&got, 0x7E8).monitor_ids);
    };
    assert!(error.is_not_supported());
}

#[test]
fn nothing_answering_sends_no_mode_02_or_06_request() {
    let mut car = Car::new(|_, _| Vec::new());
    let got = obd_only(&mut car);
    assert_eq!(got.ecus.len(), 0);
    assert!(sent_with(&car, "7DF 02").is_empty() && sent_with(&car, "7DF 06").is_empty());
}

#[test]
fn an_adapter_failure_in_a_new_read_stops_the_scan() {
    let mut car = Car::new(dtc_car);
    car.fail_after = Some(5);
    let err = scan(&mut car, &Policy::read_only(), &[], TIMING).unwrap_err();
    assert_eq!(
        err,
        FingerprintError::Transport(Error::Adapter("unplugged".to_owned()))
    );
}
