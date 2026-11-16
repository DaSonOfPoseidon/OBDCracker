//! The live-data poller: how it batches, how it reads each ECU's reply, and `next_due`. The replies
//! are made by hand from SAE J1979; the poller on the simulated car is tested in
//! `obdcracker-sim`'s `live.rs`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use obdcracker_core::obd::Unit;
use obdcracker_core::response::Error as ReplyError;
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::{ReadError, UdsModule};
use obdcracker_transport::live::{DidPoll, LONGEST_INTERVAL, PollError, Poller, next_due};
use obdcracker_transport::read_dids::{DidsData, MAX_DIDS, ReadDidsError};
use obdcracker_transport::scan::PidValue;
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

type Answer = Box<dyn FnMut(u32, &[u8]) -> Vec<Response>>;

struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
    overflow: bool,
    fail_after: Option<usize>,
    // The PIDs each ECU lists, which it says in answer to the supported-PID bitmap requests (the
    // answer closure doesn't see those while this is set).
    listed: Vec<(u32, Vec<u8>)>,
}

// A mode 01 request for a supported-PID bitmap: 01 00, 01 20, ...
fn is_bitmap(request: &[u8]) -> bool {
    matches!(request, [0x01, pid] if pid % 0x20 == 0)
}

impl Car {
    fn new(answer: impl FnMut(u32, &[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
            overflow: false,
            fail_after: None,
            listed: Vec::new(),
        }
    }

    // `source` lists `pids` (and answers the bitmaps that show it).
    fn listing(mut self, source: u32, pids: impl IntoIterator<Item = u8>) -> Self {
        self.listed.push((source, pids.into_iter().collect()));
        self
    }

    // What the ECUs say to the request for the bitmap at `base`.
    fn bitmap_replies(&self, base: u8) -> Vec<Response> {
        let mut replies = Vec::new();
        for (source, pids) in &self.listed {
            // A page is asked for only if the one before listed a PID above it.
            if base != 0 && !pids.iter().any(|&pid| pid > base) {
                continue;
            }
            let mut bits = 0u32;
            for &pid in pids {
                if pid > base && u16::from(pid) <= u16::from(base) + 32 {
                    bits |= 1 << (32 - (pid - base));
                }
            }
            if pids
                .iter()
                .any(|&pid| u16::from(pid) > u16::from(base) + 32)
            {
                bits |= 1;
            }
            let mut payload = vec![0x41, base];
            payload.extend(bits.to_be_bytes());
            replies.push(reply(*source, &payload));
        }
        replies
    }

    // What was sent besides the supported-PID bitmap requests.
    fn batches(&self) -> Vec<&str> {
        self.sent
            .iter()
            .map(String::as_str)
            .filter(|sent| {
                let bytes: Vec<u8> = sent
                    .split(' ')
                    .skip(1)
                    .filter_map(|byte| u8::from_str_radix(byte, 16).ok())
                    .collect();
                !is_bitmap(&bytes)
            })
            .collect()
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
        if is_bitmap(request.payload()) && !self.listed.is_empty() {
            self.replies
                .extend(self.bitmap_replies(request.payload()[1]));
        } else {
            self.replies.extend((self.answer)(id, request.payload()));
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }

    fn broadcasts_can_overflow(&self) -> bool {
        self.overflow
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

const ENGINE: u32 = 0x7E8;
const TCU: u32 = 0x7E9;

fn poller(pids: &[u8]) -> Poller {
    Poller::new(&Policy::read_only(), pids, Vec::new()).unwrap()
}

fn undecodable(error: ReplyError, reply: &[u8]) -> ReadError {
    ReadError::Undecodable {
        error,
        reply: reply.to_vec(),
    }
}

#[expect(clippy::unnecessary_wraps, reason = "a reading is a result")]
fn quantity(value: f32, unit: Unit) -> Result<PidValue, ReadError> {
    Ok(PidValue::Quantity { value, unit })
}

// An ECU that answers a request for PIDs with the data in `table` for each PID it has, in the
// order asked.
fn ecu_answer(source: u32, table: &'static [(u8, &'static [u8])], request: &[u8]) -> Vec<Response> {
    let [0x01, pids @ ..] = request else {
        return Vec::new();
    };
    let mut payload = vec![0x41];
    for pid in pids {
        if let Some((_, data)) = table.iter().find(|(have, _)| have == pid) {
            payload.push(*pid);
            payload.extend(*data);
        }
    }
    if payload.len() == 1 {
        Vec::new()
    } else {
        vec![reply(source, &payload)]
    }
}

// RPM 1726, speed 50, coolant 83, intake map 98, load 100%, throttle 0%.
const ENGINE_PIDS: &[(u8, &[u8])] = &[
    (0x0C, &[0x1A, 0xF8]),
    (0x0D, &[0x32]),
    (0x05, &[0x7B]),
    (0x0B, &[0x62]),
    (0x04, &[0xFF]),
    (0x11, &[0x00]),
    (0x0F, &[0x00]),
    (0x1B, &[0x01]),
    (0x1E, &[0x00]),
];

const TCU_PIDS: &[(u8, &[u8])] = &[(0x0C, &[0x00, 0x04]), (0x0D, &[0x00])];

fn pids_of(table: &[(u8, &[u8])]) -> Vec<u8> {
    table.iter().map(|&(pid, _)| pid).collect()
}

// A car with the engine alone, which answers PIDs from `ENGINE_PIDS`.
fn engine_car() -> Car {
    Car::new(engine_only).listing(ENGINE, pids_of(ENGINE_PIDS))
}

// A car with the engine and the TCU, which has fewer PIDs.
fn two_ecu_car() -> Car {
    Car::new(each_ecus_reply::two_ecus)
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS))
}

fn engine_only(id: u32, request: &[u8]) -> Vec<Response> {
    if id == 0x7DF {
        ecu_answer(ENGINE, ENGINE_PIDS, request)
    } else {
        Vec::new()
    }
}

mod building {
    use super::*;

    #[test]
    fn needs_something_to_poll() {
        assert_eq!(
            Poller::new(&Policy::read_only(), &[], vec![]).unwrap_err(),
            PollError::NothingToPoll
        );
    }

    #[test]
    fn refuses_a_bitmap_pid_and_a_repeated_pid() {
        for pid in [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0] {
            assert_eq!(
                Poller::new(&Policy::read_only(), &[0x0C, pid], vec![]).unwrap_err(),
                PollError::BitmapPid(pid)
            );
        }
        assert_eq!(
            Poller::new(&Policy::read_only(), &[0x0C, 0x0D, 0x0C], vec![]).unwrap_err(),
            PollError::DuplicatePid(0x0C)
        );
    }

    fn engine() -> UdsModule {
        UdsModule {
            name: "engine".to_owned(),
            request_id: 0x7E0,
            response_id: 0x7E8,
        }
    }

    fn gateway() -> UdsModule {
        UdsModule {
            name: "gateway".to_owned(),
            request_id: 0x710,
            response_id: 0x77A,
        }
    }

    fn poll_dids(module: UdsModule, dids: &[(u16, Option<usize>)]) -> DidPoll {
        DidPoll {
            module,
            dids: dids.to_vec(),
        }
    }

    #[test]
    fn refuses_a_bad_did_list_and_a_module_named_twice() {
        let bad = |dids: &[(u16, Option<usize>)]| {
            Poller::new(&Policy::read_only(), &[], vec![poll_dids(engine(), dids)]).unwrap_err()
        };
        assert_eq!(
            bad(&[]),
            PollError::BadDids {
                module: "engine".to_owned(),
                error: ReadDidsError::NoDids
            }
        );
        let too_many: Vec<_> = (0..=u16::try_from(MAX_DIDS).unwrap())
            .map(|i| (0xF100 + i, None))
            .collect();
        assert_eq!(
            bad(&too_many),
            PollError::BadDids {
                module: "engine".to_owned(),
                error: ReadDidsError::TooMany(MAX_DIDS + 1)
            }
        );
        // The most is fine.
        assert!(
            Poller::new(
                &Policy::read_only(),
                &[],
                vec![poll_dids(engine(), &too_many[..MAX_DIDS])]
            )
            .is_ok()
        );
        assert_eq!(
            bad(&[(0xF190, None), (0xF187, None), (0xF190, Some(17))]),
            PollError::BadDids {
                module: "engine".to_owned(),
                error: ReadDidsError::Duplicate(0xF190)
            }
        );
        // The same module twice, by name or by request ID.
        let same_name = UdsModule {
            request_id: 0x7E1,
            response_id: 0x7E9,
            ..engine()
        };
        let same_id = UdsModule {
            name: "motor".to_owned(),
            ..engine()
        };
        for second in [same_name, same_id] {
            assert_eq!(
                Poller::new(
                    &Policy::read_only(),
                    &[],
                    vec![
                        poll_dids(engine(), &[(0xF190, None)]),
                        poll_dids(second.clone(), &[(0xF187, None)])
                    ]
                )
                .unwrap_err(),
                PollError::DuplicateModule(second.name)
            );
        }
        // Different modules are fine, and so is a DID both read.
        assert!(
            Poller::new(
                &Policy::read_only(),
                &[],
                vec![
                    poll_dids(engine(), &[(0xF190, None)]),
                    poll_dids(gateway(), &[(0xF190, None)])
                ]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_refusal_is_an_error_from_new_before_anything_can_be_sent() {
        // A policy narrowed to the gateway refuses a request to the engine.
        let policy = Policy::read_only()
            .narrowed_to(&[ModuleIds {
                request: 0x710,
                reply: 0x77A,
            }])
            .unwrap();
        assert_eq!(
            Poller::new(
                &policy,
                &[0x0C],
                vec![
                    poll_dids(gateway(), &[(0xF190, None)]),
                    poll_dids(engine(), &[(0xF190, None)])
                ]
            )
            .unwrap_err(),
            PollError::Rejected(Rejection::WrongTarget)
        );
        // With a module the policy knows, it builds; PIDs are broadcast, which narrowing leaves.
        assert!(
            Poller::new(
                &policy,
                &[0x0C],
                vec![poll_dids(gateway(), &[(0xF190, None)])]
            )
            .is_ok()
        );
    }
}

mod batching {
    use super::*;

    // What a poll of `pids` sends, if the engine lists them all.
    fn requests(pids: &[u8]) -> Vec<String> {
        let mut car = Car::new(engine_only).listing(ENGINE, pids.iter().copied());
        poller(pids).poll(&mut car, TIMING).unwrap();
        car.batches().into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn six_known_pids_go_in_one_request() {
        assert_eq!(
            requests(&[0x0C, 0x0D, 0x05, 0x0B, 0x04, 0x11]),
            ["7DF 01 0C 0D 05 0B 04 11"]
        );
    }

    #[test]
    fn a_seventh_makes_a_second_request_and_none_is_over_six() {
        assert_eq!(
            requests(&[0x0C, 0x0D, 0x05, 0x0B, 0x04, 0x11, 0x0F]),
            ["7DF 01 0C 0D 05 0B 04 11", "7DF 01 0F"]
        );
        let twelve = [
            0x04, 0x05, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x1F, 0x21, 0x30, 0x33,
        ];
        let sent = requests(&twelve);
        assert_eq!(sent.len(), 2);
        // Seven bytes: the service and six PIDs.
        assert!(
            sent.iter()
                .all(|request| request.len() == "7DF 01".len() + 6 * 3)
        );
    }

    #[test]
    fn one_pid_is_one_request() {
        assert_eq!(requests(&[0x0C]), ["7DF 01 0C"]);
    }

    #[test]
    fn an_unknown_pid_is_asked_alone_after_the_known_ones() {
        // 0x1B is reserved in SAE J1979, so the decoder doesn't know its length.
        assert_eq!(
            requests(&[0x0C, 0x1B, 0x0D, 0x1E]),
            ["7DF 01 0C 0D", "7DF 01 1B", "7DF 01 1E"]
        );
    }

    #[test]
    fn readings_come_back_in_the_order_given_whatever_the_requests() {
        const TABLE: &[(u8, &[u8])] = &[(0x0C, &[0x1A, 0xF8]), (0x1B, &[1, 2, 3]), (0x0D, &[0x32])];
        let mut car = Car::new(|id, request| {
            if id != 0x7DF {
                return Vec::new();
            }
            ecu_answer(ENGINE, TABLE, request)
        })
        .listing(ENGINE, pids_of(TABLE));
        let sample = poller(&[0x0D, 0x1B, 0x0C]).poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.pids[&ENGINE],
            [
                (0x0D, quantity(50.0, Unit::KilometresPerHour)),
                (0x1B, Ok(PidValue::Raw(vec![1, 2, 3]))),
                (0x0C, quantity(1726.0, Unit::Rpm)),
            ]
        );
    }

    #[test]
    fn a_poll_reads_all_six_known_values() {
        let mut car = engine_car();
        let sample = poller(&[0x0C, 0x0D, 0x05, 0x0B, 0x04, 0x11])
            .poll(&mut car, TIMING)
            .unwrap();
        assert_eq!(
            sample.pids[&ENGINE],
            [
                (0x0C, quantity(1726.0, Unit::Rpm)),
                (0x0D, quantity(50.0, Unit::KilometresPerHour)),
                (0x05, quantity(83.0, Unit::Celsius)),
                (0x0B, quantity(98.0, Unit::Kilopascals)),
                (0x04, quantity(100.0, Unit::Percent)),
                (0x11, quantity(0.0, Unit::Percent)),
            ]
        );
        assert_eq!(sample.pids.len(), 1);
        assert_eq!(sample.dids, vec![]);
        assert!(sample.started <= sample.finished);
    }

    #[test]
    fn every_poll_sends_the_same_requests_again() {
        let mut car = engine_car();
        let mut poller = poller(&[0x0C, 0x1B]);
        for _ in 0..3 {
            poller.poll(&mut car, TIMING).unwrap();
        }
        assert_eq!(car.batches(), ["7DF 01 0C", "7DF 01 1B"].repeat(3));
    }
}

mod each_ecus_reply {
    use super::*;

    pub(super) fn two_ecus(id: u32, request: &[u8]) -> Vec<Response> {
        if id != 0x7DF {
            return Vec::new();
        }
        let mut replies = ecu_answer(ENGINE, ENGINE_PIDS, request);
        replies.extend(ecu_answer(TCU, TCU_PIDS, request));
        replies
    }

    #[test]
    fn two_ecus_answering_one_batch_each_keep_their_own_values() {
        let mut car = two_ecu_car();
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert_eq!(car.batches(), ["7DF 01 0C 0D"]);
        assert_eq!(
            sample.pids[&ENGINE],
            [
                (0x0C, quantity(1726.0, Unit::Rpm)),
                (0x0D, quantity(50.0, Unit::KilometresPerHour)),
            ]
        );
        assert_eq!(
            sample.pids[&TCU],
            [
                (0x0C, quantity(1.0, Unit::Rpm)),
                (0x0D, quantity(0.0, Unit::KilometresPerHour)),
            ]
        );
    }

    #[test]
    fn a_pid_an_ecu_leaves_out_is_not_answered_and_the_rest_are_read() {
        let mut car = two_ecu_car();
        // The TCU has no coolant temperature or load.
        let sample = poller(&[0x05, 0x0C, 0x04]).poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.pids[&TCU],
            [
                (0x05, Err(ReadError::NoReply)),
                (0x0C, quantity(1.0, Unit::Rpm)),
                (0x04, Err(ReadError::NoReply)),
            ]
        );
        assert_eq!(sample.pids[&ENGINE].len(), 3);
        assert!(sample.pids[&ENGINE].iter().all(|(_, value)| value.is_ok()));
    }

    #[test]
    fn an_ecu_that_answers_one_request_but_not_another_is_not_answered_for_the_other() {
        let mut car = Car::new(|id, request| match (id, request) {
            // The TCU answers the known batch, and not the PID asked alone.
            (0x7DF, [0x01, 0x1B]) => ecu_answer(ENGINE, &[(0x1B, &[9])], request),
            _ => two_ecus(id, request),
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS));
        let sample = poller(&[0x0C, 0x1B]).poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.pids[&TCU],
            [
                (0x0C, quantity(1.0, Unit::Rpm)),
                (0x1B, Err(ReadError::NoReply))
            ]
        );
        assert_eq!(sample.pids[&ENGINE][1], (0x1B, Ok(PidValue::Raw(vec![9]))));
    }

    // The replies a car gives an `01 0C 0D` request, the engine's as given and the TCU's good.
    fn engine_says(payload: &'static [u8]) -> Car {
        Car::new(move |id, request| {
            if id != 0x7DF {
                return Vec::new();
            }
            let mut replies = vec![reply(ENGINE, payload)];
            replies.extend(ecu_answer(TCU, TCU_PIDS, request));
            replies
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS))
    }

    // Every PID the engine was asked for is undecodable, with its reply, and the TCU's are read.
    fn assert_engine_malformed(payload: &'static [u8], error: ReplyError) {
        let mut car = engine_says(payload);
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.pids[&ENGINE],
            [
                (0x0C, Err(undecodable(error, payload))),
                (0x0D, Err(undecodable(error, payload))),
            ],
            "{payload:02X?}"
        );
        assert_eq!(
            sample.pids[&TCU],
            [
                (0x0C, quantity(1.0, Unit::Rpm)),
                (0x0D, quantity(0.0, Unit::KilometresPerHour)),
            ]
        );
    }

    #[test]
    fn a_pid_that_was_not_asked_for_makes_the_whole_reply_malformed() {
        // Coolant temperature (05) was never asked for, after two good readings.
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32, 0x05, 0x7B],
            ReplyError::Malformed,
        );
        // And in the middle.
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x05, 0x7B, 0x0D, 0x32],
            ReplyError::Malformed,
        );
    }

    #[test]
    fn a_repeated_pid_makes_the_whole_reply_malformed() {
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32, 0x0C, 0x1A, 0xF8],
            ReplyError::Malformed,
        );
        assert_engine_malformed(&[0x41, 0x0D, 0x32, 0x0D, 0x32], ReplyError::Malformed);
    }

    #[test]
    fn a_cut_off_last_pid_makes_the_whole_reply_too_short() {
        assert_engine_malformed(&[0x41, 0x0C, 0x1A, 0xF8, 0x0D], ReplyError::TooShort);
        assert_engine_malformed(&[0x41, 0x0C, 0x1A], ReplyError::TooShort);
    }

    #[test]
    fn bytes_after_the_last_pid_make_the_whole_reply_unreadable() {
        // One byte left over: a PID with no data.
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32, 0xFF],
            ReplyError::TooShort,
        );
        // Zero padding after the data, as a transport might add, isn't the poller's to drop:
        // 00 is the first bitmap PID, which needs four bytes.
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32, 0x00],
            ReplyError::TooShort,
        );
        // Enough left over to be a bitmap, which isn't a value to poll.
        assert_engine_malformed(
            &[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32, 0x00, 0, 0, 0, 0],
            ReplyError::Malformed,
        );
    }

    #[test]
    fn an_unrequested_pid_asked_first_in_the_reply_is_not_an_answer_at_all() {
        // `exchange` drops a reply whose first PID wasn't asked for, so the ECU has no entry.
        let mut car = engine_says(&[0x41, 0x05, 0x7B, 0x0C, 0x1A, 0xF8]);
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert!(!sample.pids.contains_key(&ENGINE));
        assert!(sample.pids.contains_key(&TCU));
    }

    #[test]
    fn a_refusal_is_every_pid_of_that_request_for_that_ecu() {
        let mut car = Car::new(|id, request| {
            let mut replies = vec![reply(ENGINE, &[0x7F, 0x01, 0x12])];
            replies.extend(
                two_ecus(id, request)
                    .into_iter()
                    .filter(|r| r.source == TCU),
            );
            replies
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS));
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        let refused = Err(ReadError::Reply(ReplyError::Negative(
            obdcracker_core::response::NegativeResponse {
                sid: 0x01,
                nrc: obdcracker_core::response::Nrc::SubFunctionNotSupported,
            },
        )));
        assert_eq!(
            sample.pids[&ENGINE],
            [(0x0C, refused.clone()), (0x0D, refused)]
        );
        assert!(sample.pids[&TCU].iter().all(|(_, value)| value.is_ok()));
    }

    #[test]
    fn a_silent_car_gives_no_ecus_and_gets_only_the_first_bitmap_request_each_poll() {
        let mut car = Car::new(|_, _| Vec::new());
        let mut poller = poller(&[0x0C, 0x1B]);
        for _ in 0..2 {
            let sample = poller.poll(&mut car, TIMING).unwrap();
            assert!(sample.pids.is_empty());
            assert_eq!(sample.unsupported_pids, Vec::<u8>::new());
        }
        assert_eq!(car.sent, ["7DF 01 00", "7DF 01 00"]);
    }

    #[test]
    fn an_ecu_that_stops_answering_is_not_answered_for_that_poll_only() {
        let mut poller = poller(&[0x0C]);
        let mut car = two_ecu_car();
        assert_eq!(poller.poll(&mut car, TIMING).unwrap().pids.len(), 2);
        let mut car = Car::new(|id, request| {
            two_ecus(id, request)
                .into_iter()
                .filter(|r| r.source == ENGINE)
                .collect()
        });
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(sample.pids.keys().copied().collect::<Vec<_>>(), [ENGINE]);
    }

    #[test]
    fn an_adapter_failure_is_an_error_and_loses_the_poll() {
        let mut car = two_ecu_car();
        // The bitmap request and the first batch go out; the second batch fails.
        car.fail_after = Some(2);
        let mut poller = poller(&[0x0C, 0x1B]);
        assert_eq!(
            poller.poll(&mut car, TIMING).unwrap_err(),
            PollError::Transport(Error::Adapter("unplugged".to_owned()))
        );
        // Both requests were tried in order; the first went out, the second failed.
        assert_eq!(car.batches(), ["7DF 01 0C"]);
    }
}

mod an_ecu_asked_alone {
    use super::*;

    // A transport that overflows on a broadcast of long replies: each ECU is asked on its own ID.
    fn overflow_car() -> Car {
        let mut car = Car::new(|id, request| match id {
            0x7E0 => ecu_answer(ENGINE, ENGINE_PIDS, request),
            0x7E1 => ecu_answer(TCU, TCU_PIDS, request),
            _ => Vec::new(),
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS));
        car.overflow = true;
        car
    }

    #[test]
    fn reads_the_bitmaps_once_and_then_asks_each_in_turn() {
        let mut car = overflow_car();
        let mut poller = poller(&[0x0C, 0x0D]);
        let first = poller.poll(&mut car, TIMING).unwrap();
        poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(
            car.sent,
            [
                "7DF 01 00",
                "7E0 01 0C 0D",
                "7E1 01 0C 0D",
                "7E0 01 0C 0D",
                "7E1 01 0C 0D"
            ]
        );
        assert_eq!(first.pids[&TCU][0], (0x0C, quantity(1.0, Unit::Rpm)));
        assert_eq!(first.pids.len(), 2);
    }

    #[test]
    fn a_request_goes_only_to_the_ecus_that_list_one_of_its_pids() {
        let mut car = overflow_car();
        // The TCU lists neither.
        poller(&[0x0F, 0x05]).poll(&mut car, TIMING).unwrap();
        assert_eq!(car.batches(), ["7E0 01 0F 05"]);
    }

    #[test]
    fn an_ecu_asked_alone_that_lists_a_pid_and_stays_silent_is_flagged() {
        let mut car = Car::new(|id, request| match id {
            0x7E0 => ecu_answer(ENGINE, ENGINE_PIDS, request),
            _ => Vec::new(),
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS))
        .listing(TCU, pids_of(TCU_PIDS));
        car.overflow = true;
        let sample = poller(&[0x0C]).poll(&mut car, TIMING).unwrap();
        assert!(sample.pids.contains_key(&ENGINE));
        assert!(sample.out_of_step);
    }

    #[test]
    fn a_transport_that_cannot_overflow_reads_the_bitmaps_once_and_broadcasts() {
        let mut car = engine_car();
        let mut poller = poller(&[0x0C]);
        poller.poll(&mut car, TIMING).unwrap();
        poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(car.sent, ["7DF 01 00", "7DF 01 0C", "7DF 01 0C"]);
    }

    #[test]
    fn a_poll_of_dids_only_reads_no_bitmaps() {
        let mut car = overflow_car();
        let dids = vec![DidPoll {
            module: UdsModule {
                name: "engine".to_owned(),
                request_id: 0x7E0,
                response_id: 0x7E8,
            },
            dids: vec![(0xF190, None)],
        }];
        let mut poller = Poller::new(&Policy::read_only(), &[], dids).unwrap();
        poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(car.sent, ["7E0 22 F1 90"]);
    }
}

mod the_bitmaps {
    use super::each_ecus_reply::two_ecus;
    use super::*;

    #[test]
    fn are_chained_as_far_as_each_ecu_lists() {
        // The engine lists a PID in the second page (0x21 to 0x40), the TCU none.
        let mut car = Car::new(engine_only)
            .listing(ENGINE, [0x0C, 0x21])
            .listing(TCU, [0x0C]);
        let sample = poller(&[0x0C, 0x21]).poll(&mut car, TIMING).unwrap();
        assert_eq!(car.sent, ["7DF 01 00", "7DF 01 20", "7DF 01 0C 21"]);
        assert_eq!(sample.unsupported_pids, Vec::<u8>::new());
    }

    #[test]
    fn a_pid_no_ecu_lists_is_not_sent_and_is_named_in_the_sample() {
        let mut car = engine_car();
        // 0x10 isn't in the engine's table.
        let sample = poller(&[0x0C, 0x10, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert_eq!(car.batches(), ["7DF 01 0C 0D"]);
        assert_eq!(sample.unsupported_pids, [0x10]);
        assert_eq!(sample.pids[&ENGINE].len(), 3);
        assert_eq!(sample.pids[&ENGINE][1], (0x10, Err(ReadError::NoReply)));
        assert!(!sample.out_of_step);
    }

    #[test]
    fn a_list_nothing_lists_is_an_error_and_sends_no_request_for_a_pid() {
        let mut car = engine_car();
        let mut poller = poller(&[0x10, 0x1F]);
        for _ in 0..2 {
            assert_eq!(
                poller.poll(&mut car, TIMING).unwrap_err(),
                PollError::NothingSupported(vec![0x10, 0x1F])
            );
        }
        // The bitmaps were read the first time only.
        assert_eq!(car.sent, ["7DF 01 00"]);
        assert_eq!(
            PollError::NothingSupported(vec![0x10, 0x1F]).to_string(),
            "no ECU lists any of the PIDs 10 1F"
        );
    }

    #[test]
    fn a_list_nothing_lists_is_fine_beside_dids() {
        let mut car = engine_car();
        let dids = vec![DidPoll {
            module: UdsModule {
                name: "engine".to_owned(),
                request_id: 0x7E0,
                response_id: 0x7E8,
            },
            dids: vec![(0xF190, None)],
        }];
        let mut poller = Poller::new(&Policy::read_only(), &[0x10], dids).unwrap();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(sample.unsupported_pids, [0x10]);
        assert!(sample.pids.is_empty());
        assert_eq!(sample.dids.len(), 1);
    }

    #[test]
    fn an_ecu_whose_first_bitmap_is_malformed_is_left_out_with_its_error() {
        // The TCU's answer to 01 00 is cut short, and it would answer the PIDs too.
        let mut car = Car::new(|id, request| {
            if is_bitmap(request) {
                return vec![
                    reply(ENGINE, &[0x41, 0x00, 0x00, 0x18, 0x00, 0x00]),
                    reply(TCU, &[0x41, 0x00, 0x18]),
                ];
            }
            two_ecus(id, request)
        });
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert!(sample.pids.contains_key(&ENGINE));
        assert!(!sample.pids.contains_key(&TCU));
        assert_eq!(
            sample.bitmap_errors,
            std::collections::BTreeMap::from([(
                TCU,
                undecodable(ReplyError::TooShort, &[0x41, 0x00, 0x18])
            )])
        );
        // The TCU answered the bitmap, and was never asked to answer the PIDs.
        assert!(!sample.out_of_step);
    }

    #[test]
    fn a_chain_that_breaks_keeps_the_pids_before_the_break() {
        // The engine says 01 20 is supported and never answers it.
        let mut car = Car::new(|id, request| match request {
            [0x01, 0x00] => vec![reply(ENGINE, &[0x41, 0x00, 0x00, 0x10, 0x00, 0x01])],
            [0x01, 0x20] => Vec::new(),
            _ => engine_only(id, request),
        });
        let sample = poller(&[0x0C, 0x21]).poll(&mut car, TIMING).unwrap();
        assert_eq!(sample.pids[&ENGINE][0], (0x0C, quantity(1726.0, Unit::Rpm)));
        assert_eq!(sample.unsupported_pids, [0x21]);
        assert_eq!(
            sample.bitmap_errors,
            std::collections::BTreeMap::from([(ENGINE, ReadError::NoReply)])
        );
        assert!(sample.out_of_step);
    }
}

mod out_of_step {
    use super::*;

    #[test]
    fn answered_polls_stay_in_step() {
        let mut car = engine_car();
        let mut poller = poller(&[0x0C, 0x0D]);
        assert!(!poller.poll(&mut car, TIMING).unwrap().out_of_step);
        assert!(!poller.poll(&mut car, TIMING).unwrap().out_of_step);
    }

    #[test]
    fn an_ecu_that_lists_none_of_the_pids_and_stays_silent_never_flags() {
        // The TCU lists 0C and 0D only, so it is never asked for the engine's other PIDs, and
        // its silence to them is the normal case.
        let mut car = two_ecu_car();
        let mut poller = poller(&[0x05, 0x0B, 0x04]);
        for _ in 0..3 {
            let sample = poller.poll(&mut car, TIMING).unwrap();
            assert!(!sample.out_of_step);
            assert!(!sample.pids.contains_key(&TCU));
        }
        assert_eq!(car.batches(), ["7DF 01 05 0B 04"].repeat(3));
    }

    #[test]
    fn an_ecu_that_lists_a_pid_and_stays_silent_is_flagged_for_good() {
        let mut poller = poller(&[0x0C, 0x0D]);
        assert!(!poller.poll(&mut two_ecu_car(), TIMING).unwrap().out_of_step);
        // The TCU lists 0C and 0D but stops answering.
        let mut car = Car::new(|id, request| {
            each_ecus_reply::two_ecus(id, request)
                .into_iter()
                .filter(|r| r.source == ENGINE)
                .collect()
        });
        assert!(poller.poll(&mut car, TIMING).unwrap().out_of_step);
        // Even when it answers again.
        assert!(poller.poll(&mut two_ecu_car(), TIMING).unwrap().out_of_step);
    }

    #[test]
    fn a_pid_left_out_of_a_reply_that_answered_the_rest_is_not_flagged() {
        let mut car = Car::new(|_, _| vec![reply(ENGINE, &[0x41, 0x0C, 0x1A, 0xF8])])
            .listing(ENGINE, [0x0C, 0x0D]);
        let sample = poller(&[0x0C, 0x0D]).poll(&mut car, TIMING).unwrap();
        assert_eq!(sample.pids[&ENGINE][1], (0x0D, Err(ReadError::NoReply)));
        assert!(!sample.out_of_step);
    }

    #[test]
    fn a_bitmap_read_nobody_answers_is_flagged_and_asked_again() {
        let mut poller = poller(&[0x0C]);
        let mut silent = Car::new(|_, _| Vec::new());
        assert!(poller.poll(&mut silent, TIMING).unwrap().out_of_step);
        let mut car = engine_car();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert!(sample.pids.contains_key(&ENGINE));
        assert!(sample.out_of_step);
    }

    #[test]
    fn a_late_reply_taken_by_the_next_poll_is_flagged() {
        // The first batch's reply comes in only after the poll gave up, so the second poll's
        // identical request takes it as its answer. Nothing in the reply says so; the flag does.
        let mut batches = 0;
        let mut car = Car::new(move |id, request| {
            batches += 1;
            if batches == 1 {
                return Vec::new();
            }
            engine_only(id, request)
        })
        .listing(ENGINE, [0x0D]);
        let mut poller = poller(&[0x0D]);
        assert!(poller.poll(&mut car, TIMING).unwrap().out_of_step);
        car.replies.push_back(reply(ENGINE, &[0x41, 0x0D, 0x10]));
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.pids[&ENGINE],
            [(0x0D, quantity(16.0, Unit::KilometresPerHour))]
        );
        assert!(sample.out_of_step);
    }

    #[test]
    fn a_module_that_does_not_answer_is_flagged_and_one_that_does_is_not() {
        let modules = || {
            vec![DidPoll {
                module: UdsModule {
                    name: "instruments".to_owned(),
                    request_id: 0x714,
                    response_id: 0x77E,
                },
                dids: vec![(0xF190, None)],
            }]
        };
        let mut car = Car::new(|_, _| vec![reply(0x77E, &[0x62, 0xF1, 0x90, b'W'])]);
        let mut answered = Poller::new(&Policy::read_only(), &[], modules()).unwrap();
        assert!(!answered.poll(&mut car, TIMING).unwrap().out_of_step);
        let mut car = Car::new(|_, _| Vec::new());
        let mut silent = Poller::new(&Policy::read_only(), &[], modules()).unwrap();
        assert!(silent.poll(&mut car, TIMING).unwrap().out_of_step);
    }

    #[test]
    fn an_adapter_failure_leaves_the_next_sample_flagged() {
        let mut car = engine_car();
        car.fail_after = Some(0);
        let mut poller = poller(&[0x0C]);
        poller.poll(&mut car, TIMING).unwrap_err();
        car.fail_after = None;
        assert!(poller.poll(&mut car, TIMING).unwrap().out_of_step);
    }
}

mod dids {
    use super::*;

    const GATEWAY: u32 = 0x77A;

    fn gateway() -> UdsModule {
        UdsModule {
            name: "gateway".to_owned(),
            request_id: 0x710,
            response_id: GATEWAY,
        }
    }

    fn instruments() -> UdsModule {
        UdsModule {
            name: "instruments".to_owned(),
            request_id: 0x714,
            response_id: 0x77E,
        }
    }

    fn two_modules() -> Vec<DidPoll> {
        vec![
            DidPoll {
                module: gateway(),
                dids: vec![(0xF187, Some(3)), (0xF189, Some(2))],
            },
            DidPoll {
                module: instruments(),
                dids: vec![(0xF190, None)],
            },
        ]
    }

    #[test]
    fn reads_each_module_with_one_request_and_keeps_the_modules_apart() {
        let mut car = Car::new(|id, request| match (id, request) {
            (0x710, [0x22, 0xF1, 0x87, 0xF1, 0x89]) => {
                vec![reply(
                    GATEWAY,
                    &[0x62, 0xF1, 0x87, b'A', b'B', b'C', 0xF1, 0x89, 1, 2],
                )]
            }
            (0x714, [0x22, 0xF1, 0x90]) => vec![reply(0x77E, &[0x62, 0xF1, 0x90, b'W', b'A'])],
            _ => Vec::new(),
        });
        let mut poller = Poller::new(&Policy::read_only(), &[], two_modules()).unwrap();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(car.sent, ["710 22 F1 87 F1 89", "714 22 F1 90"]);
        assert!(sample.pids.is_empty());
        assert_eq!(
            sample.dids,
            [
                obdcracker_transport::live::DidSample {
                    module: gateway(),
                    result: Ok(DidsData {
                        split: vec![(0xF187, vec![b'A', b'B', b'C']), (0xF189, vec![1, 2])],
                        left_out: vec![],
                        unsplit: vec![],
                    }),
                },
                obdcracker_transport::live::DidSample {
                    module: instruments(),
                    result: Ok(DidsData {
                        split: vec![(0xF190, vec![b'W', b'A'])],
                        left_out: vec![],
                        unsplit: vec![],
                    }),
                },
            ]
        );
    }

    #[test]
    fn a_module_that_does_not_answer_is_no_reply_and_the_other_is_still_read() {
        let mut car = Car::new(|id, request| match (id, request) {
            (0x714, [0x22, 0xF1, 0x90]) => vec![reply(0x77E, &[0x62, 0xF1, 0x90, b'W'])],
            _ => Vec::new(),
        });
        let mut poller = Poller::new(&Policy::read_only(), &[], two_modules()).unwrap();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(sample.dids[0].result, Err(ReadError::NoReply));
        assert!(sample.dids[1].result.is_ok());
    }

    #[test]
    fn a_reply_that_does_not_fit_the_lengths_is_undecodable() {
        // F187 is 3 bytes, so this reply is cut short.
        let bad = [0x62, 0xF1, 0x87, b'A', b'B'];
        let mut car = Car::new(move |id, _| {
            if id == 0x710 {
                vec![reply(GATEWAY, &bad)]
            } else {
                Vec::new()
            }
        });
        let mut poller = Poller::new(&Policy::read_only(), &[], two_modules()).unwrap();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(
            sample.dids[0].result,
            Err(undecodable(ReplyError::TooShort, &bad))
        );
    }

    #[test]
    fn pids_are_read_before_dids_in_the_same_poll() {
        let mut car = Car::new(|id, request| match id {
            0x7DF => engine_only(id, request),
            0x714 => vec![reply(0x77E, &[0x62, 0xF1, 0x90, b'W'])],
            _ => Vec::new(),
        })
        .listing(ENGINE, pids_of(ENGINE_PIDS));
        let dids = vec![DidPoll {
            module: instruments(),
            dids: vec![(0xF190, None)],
        }];
        let mut poller = Poller::new(&Policy::read_only(), &[0x0C], dids).unwrap();
        let sample = poller.poll(&mut car, TIMING).unwrap();
        assert_eq!(car.sent, ["7DF 01 00", "7DF 01 0C", "714 22 F1 90"]);
        assert_eq!(sample.pids[&ENGINE].len(), 1);
        assert!(sample.dids[0].result.is_ok());
    }
}

mod scheduling {
    use super::*;

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    #[test]
    fn is_due_one_interval_after_the_start_when_the_poll_was_quicker() {
        let t0 = Instant::now();
        assert_eq!(
            next_due(t0, Duration::from_millis(500), at(t0, 120)),
            at(t0, 500)
        );
        // Right at the start, and just before the deadline.
        assert_eq!(next_due(t0, Duration::from_millis(500), t0), at(t0, 500));
        assert_eq!(
            next_due(t0, Duration::from_millis(500), at(t0, 499)),
            at(t0, 500)
        );
    }

    #[test]
    fn is_due_now_when_the_poll_took_as_long_as_the_interval_or_longer() {
        let t0 = Instant::now();
        assert_eq!(
            next_due(t0, Duration::from_millis(500), at(t0, 500)),
            at(t0, 500)
        );
        // Three intervals late: one poll now, not a backlog of three at past times.
        let late = at(t0, 1500);
        assert_eq!(next_due(t0, Duration::from_millis(500), late), late);
        // And the poll after that is an interval after that one's start.
        assert_eq!(
            next_due(late, Duration::from_millis(500), at(late, 10)),
            at(late, 500)
        );
    }

    #[test]
    fn an_interval_of_zero_is_always_due_now() {
        let t0 = Instant::now();
        assert_eq!(next_due(t0, Duration::ZERO, t0), t0);
        assert_eq!(next_due(t0, Duration::ZERO, at(t0, 40)), at(t0, 40));
    }

    #[test]
    fn a_huge_interval_is_capped_and_cannot_overflow() {
        let t0 = Instant::now();
        for interval in [
            Duration::MAX,
            Duration::from_secs(u64::MAX),
            LONGEST_INTERVAL * 2,
        ] {
            assert_eq!(next_due(t0, interval, t0), t0 + LONGEST_INTERVAL);
        }
        assert_eq!(next_due(t0, LONGEST_INTERVAL, t0), t0 + LONGEST_INTERVAL);
    }
}

mod props {
    use proptest::prelude::*;

    use super::*;

    // The PIDs polled, and their data lengths from SAE J1979: RPM 2, speed 1, coolant 1.
    const POLLED: [u8; 3] = [0x0C, 0x0D, 0x05];

    // What a reply may hold, worked out without the poller's decoder: each PID once, from the
    // polled ones, with its whole data, and no byte left over.
    fn parse(after_service: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
        let mut rest = after_service;
        let mut got: Vec<(u8, Vec<u8>)> = Vec::new();
        while let Some((&pid, data)) = rest.split_first() {
            let length = match pid {
                0x0C => 2,
                0x0D | 0x05 => 1,
                _ => return None,
            };
            if got.iter().any(|(seen, _)| *seen == pid) || data.len() < length {
                return None;
            }
            got.push((pid, data[..length].to_vec()));
            rest = &data[length..];
        }
        Some(got)
    }

    fn expected(pid: u8, data: &[u8]) -> Result<PidValue, ReadError> {
        let byte = |i: usize| f32::from(data[i]);
        match pid {
            0x0C => quantity((byte(0) * 256.0 + byte(1)) / 4.0, Unit::Rpm),
            0x0D => quantity(byte(0), Unit::KilometresPerHour),
            _ => quantity(byte(0) - 40.0, Unit::Celsius),
        }
    }

    proptest! {
        // Whatever bytes follow a first PID that was asked for, the poller never panics, takes
        // exactly what an independent parse of the reply takes, and when the reply isn't exactly
        // some of the polled PIDs, once each, accepts none of it.
        #[test]
        fn a_reply_is_taken_exactly_or_not_at_all(
            first in prop::sample::select(POLLED.to_vec()),
            tail in prop::collection::vec(
                prop_oneof![
                    Just(0x0Cu8), Just(0x0D), Just(0x05), Just(0x41), Just(0x00), any::<u8>()
                ],
                0..12,
            ),
        ) {
            let mut payload = vec![0x41, first];
            payload.extend(&tail);
            let sent = payload.clone();
            let mut car = Car::new(move |id, _| {
                if id == 0x7DF { vec![reply(ENGINE, &sent)] } else { Vec::new() }
            })
            .listing(ENGINE, POLLED);
            let sample = poller(&POLLED).poll(&mut car, TIMING).unwrap();
            let readings = &sample.pids[&ENGINE];
            prop_assert_eq!(readings.len(), POLLED.len());
            match parse(&payload[1..]) {
                Some(got) => {
                    for ((pid, reading), want) in readings.iter().zip(POLLED) {
                        prop_assert_eq!(*pid, want);
                        let value = got.iter().find(|(seen, _)| *seen == want);
                        let want_reading = value
                            .map_or(Err(ReadError::NoReply), |(_, data)| expected(want, data));
                        prop_assert_eq!(reading, &want_reading);
                    }
                }
                None => {
                    for (_, reading) in readings {
                        prop_assert!(
                            matches!(reading, Err(ReadError::Undecodable { reply, .. }) if *reply == payload),
                            "{:?}", reading
                        );
                    }
                }
            }
        }
    }
}
