use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use obdcracker_safety::{Policy, Protocol, Target};
use proptest::prelude::*;

use super::port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};
use super::{Limits, RawCan};
use crate::{Error, Expect, LinkEvent, Timing, Transport, exchange};

type Responder = Box<dyn FnMut(&TxFrame) -> Vec<PortEvent>>;

#[derive(Default)]
struct Fake {
    inbox: VecDeque<PortEvent>,
    log: Vec<Logged>,
    responder: Option<Responder>,
    // Fail the write with this index (counting from 0), as an unconfirmed frame.
    fail_write: Option<usize>,
    // Hand this frame over for ever.
    flood: Option<RxFrame>,
    // Every write must find this set: the caller has to have said it was about to send.
    announced: Option<Rc<Cell<bool>>>,
}

#[derive(Debug, Clone, PartialEq)]
enum Logged {
    Filters(Vec<Filter>),
    Write(TxFrame, Instant),
}

impl std::fmt::Debug for Fake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fake")
    }
}

impl Fake {
    fn answering(responder: impl FnMut(&TxFrame) -> Vec<PortEvent> + 'static) -> Self {
        Self {
            responder: Some(Box::new(responder)),
            ..Self::default()
        }
    }

    fn written(&self) -> Vec<TxFrame> {
        self.log
            .iter()
            .filter_map(|entry| match entry {
                Logged::Write(frame, _) => Some(*frame),
                Logged::Filters(_) => None,
            })
            .collect()
    }

    fn filters(&self) -> Vec<Vec<Filter>> {
        self.log
            .iter()
            .filter_map(|entry| match entry {
                Logged::Filters(filters) => Some(filters.clone()),
                Logged::Write(..) => None,
            })
            .collect()
    }
}

impl CanPort for Fake {
    fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error> {
        self.log.push(Logged::Filters(filters.to_vec()));
        Ok(())
    }

    fn write(&mut self, frame: &TxFrame) -> Result<(), Error> {
        if let Some(announced) = &self.announced {
            assert!(announced.get(), "written before it was announced");
        }
        let index = self.written().len();
        if self.fail_write == Some(index) {
            return Err(Error::Adapter("no TX confirmation".to_owned()));
        }
        self.log.push(Logged::Write(*frame, Instant::now()));
        if let Some(responder) = self.responder.as_mut() {
            self.inbox.extend(responder(frame));
        }
        Ok(())
    }

    fn read(&mut self, _timeout: Duration) -> Result<PortEvent, Error> {
        if let Some(event) = self.inbox.pop_front() {
            return Ok(event);
        }
        match &self.flood {
            Some(frame) => Ok(PortEvent::Frame(frame.clone())),
            None => Err(Error::Timeout),
        }
    }
}

fn rx(id: u32, extended: bool, data: &[u8]) -> RxFrame {
    RxFrame {
        id,
        extended,
        data: data.to_vec(),
        time: None,
    }
}

fn frame(id: u32, data: &[u8]) -> PortEvent {
    PortEvent::Frame(rx(id, false, data))
}

fn frame29(id: u32, data: &[u8]) -> PortEvent {
    PortEvent::Frame(rx(id, true, data))
}

fn approve(target: Target, payload: &[u8]) -> obdcracker_safety::Approved {
    Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap()
}

fn read_did(target: Target) -> obdcracker_safety::Approved {
    approve(target, &[0x22, 0xF1, 0x87])
}

// A request of `len` bytes that the read-only policy approves: `19` takes any length.
fn long_request(target: Target, len: usize) -> obdcracker_safety::Approved {
    let mut payload = vec![0x19];
    payload.extend((1..len).map(|i| u8::try_from(i % 251).unwrap()));
    approve(target, &payload)
}

fn flow_control(status: u8, block_size: u8, st_min: u8) -> Vec<u8> {
    vec![0x30 | status, block_size, st_min]
}

// The frames a module sends for `payload`, split after the first frame.
fn first_and_consecutive(payload: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let len = payload.len();
    let mut first = vec![
        0x10 | u8::try_from(len >> 8).unwrap(),
        u8::try_from(len & 0xFF).unwrap(),
    ];
    first.extend(&payload[..6]);
    let consecutive = payload[6..]
        .chunks(7)
        .enumerate()
        .map(|(i, chunk)| {
            let mut data = vec![0x20 | u8::try_from((i + 1) & 0x0F).unwrap()];
            data.extend(chunk);
            data.resize(8, 0);
            data
        })
        .collect();
    (first, consecutive)
}

// An ECU that hears requests on `request_ids`, answers on `response_id`, and wants its flow
// control on `physical`.
struct Ecu {
    response_id: u32,
    extended: bool,
    request_ids: Vec<u32>,
    physical: u32,
    reply: Vec<u8>,
}

impl Ecu {
    fn obd(request: u32, reply: &[u8]) -> Self {
        Self {
            response_id: request + 8,
            extended: false,
            request_ids: vec![0x7DF, request],
            physical: request,
            reply: reply.to_vec(),
        }
    }

    fn answer(&self, sent: &TxFrame) -> Vec<PortEvent> {
        let out = |id, extended, data: &[u8]| PortEvent::Frame(rx(id, extended, data));
        if sent.id == self.physical && sent.extended == self.extended && sent.data[0] == 0x30 {
            return first_and_consecutive(&self.reply)
                .1
                .iter()
                .map(|data| out(self.response_id, self.extended, data))
                .collect();
        }
        if !self.request_ids.contains(&sent.id) || sent.data[0] >> 4 != 0 {
            return Vec::new();
        }
        if self.reply.len() <= 7 {
            let mut data = vec![u8::try_from(self.reply.len()).unwrap()];
            data.extend(&self.reply);
            return vec![out(self.response_id, self.extended, &data)];
        }
        vec![out(
            self.response_id,
            self.extended,
            &first_and_consecutive(&self.reply).0,
        )]
    }
}

fn ecus(list: Vec<Ecu>) -> Fake {
    Fake::answering(move |sent| list.iter().flat_map(|ecu| ecu.answer(sent)).collect())
}

fn raw(fake: Fake) -> RawCan<Fake> {
    RawCan::new(fake).with_limits(Limits {
        flow_control: Duration::from_millis(60),
        max_waits: 3,
    })
}

const SHORT: Duration = Duration::from_millis(20);

fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

// Frames a module sends to answer a long request: flow control that lets everything through.
fn module_flow_control(reply: u32, st_min: u8) -> Fake {
    Fake::answering(move |sent| {
        if sent.data[0] >> 4 == 1 {
            vec![frame(reply, &flow_control(0, 0, st_min))]
        } else {
            Vec::new()
        }
    })
}

// ---- #42 requirement 1: DLC 8

#[test]
fn every_frame_written_has_eight_bytes_padded() {
    let mut can = raw(module_flow_control(0x7E8, 0));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    let written = can.port.written();
    assert_eq!(
        written[0].data,
        [3, 0x22, 0xF1, 0x87, 0xAA, 0xAA, 0xAA, 0xAA]
    );
    // first frame, three consecutive frames, the last one short
    assert_eq!(written.len(), 1 + 1 + 3);
    assert_eq!(
        written[4].data,
        [0x23, 20, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
    );
}

#[test]
fn flow_control_written_is_padded_to_eight_bytes() {
    let ecu = Ecu::obd(0x7E0, &payload_of(20));
    let mut can = raw(ecus(vec![ecu]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.recv(SHORT).unwrap();
    let written = can.port.written();
    assert_eq!(written[1].id, 0x7E0);
    assert_eq!(written[1].data, [0x30, 0, 0, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
}

// ---- #42 requirement 2: one frame in flight, in order

#[test]
fn consecutive_frames_go_out_in_order_with_wrapping_sequence_numbers() {
    let mut can = raw(module_flow_control(0x7E8, 0));
    can.send(&long_request(Target::Physical(0x7E0), 200))
        .unwrap();
    let written = can.port.written();
    let sequence: Vec<u8> = written[1..].iter().map(|f| f.data[0]).collect();
    let expected: Vec<u8> = (1..)
        .take(sequence.len())
        .map(|n| 0x20 | (n & 0x0F))
        .collect();
    assert_eq!(sequence, expected);
    assert!(written[1..].len() > 16, "must wrap past sequence number 15");
}

#[test]
fn an_unconfirmed_frame_stops_the_transfer() {
    for failing in [0, 1, 3] {
        let mut fake = module_flow_control(0x7E8, 0);
        fake.fail_write = Some(failing);
        let mut can = raw(fake);
        let result = can.send(&long_request(Target::Physical(0x7E0), 100));
        assert_eq!(result, Err(Error::Adapter("no TX confirmation".to_owned())));
        assert_eq!(can.port.written().len(), failing);
    }
}

#[test]
fn a_failed_send_leaves_no_window_to_take_replies() {
    let mut fake = module_flow_control(0x7E8, 0);
    fake.fail_write = Some(2);
    let mut can = raw(fake);
    can.send(&long_request(Target::Physical(0x7E0), 100))
        .unwrap_err();
    can.port
        .inbox
        .push_back(frame(0x7E8, &[3, 0x62, 0xF1, 0x87]));
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

// ---- #42 requirement 3: filters and overrun

#[test]
fn filters_come_from_the_approved_target_and_are_set_before_any_frame() {
    let cases = [
        (
            read_did(Target::Physical(0x7E0)),
            Filter {
                id: 0x7E8,
                mask: 0x7FF,
                extended: false,
            },
        ),
        (
            approve(Target::ObdFunctional, &[0x01, 0x00]),
            Filter {
                id: 0x7E8,
                mask: 0x7F8,
                extended: false,
            },
        ),
        (
            read_did(Target::Physical29(0x18DA_10F1)),
            Filter {
                id: 0x18DA_F110,
                mask: 0x1FFF_FFFF,
                extended: true,
            },
        ),
        (
            read_did(Target::Physical(0x710)),
            Filter {
                id: 0x700,
                mask: 0x700,
                extended: false,
            },
        ),
    ];
    for (request, filter) in cases {
        let mut can = raw(Fake::default());
        can.send(&request).unwrap();
        assert_eq!(can.port.filters(), vec![vec![filter]]);
        assert!(matches!(can.port.log[0], Logged::Filters(_)));
    }
}

#[test]
fn filters_are_set_again_only_when_they_change() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.send(&read_did(Target::Physical(0x7E1))).unwrap();
    assert_eq!(can.port.filters().len(), 2);
}

#[test]
fn a_receive_overrun_is_an_adapter_error_and_drops_the_partial_reply() {
    let ecu = Ecu::obd(0x7E0, &payload_of(20));
    let mut can = raw(ecus(vec![ecu]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port.inbox.push_back(PortEvent::Overrun);
    match can.recv(SHORT) {
        Err(Error::Adapter(message)) => assert!(message.contains("overrun"), "{message}"),
        other => panic!("{other:?}"),
    }
    // Not latched: the bus is fine, only that reply is lost.
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
}

// ---- #42 requirement 4: bus state

#[test]
fn bus_off_error_passive_and_error_frames_are_errors_and_latch() {
    for event in [
        PortEvent::BusOff,
        PortEvent::ErrorPassive,
        PortEvent::ErrorFrame,
    ] {
        let mut can = raw(Fake::default());
        can.send(&read_did(Target::Physical(0x7E0))).unwrap();
        let written = can.port.written().len();
        can.port.inbox.push_back(event.clone());
        let error = can.recv(SHORT).unwrap_err();
        assert!(matches!(error, Error::Adapter(_)), "{event:?}");
        assert_eq!(
            can.send(&read_did(Target::Physical(0x7E0))),
            Err(error.clone())
        );
        assert_eq!(can.recv(SHORT), Err(error));
        assert_eq!(can.port.written().len(), written, "{event:?}");
    }
}

#[test]
fn a_bus_fault_while_waiting_for_flow_control_latches_and_sends_no_more() {
    let fake = Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            vec![PortEvent::BusOff]
        } else {
            Vec::new()
        }
    });
    let mut can = raw(fake);
    let request = long_request(Target::Physical(0x7E0), 21);
    can.send(&request).unwrap_err();
    assert_eq!(can.port.written().len(), 1);
    can.send(&request).unwrap_err();
    assert_eq!(can.port.written().len(), 1);
}

#[test]
fn a_bus_fault_stops_flow_control_a_reply_needed() {
    let mut can = raw(ecus(vec![Ecu::obd(0x7E0, &payload_of(20))]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    let first = can.port.inbox.pop_front().unwrap();
    can.port.inbox.push_front(PortEvent::ErrorFrame);
    can.port.inbox.push_back(first);
    can.recv(SHORT).unwrap_err();
    assert_eq!(can.port.written().len(), 1);
}

// ---- #42 requirement 6: STmin

thread_local! {
    static NAPS: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
}

fn nap(d: Duration) {
    NAPS.with(|naps| naps.borrow_mut().push(d));
}

fn naps() -> Vec<Duration> {
    NAPS.with(|naps| std::mem::take(&mut *naps.borrow_mut()))
}

#[test]
fn st_min_zero_never_sleeps() {
    naps();
    let mut can = RawCan::new(module_flow_control(0x7E8, 0)).with_sleeper(nap);
    can.send(&long_request(Target::Physical(0x7E0), 200))
        .unwrap();
    assert_eq!(naps(), Vec::<Duration>::new());
}

#[test]
fn a_short_st_min_is_waited_by_spinning_and_never_cut_short() {
    // 0xF5 is 500 us; 0x01 is 1 ms
    for (code, gap) in [
        (0xF5, Duration::from_micros(500)),
        (0x01, Duration::from_millis(1)),
    ] {
        naps();
        let mut can = RawCan::new(module_flow_control(0x7E8, code)).with_sleeper(nap);
        can.send(&long_request(Target::Physical(0x7E0), 40))
            .unwrap();
        assert_eq!(naps(), Vec::<Duration>::new());
        let times: Vec<Instant> = can
            .port
            .log
            .iter()
            .filter_map(|entry| match entry {
                Logged::Write(_, at) => Some(*at),
                Logged::Filters(_) => None,
            })
            .collect();
        for pair in times[1..].windows(2) {
            assert!(
                pair[1] - pair[0] >= gap,
                "{:?} < {gap:?}",
                pair[1] - pair[0]
            );
        }
    }
}

#[test]
fn a_long_st_min_sleeps_for_less_than_it_asks() {
    naps();
    let mut can = RawCan::new(module_flow_control(0x7E8, 20)).with_sleeper(nap);
    can.send(&long_request(Target::Physical(0x7E0), 14))
        .unwrap();
    let naps = naps();
    assert_ne!(naps.len(), 0);
    assert!(naps.iter().all(|nap| *nap < Duration::from_millis(20)));
}

#[test]
fn the_gap_counts_from_the_confirmed_frame_not_before() {
    // A port that takes 5 ms to confirm each frame. Stamped before the write, a 1 ms gap would
    // already be over when it returned.
    #[derive(Debug)]
    struct Slow(Fake);
    impl CanPort for Slow {
        fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error> {
            self.0.set_filters(filters)
        }
        fn write(&mut self, frame: &TxFrame) -> Result<(), Error> {
            std::thread::sleep(Duration::from_millis(5));
            self.0.write(frame)
        }
        fn read(&mut self, timeout: Duration) -> Result<PortEvent, Error> {
            self.0.read(timeout)
        }
    }
    let mut can = RawCan::new(Slow(module_flow_control(0x7E8, 1)));
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    let times: Vec<Instant> = can
        .port
        .0
        .log
        .iter()
        .filter_map(|entry| match entry {
            Logged::Write(_, at) => Some(*at),
            Logged::Filters(_) => None,
        })
        .collect();
    for pair in times[1..].windows(2) {
        assert!(pair[1] - pair[0] >= Duration::from_millis(6));
    }
}

// ---- #42 requirement 7: flow control goes to the responder's physical ID

#[test]
fn flow_control_after_a_broadcast_goes_to_the_responders_physical_id() {
    let list = vec![Ecu::obd(0x7E1, &payload_of(20))];
    let mut can = raw(ecus(list));
    can.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
        .unwrap();
    let reply = can.recv(SHORT).unwrap();
    assert_eq!((reply.source, reply.payload), (0x7E9, payload_of(20)));
    let flow: Vec<u32> = can
        .port
        .written()
        .iter()
        .filter(|f| f.data[0] == 0x30)
        .map(|f| f.id)
        .collect();
    assert_eq!(flow, vec![0x7E1]);
}

#[test]
fn two_responders_to_a_broadcast_each_get_their_own_flow_control() {
    let list = vec![
        Ecu::obd(0x7E0, &payload_of(20)),
        Ecu::obd(0x7E1, &payload_of(30)),
    ];
    let mut can = raw(ecus(list));
    can.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
        .unwrap();
    let mut replies = [can.recv(SHORT).unwrap(), can.recv(SHORT).unwrap()];
    replies.sort_by_key(|r| r.source);
    assert_eq!(replies[0].payload, payload_of(20));
    assert_eq!(replies[1].payload, payload_of(30));
    let mut flow: Vec<u32> = can
        .port
        .written()
        .iter()
        .filter(|f| f.data[0] == 0x30)
        .map(|f| f.id)
        .collect();
    flow.sort_unstable();
    assert_eq!(flow, vec![0x7E0, 0x7E1]);
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

// ---- the echo check stays the caller's

#[test]
fn exchange_drops_a_stray_single_frame_that_does_not_echo_the_request() {
    // A physical request with no known reply ID takes a single frame from any 0x7xx source.
    let fake = Fake::answering(|sent| {
        if sent.data[0] >> 4 == 0 {
            vec![
                frame(0x7F3, &[4, 0x62, 0xF1, 0x90, 0x41]),
                frame(0x7F3, &[4, 0x62, 0xF1, 0x87, 0x42]),
            ]
        } else {
            Vec::new()
        }
    });
    let mut can = raw(fake);
    let replies = exchange(
        &mut can,
        &read_did(Target::Physical(0x710)),
        Expect::Module(0x7F3),
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].payload, vec![0x62, 0xF1, 0x87, 0x42]);
}

// ---- recv, flow control logging and bus time

#[test]
fn before_send_sees_each_flow_control_before_the_port_does() {
    let mut can = raw(ecus(vec![Ecu::obd(0x7E0, &payload_of(20))]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    let before = can.port.written().len();
    let announced = Rc::new(Cell::new(false));
    can.port.announced = Some(Rc::clone(&announced));
    let mut seen = Vec::new();
    can.recv_logged(SHORT, &mut |token| {
        seen.push((token.destination_id(), token.data().to_vec()));
        announced.set(true);
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, vec![(0x7E0, vec![0x30, 0, 0])]);
    assert_eq!(can.port.written().len(), before + 1);
}

#[test]
fn a_refused_before_send_writes_nothing_and_returns_its_error() {
    let mut can = raw(ecus(vec![Ecu::obd(0x7E0, &payload_of(20))]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    let before = can.port.written().len();
    let refusal = Error::Adapter("audit log full".to_owned());
    let result = can.recv_logged(SHORT, &mut |_| Err(refusal.clone()));
    assert_eq!(result, Err(refusal));
    assert_eq!(can.port.written().len(), before);
}

#[test]
fn the_reply_carries_the_bus_time_of_its_last_frame() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    let earlier = Instant::now();
    let last = earlier + Duration::from_millis(3);
    let (first, rest) = first_and_consecutive(&payload_of(20));
    let mut frames = vec![first];
    frames.extend(rest);
    for (i, data) in frames.iter().enumerate() {
        let mut frame = rx(0x7E8, false, data);
        frame.time = Some(if i + 1 == frames.len() { last } else { earlier });
        can.port.inbox.push_back(PortEvent::Frame(frame));
    }
    assert_eq!(can.recv(SHORT).unwrap().bus_time, Some(last));
}

#[test]
fn a_reply_with_no_port_time_has_no_bus_time() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x7E8, &[3, 0x62, 0xF1, 0x87]));
    assert_eq!(can.recv(SHORT).unwrap().bus_time, None);
}

// ---- edge cases

#[test]
fn no_flow_control_ends_the_send_without_more_frames() {
    let mut can = raw(Fake::default());
    let result = can.send(&long_request(Target::Physical(0x7E0), 21));
    assert!(matches!(result, Err(Error::Adapter(m)) if m.contains("no flow control")));
    assert_eq!(can.port.written().len(), 1);
}

#[test]
fn too_many_wait_flow_controls_end_the_send() {
    let mut fake = Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            (0..10)
                .map(|_| frame(0x7E8, &flow_control(1, 0, 0)))
                .collect()
        } else {
            Vec::new()
        }
    });
    fake.fail_write = None;
    let mut can = raw(fake);
    let result = can.send(&long_request(Target::Physical(0x7E0), 21));
    assert!(matches!(result, Err(Error::Adapter(m)) if m.contains("kept asking to wait")));
    assert_eq!(can.port.written().len(), 1);
}

#[test]
fn a_few_wait_flow_controls_are_waited_through() {
    let mut can = raw(Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            vec![
                frame(0x7E8, &flow_control(1, 0, 0)),
                frame(0x7E8, &flow_control(1, 0, 0)),
                frame(0x7E8, &flow_control(0, 0, 0)),
            ]
        } else {
            Vec::new()
        }
    }));
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    assert_eq!(can.port.written().len(), 4);
}

#[test]
fn an_overflow_flow_control_aborts_the_send() {
    let mut can = raw(Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            vec![frame(0x7E8, &flow_control(2, 0, 0))]
        } else {
            Vec::new()
        }
    }));
    let result = can.send(&long_request(Target::Physical(0x7E0), 100));
    assert!(matches!(result, Err(Error::Adapter(m)) if m.contains("too long")));
    assert_eq!(can.port.written().len(), 1);
}

#[test]
fn a_block_size_makes_the_sender_wait_for_the_next_flow_control() {
    let mut can = raw(Fake::answering(|sent| {
        let (kind, low) = (sent.data[0] >> 4, sent.data[0] & 0x0F);
        if kind == 1 || (kind == 2 && low % 2 == 0) {
            vec![frame(0x7E8, &flow_control(0, 2, 0))]
        } else {
            Vec::new()
        }
    }));
    // First frame, then 6 consecutive frames in blocks of 2.
    can.send(&long_request(Target::Physical(0x7E0), 48))
        .unwrap();
    assert_eq!(can.port.written().len(), 7);
    // Without the second and third flow control, the sender would have stopped after frame 3.
    let mut stuck = raw(Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            vec![frame(0x7E8, &flow_control(0, 2, 0))]
        } else {
            Vec::new()
        }
    }));
    assert!(
        stuck
            .send(&long_request(Target::Physical(0x7E0), 48))
            .is_err()
    );
    assert_eq!(stuck.port.written().len(), 3);
}

#[test]
fn frames_from_an_unexpected_id_are_ignored() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x7E9, &[3, 0x62, 0xF1, 0x87]));
    can.port
        .inbox
        .push_back(frame(0x123, &[3, 0x62, 0xF1, 0x87]));
    can.port
        .inbox
        .push_back(frame(0x7E8, &[3, 0x62, 0xF1, 0x87]));
    let reply = can.recv(SHORT).unwrap();
    assert_eq!(reply.source, 0x7E8);
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

#[test]
fn a_frame_of_the_other_id_width_is_ignored() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame29(0x7E8, &[3, 0x62, 0xF1, 0x87]));
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    can.send(&read_did(Target::Physical29(0x18DA_10F1)))
        .unwrap();
    can.port
        .inbox
        .push_back(frame(0x18DA_F110 & 0x7FF, &[3, 0x62, 0xF1, 0x87]));
    can.port
        .inbox
        .push_back(frame29(0x18DA_F110, &[3, 0x62, 0xF1, 0x87]));
    assert_eq!(can.recv(SHORT).unwrap().source, 0x18DA_F110);
}

#[test]
fn a_29_bit_transfer_uses_29_bit_ids_both_ways() {
    let ecu = Ecu {
        response_id: 0x18DA_F110,
        extended: true,
        request_ids: vec![0x18DA_10F1],
        physical: 0x18DA_10F1,
        reply: payload_of(20),
    };
    let mut can = raw(ecus(vec![ecu]));
    can.send(&read_did(Target::Physical29(0x18DA_10F1)))
        .unwrap();
    assert_eq!(can.recv(SHORT).unwrap().payload, payload_of(20));
    for written in can.port.written() {
        assert_eq!((written.id, written.extended), (0x18DA_10F1, true));
    }
}

#[test]
fn a_wrong_sequence_number_drops_the_reply_and_is_noted() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x7E8, &[0x10, 20, 0, 1, 2, 3, 4, 5]));
    can.port
        .inbox
        .push_back(frame(0x7E8, &[0x23, 6, 7, 8, 9, 10, 11, 12]));
    can.port
        .inbox
        .push_back(frame(0x7E8, &[0x22, 13, 14, 15, 16, 17, 18, 19]));
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    let events = can.take_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LinkEvent::Status { line, .. } if line.contains("7E8"))),
        "{events:?}"
    );
}

#[test]
fn an_empty_single_frame_is_not_a_reply() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x7E8, &[0, 0, 0, 0, 0, 0, 0, 0]));
    can.port.inbox.push_back(frame(0x7E8, &[]));
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}

#[test]
fn the_longest_short_request_and_one_byte_more_both_go_out() {
    // 4095 bytes use the 12-bit length; 4096 the 32-bit escape. `0x19` takes any length.
    for len in [4095, 4096] {
        let mut can = raw(module_flow_control(0x7E8, 0));
        let mut payload = vec![0x19];
        payload.extend(payload_of(len - 1));
        can.send(&approve(Target::Physical(0x7E0), &payload))
            .unwrap();
        let written = can.port.written();
        let mut sent: Vec<u8> = Vec::new();
        let (first_bytes, header) = if len == 4095 { (6, 2) } else { (2, 6) };
        sent.extend(&written[0].data[header..header + first_bytes]);
        for frame in &written[1..] {
            sent.extend(&frame.data[1..]);
        }
        sent.truncate(len);
        assert_eq!(sent, payload, "{len}");
    }
}

#[test]
fn a_reply_of_4095_bytes_is_taken() {
    let mut can = raw(ecus(vec![Ecu::obd(0x7E0, &payload_of(4095))]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(
        can.recv(Duration::from_secs(1)).unwrap().payload.len(),
        4095
    );
}

#[test]
fn a_reply_longer_than_4095_bytes_gets_no_flow_control() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    // 4096 bytes announced with the 32-bit length escape.
    can.port.inbox.push_back(frame(
        0x7E8,
        &[0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x62, 0x00],
    ));
    let written = can.port.written().len();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    assert_eq!(can.port.written().len(), written);
}

#[test]
fn a_multi_frame_reply_with_no_known_reply_id_says_so_instead_of_timing_out() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x710))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x718, &[0x10, 20, 0x62, 0xF1, 0x87, 1, 2, 3]));
    let written = can.port.written().len();
    match can.recv(SHORT) {
        Err(Error::Adapter(message)) => assert!(message.contains("718"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(can.port.written().len(), written);
}

#[test]
fn a_multi_frame_request_with_no_known_reply_id_is_refused_before_any_frame() {
    let mut can = raw(Fake::default());
    let result = can.send(&long_request(Target::Physical(0x710), 21));
    assert!(matches!(result, Err(Error::Adapter(_))));
    assert_eq!(can.port.log.len(), 0);
}

#[test]
fn tp20_requests_are_refused_and_nothing_reaches_the_port() {
    // Raw CAN has no TP2.0 yet: https://github.com/DaSonOfPoseidon/OBDCracker/issues/259
    let policy = Policy::read_only().narrowed_to_tp20(&[0x01]);
    let setup = policy.approve_tp20_setup(0x01).unwrap();
    let reply = [0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01];
    let setup_id = obdcracker_core::tp20::setup_reply_id(0x01);
    let channel = policy.tp20_channel(&setup, setup_id, &reply).unwrap();
    let requests = [
        setup,
        policy.approve_tp20_parameters(&channel).unwrap(),
        policy.approve_tp20_keep_alive(&channel).unwrap(),
        policy.approve_tp20_disconnect(&channel).unwrap(),
    ];
    for request in requests {
        let mut can = raw(Fake::default());
        let result = can.send(&request);
        assert!(
            matches!(&result, Err(Error::Adapter(m)) if m.contains("TP2.0") && m.contains("#259"))
        );
        assert_eq!(can.port.log.len(), 0);
        // Refusing doesn't latch.
        can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    }
}

#[test]
fn stale_frames_from_the_last_request_are_not_taken_as_the_next_reply() {
    let mut can = raw(Fake::default());
    can.port
        .inbox
        .push_back(frame(0x7E8, &[3, 0x62, 0xF1, 0x90]));
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    let events = can.take_events();
    assert!(matches!(&events[..], [LinkEvent::Unread { line, .. }] if line.contains("62 F1 90")));
}

#[test]
fn a_bus_fault_among_stale_frames_latches_before_any_frame_is_sent() {
    let mut can = raw(Fake::default());
    can.port.inbox.push_back(PortEvent::BusOff);
    can.send(&read_did(Target::Physical(0x7E0))).unwrap_err();
    assert_eq!(can.port.written().len(), 0);
}

#[test]
fn a_flood_of_foreign_frames_cannot_hold_recv_past_its_timeout() {
    let mut can = raw(Fake {
        flood: Some(rx(0x123, false, &[1, 2, 3])),
        ..Fake::default()
    });
    let start = Instant::now();
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_flood_while_waiting_for_flow_control_cannot_hold_send_past_its_limit() {
    let mut can = raw(Fake {
        flood: Some(rx(0x123, false, &[1, 2, 3])),
        ..Fake::default()
    });
    let start = Instant::now();
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap_err();
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_zero_timeout_polls_once() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    can.port
        .inbox
        .push_back(frame(0x7E8, &[3, 0x62, 0xF1, 0x87]));
    assert!(can.recv(Duration::ZERO).is_ok());
    assert_eq!(can.recv(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn events_kept_between_calls_are_bounded() {
    let mut can = raw(Fake::default());
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    for _ in 0..200 {
        can.port
            .inbox
            .push_back(frame(0x7E8, &[0x21, 1, 2, 3, 4, 5, 6, 7]));
    }
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
    let events = can.take_events();
    assert!(events.len() <= 65, "{}", events.len());
    assert!(matches!(events.last(), Some(LinkEvent::Lost(n)) if *n > 0));
}

proptest! {
    // Whatever arrives, recv ends, never panics, and writes only flow control to the module that
    // sent the first frame.
    #[test]
    fn any_received_frames_are_handled(
        frames in proptest::collection::vec(
            (prop_oneof![Just(0x7E8u32), Just(0x7E9), Just(0x123), Just(0x18DA_F110)], any::<bool>(),
             proptest::collection::vec(any::<u8>(), 0..=10)),
            0..40,
        ),
        broadcast in any::<bool>(),
    ) {
        let mut can = raw(Fake::default());
        let target = if broadcast { Target::ObdFunctional } else { Target::Physical(0x7E0) };
        let request = if broadcast { approve(target, &[0x09, 0x02]) } else { read_did(target) };
        can.send(&request).unwrap();
        let before = can.port.written().len();
        for (id, extended, data) in frames {
            can.port.inbox.push_back(PortEvent::Frame(rx(id, extended, &data)));
        }
        while can.recv(Duration::ZERO).is_ok() {}
        for written in &can.port.written()[before..] {
            prop_assert_eq!(written.data, [0x30, 0, 0, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
            prop_assert!(!written.extended);
            prop_assert!(written.id == 0x7E0 || (broadcast && written.id == 0x7E1));
        }
    }
}

fn answers_early_then_allows() -> Fake {
    Fake::answering(|sent| {
        if sent.data[0] >> 4 == 1 {
            vec![
                frame(0x7E8, &[3, 0x7F, 0x19, 0x31]),
                frame(0x7E8, &flow_control(0, 0, 0)),
            ]
        } else {
            Vec::new()
        }
    })
}

#[test]
fn a_module_answering_during_the_request_is_heard() {
    let mut can = raw(answers_early_then_allows());
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    assert_eq!(can.recv(SHORT).unwrap().payload, vec![0x7F, 0x19, 0x31]);
}

#[test]
fn a_reply_from_the_last_request_is_not_the_next_ones() {
    let mut can = raw(answers_early_then_allows());
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    can.send(&read_did(Target::Physical(0x7E0))).unwrap();
    assert_eq!(can.recv(SHORT), Err(Error::Timeout));
}
