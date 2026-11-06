//! The SocketCAN backend on a real kernel interface, `vcan0`, with `obdcracker-sim` answering on
//! the other end. The tests are ignored in an ordinary `cargo test`, which has no `vcan0`; the CI
//! job `vcan` creates it and runs them with `--ignored`. They fail, not skip, if `vcan0` is
//! missing, so a runner that can't load the module turns the job red.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use obdcracker_core::isotp::{Addressing, Frame, Segmenter, Step};
use obdcracker_safety::{Policy, Protocol, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::socketcan::{BitrateCheck, Mode, Options, SocketCan};
use obdcracker_transport::tp20::{self, Answer, ChannelSession, Disconnect};
use obdcracker_transport::{Error, Expect, Timing, Transport, exchange};
use socketcan::{CanSocket, Socket};

const PAD: u8 = 0xAA;

fn interface() -> String {
    std::env::var("OBDCRACKER_VCAN").unwrap_or_else(|_| "vcan0".to_owned())
}

// One test at a time: they share one interface, and two simulated cars on it would both answer.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn raw_frame(id: u32, data: &[u8]) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0..4].copy_from_slice(&id.to_ne_bytes());
    bytes[4] = u8::try_from(data.len()).unwrap();
    bytes[8..8 + data.len()].copy_from_slice(data);
    bytes
}

// A second socket on the interface, for what the tests put on it themselves.
fn side_socket() -> CanSocket {
    CanSocket::open(&interface()).unwrap_or_else(|e| {
        panic!(
            "can't open {}: {e}. This test needs the vcan interface (`sudo modprobe vcan && \
             sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`)",
            interface()
        )
    })
}

// --- The simulated car on the other end ---

type Seen = Arc<Mutex<Vec<(u32, Vec<u8>)>>>;

struct Car {
    stop: Arc<AtomicBool>,
    seen: Seen,
    thread: Option<JoinHandle<()>>,
}

impl Car {
    // Answers every request it hears, from the A7's simulated modules, as ISO-TP frames.
    fn start() -> Self {
        let socket = side_socket();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen: Seen = Arc::default();
        let thread = {
            let (stop, seen) = (stop.clone(), seen.clone());
            std::thread::spawn(move || run_car(socket, &stop, &seen))
        };
        Self {
            stop,
            seen,
            thread: Some(thread),
        }
    }

    // Every frame the car heard, in order.
    fn heard(&self) -> Vec<(u32, Vec<u8>)> {
        self.seen.lock().unwrap().clone()
    }

    fn stop(mut self) -> Vec<(u32, Vec<u8>)> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        self.heard()
    }
}

impl Drop for Car {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_one(socket: &mut CanSocket) -> Option<(u32, Vec<u8>)> {
    let mut buffer = [0u8; 16];
    match socket.read(&mut buffer) {
        Ok(16) => {
            let id = u32::from_ne_bytes(buffer[..4].try_into().unwrap());
            Some((id, buffer[8..8 + usize::from(buffer[4].min(8))].to_vec()))
        }
        _ => None,
    }
}

fn run_car(mut socket: CanSocket, stop: &AtomicBool, seen: &Seen) {
    let mut car = SimBus::builtin("a7").unwrap();
    while !stop.load(Ordering::SeqCst) {
        let Some((id, data)) = read_one(&mut socket) else {
            continue;
        };
        seen.lock().unwrap().push((id, data.clone()));
        // Only single-frame requests: that is all a T0 read in these tests needs.
        let Ok(Frame::Single(payload)) = Frame::parse(&data, Addressing::Normal) else {
            continue;
        };
        let target = if id == 0x7DF {
            Target::ObdFunctional
        } else {
            Target::Physical(id)
        };
        let Ok(request) = Policy::read_only().approve(Protocol::Uds, target, payload) else {
            continue;
        };
        car.send(&request).unwrap();
        while let Ok(reply) = car.recv(Duration::ZERO) {
            // A module answers at its request ID + 8, and the tester's flow control goes to its
            // physical request ID, which a broadcast request doesn't have.
            answer(
                &mut socket,
                stop,
                seen,
                reply.source - 8,
                reply.source,
                &reply.payload,
            );
        }
    }
}

// Sends one reply as the module would: a single frame, or a first frame, then the consecutive
// frames once the tester's flow control comes.
fn answer(
    socket: &mut CanSocket,
    stop: &AtomicBool,
    seen: &Seen,
    request_id: u32,
    reply_id: u32,
    payload: &[u8],
) {
    let mut segmenter = Segmenter::new(payload, Addressing::Normal).unwrap();
    loop {
        match segmenter.step() {
            Step::Send(data) => {
                let mut padded = [PAD; 8];
                padded[..data.as_bytes().len()].copy_from_slice(data.as_bytes());
                socket.write_all(&raw_frame(reply_id, &padded)).unwrap();
                std::thread::sleep(segmenter.st_min());
            }
            Step::WaitForFlowControl => {
                let until = Instant::now() + Duration::from_secs(1);
                loop {
                    assert!(
                        Instant::now() < until && !stop.load(Ordering::SeqCst),
                        "the tester sent no flow control"
                    );
                    let Some((id, data)) = read_one(socket) else {
                        continue;
                    };
                    seen.lock().unwrap().push((id, data.clone()));
                    if id != request_id {
                        continue;
                    }
                    if let Ok(Frame::FlowControl(fc)) = Frame::parse(&data, Addressing::Normal) {
                        segmenter.flow_control(fc).unwrap();
                        break;
                    }
                }
            }
            Step::Done => return,
            Step::Aborted => panic!("the tester aborted the transfer"),
        }
    }
}

fn obdcracker(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .env("OBDCRACKER_TEST_PORTS", "")
        .args(args)
        .output()
        .unwrap()
}

fn temp_log(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "obdcracker-vcan-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn read_vin_request() -> obdcracker_safety::Approved {
    Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::ObdFunctional,
            &obdcracker_core::obd::vehicle_info(0x02),
        )
        .unwrap()
}

// --- The CLI ---

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn vin_over_vcan_is_answered_by_the_sim_with_flow_control_on_the_wire() {
    let _one = exclusive();
    let car = Car::start();
    let log = temp_log("vin");
    let out = obdcracker(&[
        "--socketcan",
        &interface(),
        "--profile",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    let heard = car.stop();
    assert!(out.status.success(), "{}", lossy(&out.stderr));
    assert_eq!(lossy(&out.stdout), "7E8 WAU2MBFC6EN093415\n");
    // vcan has no bitrate to report, so the profile's can't be confirmed, and the user is told.
    assert!(
        lossy(&out.stderr).contains("reports no bitrate"),
        "{}",
        lossy(&out.stderr)
    );

    // On the wire: the request on the broadcast ID, padded to 8 bytes, then the flow control to
    // the answering module's physical ID, also padded.
    assert_eq!(
        heard[0],
        (0x7DF, vec![0x02, 0x09, 0x02, PAD, PAD, PAD, PAD, PAD])
    );
    assert_eq!(
        heard[1],
        (0x7E0, vec![0x30, 0x00, 0x00, PAD, PAD, PAD, PAD, PAD])
    );
    assert_eq!(heard.len(), 2, "{heard:x?}");

    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""link":"socketcan:vcan0:active""#),
        "{audit}"
    );
    assert!(
        audit.contains(r#""dir":"tx","id":"7DF","payload":"09 02""#),
        "{audit}"
    );
    // What was read from the interface is in the log.
    assert!(audit.contains("interface vcan0: CAN, up"), "{audit}");
    assert!(audit.contains("CAN_RAW_FILTER"), "{audit}");
    // Which path ran: the one the interface allows. The CI job runs vcan both ways (`modprobe
    // vcan echo=1` and without) and says which it set up, so neither can pass by testing only the
    // other.
    let echoes = interface_echoes();
    assert!(
        audit.contains(if echoes {
            "the driver echoes sent frames"
        } else {
            "the driver doesn't echo sent frames"
        }),
        "{audit}"
    );
    if let Ok(expected) = std::env::var("OBDCRACKER_VCAN_ECHO") {
        assert_eq!(expected, if echoes { "yes" } else { "no" });
    }
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn fingerprint_over_vcan_reads_each_module_on_its_physical_id() {
    let _one = exclusive();
    let car = Car::start();
    let log = temp_log("fingerprint");
    let out = obdcracker(&[
        "--socketcan",
        &interface(),
        "--profile",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "fingerprint",
    ]);
    let heard = car.stop();
    assert!(out.status.success(), "{}", lossy(&out.stderr));
    let stdout = lossy(&out.stdout);
    assert!(stdout.contains("CALID"), "{stdout}");
    // Requests only ever went to the broadcast ID and the modules' request IDs, every one of
    // them a whole, padded frame.
    for (id, data) in &heard {
        if data.first().is_some_and(|pci| pci >> 4 == 3) {
            continue;
        }
        assert!(matches!(id, 0x7DF..=0x7E1), "{id:x}");
        assert_eq!(data.len(), 8, "{data:x?}");
    }
    assert!(heard.iter().any(|(id, _)| *id == 0x7E1), "{heard:x?}");
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn a_listen_only_run_over_vcan_puts_nothing_on_the_bus() {
    let _one = exclusive();
    let car = Car::start();
    let log = temp_log("listen-only");
    let out = obdcracker(&[
        "--socketcan",
        &interface(),
        "--listen-only",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    // Give the car time to answer what it should never have been asked.
    std::thread::sleep(Duration::from_millis(100));
    let heard = car.stop();
    assert!(!out.status.success());
    assert!(
        lossy(&out.stderr).contains("listen-only"),
        "{}",
        lossy(&out.stderr)
    );
    // vcan has no controller, so it can't say it is in listen-only mode: the user is told that
    // the tap may still be acknowledged.
    assert!(
        lossy(&out.stderr).contains("still acknowledges"),
        "{}",
        lossy(&out.stderr)
    );
    assert!(heard.is_empty(), "{heard:x?}");
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""link":"socketcan:vcan0:listen-only""#),
        "{audit}"
    );
    assert!(
        audit.contains("acknowledges the frames it receives"),
        "{audit}"
    );
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn an_interface_name_that_is_not_a_can_interface_is_refused_before_any_socket() {
    let _one = exclusive();
    // The loopback interface exists, is up, and is not CAN.
    let out = obdcracker(&["--socketcan", "lo", "vin"]);
    assert!(!out.status.success());
    assert!(
        lossy(&out.stderr).contains("isn't a CAN interface"),
        "{}",
        lossy(&out.stderr)
    );
}

// --- The library ---

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn the_library_reads_the_interface_and_never_writes_to_it() {
    let _one = exclusive();
    let ip_before = interface_state();
    let car = Car::start();
    let mut options = Options::new(interface());
    options.bitrate = Some(500_000);
    let mut session = SocketCan::open(&options).unwrap();
    assert_eq!(session.link_name(), "socketcan:vcan0:active");
    assert_eq!(session.mode(), Mode::Active);
    assert_eq!(session.bitrate_check(), BitrateCheck::Unconfirmed);
    assert_eq!(session.bitrate(), None);
    let replies = exchange(
        &mut session,
        &read_vin_request(),
        Expect::ObdEcus,
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
    // A second request reuses the socket: the filters follow the request.
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E1), &[0x22, 0xF1, 0x87])
        .unwrap();
    let replies = exchange(
        &mut session,
        &request,
        Expect::Module(0x7E9),
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies[0].source, 0x7E9);
    drop(session);
    let heard = car.stop();
    assert!(heard.len() >= 3, "{heard:x?}");
    // Opening, using and closing it left the interface exactly as it was.
    assert_eq!(interface_state(), ip_before);
}

// The interface's flags and MTU, as sysfs gives them.
fn interface_state() -> Vec<String> {
    ["flags", "mtu", "type", "operstate"]
        .iter()
        .map(|file| {
            std::fs::read_to_string(format!("/sys/class/net/{}/{file}", interface())).unwrap()
        })
        .collect()
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn an_error_frame_on_the_bus_latches_the_session() {
    let _one = exclusive();
    let car = Car::start();
    let mut session = SocketCan::open(&Options::new(interface())).unwrap();
    exchange(
        &mut session,
        &read_vin_request(),
        Expect::ObdEcus,
        Timing::default(),
    )
    .unwrap();
    // A bus-off error frame, as a controller would raise it.
    let mut side = side_socket();
    side.write_all(&raw_frame(0x2000_0040, &[0, 0, 0, 0, 0, 0, 0, 0]))
        .expect("the kernel refused an error frame from user space");
    std::thread::sleep(Duration::from_millis(50));
    let err = session.send(&read_vin_request()).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    let sent = car.stop().len();
    // Nothing more goes out after it, and every later call fails the same way.
    assert!(session.send(&read_vin_request()).is_err());
    assert!(session.recv(Duration::from_millis(10)).is_err());
    assert_eq!(sent, 2, "only the first request and its flow control");
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn frames_the_kernel_dropped_are_an_error_not_a_gap() {
    let _one = exclusive();
    let mut session = SocketCan::open(&Options::new(interface())).unwrap();
    // The first request narrows the kernel filter to the engine's replies.
    session.send(&read_vin_request()).unwrap();
    // Far more matching frames than the socket's queue holds, with nobody reading.
    let mut side = side_socket();
    let junk = raw_frame(0x7E8, &[0xFF; 8]);
    for _ in 0..4000 {
        side.write_all(&junk).unwrap();
    }
    // One read skips what is queued until it is empty. The frames that were dropped are gone, and
    // none of the ones left carries the news: the socket's drop counter rides on the next frame
    // that is queued after a loss.
    match session.recv(Duration::from_millis(100)) {
        Ok(reply) => panic!("junk read as a reply: {reply:?}"),
        Err(Error::Timeout) => {}
        Err(e) => {
            assert!(e.to_string().contains("dropped received frames"), "{e}");
            return;
        }
    }
    side.write_all(&junk).unwrap();
    let err = session.recv(Duration::from_secs(2)).unwrap_err();
    assert!(err.to_string().contains("dropped received frames"), "{err}");
}

// IFF_ECHO, from the interface flags sysfs prints.
fn interface_echoes() -> bool {
    let flags = std::fs::read_to_string(format!("/sys/class/net/{}/flags", interface())).unwrap();
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
    flags & 0x4_0000 != 0
}

// --- VW TP2.0 (#259) ---

// A VW TP2.0 module at address 1, written out frame by frame here and not taken from the sim, so
// what the tester sends is checked against a second reading of the layouts (docs/tp20.md). It
// answers on a channel it opens: the module sends on 0x300 and listens on 0x740 (the passenger
// door's answer in session 6), and every frame it sends is as long as the layout says.
fn run_tp20_car(mut socket: CanSocket, stop: &AtomicBool, seen: &Seen) {
    let send = |socket: &mut CanSocket, id: u32, data: &[u8]| {
        socket.write_all(&raw_frame(id, data)).unwrap();
    };
    while !stop.load(Ordering::SeqCst) {
        let Some((id, data)) = read_one(&mut socket) else {
            continue;
        };
        seen.lock().unwrap().push((id, data.clone()));
        match (id, data.as_slice()) {
            (0x200, [0x01, 0xC0, ..]) => {
                send(
                    &mut socket,
                    0x201,
                    &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01],
                );
            }
            (0x740, [0xA0, ..] | [0xA3]) => {
                send(&mut socket, 0x300, &[0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]);
            }
            (0x740, [0xA8]) => send(&mut socket, 0x300, &[0xA8]),
            // The identification request in one data frame (sequence 0, last, ACK wanted): the
            // module ACKs it, then answers `5A 9B 01 02` in one frame.
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => {
                send(&mut socket, 0x300, &[0xB1]);
                send(
                    &mut socket,
                    0x300,
                    &[0x10, 0x00, 0x04, 0x5A, 0x9B, 0x01, 0x02],
                );
            }
            _ => {}
        }
    }
}

struct Tp20Car {
    stop: Arc<AtomicBool>,
    seen: Seen,
    thread: Option<JoinHandle<()>>,
}

impl Tp20Car {
    fn start() -> Self {
        let socket = side_socket();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen: Seen = Arc::default();
        let thread = {
            let (stop, seen) = (stop.clone(), seen.clone());
            std::thread::spawn(move || run_tp20_car(socket, &stop, &seen))
        };
        Self {
            stop,
            seen,
            thread: Some(thread),
        }
    }

    fn stop(mut self) -> Vec<(u32, Vec<u8>)> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Tp20Car {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn a_tp20_session_over_vcan_puts_every_frame_on_the_bus_at_its_own_length() {
    let _one = exclusive();
    let car = Tp20Car::start();
    let mut session = SocketCan::open(&Options::new(interface())).unwrap();
    let policy = Policy::read_only().narrowed_to_tp20(&[0x01]);
    // A generous wait: the CI runner is slow, and what is checked is the frames.
    let timing = Timing {
        p2: Duration::from_millis(500),
        ..Timing::default()
    };
    let mut channel = ChannelSession::open(&mut session, &policy, 0x01, timing).unwrap();
    assert_eq!(
        channel.request(&[0x1A, 0x9B]).unwrap(),
        [0x5A, 0x9B, 0x01, 0x02]
    );
    assert_eq!(channel.close(), Ok(Disconnect::Closed));
    drop(session);
    let heard = car.stop();
    // The kernel took each frame at the DLC it was sent with, whether the interface echoes
    // (`vcan echo=1`) or the transmit counter confirmed it: the setup 7 bytes, the parameters 6,
    // the request 5, the ACK of the answer 1 and the disconnect 1, none padded.
    assert_eq!(
        heard,
        [
            (0x200, vec![0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
            (0x740, vec![0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]),
            (0x740, vec![0x10, 0x00, 0x02, 0x1A, 0x9B]),
            (0x740, vec![0xB1]),
            (0x740, vec![0xA8]),
        ]
    );
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn tp20_discovery_over_vcan_finds_the_module_and_closes_its_channel() {
    let _one = exclusive();
    let car = Tp20Car::start();
    let mut session = SocketCan::open(&Options::new(interface())).unwrap();
    let policy = Policy::read_only().narrowed_to_tp20(&[0x01, 0x02]);
    let timing = Timing {
        p2: Duration::from_millis(500),
        ..Timing::default()
    };
    let found = tp20::probe(&mut session, &policy, &[0x01, 0x02], timing).unwrap();
    drop(session);
    let heard = car.stop();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].address, 0x01);
    assert!(matches!(found[0].answer, Answer::Channel(_)));
    assert_eq!(found[0].disconnect, Some(Disconnect::Closed));
    // The silent address got its setup too, at the same length.
    assert_eq!(
        heard,
        [
            (0x200, vec![0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
            (0x740, vec![0xA8]),
            (0x200, vec![0x02, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
        ]
    );
}

#[test]
#[ignore = "needs the vcan0 interface: the vcan CI job runs it with --ignored"]
fn a_listen_only_session_over_vcan_puts_no_tp2_0_frame_on_the_bus() {
    let _one = exclusive();
    let car = Tp20Car::start();
    let mut options = Options::new(interface());
    options.mode = Mode::ListenOnly;
    let mut session = SocketCan::open(&options).unwrap();
    let policy = Policy::read_only().narrowed_to_tp20(&[0x01]);
    let err = tp20::probe(&mut session, &policy, &[0x01], Timing::default()).unwrap_err();
    assert!(err.to_string().contains("listen-only"), "{err}");
    assert!(
        ChannelSession::open(&mut session, &policy, 0x01, Timing::default()).is_err(),
        "no channel without a setup on the bus"
    );
    drop(session);
    std::thread::sleep(Duration::from_millis(100));
    let heard = car.stop();
    assert!(heard.is_empty(), "{heard:x?}");
}
