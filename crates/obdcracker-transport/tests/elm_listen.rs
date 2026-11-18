//! The ELM327 driver listening to the bus (`Listen`, #104): silent, in a fixed order, and with
//! the driver as it was for the next request.

mod support;

use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use obdcracker_safety::{Approved, Policy, Protocol, Target};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::{Audited, Error, Heard, Listen, ListenEnd, ListenFilter, Transport};
use proptest::prelude::*;
use support::fake_elm::{FakeElm, FakeLink};

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";
const MS: Duration = Duration::from_millis(1);

fn filter(pattern: &str) -> ListenFilter {
    pattern.parse().unwrap()
}

// An STN or a plain ELM327 on a bus where other nodes acknowledge, with these frames on it once
// it monitors. Module 7E0 answers mode 09 PID 02.
fn bus(stn: bool, traffic: Vec<(Duration, u32, Vec<u8>)>) -> FakeElm {
    let mut car = FakeElm::new(Box::new(|header, request| {
        if header == 0x7E0 && request == [0x09, 0x02] {
            vec![(0x7E8, VIN.to_vec())]
        } else {
            Vec::new()
        }
    }))
    .with_traffic(traffic);
    car.two_node_bus = false;
    if stn {
        car.sti = Some("STN2232 v5.12.4".into());
    }
    car
}

fn traffic() -> Vec<(Duration, u32, Vec<u8>)> {
    vec![
        (5 * MS, 0x7E8, vec![0x03, 0x41, 0x0C, 0x1A]),
        (10 * MS, 0x6F1, vec![0x02, 0x10, 0x03]),
        (15 * MS, 0x7E9, vec![0x10, 0x14, 0x62, 0xF1, 0x87]),
    ]
}

fn connect(car: FakeElm) -> Elm<FakeLink> {
    Elm::connect(FakeLink::new(car)).unwrap()
}

fn commands(elm: &Elm<FakeLink>) -> &[String] {
    &elm.link().elm.commands
}

fn approve(target: Target, payload: &[u8]) -> Approved {
    Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap()
}

// Listens for `wait` and returns how it ended and every frame heard.
fn listen_for<T: Listen>(
    transport: &mut T,
    pattern: &str,
    wait: Duration,
) -> (Result<ListenEnd, Error>, Vec<Heard>) {
    let mut heard = Vec::new();
    let end = transport.listen(&filter(pattern), wait, &mut |frame| {
        heard.push(frame.clone());
        Ok(ControlFlow::Continue(()))
    });
    (end, heard)
}

fn read_vin(elm: &mut Elm<FakeLink>) {
    elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
        .unwrap();
    while elm.recv(Duration::from_secs(1)).is_ok() {}
}

// Every write on the link is an adapter command, a carriage return or the stop character: never
// a line of hex digits, which an ELM327 sends to the bus.
fn assert_nothing_for_the_bus(elm: &Elm<FakeLink>) {
    for write in &elm.link().writes {
        let text = String::from_utf8_lossy(write);
        let line = text.trim_end_matches('\r');
        assert!(
            line.is_empty() || line.bytes().any(|b| !b.is_ascii_hexdigit() && b != b' '),
            "{text:?} could be a bus request"
        );
    }
    assert_eq!(elm.link().elm.sent, []);
}

mod order {
    use super::*;

    #[test]
    fn an_stn_is_made_silent_first_then_filtered_then_monitored_then_stopped() {
        let mut elm = connect(bus(true, traffic()));
        let before = commands(&elm).len();
        let (end, heard) = listen_for(&mut elm, "7EX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(
            commands(&elm)[before..],
            [
                "STCMM0", "ATCFC0", "ATV1", "ATCAF0", "ATAT0", "ATCRA7EX", "STM", "ATCAF1", "ATV0",
                "ATCFC1", "STCMM0", "ATAT1"
            ]
        );
        // `X` stops the monitor, right after `STM`'s carriage return and before anything else.
        let writes = &elm.link().writes;
        let monitor = writes.iter().position(|w| w == b"STM").unwrap();
        assert_eq!(writes[monitor + 1], b"\r");
        assert_eq!(writes[monitor + 2], b"X");
        assert_eq!(elm.link().elm.interrupted, 1);
        assert_nothing_for_the_bus(&elm);
        let heard: Vec<_> = heard.iter().map(|f| (f.id, f.data.clone())).collect();
        assert_eq!(
            heard,
            [
                (0x7E8, vec![0x03, 0x41, 0x0C, 0x1A]),
                (0x7E9, vec![0x10, 0x14, 0x62, 0xF1, 0x87])
            ],
            "0x6F1 is outside the filter"
        );
    }

    #[test]
    fn a_plain_elm_uses_atcsm1_and_atma() {
        let mut elm = connect(bus(false, traffic()));
        let before = commands(&elm).len();
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(
            commands(&elm)[before..],
            [
                "ATCSM1", "ATCFC0", "ATV1", "ATCAF0", "ATMA", "ATCAF1", "ATV0", "ATCFC1", "ATCSM1"
            ]
        );
        // The setup left the filter at 7XX, and the driver knows it.
        assert_eq!(heard.len(), 2);
        assert_nothing_for_the_bus(&elm);
    }

    #[test]
    fn the_commands_a_dry_run_names_are_the_ones_a_listen_writes() {
        for (stn, pattern) in [
            (false, "7E8"),
            (true, "7E8"),
            (false, "18DAF1XX"),
            (true, "18DAF1XX"),
        ] {
            let mut elm = connect(bus(stn, Vec::new()));
            let before = commands(&elm).len();
            listen_for(&mut elm, pattern, MS).0.unwrap();
            // Adaptive timing follows the mode switches on an STN that isn't paced.
            let written: Vec<_> = commands(&elm)[before..]
                .iter()
                .filter(|c| !c.starts_with("ATAT"))
                .cloned()
                .collect();
            let named: Vec<_> = obdcracker_transport::elm::listen_commands(stn, &filter(pattern))
                .into_iter()
                .filter(|c| c != "X")
                .collect();
            assert_eq!(written, named, "{stn} {pattern}");
        }
    }

    #[test]
    fn the_first_command_of_a_connection_is_the_silent_setting() {
        // A fresh process has not shown that the adapter echoes each character; the silent
        // setting is what shows it, with nothing on the bus.
        let mut elm = connect(bus(true, traffic()));
        let before = commands(&elm).len();
        let _ = listen_for(&mut elm, "7XX", MS);
        assert_eq!(commands(&elm)[before], "STCMM0");
    }

    #[test]
    fn frames_carry_their_width_and_time() {
        let mut elm = connect(bus(
            false,
            vec![(20 * MS, 0x17FE_0076, vec![0x03, 0x62, 0xF1, 0x87])],
        ));
        let (end, heard) = listen_for(&mut elm, "17FE00XX", Duration::from_millis(200));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 1);
        assert!(heard[0].extended);
        assert_eq!(heard[0].id, 0x17FE_0076);
        assert!(heard[0].elapsed >= 15 * MS, "{:?}", heard[0].elapsed);
    }
}

mod refusals {
    use super::*;

    #[test]
    fn a_refused_silent_setting_stops_before_anything_else_is_sent() {
        for (stn, silent) in [(true, "STCMM0"), (false, "ATCSM1")] {
            let mut car = bus(stn, traffic());
            car.unsupported.push(silent.to_owned());
            let mut elm = connect(car);
            let before = commands(&elm).len();
            let err = listen_for(&mut elm, "7XX", 50 * MS).0.unwrap_err();
            assert!(err.to_string().contains(silent), "{err}");
            assert_eq!(commands(&elm)[before..], [silent]);
            assert!(
                !elm.link()
                    .writes
                    .iter()
                    .any(|w| w == b"STM" || w == b"ATMA")
            );
            // Failed closed: nothing more reaches the adapter.
            let writes = elm.link().writes.len();
            assert!(listen_for(&mut elm, "7XX", MS).0.is_err());
            assert!(
                elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                    .is_err()
            );
            assert_eq!(elm.link().writes.len(), writes);
        }
    }

    #[test]
    fn a_clone_that_says_ok_but_acknowledges_gets_can_error_instead_of_frames() {
        // Behind a gateway the adapter is one of two nodes: its silent monitor leaves the
        // module's frame unacknowledged, which the adapter reports as CAN ERROR (#301). The
        // listen fails with that and sends nothing.
        let mut car = bus(true, traffic());
        car.two_node_bus = true;
        let mut elm = connect(car);
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_millis(200));
        let err = end.unwrap_err();
        assert!(err.to_string().contains("CAN ERROR"), "{err}");
        assert_eq!(heard, []);
        assert_nothing_for_the_bus(&elm);
    }

    #[test]
    fn an_adapter_that_does_not_echo_each_character_is_refused_before_the_bus_is_touched() {
        let mut car = bus(true, traffic());
        car.echo_at_line_end = true;
        let mut elm = connect(car);
        let err = listen_for(&mut elm, "7XX", 50 * MS).0.unwrap_err();
        assert!(err.to_string().contains("echo"), "{err}");
        assert!(!elm.link().writes.iter().any(|w| w == b"STM"));
        assert_nothing_for_the_bus(&elm);
    }

    #[test]
    fn buffer_full_fails_the_listen_after_stopping_it_and_the_driver_goes_on() {
        let mut elm = connect(bus(true, Vec::new()));
        read_vin(&mut elm);
        let sent = elm.link().elm.sent.len();
        elm.link_mut()
            .scheduled
            .push_back((Instant::now() + 100 * MS, b"BUFFER FULL\r".to_vec()));
        let (end, _) = listen_for(&mut elm, "7XX", Duration::from_secs(2));
        let err = end.unwrap_err();
        assert!(err.to_string().contains("BUFFER FULL"), "{err}");
        assert!(err.to_string().contains("filter"), "{err}");
        assert_eq!(elm.link().elm.interrupted, 1, "the monitor was stopped");
        assert_eq!(elm.link().elm.sent.len(), sent);
        // The adapter is back at its prompt, and a request works.
        read_vin(&mut elm);
        assert_eq!(elm.link().elm.sent.len(), sent + 1);
    }

    #[test]
    fn a_prompt_the_adapter_prints_by_itself_means_it_stopped_and_fails_it_closed() {
        let mut elm = connect(bus(true, Vec::new()));
        elm.link_mut()
            .scheduled
            .push_back((Instant::now() + 100 * MS, b"\r>".to_vec()));
        let err = listen_for(&mut elm, "7XX", Duration::from_secs(2))
            .0
            .unwrap_err();
        assert!(err.to_string().contains("on its own"), "{err}");
        let writes = elm.link().writes.len();
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().writes.len(), writes);
    }

    #[test]
    fn a_line_that_is_not_a_frame_is_unexpected_output_and_not_decoded() {
        let mut elm = connect(bus(true, Vec::new()));
        elm.link_mut()
            .scheduled
            .push_back((Instant::now() + 100 * MS, b"7E8 03 41 ZZ\r".to_vec()));
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_secs(2));
        assert!(end.unwrap_err().to_string().contains("unexpected output"));
        assert_eq!(heard, []);
    }

    #[test]
    fn an_error_frame_is_reported_in_the_log_and_the_listen_goes_on() {
        let mut elm = connect(bus(true, traffic()));
        elm.link_mut().scheduled.push_back((
            Instant::now() + 80 * MS,
            b"7E8 03 41 0C <DATA ERROR\r".to_vec(),
        ));
        let (end, heard) = listen_for(&mut elm, "XXX", Duration::from_millis(400));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 3);
        let lines: Vec<_> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                obdcracker_transport::LinkEvent::Status { line, .. } => Some(line),
                _ => None,
            })
            .collect();
        assert!(lines.iter().any(|l| l.contains("DATA ERROR")), "{lines:?}");
    }
}

mod ending {
    use super::*;

    #[test]
    fn a_zero_wait_starts_and_stops_the_monitor_and_hears_nothing() {
        let mut elm = connect(bus(true, traffic()));
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::ZERO);
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard, []);
        assert_eq!(elm.link().elm.interrupted, 1);
        assert_nothing_for_the_bus(&elm);
    }

    #[test]
    fn a_quiet_bus_ends_at_the_deadline() {
        let mut elm = connect(bus(true, Vec::new()));
        let started = Instant::now();
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_millis(150));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard, []);
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_bus_that_never_stops_ends_at_the_deadline_too() {
        // 30000 frames 10 us apart would take 300 ms to arrive; the listen ends at 100 ms.
        let frames = (0..30_000)
            .map(|i| {
                (
                    Duration::from_micros(10 * i),
                    0x7E8,
                    vec![0x03, 0x41, 0x0C, 0x1A],
                )
            })
            .collect();
        let mut elm = connect(bus(true, frames));
        let started = Instant::now();
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(!heard.is_empty() && heard.len() < 30_000, "{}", heard.len());
        assert_eq!(elm.link().elm.interrupted, 1);
    }

    #[test]
    fn the_callback_stops_the_listen() {
        let mut elm = connect(bus(true, traffic()));
        let mut count = 0;
        let started = Instant::now();
        let end = elm.listen(&filter("7XX"), Duration::from_secs(30), &mut |_| {
            count += 1;
            Ok(if count == 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        });
        assert_eq!(end, Ok(ListenEnd::Stopped));
        assert_eq!(count, 2);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(elm.link().elm.interrupted, 1);
    }

    #[test]
    fn a_callback_error_stops_the_listen_and_comes_back() {
        let mut elm = connect(bus(true, traffic()));
        let end = elm.listen(&filter("7XX"), Duration::from_secs(30), &mut |_| {
            Err(Error::Adapter("log is full".into()))
        });
        assert_eq!(end, Err(Error::Adapter("log is full".into())));
        assert_eq!(elm.link().elm.interrupted, 1);
        // Back at its prompt: usable.
        read_vin(&mut elm);
    }
}

mod afterwards {
    use super::*;

    #[test]
    fn a_request_after_the_monitor_sets_its_own_filter_and_gets_its_reply() {
        for stn in [true, false] {
            let mut elm = connect(bus(stn, traffic()));
            read_vin(&mut elm);
            let (end, _) = listen_for(&mut elm, "7EX", Duration::from_millis(100));
            assert_eq!(end, Ok(ListenEnd::Deadline));
            let before = commands(&elm).len();
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .unwrap();
            let reply = elm.recv(Duration::from_secs(1)).unwrap();
            assert_eq!((reply.source, reply.payload), (0x7E8, VIN.to_vec()));
            // The monitor's filter was in effect; the request puts its own back.
            assert_eq!(commands(&elm)[before], "ATCRA7E8", "{stn}");
            let settings = &elm.link().elm.settings;
            assert!(
                settings.caf && settings.cfc && !settings.variable_dlc,
                "{stn}"
            );
            assert!(!settings.monitor_ack, "{stn}");
        }
    }

    #[test]
    fn a_filter_the_next_request_wants_too_is_not_sent_again() {
        let mut elm = connect(bus(true, Vec::new()));
        read_vin(&mut elm);
        // The request's filter is 7E8; the monitor sets it and the cache says so.
        listen_for(&mut elm, "7E8", 10 * MS).0.unwrap();
        let before = commands(&elm).len();
        read_vin(&mut elm);
        assert!(!commands(&elm)[before..].contains(&"ATCRA7E8".to_owned()));
        assert_eq!(elm.link().elm.settings.cra.as_deref(), Some("7E8"));
    }

    #[test]
    fn a_29_bit_filter_switches_the_protocol_and_the_next_11_bit_request_switches_back() {
        let mut elm = connect(bus(false, Vec::new()));
        read_vin(&mut elm);
        let before = commands(&elm).len();
        listen_for(&mut elm, "18DAF1XX", 10 * MS).0.unwrap();
        let log = commands(&elm)[before..].to_vec();
        let width = log.iter().position(|c| c == "ATSP7").unwrap();
        let filter = log.iter().position(|c| c == "ATCRA18DAF1XX").unwrap();
        assert!(width < filter, "{log:?}");
        let before = commands(&elm).len();
        read_vin(&mut elm);
        let log = &commands(&elm)[before..];
        assert!(log.contains(&"ATSP6".to_owned()), "{log:?}");
        assert!(log.contains(&"ATCRA7E8".to_owned()), "{log:?}");
    }

    // A 29-bit ID with an 11-bit value prints as four header bytes, and is still not the 11-bit
    // ID (#104).
    #[test]
    fn a_29_bit_filter_hears_ids_whose_value_fits_in_11_bits() {
        let frames = vec![
            (5 * MS, 0x123, vec![0x01, 0x02]),
            (10 * MS, 0x7E8, vec![0x03]),
        ];
        let mut elm = connect(bus(true, frames));
        let (end, heard) = listen_for(&mut elm, "00000123", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        let heard: Vec<_> = heard.iter().map(|f| (f.id, f.extended)).collect();
        assert_eq!(heard, [(0x123, true)]);
        let mut elm = connect(bus(true, vec![(5 * MS, 0x123, vec![0x01])]));
        let (end, heard) = listen_for(&mut elm, "000001XX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 1);
        assert!(heard[0].extended);
    }

    #[test]
    fn a_listen_after_a_request_still_running_waits_for_it() {
        let mut elm = connect(bus(true, traffic()));
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        // Never received: the listen finishes it first.
        let (end, heard) = listen_for(&mut elm, "XXX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 3);
    }

    #[test]
    fn a_tp20_session_left_open_is_left_and_the_driver_is_as_after_leaving_it() {
        let mut elm = connect(bus(true, traffic()));
        read_vin(&mut elm);
        elm.send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
            .unwrap();
        while elm.recv(Duration::from_millis(200)).is_ok() {}
        let before = commands(&elm).len();
        let sent = elm.link().elm.sent.len();
        let (end, heard) = listen_for(&mut elm, "XXX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 3);
        let log = &commands(&elm)[before..];
        // Raw mode was already on, so only the silent setting comes before the filter.
        assert_eq!(log[0], "STCMM0", "{log:?}");
        assert!(!log.contains(&"STCMM1".to_owned()), "{log:?}");
        let settings = &elm.link().elm.settings;
        assert!(settings.caf && settings.cfc && !settings.variable_dlc && !settings.monitor_ack);
        assert_eq!(elm.link().elm.sent.len(), sent, "the listen sent a frame");
    }
}

mod audited {
    use super::*;

    #[test]
    fn the_log_has_the_commands_and_every_frame_heard() {
        let path = std::env::temp_dir().join(format!(
            "obdcracker-elm-listen-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut elm = Audited::open(&path, connect(bus(true, traffic())), "usb-serial").unwrap();
        let (end, heard) = listen_for(&mut elm, "XXX", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 3);
        drop(elm);
        let log = std::fs::read_to_string(&path).unwrap();
        // Commands are logged after the listen with their own times, so order by those.
        let entries: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let time = |key: &str, value: &str| {
            entries
                .iter()
                .find(|e| e[key] == value)
                .unwrap_or_else(|| panic!("{key}={value} not in {log}"))["ts_ms"]
                .as_u64()
                .unwrap()
        };
        for (id, payload) in [
            ("7E8", "03 41 0C 1A"),
            ("6F1", "02 10 03"),
            ("7E9", "10 14 62 F1 87"),
        ] {
            assert!(
                entries
                    .iter()
                    .any(|e| e["dir"] == "heard" && e["id"] == id && e["payload"] == payload),
                "{id} not in {log}"
            );
        }
        assert!(time("cmd", "STCMM0") <= time("cmd", "ATCRAXXX"));
        assert!(time("cmd", "ATCRAXXX") <= time("cmd", "STM"));
        assert!(time("cmd", "STM") <= time("dir", "heard"));
        // Nothing the log calls a request.
        assert!(!log.contains(r#""dir":"tx""#), "{log}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_29_bit_id_with_a_small_value_is_logged_in_8_digits() {
        let path = std::env::temp_dir().join(format!(
            "obdcracker-elm-listen-wide-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let frames = vec![(5 * MS, 0x123, vec![0x01])];
        let mut elm = Audited::open(&path, connect(bus(true, frames)), "usb-serial").unwrap();
        let (end, heard) = listen_for(&mut elm, "00000123", Duration::from_millis(100));
        assert_eq!(end, Ok(ListenEnd::Deadline));
        assert_eq!(heard.len(), 1);
        drop(elm);
        let log = std::fs::read_to_string(&path).unwrap();
        assert!(log.contains(r#""dir":"heard","id":"00000123""#), "{log}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_unwritable_log_stops_the_listen() {
        let path = std::env::temp_dir().join(format!(
            "obdcracker-elm-listen-full-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut elm = Audited::open(&path, connect(bus(true, traffic())), "usb-serial").unwrap();
        // The callback's own error comes back through the wrapper.
        let end = elm.listen(&filter("7XX"), Duration::from_secs(30), &mut |_| {
            Err(Error::Adapter("stop".into()))
        });
        assert_eq!(end, Err(Error::Adapter("stop".into())));
        let log = std::fs::read_to_string(&path).unwrap();
        // The frame was logged before the callback saw it.
        assert!(log.contains(r#""dir":"heard""#), "{log}");
        std::fs::remove_file(&path).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn whatever_the_adapter_prints_while_monitoring_never_panics_or_hangs(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..60), 0..6),
        stn in any::<bool>(),
    ) {
        let mut elm = connect(bus(stn, traffic()));
        for (i, chunk) in chunks.into_iter().enumerate() {
            elm.link_mut().scheduled.push_back((
                Instant::now() + Duration::from_millis(3 * (i as u64 + 1)),
                chunk,
            ));
        }
        let started = Instant::now();
        let (end, heard) = listen_for(&mut elm, "7XX", Duration::from_millis(60));
        prop_assert!(started.elapsed() < Duration::from_secs(20));
        for frame in &heard {
            prop_assert!(!frame.data.is_empty() && frame.data.len() <= 8);
        }
        // A frame is never sent, whatever came back.
        prop_assert_eq!(&elm.link().elm.sent, &Vec::<(u32, Vec<u8>)>::new());
        let _ = end;
    }
}
