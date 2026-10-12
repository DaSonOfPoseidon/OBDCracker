//! The ELM327 driver against a fake adapter: setup, requests, replies, and adapters that misbehave.

mod support;

use std::io;
use std::time::{Duration, Instant};

use obdcracker_safety::{Approved, ModuleIds, Policy, Target};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::link::{Driver, Link, LinkKind};
use obdcracker_transport::{Audited, Error, Expect, Response, Transport, exchange};
use support::fake_elm::{BANNER, FakeElm, FakeLink};

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";

// The A7's gateway and instruments, as its profile gives them.
const GATEWAY: ModuleIds = ModuleIds {
    request: 0x710,
    reply: 0x77A,
};
const INSTRUMENTS: ModuleIds = ModuleIds {
    request: 0x714,
    reply: 0x77E,
};

fn approve(target: Target, payload: &[u8]) -> Approved {
    Policy::read_only().approve(target, payload).unwrap()
}

fn connect(elm: FakeElm) -> Elm<FakeLink> {
    Elm::connect(FakeLink::new(elm)).unwrap()
}

// An adapter whose engine ECU (7E0/7E8) answers mode 09 PID 02 with a VIN, and whose second
// ECU (7E9) answers broadcasts with the same VIN.
fn car() -> FakeElm {
    FakeElm::new(Box::new(|header, request| {
        if request != [0x09, 0x02] {
            return Vec::new();
        }
        match header {
            0x7DF => vec![(0x7E8, VIN.to_vec()), (0x7E9, VIN.to_vec())],
            0x7E0 => vec![(0x7E8, VIN.to_vec())],
            _ => Vec::new(),
        }
    }))
}

// Connected to `car()`, with the header and flow control already set for broadcasts, so the
// next broadcast writes only the request.
fn broadcasting() -> Elm<FakeLink> {
    let mut elm = connect(car());
    elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
        .unwrap();
    while elm.recv(Duration::from_secs(1)).is_ok() {}
    elm
}

fn commands(elm: &Elm<FakeLink>) -> &[String] {
    &elm.link().elm.commands
}

mod setup {
    use super::*;

    #[test]
    fn runs_the_fixed_setup_script() {
        let elm = connect(FakeElm::silent());
        assert_eq!(
            commands(&elm),
            [
                "ATZ", "ATPPS", "ATL0", "ATS1", "ATH1", "ATSP6", "ATR1", "ATCRA7XX", "ATAT1",
                "ATSTFF", "STI"
            ]
        );
        let settings = &elm.link().elm.settings;
        assert!(settings.echo && settings.headers && settings.spaces && !settings.linefeeds);
        assert_eq!(settings.protocol.as_deref(), Some("6"));
        assert!(
            elm.link().elm.sent.is_empty(),
            "setup put a frame on the bus"
        );
    }

    // Every line the driver writes other than a request: the reset, the setup, `info`, and the
    // header and flow control settings for each kind of target, on a plain ELM327 (paced) and
    // on an STN (not).
    fn every_command() -> Vec<String> {
        let mut stn = car();
        stn.sti = Some("STN2232 v5.12.4".into());
        let mut all = commands_for(car());
        all.extend(commands_for(stn));
        all
    }

    fn commands_for(adapter: FakeElm) -> Vec<String> {
        let mut elm = connect(adapter);
        elm.info().unwrap();
        for target in [
            Target::ObdFunctional,
            Target::Physical(0x7E0),
            Target::Physical(0x714),
            Target::Physical(0x7E1),
        ] {
            elm.send(&approve(target, &[0x09, 0x02])).unwrap();
            while elm.recv(Duration::from_secs(1)).is_ok() {}
        }
        // A module whose reply ID a profile gives
        let narrowed = Policy::read_only().narrowed_to(&[INSTRUMENTS]).unwrap();
        elm.send(
            &narrowed
                .approve(Target::Physical(0x714), &[0x22, 0xF1, 0x87])
                .unwrap(),
        )
        .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        commands(&elm)
            .iter()
            .filter(|c| !c.bytes().all(|b| b.is_ascii_hexdigit()))
            .cloned()
            .collect()
    }

    #[test]
    fn no_single_bit_error_turns_a_command_into_a_bus_request() {
        // An ELM327 sends any line of hex digits to the bus, ignoring spaces and control
        // characters, so a bit flipped on a serial line must never leave one. A flipped carriage
        // return joins the command to the next line.
        let commands = every_command();
        for expected in [
            "ATZ",
            "ATPPS",
            "STI",
            "ATSH714",
            "ATFCSD300000",
            "ATFCSD300003",
            "ATFCSD300015",
            "ATFCSM1",
            "ATFCSM2",
            "ATFCSM0",
            "ATCRA7EX",
            "ATCRA7E8",
            "ATCRA77E",
        ] {
            assert!(
                commands.iter().any(|c| c == expected),
                "{expected}: {commands:?}"
            );
        }
        for command in &commands {
            let line = format!("{command}\r");
            for index in 0..line.len() {
                for bit in 0..8 {
                    let mut bytes = line.clone().into_bytes();
                    bytes[index] ^= 1 << bit;
                    bytes.extend(b"ATI\r");
                    let mut elm = FakeElm::silent();
                    elm.settings.protocol = Some("6".into());
                    // One byte at a time, reading everything, so nothing counts as an interrupt.
                    for byte in bytes {
                        elm.write(&[byte]);
                        elm.read(usize::MAX);
                    }
                    assert_eq!(
                        elm.sent,
                        [],
                        "{command} with bit {bit} of byte {index} flipped"
                    );
                }
            }
        }
    }

    #[test]
    fn fails_closed_on_an_adapter_that_doesnt_echo() {
        // The echo is how the driver knows the adapter heard what it wrote.
        for pps in [true, false] {
            let mut elm = FakeElm::silent();
            elm.pp.push((0x09, 0xFF));
            if !pps {
                elm.unsupported.push("ATPPS".into());
            }
            let err = Elm::connect(FakeLink::new(elm)).unwrap_err();
            assert!(err.to_string().contains("echo"), "{err}");
        }
    }

    #[test]
    fn fails_closed_when_a_programmable_parameter_changes_a_default_it_relies_on() {
        // CAN auto formatting and flow control are on, and the data length isn't shown, after a
        // reset unless PP 24, 25 or 29 says otherwise; the setup doesn't send the commands for
        // them.
        // PP 29 would put the data length between the CAN ID and the data of every frame.
        for (pp, value) in [(0x24, 0xFF), (0x25, 0xFF), (0x29, 0x00)] {
            let mut elm = FakeElm::silent();
            elm.pp.push((pp, value));
            let err = Elm::connect(FakeLink::new(elm)).unwrap_err();
            assert!(err.to_string().contains(&format!("PP {pp:02X}")), "{err}");
        }
    }

    #[test]
    fn accepts_programmable_parameters_that_keep_the_defaults_it_relies_on() {
        let mut elm = FakeElm::silent();
        // PP 01 turns headers on by default, which the setup does anyway.
        elm.pp = vec![
            (0x01, 0x00),
            (0x09, 0x00),
            (0x24, 0x00),
            (0x25, 0x00),
            (0x29, 0xFF),
        ];
        connect(elm);
        // A clone without programmable parameters is at the factory defaults.
        let mut clone = FakeElm::silent();
        clone.unsupported.push("ATPPS".into());
        connect(clone);
    }

    #[test]
    fn fails_closed_on_a_parameter_summary_it_cant_read() {
        for pps in [
            vec!["OK".to_owned()],
            vec!["24:FF".to_owned()],
            vec!["24:FF X".to_owned()],
            vec!["24 FF N".to_owned()],
            vec!["24:F N".to_owned()],
            vec!["24:00 N  24:FF N".to_owned()],
            vec!["124:00 N".to_owned()],
            vec!["+4:FF N".to_owned()],
            // Cut short: every version with PPS lists the parameters the driver relies on.
            vec!["00:FF F  01:FF F  02:FF F  03:32 F".to_owned()],
            vec![],
            vec!["24:+F N".to_owned()],
        ] {
            let mut elm = FakeElm::silent();
            elm.pps = Some(pps.clone());
            let err = Elm::connect(FakeLink::new(elm)).unwrap_err();
            assert!(err.to_string().contains("ATPPS"), "{pps:?}: {err}");
        }
    }

    #[test]
    fn never_sends_a_bare_carriage_return() {
        // A bare carriage return repeats the last command, which could be another program's.
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(elm.link().elm.repeats, 0);
        assert!(!elm.link().written.starts_with(b"\r"));
        assert!(!elm.link().written.windows(2).any(|w| w == b"\r\r"));
    }

    #[test]
    fn fails_closed_when_the_adapter_lacks_a_setup_command() {
        for missing in ["ATSP6", "ATH1", "ATCRA7XX", "ATSTFF"] {
            let mut elm = FakeElm::silent();
            elm.unsupported.push(missing.to_owned());
            let err = Elm::connect(FakeLink::new(elm)).unwrap_err();
            assert!(err.to_string().contains(missing), "{missing}: {err}");
        }
    }

    #[test]
    fn records_the_banner_and_identifies_an_stn() {
        let mut elm = connect(FakeElm::silent());
        let info = elm.info().unwrap();
        assert_eq!(info.id, BANNER);
        assert_eq!(info.stn, None);
        assert_eq!(info.voltage.as_deref(), Some("12.6V"));

        let mut stn = FakeElm::silent();
        stn.sti = Some("STN1155 v5.6.19".into());
        let info = connect(stn).info().unwrap();
        assert_eq!(info.stn.as_deref(), Some("STN1155 v5.6.19"));

        // A clone that answers STI with nothing at all, or with anything but an STN's name,
        // isn't an STN.
        for answer in ["", "OK", "v1.5"] {
            let mut clone = FakeElm::silent();
            clone.sti = Some(answer.into());
            assert_eq!(connect(clone).info().unwrap().stn, None, "{answer:?}");
        }
    }

    #[test]
    fn info_takes_the_id_from_the_reset_banner() {
        // Asking again with ATI would make a reset during `info` look like an answer.
        let mut elm = connect(FakeElm::silent());
        elm.info().unwrap();
        assert!(
            !commands(&elm).iter().any(|c| c == "ATI"),
            "{:?}",
            commands(&elm)
        );
    }

    #[test]
    fn a_banner_in_any_answer_is_a_reset() {
        let mut elm = connect(car());
        elm.link_mut().elm.after_echo = b"\rELM327 v2.0\r".to_vec();
        assert!(elm.info().is_err());
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn info_puts_nothing_on_the_bus() {
        let mut elm = connect(FakeElm::silent());
        elm.info().unwrap();
        assert_eq!(elm.link().elm.sent, []);
    }

    #[test]
    fn reports_the_link_kind() {
        assert_eq!(connect(FakeElm::silent()).link_kind(), LinkKind::UsbSerial);
    }

    #[test]
    fn rejects_something_that_isnt_an_elm327() {
        let err = Elm::connect(Scripted::new(b"HELLO\r>")).unwrap_err();
        assert!(err.to_string().contains("ELM327"), "{err}");
    }
}

mod requests {
    use super::*;

    #[test]
    fn reads_every_ecus_vin_from_a_broadcast() {
        let mut elm = connect(car());
        let request = approve(Target::ObdFunctional, &[0x09, 0x02]);
        let replies = exchange(
            &mut elm,
            &request,
            Expect::ObdEcus,
            Elm::<FakeLink>::timing(),
        )
        .unwrap();
        assert_eq!(
            replies,
            [
                Response {
                    source: 0x7E8,
                    payload: VIN.to_vec()
                },
                Response {
                    source: 0x7E9,
                    payload: VIN.to_vec()
                },
            ]
        );
        assert_eq!(elm.link().elm.sent, [(0x7DF, vec![0x09, 0x02])]);
    }

    #[test]
    fn works_when_the_adapter_trickles_one_byte_per_read() {
        let mut link = FakeLink::new(car());
        link.chunk = 1;
        let mut elm = Elm::connect(link).unwrap();
        let request = approve(Target::Physical(0x7E0), &[0x09, 0x02]);
        let replies = exchange(
            &mut elm,
            &request,
            Expect::Module(0x7E8),
            Elm::<FakeLink>::timing(),
        )
        .unwrap();
        assert_eq!(replies[0].payload, VIN);
    }

    #[test]
    fn sets_the_header_and_flow_control_only_when_the_target_changes() {
        let mut elm = connect(car());
        let setup = commands(&elm).len();
        for target in [
            Target::ObdFunctional,
            Target::ObdFunctional,
            Target::Physical(0x7E0),
            Target::Physical(0x714),
            Target::Physical(0x714),
            Target::Physical(0x7E1),
        ] {
            elm.send(&approve(target, &[0x09, 0x02])).unwrap();
            while elm.recv(Duration::from_secs(1)).is_ok() {}
        }
        assert_eq!(
            commands(&elm)[setup..],
            [
                // OBD-II IDs: the adapter's own ISO 15765-4 flow control, with a gap between
                // frames (#23), 8 times as long for a broadcast that every emissions ECU may
                // answer at once. A broadcast shows every emissions ECU's reply, a physical
                // request only its own ECU's.
                "ATSH7DF",
                "ATFCSD300015",
                "ATFCSM2",
                "ATCRA7EX",
                "0902",
                "0902",
                "ATSH7E0",
                "ATFCSD300003",
                "ATFCSM2",
                "ATCRA7E8",
                "0902",
                // Any other module: flow control goes to the module's request ID. Without a
                // profile its reply ID isn't known, so every diagnostic ID shows.
                "ATSH714",
                "ATFCSH714",
                "ATFCSD300003",
                "ATFCSM1",
                "ATCRA7XX",
                "0902",
                "0902",
                "ATSH7E1",
                "ATFCSD300003",
                "ATFCSM2",
                "ATCRA7E9",
                "0902",
            ]
        );
    }

    // A busy bus: while the gateway answers, the instruments send a long reply of their own.
    fn busy_bus() -> FakeElm {
        FakeElm::new(Box::new(|header, request| {
            if header != 0x710 || request != [0x22, 0xF1, 0x87] {
                return Vec::new();
            }
            vec![
                (0x77E, b"\x62\xF1\x874G8920930A ".to_vec()),
                (0x77A, b"\x62\xF1\x874G0907468  ".to_vec()),
            ]
        }))
    }

    #[test]
    fn a_profile_module_shows_only_its_own_replies() {
        let narrowed = Policy::read_only().narrowed_to(&[GATEWAY]).unwrap();
        let request = narrowed
            .approve(Target::Physical(0x710), &[0x22, 0xF1, 0x87])
            .unwrap();
        let mut elm = connect(busy_bus());
        elm.send(&request).unwrap();
        let mut sources = Vec::new();
        while let Ok(reply) = elm.recv(Duration::from_secs(1)) {
            sources.push(reply.source);
        }
        assert_eq!(sources, [0x77A]);
        // The adapter acknowledged only the gateway's reply, never the instruments'.
        assert_eq!(elm.link().elm.flow_control_for, [0x77A]);
        assert_eq!(commands(&elm).last().map(String::as_str), Some("22F187"));
        assert!(commands(&elm).iter().any(|c| c == "ATCRA77A"));
    }

    #[test]
    fn without_a_profile_every_diagnostic_id_shows() {
        let mut elm = connect(busy_bus());
        elm.send(&approve(Target::Physical(0x710), &[0x22, 0xF1, 0x87]))
            .unwrap();
        let mut sources = Vec::new();
        while let Ok(reply) = elm.recv(Duration::from_secs(1)) {
            sources.push(reply.source);
        }
        assert_eq!(sources, [0x77E, 0x77A]);
        assert_eq!(elm.link().elm.flow_control_for, [0x77E, 0x77A]);
    }

    #[test]
    fn a_command_the_adapter_misheard_fails_closed() {
        let mut elm = connect(car());
        // ATSH7E0 arrives as ATSH5E0: a valid command, but not the header that was approved.
        elm.link_mut().corrupt_next_write = Some((4, 0x02));
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("ATSH5E0"), "{err}");
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
        assert_eq!(elm.link().elm.sent, []);
    }

    #[test]
    fn a_request_the_adapter_misheard_never_reaches_the_bus() {
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let sent = elm.link().elm.sent.len();
        // 0902 arrives as 0912. Its echo shows that before the carriage return is written, so
        // the driver ends the line with non-hex characters instead (#34): the adapter refuses
        // it, and nothing goes on the bus.
        elm.link_mut().corrupt_next_write = Some((2, 0x01));
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("0912"), "{err}");
        assert_eq!(elm.link().elm.sent.len(), sent);
        assert_eq!(commands(&elm).last().unwrap(), "0912XX");
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn the_audit_log_records_a_request_the_adapter_misheard() {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-misheard.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        // 0902 arrives as 0912; the driver kills the line before its carriage return.
        elm.link_mut().corrupt_next_write = Some((2, 0x01));
        let mut elm = Audited::open(&log, elm, "fake").unwrap();
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();

        let audit = std::fs::read_to_string(&log).unwrap();
        let last: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(last["dir"], "err", "{audit}");
        assert_eq!(last["op"], "send", "{audit}");
        assert_eq!(last["error"], err.to_string(), "{audit}");
        assert!(last["error"].as_str().unwrap().contains("0912"), "{audit}");
    }

    #[test]
    fn a_reply_without_the_echo_fails_closed() {
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        // It echoed the first request before its carriage return, so a request it doesn't echo
        // is killed, not sent.
        let sent = elm.link().elm.sent.len();
        elm.link_mut().elm.settings.echo = false;
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("echo"), "{err}");
        assert_eq!(elm.link().elm.sent.len(), sent);
        assert_eq!(commands(&elm).last().unwrap(), "0902XX");
    }

    #[test]
    fn the_carriage_return_waits_for_the_echo() {
        // The STN echoes each character as it arrives and holds the line until the carriage
        // return (#54), so the request's digits go first, and the carriage return only once they
        // have all come back.
        let mut elm = broadcasting();
        elm.link_mut().writes.clear();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.link().writes, [b"0902".to_vec(), b"\r".to_vec()]);
        assert!(elm.recv(Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn an_adapter_that_echoes_only_whole_lines_still_works() {
        // Some clones may echo a line only once it ends. With nothing echoed before the carriage
        // return on the first request, the driver checks the echo afterwards, as it did before
        // #34, and doesn't wait for an early echo again.
        let mut fake = car();
        fake.echo_at_line_end = true;
        let mut elm = connect(fake);
        for _ in 0..2 {
            let start = Instant::now();
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            assert!(elm.recv(Duration::from_secs(1)).is_ok());
            while elm.recv(Duration::from_secs(1)).is_ok() {}
            if elm.link().elm.sent.len() == 2 {
                assert!(
                    start.elapsed() < Duration::from_millis(500),
                    "{:?}",
                    start.elapsed()
                );
            }
        }
        assert_eq!(elm.link().elm.sent.len(), 2);
        // Its late echo is still checked: a misheard request fails, though it went out.
        elm.link_mut().corrupt_next_write = Some((2, 0x01));
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("0912"), "{err}");
    }

    #[test]
    fn no_single_bit_error_in_the_kill_lets_the_line_out() {
        // A misheard line (any line of hex digits) ended with the driver's kill, `XX` and a
        // carriage return, with any one bit of the kill flipped: the adapter never sends it.
        for line in ["0912", "22F187", "1902AF"] {
            let kill = b"XX\r";
            for index in 0..kill.len() {
                for bit in 0..8 {
                    let mut bytes = line.as_bytes().to_vec();
                    let mut flipped = kill.to_vec();
                    flipped[index] ^= 1 << bit;
                    bytes.extend(flipped);
                    bytes.extend(b"ATI\r");
                    let mut elm = FakeElm::silent();
                    elm.settings.protocol = Some("6".into());
                    for byte in bytes {
                        elm.write(&[byte]);
                        elm.read(usize::MAX);
                    }
                    assert_eq!(
                        elm.sent,
                        [],
                        "{line} with bit {bit} of kill byte {index} flipped"
                    );
                }
            }
        }
    }

    #[test]
    fn p2_outlasts_printing_the_longest_reply_at_the_slowest_baud_rate() {
        // A 4095-byte reply is a first frame and 585 consecutive frames. Each prints as
        // `7E8 21 xx xx xx xx xx xx xx \r`: 29 characters. At 9600 baud (the slowest an ELM327
        // starts at), 8-N-1, that's 10 bits a character.
        let lines = 1 + (4095 - 6_u32).div_ceil(7);
        let printing = Duration::from_secs_f64(f64::from(lines * 29 * 10) / 9600.0);
        // Up to 16 modules can each send one, all printed before the prompt.
        let p2 = Elm::<FakeLink>::timing().p2;
        assert!(
            p2 > obdcracker_transport::elm::ADAPTER_TIMEOUT + printing * 16,
            "{p2:?} vs {printing:?}"
        );
    }

    #[test]
    fn p2_star_also_outlasts_printing_the_longest_reply() {
        // After response-pending the final reply can be the longest one too.
        let lines = 1 + (4095 - 6_u32).div_ceil(7);
        let printing = Duration::from_secs_f64(f64::from(lines * 29 * 10) / 9600.0);
        let p2_star = Elm::<FakeLink>::timing().p2_star;
        assert!(
            p2_star > obdcracker_transport::Timing::default().p2_star + printing * 16,
            "{p2_star:?} vs {printing:?}"
        );
    }

    #[test]
    fn refuses_a_request_longer_than_one_frame_and_writes_nothing() {
        let mut elm = connect(car());
        let written = elm.link().written.len();
        let long = approve(
            Target::Physical(0x7E0),
            &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90, 0xF1, 0x91],
        );
        let err = elm.send(&long).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn sends_a_full_seven_byte_frame() {
        let mut elm = connect(car());
        let seven = approve(
            Target::Physical(0x7E0),
            &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90],
        );
        elm.send(&seven).unwrap();
        assert_eq!(elm.link().elm.sent, [(0x7E0, seven.payload().to_vec())]);
    }

    #[test]
    fn no_data_is_a_timeout() {
        let mut elm = connect(FakeElm::silent());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)), Err(Error::Timeout));
    }

    #[test]
    fn recv_without_a_request_is_a_timeout() {
        let mut elm = connect(car());
        let start = Instant::now();
        assert_eq!(elm.recv(Duration::from_secs(5)), Err(Error::Timeout));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_bus_error_is_an_adapter_error() {
        let mut elm = connect(FakeElm::new(Box::new(|_, _| Vec::new())));
        // Setting a protocol other than CAN makes the fake answer CAN ERROR.
        elm.link_mut().elm.settings.protocol = Some("3".into());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("CAN ERROR"), "{err}");
    }

    #[test]
    fn waits_for_the_last_request_to_finish_instead_of_interrupting_it() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        // Take only the first ECU's reply; the second is still in the adapter's output.
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x7E8);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.link().elm.interrupted, 0);
        // The leftover reply from 7E9 belongs to the old request and is gone.
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!((reply.source, reply.payload.as_slice()), (0x7E8, VIN));
        assert_eq!(elm.recv(Duration::from_secs(1)), Err(Error::Timeout));
    }
}

mod response_pending {
    use super::*;

    // A module at 0x7E0 that answers 22 F1 87 with response-pending only.
    fn busy_module() -> FakeElm {
        FakeElm::new(Box::new(|header, request| {
            if header == 0x7E0 && request == [0x22, 0xF1, 0x87] {
                vec![(0x7E8, vec![0x7F, 0x22, 0x78])]
            } else {
                Vec::new()
            }
        }))
    }

    #[test]
    fn an_answer_2_s_after_response_pending_arrives() {
        // The STN keeps listening for P2* after `7F xx 78`: in #54 the transmission answered
        // 1969 ms after one. The adapter prints the answer and its prompt when they come.
        let mut elm = connect(busy_module());
        elm.link_mut().elm.hang_after_request = true;
        let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x87]);
        let start = Instant::now();
        elm.link_mut().scheduled = [(
            start + Duration::from_secs(2),
            b"7E8 07 62 F1 87 34 47 30 39\r\r>".to_vec(),
        )]
        .into_iter()
        .collect();
        let got = exchange(
            &mut elm,
            &read,
            Expect::Module(0x7E8),
            Elm::<FakeLink>::timing(),
        )
        .unwrap();
        assert_eq!(got[0].payload, b"\x62\xF1\x874G09");
        assert!(start.elapsed() >= Duration::from_secs(2));
    }

    #[test]
    fn an_adapter_that_stops_listening_after_response_pending_says_so() {
        // A plain ELM327 may end the request at its own timeout after `7F xx 78` (#17). That's
        // not a silent module: it said it was busy.
        let mut elm = connect(busy_module());
        let read = approve(Target::Physical(0x7E0), &[0x22, 0xF1, 0x87]);
        let got = exchange(
            &mut elm,
            &read,
            Expect::Module(0x7E8),
            Elm::<FakeLink>::timing(),
        );
        assert_eq!(got, Err(Error::StillPending));
        assert!(got.unwrap_err().to_string().contains("busy"));
        // The adapter is fine: the next request goes out.
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_ok()
        );
    }
}

mod misbehaving {
    use super::*;

    #[test]
    fn an_adapter_that_never_prompts_after_a_request_fails_closed() {
        let mut fake = car();
        fake.hang_after_request = true;
        let mut elm = connect(fake);
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_millis(50)).is_ok() {}
        // The adapter never said it was ready, so nothing more may be written to it.
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        assert_eq!(elm.link().written.len(), written);
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    // The adapter never stays quiet in a request for longer than its own timeout (plus a
    // response-pending wait), so a long P2 mustn't make the caller wait out a hung one.
    #[test]
    fn an_adapter_that_goes_quiet_mid_request_fails_closed_without_waiting_out_p2() {
        let mut elm = connect(car());
        elm.link_mut().elm.hang_after_request = true;
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let start = Instant::now();
        let err = loop {
            match elm.recv(Duration::from_secs(120)) {
                Ok(_) => {}
                Err(err) => break err,
            }
        };
        assert!(err.to_string().contains("quiet"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
    }

    #[test]
    fn short_receives_add_up_to_a_quiet_adapter() {
        // Waiting is what counts, across calls: polling in 1 s steps mustn't hide a hang.
        let mut elm = connect(car());
        elm.link_mut().elm.hang_after_request = true;
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let start = Instant::now();
        let err = loop {
            match elm.recv(Duration::from_secs(1)) {
                Ok(_) | Err(Error::Timeout) => {}
                Err(err) => break err,
            }
            assert!(start.elapsed() < Duration::from_secs(15), "never tripped");
        };
        assert!(err.to_string().contains("quiet"), "{err}");
    }

    #[test]
    fn silence_is_measured_from_the_last_byte() {
        // A stray NUL 1 s in, then nothing until 13 s: 12 s of silence, well past the limit.
        // Counting from the end of the wait the NUL came in would let it run on.
        let mut elm = connect(car());
        elm.link_mut().elm.hang_after_request = true;
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let start = Instant::now();
        elm.link_mut().scheduled = [(1, vec![0]), (13, vec![0])]
            .into_iter()
            .map(|(s, bytes)| (start + Duration::from_secs(s), bytes))
            .collect();
        let err = loop {
            match elm.recv(Duration::from_secs(60)) {
                Ok(_) => {}
                Err(err) => break err,
            }
        };
        assert!(err.to_string().contains("quiet"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(11),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_caller_that_reads_late_doesnt_count_as_a_quiet_adapter() {
        // Silence only counts while the driver waits; the replies are waiting on the link.
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        std::thread::sleep(Duration::from_secs(8));
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!(reply.payload, VIN);
    }

    #[test]
    fn recv_ends_at_its_deadline_while_frames_keep_arriving() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        // After the echo (its digits were read before the carriage return), replace the
        // adapter's output with an endless stream of first frames.
        elm.link_mut().inject = b"\r".to_vec();
        elm.link_mut().flood = Some(b"7E8 10 14 49 02 01 57 41 55\r".to_vec());
        let start = Instant::now();
        assert_eq!(elm.recv(Duration::from_millis(200)), Err(Error::Timeout));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(elm.link().flooded > 0);
    }

    #[test]
    fn an_overlong_reply_line_fails_closed() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.link_mut().flood = Some(vec![b'7'; 1000]);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        elm.link_mut().flood = None;
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn an_overlong_answer_to_a_command_fails_closed() {
        // The rest of the answer, and its prompt, may still be coming: the next command would
        // take them for its own.
        let mut elm = connect(car());
        elm.link_mut().flood = Some(vec![b'7'; 1000]);
        assert!(elm.info().is_err());
        elm.link_mut().flood = None;
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("unknown state"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    // After a reset the adapter is back at its defaults (echo on, headers off, maybe automatic
    // protocol search, which sends probe frames), so nothing more may be sent through it.
    #[test]
    fn an_adapter_that_reset_during_a_request_fails_closed() {
        for output in [
            &b"LV RESET\r"[..],
            b"ERR94\r",
            b"LP ALERT\r",
            b"ELM327 v2.0\r",
            b"BUS INIT: ...\r",
        ] {
            let mut elm = broadcasting();
            elm.link_mut().elm.after_echo = output.to_vec();
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            assert!(elm.recv(Duration::from_secs(1)).is_err());
            let written = elm.link().written.len();
            let err = elm
                .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap_err();
            assert!(
                err.to_string().contains("unknown state"),
                "{output:?}: {err}"
            );
            assert_eq!(elm.link().written.len(), written, "{output:?}");
        }
    }

    #[test]
    fn an_adapter_that_reset_while_answering_a_command_fails_closed() {
        for output in [&b"LV RESET\r"[..], b"ERR94\r", b"LP ALERT\r"] {
            let mut elm = connect(car());
            elm.link_mut().elm.after_echo = output.to_vec();
            assert!(elm.info().is_err(), "{output:?}");
            let written = elm.link().written.len();
            assert!(
                elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                    .is_err(),
                "{output:?}"
            );
            assert_eq!(elm.link().written.len(), written, "{output:?}");
        }
    }

    #[test]
    fn a_reset_while_finishing_the_last_request_fails_closed() {
        for output in [&b"LV RESET\r"[..], b"ERR94\r", b"ELM327 v2.0\r"] {
            let mut elm = connect(car());
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            // Take one reply and leave the rest; the reset arrives while `send` waits for the
            // adapter to finish.
            elm.recv(Duration::from_secs(1)).unwrap();
            elm.link_mut().inject = output.to_vec();
            let written = elm.link().written.len();
            let err = elm
                .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains(&String::from_utf8_lossy(output).trim().to_string()),
                "{output:?}: {err}"
            );
            assert_eq!(elm.link().written.len(), written, "{output:?}");
        }
    }

    #[test]
    fn a_reset_while_setting_the_header_fails_closed() {
        let mut elm = connect(car());
        // The adapter resets just as it answers ATSH: a banner comes after the echo, before the OK.
        elm.link_mut().elm.after_echo = b"\rELM327 v2.0\r".to_vec();
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
        assert_eq!(elm.link().elm.sent, []);
    }

    #[test]
    fn an_overlong_line_while_finishing_the_last_request_fails_closed() {
        // It can't be read, so it could have hidden a reset.
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.recv(Duration::from_secs(1)).unwrap();
        let mut overlong = vec![b'7'; 200];
        overlong.push(b'\r');
        elm.link_mut().inject = overlong;
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    // An adapter prints nothing between its prompt and the next line it's sent, so anything
    // it printed after the prompt, read already or not, could be a reset.
    #[test]
    fn output_after_a_reply_prompt_fails_closed() {
        let mut elm = broadcasting();
        elm.link_mut().elm.after_prompt = b"LV RESET\r".to_vec();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("LV RESET"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn output_after_a_drained_prompt_fails_closed() {
        let mut elm = broadcasting();
        elm.link_mut().elm.after_prompt = b"\rELM327 v2.0\r".to_vec();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        // The next send drains the first request's replies, then must notice the banner.
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("ELM327"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn output_after_the_header_prompt_fails_closed() {
        // Changing to 0x7E0 from broadcasts takes one command, ATSH7E0, and then the request.
        let mut elm = broadcasting();
        elm.link_mut().elm.after_prompt = b"LV RESET\r".to_vec();
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("while idle"), "{err}");
        assert_eq!(commands(&elm).last().map(String::as_str), Some("ATSH7E0"));
        assert_eq!(elm.link().elm.sent, [(0x7DF, vec![0x09, 0x02])]);
    }

    #[test]
    fn a_stray_nul_doesnt_cut_the_idle_check_short() {
        // The adapter may insert NULs (datasheet p. 8). One arriving alone mustn't end the
        // check before the reset behind it.
        let mut elm = broadcasting();
        elm.link_mut().elm.after_prompt = b"\rELM327 v2.0\r".to_vec();
        elm.link_mut().chunk = 1;
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        // Two reads inside the 1 ms check: the NUL alone, then the whole banner.
        elm.link_mut().chunk = 64;
        elm.link_mut().inject = vec![0];
        let written = elm.link().written.len();
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("while idle"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn an_answer_too_long_for_any_command_fails_closed() {
        // Thousands of short lines, as a broken or hostile adapter could send without end: the
        // answer must stay bounded.
        let mut elm = car();
        elm.sti = Some(vec!["A"; 10_000].join("\r"));
        let err = Elm::connect(FakeLink::new(elm)).unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
    }

    #[test]
    fn output_after_a_command_prompt_fails_closed() {
        for output in [
            &b"LV RESET\r"[..],
            b"\rELM327 v2.0\r",
            b"7E8 03 41 00\r",
            b">",
        ] {
            let mut elm = connect(car());
            elm.info().unwrap();
            // The adapter answers the next command, then prints more.
            elm.link_mut().elm.after_prompt = output.to_vec();
            let err = elm
                .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap_err();
            // Caught before the next command is written, not by that command's echo.
            assert!(err.to_string().contains("while idle"), "{output:?}: {err}");
            assert_eq!(elm.link().elm.sent, [], "{output:?}");
        }
    }

    // The driver never interrupts the adapter, so STOPPED means something else wrote to it, and
    // the interrupting byte may start the next line it reads.
    #[test]
    fn an_unexplained_interruption_fails_closed() {
        let mut elm = broadcasting();
        elm.link_mut().elm.after_echo = b"STOPPED\r".to_vec();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("STOPPED"), "{err}");
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);

        let mut elm = connect(car());
        elm.link_mut().elm.after_echo = b"STOPPED\r".to_vec();
        let err = elm.info().unwrap_err();
        assert!(err.to_string().contains("STOPPED"), "{err}");
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().elm.sent, []);
    }

    // A frame the receive filter should have hidden means the adapter lost the filter, and may
    // send flow control for frames it shouldn't see.
    #[test]
    fn a_frame_from_outside_the_receive_filter_fails_closed() {
        // A broadcast narrows the filter to 0x7E0..=0x7EF, so 0x77A is outside it too.
        for frame in [
            &b"6FF 02 01 00\r"[..],
            b"123 03 41 00 00\r",
            b"77A 03 41 00 00\r",
        ] {
            let mut elm = broadcasting();
            elm.link_mut().elm.after_echo = frame.to_vec();
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            let err = elm.recv(Duration::from_secs(1)).unwrap_err();
            assert!(
                err.to_string().contains("receive filter"),
                "{frame:?}: {err}"
            );
            let written = elm.link().written.len();
            assert!(
                elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                    .is_err()
            );
            assert_eq!(elm.link().written.len(), written, "{frame:?}");
        }
    }

    // Protocol 6 is set without automatic search, so searching means the adapter lost that
    // setting, and a search sends probe frames nobody approved.
    #[test]
    fn a_protocol_search_fails_closed() {
        for output in [&b"SEARCHING...\r"[..], b"UNABLE TO CONNECT\r"] {
            let mut elm = broadcasting();
            elm.link_mut().elm.after_echo = output.to_vec();
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            assert!(elm.recv(Duration::from_secs(1)).is_err(), "{output:?}");
            let written = elm.link().written.len();
            assert!(
                elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                    .is_err(),
                "{output:?}"
            );
            assert_eq!(elm.link().written.len(), written, "{output:?}");
        }
    }

    #[test]
    fn a_bus_error_leaves_the_adapter_usable() {
        let mut elm = broadcasting();
        elm.link_mut().elm.after_echo = b"CAN ERROR\r".to_vec();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        assert!(elm.recv(Duration::from_secs(1)).is_err());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
    }

    #[test]
    fn connect_gives_up_on_a_silent_link() {
        let start = Instant::now();
        let err = Elm::connect(Scripted::new(b"")).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        assert!(start.elapsed() < Duration::from_secs(15));
    }

    #[test]
    fn connect_gives_up_on_a_link_that_never_stops_talking() {
        let start = Instant::now();
        let mut link = Scripted::new(b"");
        link.forever = Some(b"7E8 03 41 0D 32\r".to_vec());
        let err = Elm::connect(link).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        assert!(start.elapsed() < Duration::from_secs(15));
    }

    #[test]
    fn a_closed_link_is_an_adapter_error() {
        let mut elm = connect(car());
        elm.link_mut().closed = true;
        let err = elm
            .send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
    }

    #[test]
    fn retries_the_reset_when_the_adapter_was_busy() {
        // The first ATZ only interrupts what the adapter was doing.
        let mut link = Scripted::new(b"STOPPED\r\r>");
        link.then = Some(FakeLink::new(FakeElm::silent()));
        let elm = Elm::connect(link).unwrap();
        assert_eq!(elm.link().then.as_ref().unwrap().elm.commands[0], "ATZ");
    }
}

/// A link that plays fixed output, then optionally hands over to a fake adapter or repeats a
/// line forever. Reads wait out their timeout when there's nothing to give, like a real port.
struct Scripted {
    output: Vec<u8>,
    forever: Option<Vec<u8>>,
    then: Option<FakeLink>,
    writes: usize,
}

impl Scripted {
    fn new(output: &[u8]) -> Self {
        Self {
            output: output.to_vec(),
            forever: None,
            then: None,
            writes: 0,
        }
    }
}

impl Link for Scripted {
    fn write_all(&mut self, bytes: &[u8], driver: Driver) -> io::Result<()> {
        self.writes += 1;
        // Everything after the first write goes to the fake adapter.
        if self.writes > 1
            && let Some(then) = &mut self.then
        {
            return then.write_all(bytes, driver);
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration, driver: Driver) -> io::Result<usize> {
        if !self.output.is_empty() {
            let n = buf.len().min(self.output.len());
            buf[..n].copy_from_slice(&self.output[..n]);
            self.output.drain(..n);
            return Ok(n);
        }
        if let Some(line) = &self.forever {
            let n = buf.len().min(line.len());
            buf[..n].copy_from_slice(&line[..n]);
            return Ok(n);
        }
        if self.writes > 1
            && let Some(then) = &mut self.then
        {
            return then.read(buf, timeout, driver);
        }
        std::thread::sleep(timeout.min(Duration::from_millis(20)));
        Ok(0)
    }

    fn kind(&self) -> LinkKind {
        LinkKind::UsbSerial
    }
}

impl std::fmt::Debug for Scripted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scripted").finish_non_exhaustive()
    }
}

// The adapter's 512-byte output buffer (#23): frames arrive at bus speed, but leave as text at the
// link's speed, so a long reply can overflow it unless the module is paced.
mod pacing {
    use super::*;

    // The engine (7E0/7E8) and the instruments (714/77E) each answer 22 F1 87 with the longest
    // reply ISO-TP's short first frame allows.
    fn long_replies() -> FakeElm {
        FakeElm::new(Box::new(|header, request| {
            if request != [0x22, 0xF1, 0x87] {
                return Vec::new();
            }
            let mut payload = vec![0x62, 0xF1, 0x87];
            payload.resize(4095, 0x41);
            match header {
                0x7E0 => vec![(0x7E8, payload)],
                0x714 => vec![(0x77E, payload)],
                _ => Vec::new(),
            }
        }))
    }

    // The instruments' reply ID comes from a profile, so the receive filter shows only it.
    fn read_long(elm: &mut Elm<FakeLink>, target: Target) -> Result<Response, Error> {
        let policy = if target == Target::Physical(0x714) {
            Policy::read_only().narrowed_to(&[INSTRUMENTS]).unwrap()
        } else {
            Policy::read_only()
        };
        elm.send(&policy.approve(target, &[0x22, 0xF1, 0x87]).unwrap())?;
        elm.recv(Duration::from_secs(30))
    }

    #[test]
    fn the_fake_adapter_overflows_without_pacing() {
        // The fake's buffer model, checked on its own: every frame back to back at 9600 baud.
        let mut elm = FakeElm::new(Box::new(|_, _| {
            let mut payload = vec![0x62, 0xF1, 0x87];
            payload.resize(4095, 0x41);
            vec![(0x77E, payload)]
        }));
        elm.drain_rate = Some(960);
        elm.settings.headers = true;
        elm.settings.protocol = Some("6".into());
        let mut out = Vec::new();
        for line in ["ATFCSH714", "ATFCSD300000", "ATFCSM1", "ATSH714", "22F187"] {
            elm.write(format!("{line}\r").as_bytes());
            out.extend(elm.read(usize::MAX));
        }
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("BUFFER FULL"), "{out}");
    }

    #[test]
    fn the_longest_reply_reads_on_a_plain_elm327_at_every_common_baud_rate() {
        for baud in [9600, 38_400, 115_200] {
            let mut elm = Elm::connect(FakeLink::at_baud(long_replies(), baud)).unwrap();
            for target in [Target::Physical(0x7E0), Target::Physical(0x714)] {
                let reply = read_long(&mut elm, target)
                    .unwrap_or_else(|e| panic!("{baud} baud, {target:?}: {e}"));
                assert_eq!(reply.payload.len(), 4095, "{baud} baud, {target:?}");
            }
        }
    }

    // Every emissions ECU answers a broadcast 09 02 with the longest reply, all at once.
    fn eight_long_replies() -> FakeElm {
        FakeElm::new(Box::new(|header, request| {
            if header != 0x7DF || request != [0x09, 0x02] {
                return Vec::new();
            }
            let mut payload = vec![0x49, 0x02, 0x01];
            payload.resize(4095, 0x41);
            (0x7E8..=0x7EF).map(|id| (id, payload.clone())).collect()
        }))
    }

    #[test]
    fn a_broadcast_is_paced_for_every_emissions_ecu_answering_at_once() {
        // Up to 8 ECUs (0x7E8..=0x7EF) can each send a long reply to one broadcast, their frames
        // interleaved, so each gets 8 times the gap (PR #70, Codex).
        for (baud, st_min) in [(38_400, "3D"), (115_200, "15")] {
            let mut elm = Elm::connect(FakeLink::at_baud(eight_long_replies(), baud)).unwrap();
            let setup = commands(&elm).len();
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            let mut sources = Vec::new();
            while let Ok(reply) = elm.recv(Duration::from_secs(30)) {
                assert_eq!(reply.payload.len(), 4095);
                sources.push(reply.source);
            }
            sources.sort_unstable();
            assert_eq!(sources, (0x7E8..=0x7EF).collect::<Vec<_>>(), "{baud}");
            assert!(
                commands(&elm)[setup..].contains(&format!("ATFCSD3000{st_min}")),
                "{baud}: {:?}",
                &commands(&elm)[setup..]
            );
        }
        // At 9600 baud that would be 242 ms, more than STmin allows, so it's 127 ms: enough
        // for 4 ECUs at once.
        let mut link = FakeLink::new(eight_long_replies());
        link.byte_rate = Some(960);
        let mut elm = Elm::connect(link).unwrap();
        let setup = commands(&elm).len();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert!(commands(&elm)[setup..].iter().any(|c| c == "ATFCSD30007F"));
    }

    #[test]
    fn the_fake_adapter_overflows_when_a_broadcast_is_paced_for_one_ecu() {
        let mut elm = eight_long_replies();
        elm.drain_rate = Some(11_520);
        elm.settings.headers = true;
        elm.settings.protocol = Some("6".into());
        let mut out = Vec::new();
        for line in ["ATFCSD300003", "ATFCSM2", "0902"] {
            elm.write(format!("{line}\r").as_bytes());
            out.extend(elm.read(usize::MAX));
        }
        assert!(String::from_utf8(out).unwrap().contains("BUFFER FULL"));
    }

    // The flow control data each target gets on a plain ELM327.
    fn flow_commands(link: FakeLink) -> Vec<String> {
        let mut elm = Elm::connect(link).unwrap();
        let setup = commands(&elm).len();
        for target in [Target::Physical(0x7E0), Target::Physical(0x714)] {
            read_long(&mut elm, target).unwrap();
        }
        commands(&elm)[setup..]
            .iter()
            .filter(|c| c.starts_with("ATFC"))
            .cloned()
            .collect()
    }

    #[test]
    fn the_gap_between_frames_is_the_time_to_print_one_at_the_links_rate() {
        // A frame line is 29 characters: `7E8 21 41 41 41 41 41 41 41 \r`, 10 bits each.
        for (rate, st_min) in [
            (Some(960), "1F"),    // 9600 baud: 30.2 ms
            (Some(3840), "08"),   // 38400: 7.6 ms
            (Some(11_520), "03"), // 115200: 2.5 ms
            (None, "1F"),         // unknown, such as Wi-Fi: as slow as 9600
            (Some(0), "1F"),
            (Some(100), "7F"), // 1000 baud would need 290 ms: the most STmin allows
        ] {
            let mut link = FakeLink::new(long_replies());
            link.byte_rate = rate;
            assert_eq!(
                flow_commands(link),
                [
                    // OBD-II IDs: the adapter picks the header, the driver the gap
                    format!("ATFCSD3000{st_min}"),
                    "ATFCSM2".to_owned(),
                    "ATFCSH714".to_owned(),
                    format!("ATFCSD3000{st_min}"),
                    "ATFCSM1".to_owned(),
                ],
                "{rate:?}"
            );
        }
    }

    #[test]
    fn an_stn_at_115200_baud_or_faster_isnt_paced() {
        // #49: an OBDLink EX (STN2232) printed a 770-byte reply at 115200 with no BUFFER FULL.
        // The fake's buffer is an ELM327's; an STN's is bigger, so it isn't modelled here.
        let mut stn = long_replies();
        stn.sti = Some("STN2232 v5.12.4".into());
        assert_eq!(
            flow_commands(FakeLink::new(stn)),
            ["ATFCSM0", "ATFCSH714", "ATFCSD300000", "ATFCSM1"]
        );
        // A clone that answers STI with something else isn't an STN.
        let mut clone = long_replies();
        clone.sti = Some("OK".into());
        assert_eq!(
            flow_commands(FakeLink::at_baud(clone, 115_200))[0],
            "ATFCSD300003"
        );
        // Untested any slower, so it's paced like any other adapter.
        let mut stn = long_replies();
        stn.sti = Some("STN2232 v5.12.4".into());
        assert_eq!(
            flow_commands(FakeLink::at_baud(stn, 38_400))[0],
            "ATFCSD300008"
        );
    }
}

// Clone adapters, from real transcripts in python-OBD's tracker (#44). Each must either work, or
// fail closed with a message that names the problem.
mod clones {
    use super::*;

    fn clone_of(version: &str) -> FakeElm {
        let mut elm = car();
        elm.banner = format!("ELM327 {version}");
        elm
    }

    #[test]
    fn noise_before_the_banner_is_ignored() {
        // python-OBD #205: `\xfc\r\rELM327 v1.5\r\r>`
        let mut elm = clone_of("v2.1");
        elm.reset_noise = b"\xfc\r".to_vec();
        let mut elm = connect(elm);
        assert_eq!(elm.info().unwrap().id, "ELM327 v2.1");
        let reply = exchange(
            &mut elm,
            &approve(Target::ObdFunctional, &[0x09, 0x02]),
            Expect::ObdEcus,
            Elm::<FakeLink>::timing(),
        )
        .unwrap();
        assert_eq!(reply.len(), 2);
    }

    #[test]
    fn a_clone_that_claims_a_version_it_doesnt_implement_is_told_so() {
        // Most clones say v1.5, a version Elm Electronics never released, and refuse `X` digits
        // in `AT CRA`; some say v2.1 and still do (python-OBD #132, #188).
        for version in ["v1.5", "v2.1"] {
            let mut elm = clone_of(version);
            elm.unsupported.push("ATCRA7XX".into());
            let err = Elm::connect(FakeLink::new(elm)).unwrap_err().to_string();
            for needed in ["ATCRA7XX", "ELM327 v2.0", "STN", version] {
                assert!(err.contains(needed), "{version}: {err}");
            }
        }
    }

    #[test]
    fn an_answer_without_its_prompt_says_so() {
        // python-OBD #160, #205: `ATE0\rOK` and then nothing. Without the prompt the driver can't
        // tell whether more is coming, so it stops rather than write over it.
        let mut elm = car();
        elm.unfinished.push("ATH1".into());
        let err = Elm::connect(FakeLink::new(elm)).unwrap_err().to_string();
        assert!(err.contains("ATH1") && err.contains("prompt"), "{err}");
        assert!(!err.contains("no ELM327"), "{err}");
    }

    #[test]
    fn a_command_echoed_and_never_answered_says_so() {
        let mut elm = car();
        elm.mute.push("ATH1".into());
        let err = Elm::connect(FakeLink::new(elm)).unwrap_err().to_string();
        assert!(err.contains("echoed ATH1 but never answered"), "{err}");
    }

    #[test]
    fn an_empty_answer_is_no_reply_and_the_adapter_stays_usable() {
        // python-OBD #205: `0100` answered with an empty line and a prompt.
        let mut elm = connect(car());
        elm.link_mut().elm.empty_answers = true;
        let err = exchange(
            &mut elm,
            &approve(Target::Physical(0x7E0), &[0x09, 0x02]),
            Expect::Module(0x7E8),
            Elm::<FakeLink>::timing(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Timeout), "{err}");
        elm.link_mut().elm.empty_answers = false;
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x7E8);
    }

    #[test]
    fn a_link_that_drops_mid_request_names_the_link() {
        // python-OBD #188: Bluetooth links that drop after a few seconds of polling.
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.link_mut().closed = true;
        let err = elm.recv(Duration::from_secs(1)).unwrap_err().to_string();
        assert!(err.contains("usb-serial link"), "{err}");
        assert!(
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .is_err()
        );
    }
}
