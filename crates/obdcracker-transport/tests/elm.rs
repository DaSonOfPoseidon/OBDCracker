//! The ELM327 driver against a fake adapter: setup, requests, replies, and adapters that misbehave.

mod support;

use std::io;
use std::time::{Duration, Instant};

use obdcracker_safety::{Approved, Policy, Target};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::link::{Driver, Link, LinkKind};
use obdcracker_transport::{Error, Expect, Response, Transport, exchange};
use support::fake_elm::{BANNER, FakeElm, FakeLink};

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";

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
                "ATSTFF"
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
    // header and flow control settings for each kind of target.
    fn every_command() -> Vec<String> {
        let mut elm = connect(car());
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
            "ATFCSM1",
            "ATFCSM0",
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

        // A clone that answers STI with nothing at all isn't an STN.
        let mut clone = connect(FakeElm::silent());
        clone.link_mut().elm.sti = Some(String::new());
        assert_eq!(clone.info().unwrap().stn, None);
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
                // OBD-II IDs: the adapter's own ISO 15765-4 flow control
                "ATSH7DF",
                "ATFCSM0",
                "0902",
                "0902",
                "ATSH7E0",
                "0902",
                // Any other module: flow control goes to the module's request ID
                "ATSH714",
                "ATFCSH714",
                "ATFCSD300000",
                "ATFCSM1",
                "0902",
                "0902",
                "ATSH7E1",
                "ATFCSM0",
                "0902",
            ]
        );
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
    fn a_request_the_adapter_misheard_fails_closed() {
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        // 0902 arrives as 0912. The adapter has sent it by the time its echo shows that, so
        // all the driver can do is stop.
        elm.link_mut().corrupt_next_write = Some((2, 0x01));
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("0912"), "{err}");
        let written = elm.link().written.len();
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn a_reply_without_the_echo_fails_closed() {
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.link_mut().elm.settings.echo = false;
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("echo"), "{err}");
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

    #[test]
    fn recv_ends_at_its_deadline_while_frames_keep_arriving() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        // After the echo, replace the adapter's output with an endless stream of first frames.
        elm.link_mut().inject = b"0902\r".to_vec();
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
