//! The ELM327 driver against a fake adapter: setup, requests, replies, and adapters that misbehave.

mod support;

use std::io;
use std::time::{Duration, Instant};

use obdcracker_safety::{Approved, ModuleIds, Policy, Protocol, Target};
use obdcracker_transport::elm::{ADAPTER_TIMEOUT, Elm};
use obdcracker_transport::link::{Driver, Link, LinkKind};
use obdcracker_transport::{Audited, Error, Expect, Response, Transport, exchange, hex};
use support::fake_elm::{BANNER, FakeElm, FakeLink, frames};

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";

const GATEWAY: ModuleIds = ModuleIds {
    request: 0x710,
    reply: 0x77A,
};
const INSTRUMENTS: ModuleIds = ModuleIds {
    request: 0x714,
    reply: 0x77E,
};
const VAG29: ModuleIds = ModuleIds {
    request: 0x17FC_0076,
    reply: 0x17FE_0076,
};

fn approve(target: Target, payload: &[u8]) -> Approved {
    Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap()
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
                "ATSTFF", "STI", "ATAT0"
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
        let narrowed = Policy::read_only().narrowed_to(&[INSTRUMENTS]).unwrap();
        elm.send(
            &narrowed
                .approve(Protocol::Uds, Target::Physical(0x714), &[0x22, 0xF1, 0x87])
                .unwrap(),
        )
        .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&approve(
            Target::Physical29(0x18DA_10F1),
            &[0x22, 0xF1, 0x87],
        ))
        .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let narrowed = Policy::read_only().narrowed_to(&[VAG29]).unwrap();
        elm.send(
            &narrowed
                .approve(
                    Protocol::Uds,
                    Target::Physical29(VAG29.request),
                    &[0x22, 0xF1, 0x87],
                )
                .unwrap(),
        )
        .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&approve(
            Target::Physical29(0x17FC_0010),
            &[0x22, 0xF1, 0x87],
        ))
        .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&approve(Target::Physical(0x714), &[0x22, 0xF1, 0x87]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        // A multi-frame request: an STN sends it as `STPX`, and a plain adapter in segments
        // (its module here sends no flow control, so it fails).
        let long = approve(
            Target::Physical(0x7E0),
            &[0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1, 0x89, 0xF1, 0x91],
        );
        let _ = elm.send(&long);
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        elm.patient(None).unwrap();
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
            "ATFCSD300004",
            "ATFCSH7E0",
            "ATFCSM1",
            "ATFCSM0",
            "ATAT0",
            "ATCRA7EX",
            "ATCRA7E8",
            "ATCRA77E",
            "ATSP7",
            "ATSP6",
            "ATCP18",
            "ATCP17",
            "ATSHDA10F1",
            "ATSHFC0076",
            "ATFCSH17FC0076",
            "ATCRA18DAF110",
            "ATCRA17FE0076",
            "ATCRA17FE00XX",
            "STPTO5000",
        ] {
            assert!(
                commands.iter().any(|c| c == expected),
                "{expected}: {commands:?}"
            );
        }
        // `ATCAF0`/`ATCAF1` are written guarded, their echo checked before the carriage return
        // (`a_misheard_caf0_never_reaches_the_bus`), so a flip in them never gets that far.
        // `STPX` lines are written the same way (`stpx::no_single_bit_error_in_the_stpx_line_sends_a_different_request`).
        assert!(
            commands.iter().any(|c| c.starts_with("STPXD:")),
            "{commands:?}"
        );
        for command in commands
            .iter()
            .filter(|c| !c.starts_with("ATCAF") && !c.starts_with("STPX"))
        {
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
                Response::new(0x7E8, VIN.to_vec()),
                Response::new(0x7E9, VIN.to_vec()),
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
                // A broadcast: the adapter's own ISO 15765-4 flow control, the only kind that
                // reaches each ECU's request ID, and it shows every emissions ECU's reply.
                "ATSH7DF",
                "ATFCSM0",
                "ATCRA7EX",
                "0902",
                "0902",
                // A physical request: flow control to the module's request ID, with a gap
                // between frames (#23), and only its own ECU's replies show.
                "ATSH7E0",
                "ATFCSH7E0",
                "ATFCSD300003",
                "ATFCSM1",
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
                "ATFCSH7E1",
                "ATFCSD300003",
                "ATFCSM1",
                "ATCRA7E9",
                "0902",
            ]
        );
    }

    fn bits29_car() -> FakeElm {
        FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x17FC_0076, [0x22, 0xF1, 0x87]) => {
                vec![(0x17FE_0076, b"\x62\xF1\x874G0907468AD".to_vec())]
            }
            (0x18DA_10F1, [0x22, 0xF1, 0x87]) => vec![(0x18DA_F110, b"\x62\xF1\x87AB".to_vec())],
            (0x710, [0x22, 0xF1, 0x87]) => vec![(0x77A, b"\x62\xF1\x87GW".to_vec())],
            _ => Vec::new(),
        }))
    }

    #[test]
    fn a_29_bit_request_switches_protocol_and_reassembles_its_reply() {
        let narrowed = Policy::read_only().narrowed_to(&[VAG29, GATEWAY]).unwrap();
        let read = |target| {
            narrowed
                .approve(Protocol::Uds, target, &[0x22, 0xF1, 0x87])
                .unwrap()
        };
        let mut elm = connect(bits29_car());
        let setup = commands(&elm).len();
        elm.send(&read(Target::Physical29(VAG29.request))).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!(
            reply,
            Response::new(0x17FE_0076, b"\x62\xF1\x874G0907468AD".to_vec())
        );
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&read(Target::Physical(0x710))).unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x77A);
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(
            commands(&elm)[setup..],
            [
                "ATSP7",
                "ATCP17",
                "ATSHFC0076",
                // Flow control goes to the request ID: the adapter's own would swap the reply
                // ID's bytes, which only suits ISO's 0x18DAF1xx.
                "ATFCSH17FC0076",
                // A 29-bit frame line takes 37 characters to print, 4 ms at 115200 baud.
                "ATFCSD300004",
                "ATFCSM1",
                "ATCRA17FE0076",
                "22F187",
                "ATSP6",
                "ATSH710",
                "ATFCSH710",
                "ATFCSD300003",
                "ATFCSM1",
                "ATCRA77A",
                "22F187",
            ]
        );
        assert_eq!(elm.link().elm.flow_control_ids, [0x17FC_0076]);
        assert_eq!(
            elm.link().elm.sent,
            [
                (0x17FC_0076, vec![0x22, 0xF1, 0x87]),
                (0x710, vec![0x22, 0xF1, 0x87])
            ]
        );
    }

    #[test]
    fn an_iso_29_bit_module_answers_on_its_known_reply_id() {
        let mut elm = connect(bits29_car());
        elm.send(&approve(
            Target::Physical29(0x18DA_10F1),
            &[0x22, 0xF1, 0x87],
        ))
        .unwrap();
        assert_eq!(
            elm.recv(Duration::from_secs(1)).unwrap().source,
            0x18DA_F110
        );
        assert!(commands(&elm).iter().any(|c| c == "ATCRA18DAF110"));
    }

    #[test]
    fn without_a_profile_a_vag_29_bit_request_shows_every_vag_reply() {
        let mut elm = connect(FakeElm::new(Box::new(|header, _| match header {
            0x17FC_0010 => vec![(0x17FE_0010, vec![0x62, 0xF1, 0x87, 0x01])],
            _ => Vec::new(),
        })));
        elm.send(&approve(
            Target::Physical29(0x17FC_0010),
            &[0x22, 0xF1, 0x87],
        ))
        .unwrap();
        assert_eq!(
            elm.recv(Duration::from_secs(1)).unwrap().source,
            0x17FE_0010
        );
        assert!(commands(&elm).iter().any(|c| c == "ATCRA17FE00XX"));
    }

    #[test]
    fn a_frame_of_the_wrong_width_or_range_fails_closed() {
        // An 11-bit frame can't pass a 29-bit filter, nor an ISO reply VAG's: the adapter lost
        // its settings.
        // Each target is set up by a first request, so the frame follows the second's echo.
        let fails_closed = |target: Target, frame: &[u8], why: &str| {
            let request = approve(target, &[0x22, 0xF1, 0x87]);
            let mut elm = connect(FakeElm::silent());
            elm.send(&request).unwrap();
            while elm.recv(Duration::from_secs(1)).is_ok() {}
            elm.link_mut().elm.after_echo = frame.to_vec();
            elm.send(&request).unwrap();
            let err = elm.recv(Duration::from_secs(1)).unwrap_err();
            assert!(err.to_string().contains(why), "{frame:?}: {err}");
        };
        let vag = Target::Physical29(0x17FC_0010);
        fails_closed(vag, b"77A 03 62 F1 87\r", "not a 29-bit frame");
        fails_closed(vag, b"18 DA F1 10 03 62 F1 87\r", "receive filter");
        fails_closed(vag, b"17 FE 01 10 03 62 F1 87\r", "receive filter");
        // And the other way round.
        let gateway = Target::Physical(0x710);
        fails_closed(gateway, b"17 FE 00 10 03 62 F1 87\r", "not an 11-bit frame");
        // Headers off after a reset: the data alone reads like a 29-bit frame (#146).
        fails_closed(gateway, b"03 62 F1 87 34\r", "not an 11-bit frame");
    }

    // A car whose module 0x5F speaks TP2.0: it gives channel 0x740/0x300 and closes it again.
    fn tp20_car() -> FakeElm {
        FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x200, [0x5F, 0xC0, ..]) => {
                vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
            }
            (0x740, [0xA8]) => vec![(0x300, vec![0xA8])],
            (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
            _ => Vec::new(),
        }))
    }

    #[test]
    fn a_tp20_channel_setup_goes_out_raw_and_its_reply_comes_back_whole() {
        let mut elm = connect(tp20_car());
        // An ISO-TP request first shows the adapter echoes each character as it reads it.
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let before = commands(&elm).len();
        let policy = Policy::read_only();
        let setup = policy.approve_tp20_setup(0x5F).unwrap();
        elm.send(&setup).unwrap();
        assert_eq!(
            elm.recv(Duration::from_secs(1)).unwrap(),
            Response::new(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])
        );
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let channel = policy
            .tp20_channel(&setup, 0x25F, &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])
            .unwrap();
        elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .unwrap();
        assert_eq!(
            elm.recv(Duration::from_secs(1)).unwrap(),
            Response::new(0x300, vec![0xA8])
        );
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(
            commands(&elm)[before..],
            [
                "ATCFC0",
                "ATV1",
                "ATCAF0",
                "ATCSM0",
                "ATSH200",
                "ATCRA25F",
                "5FC00010000301",
                "ATSH740",
                "ATCRA300",
                "A8",
                // The reply to `A8` ended the adapter's listen before the caller's wait did.
                "ATMA",
                "ATCAF1",
                "ATV0",
                "ATCFC1",
                "ATCSM1",
                "ATSH7E0",
                "ATCRA7E8",
                "0902",
            ]
        );
        assert_eq!(
            elm.link().elm.sent[1..3],
            [
                (0x200, vec![0x5F, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
                (0x740, vec![0xA8]),
            ]
        );
    }

    #[test]
    fn raw_mode_needs_an_adapter_that_echoes_characters_as_it_reads_them() {
        // Before any request has shown it, `ATCFC0` isn't written: one flipped bit could make it
        // a bus request, and only an early echo stops that before its carriage return.
        let mut elm = connect(tp20_car());
        let written = elm.link().written.len();
        let err = elm
            .send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("ATCFC0"), "{err}");
        assert_eq!(elm.link().written.len(), written);
        assert_eq!(elm.link().elm.sent, []);
    }

    const RAW_ON: [&str; 3] = ["ATCFC0", "ATV1", "ATCAF0"];
    const RAW_OFF: [&str; 3] = ["ATCAF1", "ATV0", "ATCFC1"];

    #[test]
    fn a_misheard_mode_switch_never_reaches_the_bus() {
        // Every bit of every character of every switch command: the echo shows the flip before
        // the carriage return, so the line is ended with `XX` and the adapter refuses it.
        // The monitor's ACK setting differs by adapter: `AT CSM` on an ELM327, `STCMM` on an STN.
        let read = approve(Target::Physical(0x7E0), &[0x09, 0x02]);
        for (stn, ack_on, ack_off) in [(false, "ATCSM0", "ATCSM1"), (true, "STCMM1", "STCMM0")] {
            let on = RAW_ON.into_iter().chain([ack_on]).map(|c| (false, c));
            let off = RAW_OFF.into_iter().chain([ack_off]).map(|c| (true, c));
            for (leaving, command) in on.chain(off) {
                for index in 0..command.len() {
                    for bit in 0..8 {
                        let mut car = tp20_car();
                        if stn {
                            car.sti = Some("STN2232 v5.12.4".into());
                        }
                        let mut elm = connect(car);
                        elm.send(&read).unwrap();
                        while elm.recv(Duration::from_secs(1)).is_ok() {}
                        let setup = Policy::read_only().approve_tp20_setup(0x5F).unwrap();
                        if leaving {
                            elm.send(&setup).unwrap();
                            while elm.recv(Duration::from_secs(1)).is_ok() {}
                        }
                        let sent = elm.link().elm.sent.len();
                        elm.link_mut().corrupt_write_of =
                            Some((command.as_bytes().to_vec(), index, 1 << bit));
                        let request = if leaving { &read } else { &setup };
                        let result = elm.send(request);
                        assert!(elm.link().corrupt_write_of.is_none(), "{command}");
                        let on_bus = &elm.link().elm.sent[sent..];
                        // A flip of a letter's case is the same command to the adapter: then only
                        // the request itself goes out. Any other flip is caught before the return.
                        if result.is_ok() {
                            assert_eq!(bit, 5, "{command} {index}");
                            assert_eq!(on_bus.len(), 1, "{command} {index}");
                        } else {
                            assert_eq!(on_bus, [], "{command} {index} {bit}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_misheard_mode_switch_is_still_reported() {
        // The audit log needs the command that may have reached the adapter, even when its echo
        // shows the adapter heard something else.
        use obdcracker_transport::LinkEvent;
        let mut elm = connect(tp20_car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.take_events();
        elm.link_mut().corrupt_write_of = Some((b"ATV1".to_vec(), 2, 0x01));
        let setup = Policy::read_only().approve_tp20_setup(0x5F).unwrap();
        assert!(elm.send(&setup).is_err());
        let commands: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Command { command, .. } => Some(command),
                _ => None,
            })
            .collect();
        assert_eq!(commands, ["ATCFC0", "ATV1"]);
    }

    // `tp20_car` as an STN on a fast link: its replies aren't paced, so adaptive timing is on
    // unless the driver turns it off (docs/elm327.md#timing).
    fn unpaced_tp20_car() -> FakeElm {
        let mut car = tp20_car();
        car.sti = Some("STN2232 v5.12.4".into());
        car
    }

    // Connects to `car` and sends an ISO-TP request, which shows the adapter echoes characters
    // as it reads them (raw mode needs that).
    fn with_echo_shown(car: FakeElm) -> Elm<FakeLink> {
        let mut elm = connect(car);
        read_vin(&mut elm);
        elm
    }

    fn open_tp20(elm: &mut Elm<FakeLink>) {
        elm.send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
    }

    fn read_vin(elm: &mut Elm<FakeLink>) {
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
    }

    fn atat_since(elm: &Elm<FakeLink>, before: usize) -> Vec<String> {
        commands(elm)[before..]
            .iter()
            .filter(|c| c.starts_with("ATAT"))
            .cloned()
            .collect()
    }

    #[test]
    fn raw_mode_turns_adaptive_timing_off_on_an_unpaced_adapter_and_back_on() {
        // A learned timeout from the fast setup replies ended the wait for a module's data
        // frames after its ACK, so the session gave up before its own deadline (#218).
        let mut elm = with_echo_shown(unpaced_tp20_car());
        let before = commands(&elm).len();
        open_tp20(&mut elm);
        assert_eq!(
            commands(&elm)[before..],
            [
                "ATCFC0",
                "ATV1",
                "ATCAF0",
                "STCMM1",
                "STBC1",
                "ATAT0",
                "ATSH200",
                "ATCRA25F",
                "5FC00010000301"
            ]
        );
        let before = commands(&elm).len();
        read_vin(&mut elm);
        assert_eq!(
            commands(&elm)[before..],
            [
                "ATCAF1", "ATV0", "ATCFC1", "STCMM0", "STBC0", "ATAT1", "ATSH7E0", "ATCRA7E8",
                "0902"
            ]
        );
        // And off again for the next channel.
        let before = commands(&elm).len();
        open_tp20(&mut elm);
        assert_eq!(atat_since(&elm, before), ["ATAT0"]);
    }

    #[test]
    fn a_paced_adapter_gets_no_adaptive_timing_commands_after_connecting() {
        // It runs with adaptive timing off throughout (PR #70).
        let mut elm = with_echo_shown(tp20_car());
        let before = commands(&elm).len();
        open_tp20(&mut elm);
        read_vin(&mut elm);
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        elm.patient(None).unwrap();
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
    }

    #[test]
    fn a_patient_window_opened_in_raw_mode_keeps_adaptive_timing_off_after_raw_ends() {
        // Raw mode stays on after a channel closes, so discovery can open its window in it. The
        // switch back to ISO-TP must not undo the window's `ATAT0`.
        let mut elm = with_echo_shown(unpaced_tp20_car());
        open_tp20(&mut elm);
        let before = commands(&elm).len();
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
        read_vin(&mut elm);
        assert!(commands(&elm)[before..].iter().any(|c| c == "ATCFC1"));
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
        // Closing the window turns it back on, once.
        elm.patient(None).unwrap();
        assert_eq!(atat_since(&elm, before), ["ATAT1"]);
    }

    #[test]
    fn closing_a_patient_window_in_raw_mode_leaves_adaptive_timing_off() {
        let mut elm = with_echo_shown(unpaced_tp20_car());
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        open_tp20(&mut elm);
        let before = commands(&elm).len();
        elm.patient(None).unwrap();
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
        // The next channel finds raw mode on already: nothing to switch.
        open_tp20(&mut elm);
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
        // Leaving raw mode turns adaptive timing on, once.
        read_vin(&mut elm);
        assert_eq!(atat_since(&elm, before), ["ATAT1"]);
    }

    #[test]
    fn a_patient_window_sends_each_adaptive_timing_command_once() {
        let mut elm = connect(unpaced_tp20_car());
        let before = commands(&elm).len();
        elm.patient(None).unwrap();
        assert_eq!(atat_since(&elm, before), Vec::<String>::new());
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        elm.patient(Some(Duration::from_secs(2))).unwrap();
        elm.patient(None).unwrap();
        elm.patient(None).unwrap();
        assert_eq!(atat_since(&elm, before), ["ATAT0", "ATAT1"]);
    }

    #[test]
    fn a_misheard_adaptive_timing_command_never_reaches_the_bus() {
        // As the other mode switch commands: `ATAT0` and `ATAT1` are checked before their
        // carriage return, whichever bit flips.
        for (leaving, command) in [(false, "ATAT0"), (true, "ATAT1")] {
            for index in 0..command.len() {
                for bit in 0..8 {
                    let mut elm = with_echo_shown(unpaced_tp20_car());
                    if leaving {
                        open_tp20(&mut elm);
                    }
                    let sent = elm.link().elm.sent.len();
                    elm.link_mut().corrupt_write_of =
                        Some((command.as_bytes().to_vec(), index, 1 << bit));
                    let result = if leaving {
                        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                    } else {
                        elm.send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
                    };
                    assert!(elm.link().corrupt_write_of.is_none(), "{command}");
                    let on_bus = &elm.link().elm.sent[sent..];
                    if result.is_ok() {
                        assert_eq!(bit, 5, "{command} {index}");
                        assert_eq!(on_bus.len(), 1, "{command} {index}");
                    } else {
                        assert_eq!(on_bus, [], "{command} {index} {bit}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_raw_reply_like_a_first_frame_gets_no_flow_control() {
        // With `CAF0` alone the adapter would still answer a frame starting `1x` with flow
        // control of its own, which the policy never approved.
        let mut elm = connect(FakeElm::new(Box::new(|header, request| {
            match (header, request) {
                (0x200, [0x60, 0xC0, ..]) => vec![(0x260, vec![0x10, 0x00, 0x02, 0xAA, 0xBB])],
                (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
                _ => Vec::new(),
            }
        })));
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let before = elm.link().elm.flow_control_for.len();
        elm.send(&Policy::read_only().approve_tp20_setup(0x60).unwrap())
            .unwrap();
        assert_eq!(
            elm.recv(Duration::from_secs(1)).unwrap().payload,
            [0x10, 0x00, 0x02, 0xAA, 0xBB]
        );
        assert_eq!(elm.link().elm.flow_control_for[before..], [0u32; 0]);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(elm.link().elm.flow_control_for[before..], [0x7E8]);
    }

    // A TP2.0 module at 0x5F that answers `1A 9B` in three frames, the second asking for an
    // ACK and the third sent only once it has one. The adapter listens after each raw frame
    // until the host writes, as a real one does for its whole timeout.
    fn tp20_reading_car() -> FakeElm {
        let mut car = FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x200, [0x5F, 0xC0, ..]) => {
                vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
            }
            (0x740, [0xA0, ..]) => vec![(0x300, vec![0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF])],
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => vec![
                (0x300, vec![0xB1]),
                (0x300, vec![0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43]),
                (0x300, vec![0x01, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A]),
            ],
            (0x740, [0xB2]) => vec![(0x300, vec![0x12, 0x4B, 0x4C])],
            (0x740, [0xA8]) => vec![(0x300, vec![0xA8])],
            (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
            _ => Vec::new(),
        }));
        car.listen_raw = true;
        car
    }

    #[test]
    fn an_ack_interrupts_the_adapter_instead_of_waiting_out_its_timeout() {
        use obdcracker_transport::Timing;
        use obdcracker_transport::tp20::{ChannelSession, Disconnect};
        let mut elm = connect(tp20_reading_car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_millis(100),
            ..Timing::default()
        };
        let started = Instant::now();
        let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
        assert_eq!(
            session.request(&[0x1A, 0x9B]).unwrap(),
            b"\x5A\x9BABCDEFGHIJKL"
        );
        assert_eq!(session.close(), Ok(Disconnect::Closed));
        // Each frame after the first stopped the adapter's listening for the last.
        assert!(
            started.elapsed() < ADAPTER_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            elm.link().elm.sent[1..],
            [
                (0x200, vec![0x5F, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
                (0x740, vec![0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]),
                (0x740, vec![0x10, 0x00, 0x02, 0x1A, 0x9B]),
                (0x740, vec![0xB2]),
                (0x740, vec![0xB3]),
                (0x740, vec![0xA8]),
            ]
        );
        assert_eq!(elm.link().elm.interrupted, 5);
    }

    #[test]
    fn an_interrupt_that_crosses_the_prompt_is_refused_not_run() {
        // The adapter's timeout runs out just as `X` is written, so `X` starts a line: the
        // driver ends it as `XX`, which the adapter refuses, and nothing more reaches the bus.
        use obdcracker_transport::Timing;
        use obdcracker_transport::tp20::ChannelSession;
        let mut car = tp20_reading_car();
        car.listen_ends_on_write = true;
        let mut elm = connect(car);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_millis(100),
            ..Timing::default()
        };
        let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
        assert_eq!(
            session.request(&[0x1A, 0x9B]).unwrap(),
            b"\x5A\x9BABCDEFGHIJKL"
        );
        drop(session);
        assert_eq!(elm.link().elm.interrupted, 0);
        assert_eq!(elm.link().elm.sent.len(), 7);
        let refused = commands(&elm).iter().filter(|c| *c == "XX").count();
        assert_eq!(refused, 5, "{:?}", commands(&elm));
    }

    #[test]
    fn a_broken_adapter_isnt_interrupted_before_a_channel_frame() {
        let mut elm = connect(tp20_reading_car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let policy = Policy::read_only();
        let setup = policy.approve_tp20_setup(0x5F).unwrap();
        elm.send(&setup).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        let channel = policy
            .tp20_channel(&setup, reply.source, &reply.payload)
            .unwrap();
        elm.send(&policy.approve_tp20_parameters(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0xA1);
        // Broken while the adapter still listens after the channel's last frame.
        let mut overlong = vec![b'7'; 200];
        overlong.push(b'\r');
        elm.link_mut().inject = overlong;
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
        let written = elm.link().written.len();
        assert!(
            elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
                .is_err()
        );
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn a_misheard_interrupt_never_reaches_the_bus() {
        // Every bit of `X`, and of the `X\r` that ends it when the prompt came first: at worst
        // the driver stops, and the bus gets only the frames the policy built.
        use obdcracker_transport::Timing;
        use obdcracker_transport::tp20::ChannelSession;
        for (crossing, write) in [(false, &b"X"[..]), (true, b"X"), (true, b"X\r")] {
            for index in 0..write.len() {
                for bit in 0..8 {
                    let mut car = tp20_reading_car();
                    car.listen_ends_on_write = crossing;
                    let mut elm = connect(car);
                    elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                        .unwrap();
                    while elm.recv(Duration::from_secs(1)).is_ok() {}
                    elm.link_mut().corrupt_write_of = Some((write.to_vec(), index, 1 << bit));
                    let policy = Policy::read_only();
                    let timing = Timing {
                        p2: Duration::from_millis(100),
                        ..Timing::default()
                    };
                    if let Ok(mut session) = ChannelSession::open(&mut elm, &policy, 0x5F, timing) {
                        let _ = session.request(&[0x1A, 0x9B]);
                    }
                    let built: Vec<Vec<u8>> = [
                        &[0x5F, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01][..],
                        &[0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF],
                        &[0x10, 0x00, 0x02, 0x1A, 0x9B],
                        &[0xB2],
                        &[0xB3],
                        &[0xA8],
                    ]
                    .iter()
                    .map(|frame| frame.to_vec())
                    .collect();
                    for (_, frame) in &elm.link().elm.sent[1..] {
                        assert!(
                            built.contains(frame),
                            "{crossing} {index} {bit}: {frame:02X?}"
                        );
                    }
                }
            }
        }
    }

    // An STN with module 0x5F on channel 0x740/0x300 that ends a raw listen after one frame
    // (#227). A request frame gets its immediate reply, and the frames after it come `delay`
    // later; the adapter hears them only if it listens again by then.
    fn one_frame_stn(delay: Duration) -> FakeElm {
        let mut car = FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x200, [0x5F, 0xC0, ..]) => {
                vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
            }
            (0x740, [0xA0, ..]) => vec![(0x300, vec![0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF])],
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => vec![(0x300, vec![0xB1])],
            (0x740, [0xB2]) => vec![(0x300, vec![0x22, 0x4B])],
            (0x740, [0xA8]) => vec![(0x300, vec![0xA8])],
            (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
            _ => Vec::new(),
        }));
        car.sti = Some("STN2232 v5.12.4".into());
        car.listen_raw = true;
        car.listen_one_frame = true;
        // Firmware without batched commands: the frames are listened to by re-arming `STM`.
        car.stbc_unsupported = true;
        car.delayed = Some(Box::new(move |header, request| match (header, request) {
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => vec![
                (
                    delay,
                    0x300,
                    vec![0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43],
                ),
                (
                    delay + Duration::from_millis(1),
                    0x300,
                    vec![0x01, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A],
                ),
            ],
            (0x740, [0xB2]) => vec![(delay, 0x300, vec![0x13, 0x4C])],
            _ => Vec::new(),
        }));
        car
    }

    // `one_frame_stn` with the module's frames due `delay` after the adapter starts monitoring,
    // not after the request. #227 is about a module that answers just after the host starts
    // listening; counting from the request let a test thread that was descheduled between the
    // ACK and its `recv` lose the frames before the driver could monitor.
    fn one_frame_stn_from_monitor(delay: Duration) -> FakeElm {
        let mut car = one_frame_stn(delay);
        car.delay_from_monitor = true;
        car
    }

    #[test]
    fn frames_due_from_the_monitor_wait_for_it_however_long_the_host_takes() {
        // 0 ms after the monitor starts, and the host takes 50 ms to start it: the frames are
        // heard, none lost.
        let mut elm = with_echo_shown(one_frame_stn_from_monitor(Duration::ZERO));
        request_sent(&mut elm);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x20);
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x01);
        assert_eq!(elm.link().elm.lost_frames, []);
    }

    #[test]
    fn frames_due_from_the_monitor_never_arrive_if_nothing_monitors() {
        // The trigger never fires: the frames are not on the bus, so they are not lost either,
        // and a caller waiting for them times out.
        let mut elm = with_echo_shown(one_frame_stn_from_monitor(Duration::ZERO));
        request_sent(&mut elm);
        std::thread::sleep(Duration::from_millis(20));
        elm.link_mut().elm.poll();
        assert_eq!(elm.link().elm.next_frame_at(), None);
        assert_eq!(elm.link().elm.lost_frames, []);
    }

    // Opens channel 0x740/0x300 on `elm` and sends the `1A 9B` request; the module's ACK has
    // been read when this returns.
    fn request_sent(elm: &mut Elm<FakeLink>) -> obdcracker_safety::OpenTp20Channel {
        let policy = Policy::read_only();
        let setup = policy.approve_tp20_setup(0x5F).unwrap();
        elm.send(&setup).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        let channel = policy
            .tp20_channel(&setup, reply.source, &reply.payload)
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&policy.approve_tp20_parameters(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0xA1);
        let request = policy
            .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
            .unwrap();
        elm.send(&request).unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xB1]);
        channel
    }

    #[test]
    fn a_tp20_answer_right_after_the_ack_is_heard_and_acked() {
        // The STN prints its prompt after the module's ACK, and the module's data follows 5 ms
        // later: with nothing listening, that frame was lost (#227). The 5 ms run from when the
        // adapter starts monitoring, so a loaded test thread can't make the module early. The
        // second frame, 1 ms after the first, is meant to be heard too: monitor mode keeps
        // listening after the first frame, and `lost_frames` stays empty.
        let mut elm = with_echo_shown(one_frame_stn_from_monitor(Duration::from_millis(5)));
        let channel = request_sent(&mut elm);
        let policy = Policy::read_only();
        let data = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!(
            data.payload,
            [0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43]
        );
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x01);
        elm.send(&policy.approve_tp20_ack(&channel, 2).unwrap())
            .unwrap();
        assert_eq!(
            elm.link().elm.sent.last(),
            Some(&(0x740, vec![0xB2])),
            "the ACK went out"
        );
        assert_eq!(elm.link().elm.lost_frames, []);
        // Nothing went out between the request and the ACK: no `A3` to re-arm the listen (#227).
        let sent = &elm.link().elm.sent;
        assert_eq!(
            sent[sent.len() - 2..],
            [
                (0x740, vec![0x10, 0x00, 0x02, 0x1A, 0x9B]),
                (0x740, vec![0xB2])
            ]
        );
    }

    use obdcracker_transport::Timing;
    use obdcracker_transport::tp20::{ChannelError, ChannelSession, Disconnect};

    // How long after the tester's data frame the module ACKs it, how long it then takes to
    // start a single-frame answer, and how long the STN takes to start monitoring after `STM` is
    // written. Car session 11 (#333): 35 to 52 ms, 160 ms, and about 15 ms for the echo round
    // trip plus the start. The times are wider apart than the car's so that a loaded test thread
    // can't move a frame to the other side of the monitor's start.
    const ACK_AFTER: Duration = Duration::from_millis(60);
    const ANSWER_AFTER_ACK: Duration = Duration::from_millis(150);
    const MONITOR_STARTUP: Duration = Duration::from_millis(45);

    // An STN that ends a raw listen with its prompt after the first frame and takes
    // `MONITOR_STARTUP` to monitor, in front of the TP2.0 module at `address` that listens on
    // `tester_id` and sends on 0x300, as in A7 session 11 (#333). The module ACKs each data frame
    // `ACK_AFTER` after it, and every frame it sends goes on the bus at a time counted from that
    // ACK (`ANSWER_AFTER_ACK` for its single-frame answers, `answer` for its answer to
    // `22 F1 87`), whatever the adapter is doing: a frame that arrives before the monitor is up
    // is lost. `start_answer` is its answer to `10 89`.
    fn stn_losing_frames_after_the_ack(
        address: u8,
        tester_id: u32,
        start_answer: &[u8],
        answer: Vec<(Duration, Vec<u8>)>,
    ) -> FakeElm {
        let [low, high, ..] = tester_id.to_le_bytes();
        let setup_reply = vec![0x00, 0xD0, 0x00, 0x03, low, high, 0x01];
        let setup_source = 0x200 + u32::from(address);
        let mut car = FakeElm::new(Box::new(move |header, request| match (header, request) {
            (0x200, [first, 0xC0, ..]) if *first == address => {
                vec![(setup_source, setup_reply.clone())]
            }
            (id, [0xA0, ..]) if id == tester_id => {
                vec![(0x300, vec![0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF])]
            }
            (id, [0xA8]) if id == tester_id => vec![(0x300, vec![0xA8])],
            (0x7E0, [0x09, 0x02]) => vec![(0x7E8, VIN.to_vec())],
            _ => Vec::new(),
        }));
        car.sti = Some("STN2232 v5.12.4".into());
        car.listen_raw = true;
        car.listen_one_frame = true;
        car.monitor_startup = MONITOR_STARTUP;
        let start_answer = start_answer.to_vec();
        car.delayed = Some(Box::new(move |header, request| {
            if header != tester_id {
                return Vec::new();
            }
            let ack = |next: u8| (ACK_AFTER, 0x300, vec![0xB0 | next]);
            let later = |frame: &[u8]| (ACK_AFTER + ANSWER_AFTER_ACK, 0x300, frame.to_vec());
            match request {
                [0x10, 0x00, 0x02, 0x10, 0x89] => vec![ack(1), later(&start_answer)],
                [0x11, 0x00, 0x02, 0x1A, 0x9B] => {
                    vec![ack(2), later(&[0x11, 0x00, 0x03, 0x7F, 0x1A, 0x11])]
                }
                [0x12, 0x00, 0x03, 0x22, 0xF1, 0x87] => {
                    let mut frames = vec![ack(3)];
                    frames.extend(
                        answer
                            .iter()
                            .map(|(after, frame)| (ACK_AFTER + *after, 0x300, frame.clone())),
                    );
                    frames
                }
                _ => Vec::new(),
            }
        }));
        car
    }

    // What the last read gave, and the frames the adapter lost.
    type ReadAndLost = (Result<Vec<u8>, ChannelError>, Vec<(u32, Vec<u8>)>);

    // Opens the channel to `address` on `car` and reads, as the A7's passes did: `10 89`, `1A 9B`
    // (which both modules refused) and then the one that matters, `22 F1 87`.
    fn read_f187_after_two_requests(car: FakeElm, address: u8) -> ReadAndLost {
        let mut elm = with_echo_shown(car);
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_secs(1),
            ..Timing::default()
        };
        let mut session = ChannelSession::open(&mut elm, &policy, address, timing).unwrap();
        session.request(&[0x10, 0x89]).unwrap();
        session.request(&[0x1A, 0x9B]).unwrap();
        let read = session.request(&[0x22, 0xF1, 0x87]);
        drop(session);
        (read, elm.link().elm.lost_frames.clone())
    }

    #[test]
    fn a_tp20_answer_that_starts_while_the_stn_re_arms_after_the_ack_is_heard_whole_module_52() {
        // Session 11, module 52 (4DB to 300): its answer to `22 F1 87` is ACKed (`B3`), then
        // `22 ..` and `23 ..` come about 10 and 20 ms later, while the STN, which printed its
        // prompt after the ACK, is writing and starting `STM`. Only `14 47 20` was heard, with
        // sequence 4 where 2 was due, and the session closed the channel. The part number's
        // first 9 bytes are invented; its last two are the car's.
        let answer = vec![
            (
                Duration::from_millis(10),
                vec![0x22, 0x00, 0x0E, 0x62, 0xF1, 0x87, 0x34, 0x47],
            ),
            (
                Duration::from_millis(20),
                vec![0x23, 0x38, 0x35, 0x39, 0x37, 0x39, 0x33, 0x30],
            ),
            (Duration::from_millis(100), vec![0x14, 0x47, 0x20]),
        ];
        let car =
            stn_losing_frames_after_the_ack(0x52, 0x4DB, &[0x10, 0x00, 0x02, 0x50, 0x89], answer);
        let (read, lost) = read_f187_after_two_requests(car, 0x52);
        assert_eq!(
            read,
            Ok(b"\x62\xF1\x87\x34\x47\x38\x35\x39\x37\x39\x33\x30\x47\x20".to_vec())
        );
        assert_eq!(lost, []);
    }

    #[test]
    fn a_tp20_answer_that_starts_while_the_stn_re_arms_after_the_ack_is_heard_whole_module_20() {
        // Session 11, module 20 (518 to 300): `22 ..` is lost, and the heard `23 30 39 30 37 30
        // 36 33` has sequence 3 where 2 was due, with `14 43 47` right behind it, unread.
        let answer = vec![
            (
                Duration::from_millis(10),
                vec![0x22, 0x00, 0x0E, 0x62, 0xF1, 0x87, 0x34, 0x47],
            ),
            (
                Duration::from_millis(100),
                vec![0x23, 0x30, 0x39, 0x30, 0x37, 0x30, 0x36, 0x33],
            ),
            (Duration::from_millis(101), vec![0x14, 0x43, 0x47]),
        ];
        let car = stn_losing_frames_after_the_ack(
            0x20,
            0x518,
            &[0x10, 0x00, 0x03, 0x7F, 0x10, 0x22],
            answer,
        );
        let (read, lost) = read_f187_after_two_requests(car, 0x20);
        assert_eq!(
            read,
            Ok(b"\x62\xF1\x87\x34\x47\x30\x39\x30\x37\x30\x36\x33\x43\x47".to_vec())
        );
        assert_eq!(lost, []);
    }

    #[test]
    fn with_batching_refused_the_old_gap_remains() {
        // The same replay on firmware without batched commands (`STBC` answers `?`): the driver
        // does what it did before and loses the same frames, which is why the design keeps this
        // case on record (docs/design/tp20-stn-listen.md).
        let answer = vec![
            (
                Duration::from_millis(10),
                vec![0x22, 0x00, 0x0E, 0x62, 0xF1, 0x87, 0x34, 0x47],
            ),
            (
                Duration::from_millis(20),
                vec![0x23, 0x38, 0x35, 0x39, 0x37, 0x39, 0x33, 0x30],
            ),
            (Duration::from_millis(100), vec![0x14, 0x47, 0x20]),
        ];
        let mut car =
            stn_losing_frames_after_the_ack(0x52, 0x4DB, &[0x10, 0x00, 0x02, 0x50, 0x89], answer);
        car.stbc_unsupported = true;
        let (read, lost) = read_f187_after_two_requests(car, 0x52);
        // The car's framing error; a test thread so slow that even the last frame is lost reads
        // a timeout instead, which is the same gap.
        assert!(
            matches!(read, Err(ChannelError::Framing(_) | ChannelError::Timeout)),
            "{read:?}"
        );
        assert_ne!(lost.len(), 0);
    }

    // `one_frame_stn` on firmware with batched commands.
    fn batching_stn(delay: Duration) -> FakeElm {
        let mut car = one_frame_stn(delay);
        car.stbc_unsupported = false;
        car
    }

    // Opens the channel to the module at `address` on `elm`: the setup and the parameters, both
    // answered.
    fn open_channel(elm: &mut Elm<FakeLink>, address: u8) -> obdcracker_safety::OpenTp20Channel {
        let policy = Policy::read_only();
        let setup = policy.approve_tp20_setup(address).unwrap();
        elm.send(&setup).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        let channel = policy
            .tp20_channel(&setup, reply.source, &reply.payload)
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&policy.approve_tp20_parameters(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0xA1);
        channel
    }

    // The channel frames, batching switches and monitors the driver wrote, in order.
    fn batching_commands(elm: &Elm<FakeLink>) -> Vec<String> {
        commands(elm)
            .iter()
            .filter(|c| {
                c.starts_with("STBC")
                    || c.contains('|')
                    || *c == "STM"
                    || c.starts_with("A0")
                    || *c == "A3"
                    || *c == "A8"
            })
            .cloned()
            .collect()
    }

    fn logged_commands(elm: &mut Elm<FakeLink>) -> Vec<(String, Vec<String>)> {
        use obdcracker_transport::LinkEvent;
        elm.take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Command {
                    command, answer, ..
                } => Some((command, answer)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_batched_session_writes_a_frame_and_stm_as_one_line_and_never_re_arms() {
        use obdcracker_transport::tp20::{ChannelSession, Disconnect};
        let mut elm = with_echo_shown(batching_stn(Duration::from_millis(5)));
        elm.take_events();
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_millis(100),
            ..Timing::default()
        };
        let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
        assert_eq!(
            session.request(&[0x1A, 0x9B]).unwrap(),
            b"\x5A\x9BABCDEFGHIJKL"
        );
        assert_eq!(session.close(), Ok(Disconnect::Closed));
        assert_eq!(elm.link().elm.lost_frames, []);
        // The data frame and the two ACKs it needed went as batches; the parameters and the
        // disconnect, answered by one frame each, did not. No standalone `STM`.
        assert_eq!(
            batching_commands(&elm),
            [
                "STBC1",
                "A00F8AFF32FF",
                "1000021A9B|STM",
                "B2|STM",
                "B4|STM",
                "A8"
            ]
        );
        // Leaving raw mode puts batching back, once.
        read_vin(&mut elm);
        assert_eq!(count(&elm, "STBC0"), 1);
        // The probe and each batched `STM` are in the log as commands, before anything else the
        // frame did.
        let logged = logged_commands(&mut elm);
        let stm = logged.iter().filter(|(c, _)| c == "STM").count();
        assert_eq!(stm, 3, "{logged:?}");
        assert!(logged.contains(&("STBC1".to_owned(), vec!["OK".to_owned()])));
        assert!(logged.contains(&("STBC0".to_owned(), vec!["OK".to_owned()])));
    }

    #[test]
    fn a_probe_that_isnt_ok_leaves_the_old_path_and_isnt_asked_again() {
        use obdcracker_transport::tp20::{ChannelSession, Disconnect};
        for says in [None, Some("WHAT")] {
            let mut car = if says.is_some() {
                batching_stn(Duration::from_millis(5))
            } else {
                one_frame_stn(Duration::from_millis(5))
            };
            car.delay_from_monitor = true;
            car.stbc_says = says.map(str::to_owned);
            let mut elm = with_echo_shown(car);
            let policy = Policy::read_only();
            let timing = Timing {
                p2: Duration::from_millis(100),
                ..Timing::default()
            };
            let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
            assert_eq!(
                session.request(&[0x1A, 0x9B]).unwrap(),
                b"\x5A\x9BABCDEFGHIJKL"
            );
            assert_eq!(session.close(), Ok(Disconnect::Closed));
            // Asked once, answered something other than `OK`, and so never batched: re-armed as
            // before, and nothing with a pipe was written.
            assert_eq!(count(&elm, "STBC1"), 1, "{says:?}");
            assert!(!elm.link().written.contains(&b'|'), "{says:?}");
            assert_eq!(count(&elm, "STM"), 2, "{says:?}");
            assert_eq!(count(&elm, "STBC0"), 0, "{says:?}");
            // The next channel doesn't ask again, and nothing is put back.
            read_vin(&mut elm);
            open_tp20(&mut elm);
            read_vin(&mut elm);
            assert_eq!(count(&elm, "STBC1"), 1, "{says:?}");
            assert_eq!(count(&elm, "STBC0"), 0, "{says:?}");
        }
    }

    #[test]
    fn only_an_stn_is_asked_to_batch() {
        // A plain ELM327 is never sent `STBC`; its whole byte stream is fixed, above.
        let mut plain = batching_stn(Duration::from_secs(60));
        plain.sti = None;
        let mut elm = with_echo_shown(plain);
        open_tp20(&mut elm);
        read_vin(&mut elm);
        assert_eq!(count(&elm, "STBC1") + count(&elm, "STBC0"), 0);
    }

    #[test]
    fn only_a_frame_the_module_answers_after_its_ack_is_batched() {
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        let channel = open_channel(&mut elm, 0x5F);
        let policy = Policy::read_only();
        elm.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
            .unwrap();
        elm.send(
            &policy
                .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
                .unwrap(),
        )
        .unwrap();
        elm.send(&policy.approve_tp20_ack(&channel, 2).unwrap())
            .unwrap();
        elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .unwrap();
        assert_eq!(
            batching_commands(&elm),
            [
                "STBC1",
                "A00F8AFF32FF",
                "A3",
                "1000021A9B|STM",
                "B2|STM",
                "A8"
            ]
        );
    }

    #[test]
    fn no_single_bit_error_in_a_batched_line_puts_another_frame_on_the_bus() {
        // The digits are echoed and checked before `|STM` is written, so a flip in them is ended
        // with `XX` into a line that isn't hex and nothing is sent. A flip in `|STM`, or in a
        // character that becomes a carriage return (an `M`), can leave the digits as a complete
        // first element, which the adapter sends as it was checked: the approved frame, once,
        // never another. A flip of a letter's case is the same line.
        let line = b"1000021A9B|STM";
        let digits = 10;
        let approved = (0x740, vec![0x10, 0x00, 0x02, 0x1A, 0x9B]);
        let mut same = 0;
        let mut once = 0;
        for index in 0..line.len() {
            for bit in 0..8 {
                let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
                let channel = open_channel(&mut elm, 0x5F);
                let sent = elm.link().elm.sent.len();
                let frame = Policy::read_only()
                    .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
                    .unwrap();
                // The flipped character is in the write that holds it.
                elm.link_mut().corrupt_write_of = if index < digits {
                    Some((line[..digits].to_vec(), index, 1 << bit))
                } else {
                    Some((line[digits..].to_vec(), index - digits, 1 << bit))
                };
                let result = elm.send(&frame);
                assert!(elm.link().corrupt_write_of.is_none(), "{index} {bit}");
                let on_bus = &elm.link().elm.sent[sent..];
                if bit == 5 && line[index].is_ascii_alphabetic() {
                    same += 1;
                    result.unwrap();
                    assert_eq!(on_bus, std::slice::from_ref(&approved), "{index} {bit}");
                    continue;
                }
                assert!(result.is_err(), "{index} {bit}");
                if on_bus.is_empty() {
                    assert!(
                        commands(&elm).last().unwrap().ends_with("XX"),
                        "{index} {bit}"
                    );
                } else {
                    once += 1;
                    assert!(index >= digits, "{index} {bit}");
                    assert_eq!(on_bus, std::slice::from_ref(&approved), "{index} {bit}");
                }
                let written = elm.link().written.len();
                assert!(elm.send(&frame).is_err());
                assert_eq!(elm.link().written.len(), written);
            }
        }
        // `A`, `B`, `S`, `T` and `M`: the check isn't passing vacuously.
        assert_eq!(same, 5);
        assert!(once > 0);
    }

    #[test]
    fn a_flipped_carriage_return_leaves_a_batched_frame_off_the_bus() {
        // The adapter holds the unfinished line and never runs it (the driver's next write is the
        // class `docs/pitfalls.md` describes for every line, not a batch's alone).
        for bit in 0..8 {
            let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
            let channel = open_channel(&mut elm, 0x5F);
            let sent = elm.link().elm.sent.len();
            let frame = Policy::read_only()
                .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
                .unwrap();
            elm.link_mut().corrupt_write_of = Some((b"\r".to_vec(), 0, 1 << bit));
            let _ = elm.send(&frame);
            assert!(elm.link().corrupt_write_of.is_none(), "{bit}");
            assert_eq!(elm.link().elm.sent.len(), sent, "{bit}");
        }
    }

    #[test]
    fn an_interrupt_before_the_batch_reaches_its_monitor_leaves_the_adapter_idle() {
        // The module's ACK is 60 ms away, so the frame's listen is still running when the next
        // frame goes out and writes `X`. The worst case the manual allows: the batch ends with the
        // listen, and `STM` never starts. `STOPPED` and the prompt follow, the next frame is
        // written as it would be, and the adapter is in a known state.
        let answer = vec![(Duration::from_millis(100), vec![0x14, 0x47, 0x20])];
        let mut elm = with_echo_shown(stn_losing_frames_after_the_ack(
            0x52,
            0x4DB,
            &[0x10, 0x00, 0x02, 0x50, 0x89],
            answer,
        ));
        let channel = open_channel(&mut elm, 0x52);
        let policy = Policy::read_only();
        let sent = elm.link().elm.sent.len();
        elm.send(
            &policy
                .approve_tp20_request(&channel, 0, &[0x10, 0x89])
                .unwrap(),
        )
        .unwrap();
        elm.send(&policy.approve_tp20_keep_alive(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.link().elm.interrupted, 1);
        assert_eq!(
            elm.link().elm.sent[sent..],
            [
                (0x4DB, vec![0x10, 0x00, 0x02, 0x10, 0x89]),
                (0x4DB, vec![0xA3])
            ]
        );
        // And nothing is left running: the next frame stops the A3's listen as usual.
        elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.link().elm.interrupted, 2);
        assert_eq!(count(&elm, "XX"), 0);
    }

    #[test]
    fn a_batch_that_ends_in_a_prompt_is_re_armed_with_a_plain_stm() {
        // The STN lost the batch's `STM` (an error before it, or it was dropped): the prompt
        // comes after the frame's listen, and the driver monitors as it did before batching.
        let mut car = batching_stn(Duration::from_millis(5));
        car.batch_drops_monitor = true;
        car.delay_from_monitor = true;
        let mut elm = with_echo_shown(car);
        request_sent(&mut elm);
        let data = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!(data.payload[0], 0x20);
        assert_eq!(elm.link().elm.lost_frames, []);
        let written = batching_commands(&elm);
        assert_eq!(written[written.len() - 2..], ["1000021A9B|STM", "STM"]);
    }

    #[test]
    fn a_batched_monitor_starts_at_the_acks_time_however_late_the_host_reads() {
        // The module's ACK reaches the adapter over the bus, and its answer follows 1 ms later.
        // The STN switches to monitoring at the ACK, so a host that reads only when both are
        // long due (a descheduled test thread) still hears the answer.
        let mut car = FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x200, [0x5F, 0xC0, ..]) => {
                vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
            }
            (0x740, [0xA0, ..]) => vec![(0x300, vec![0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF])],
            _ => Vec::new(),
        }));
        car.sti = Some("STN2232 v5.12.4".into());
        car.listen_raw = true;
        car.listen_one_frame = true;
        car.stbc_unsupported = false;
        car.delayed = Some(Box::new(|header, request| match (header, request) {
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => vec![
                (Duration::from_millis(2), 0x300, vec![0xB1]),
                (
                    Duration::from_millis(3),
                    0x300,
                    vec![0x20, 0x00, 0x0E, 0x5A, 0x9B, 0x41, 0x42, 0x43],
                ),
            ],
            _ => Vec::new(),
        }));
        let mut elm = with_echo_shown(car);
        let policy = Policy::read_only();
        let setup = policy.approve_tp20_setup(0x5F).unwrap();
        elm.send(&setup).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        let channel = policy
            .tp20_channel(&setup, reply.source, &reply.payload)
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm.send(&policy.approve_tp20_parameters(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0xA1);
        elm.send(
            &policy
                .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
                .unwrap(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xB1]);
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x20);
        assert_eq!(elm.link().elm.lost_frames, []);
    }

    #[test]
    fn a_prompt_after_the_batch_started_its_monitor_is_still_a_failure() {
        // Once the monitor's first line has come (its output follows the pipe), a prompt is the
        // adapter stopping on its own, as for a monitor started by `STM`.
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        elm.link_mut().inject = b"|300 20 00 0E 5A 9B 41 42 43\r>".to_vec();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x20);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("stopped monitoring"), "{err}");
    }

    #[test]
    fn a_second_pipe_in_a_batch_and_a_pipe_outside_one_are_unexpected_output() {
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        elm.link_mut().inject =
            b"|300 20 00 0E 5A 9B 41 42 43\r|300 01 44 45 46 47 48 49 4A\r".to_vec();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x20);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "{err}");
        // Outside a batch: an ISO-TP request's reply.
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        elm.link_mut().elm.after_echo = b"|7E8 10 13 49 02 01 57 41 55\r".to_vec();
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "{err}");
    }

    #[test]
    fn a_pipe_in_the_monitor_after_the_batch_printed_none_is_unexpected_output() {
        // The STN printed the frame's reply and then monitor lines with no pipe at all: the
        // batch's pipe isn't still to come, so a `|` that starts a later line is not taken for it.
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        elm.link_mut().inject = b"300 20 00 0E 5A 9B 41 42 43\r|300 01 44 45 46 47 48 49 4A\r".to_vec();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload[0], 0x20);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "{err}");
    }

    #[test]
    fn a_batched_stm_is_not_logged_when_the_digits_before_it_were_misheard() {
        // The `STM` is logged once the digits are written and echoed right, before its own bytes
        // go out: a wrong echo ends the line with the kill and `|STM` is never written.
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        let channel = open_channel(&mut elm, 0x5F);
        elm.take_events();
        let frame = Policy::read_only()
            .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
            .unwrap();
        elm.link_mut().corrupt_write_of = Some((b"1000021A9B".to_vec(), 3, 0x01));
        let err = elm.send(&frame).unwrap_err();
        assert!(err.to_string().contains("echoed"), "{err}");
        assert!(logged_commands(&mut elm).is_empty());
        assert!(!commands(&elm).iter().any(|c| c.contains("STM")));
    }

    #[test]
    fn a_batched_stm_and_the_probe_are_logged_when_their_writes_fail() {
        // The audit log is written before the adapter acts, and however the write ends: a line
        // that failed part-way may still have run.
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        let channel = open_channel(&mut elm, 0x5F);
        elm.take_events();
        let frame = Policy::read_only()
            .approve_tp20_request(&channel, 0, &[0x1A, 0x9B])
            .unwrap();
        // The digits go out, and then the link is gone.
        elm.link_mut().kill_after_writes = Some(1);
        assert!(elm.send(&frame).is_err());
        let logged = logged_commands(&mut elm);
        assert_eq!(logged, [("STM".to_owned(), Vec::new())]);
        // The probe: echoed, and never answered.
        let mut car = batching_stn(Duration::from_secs(60));
        car.mute = vec!["STBC1".to_owned()];
        let mut elm = with_echo_shown(car);
        elm.take_events();
        assert!(
            elm.send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
                .is_err()
        );
        let logged = logged_commands(&mut elm);
        assert!(logged.iter().any(|(c, _)| c == "STBC1"), "{logged:?}");
    }

    #[test]
    fn a_batched_frame_the_module_never_answers_gets_one_timeout_and_nothing_sent() {
        let mut elm = with_echo_shown(batching_stn(Duration::from_secs(60)));
        let channel = request_sent(&mut elm);
        let sent = elm.link().elm.sent.len();
        let started = Instant::now();
        assert!(matches!(
            elm.recv(Duration::from_millis(300)),
            Err(Error::Timeout)
        ));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(matches!(
            elm.recv(Duration::from_millis(100)),
            Err(Error::Timeout)
        ));
        assert_eq!(elm.link().elm.sent.len(), sent, "nothing was sent");
        assert_eq!(count(&elm, "STM"), 0);
        // The next frame stops the monitor first.
        let policy = Policy::read_only();
        elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xA8]);
        assert_eq!(elm.link().elm.interrupted, 1);
    }

    #[test]
    fn a_plain_elm327_gets_exactly_the_same_bytes_in_a_channel_session() {
        // It has no batched commands, so the byte stream of a whole session (everything the
        // driver writes, from the first request that shows its echo to the disconnect) is fixed.
        let mut elm = with_echo_shown(tp20_reading_car());
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_millis(100),
            ..Timing::default()
        };
        let start = elm.link().written.len();
        let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
        assert_eq!(
            session.request(&[0x1A, 0x9B]).unwrap(),
            b"\x5A\x9BABCDEFGHIJKL"
        );
        assert_eq!(session.close(), Ok(Disconnect::Closed));
        let written = String::from_utf8(elm.link().written[start..].to_vec()).unwrap();
        assert_eq!(
            written.replace('\r', "\\r"),
            "ATCFC0\\rATV1\\rATCAF0\\rATCSM0\\rATSH200\\rATCRA25F\\r5FC00010000301\\rXATSH740\\rATCRA300\\r\
             A00F8AFF32FF\\rX1000021A9B\\rXB2\\rXB3\\rXA8\\r"
        );
        assert!(!written.contains("STBC") && !written.contains('|'));
    }

    fn count(elm: &Elm<FakeLink>, command: &str) -> usize {
        commands(elm).iter().filter(|c| *c == command).count()
    }

    #[test]
    fn a_multi_frame_answer_is_heard_whole_over_an_adapter_that_ends_every_listen() {
        // Monitor, stop for the ACK, and monitor again, each cycle with no frame lost: the second
        // ACK's reply arrives one frame at a time too.
        use obdcracker_transport::Timing;
        use obdcracker_transport::tp20::{ChannelSession, Disconnect};
        let mut elm = with_echo_shown(one_frame_stn_from_monitor(Duration::from_millis(5)));
        let policy = Policy::read_only();
        let timing = Timing {
            p2: Duration::from_millis(100),
            ..Timing::default()
        };
        let mut session = ChannelSession::open(&mut elm, &policy, 0x5F, timing).unwrap();
        assert_eq!(
            session.request(&[0x1A, 0x9B]).unwrap(),
            b"\x5A\x9BABCDEFGHIJKL"
        );
        assert_eq!(session.close(), Ok(Disconnect::Closed));
        assert_eq!(elm.link().elm.lost_frames, []);
        assert_eq!(
            elm.link().elm.sent[1..],
            [
                (0x200, vec![0x5F, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01]),
                (0x740, vec![0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF]),
                (0x740, vec![0x10, 0x00, 0x02, 0x1A, 0x9B]),
                (0x740, vec![0xB2]),
                (0x740, vec![0xB4]),
                (0x740, vec![0xA8]),
            ]
        );
        // After the module's ACK, and after the first frame of the ACK's reply.
        assert_eq!(count(&elm, "STM"), 2, "{:?}", commands(&elm));
        assert_eq!(count(&elm, "STMA") + count(&elm, "ATMA"), 0);
        // The ACK setting is sent once with raw mode, not for each monitor.
        assert_eq!(count(&elm, "STCMM1"), 1);
    }

    #[test]
    fn a_module_that_never_answers_gets_one_timeout_and_nothing_sent() {
        use obdcracker_transport::LinkEvent;
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        let channel = request_sent(&mut elm);
        elm.take_events();
        let sent = elm.link().elm.sent.len();
        let started = Instant::now();
        assert!(matches!(
            elm.recv(Duration::from_millis(300)),
            Err(Error::Timeout)
        ));
        assert!(started.elapsed() >= Duration::from_millis(300));
        // Still monitoring: a second wait doesn't start it again.
        assert!(matches!(
            elm.recv(Duration::from_millis(100)),
            Err(Error::Timeout)
        ));
        assert_eq!(elm.link().elm.sent.len(), sent, "nothing was sent");
        assert_eq!(count(&elm, "STM"), 1);
        // The monitor command is in the log.
        let logged: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Command { command, .. } => Some(command),
                _ => None,
            })
            .collect();
        assert_eq!(logged, ["STM"]);
        // The channel's next frame stops the monitor first.
        let policy = Policy::read_only();
        elm.send(&policy.approve_tp20_disconnect(&channel).unwrap())
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xA8]);
        assert_eq!(elm.link().elm.interrupted, 1);
    }

    #[test]
    fn only_a_raw_channel_frame_is_listened_to_with_a_monitor() {
        // An ISO-TP request, a channel setup and a plain ELM327's channel frame: the first two
        // never monitor, and the last uses `ATMA`.
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        let started = Instant::now();
        open_tp20(&mut elm);
        read_vin(&mut elm);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(count(&elm, "STM") + count(&elm, "ATMA"), 0);
        let mut plain = one_frame_stn(Duration::from_secs(60));
        plain.sti = None;
        let mut elm = with_echo_shown(plain);
        request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(50)),
            Err(Error::Timeout)
        ));
        assert_eq!(count(&elm, "ATMA"), 1);
        assert_eq!(count(&elm, "STM") + count(&elm, "STMA"), 0);
    }

    #[test]
    fn a_monitor_is_stopped_before_anything_else_is_written() {
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        // An ISO-TP request, which can't take a monitor's place, and a command.
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, VIN);
        assert_eq!(elm.link().elm.interrupted, 1);
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        assert_eq!(elm.info().unwrap().stn.as_deref(), Some("STN2232 v5.12.4"));
        assert_eq!(elm.link().elm.interrupted, 1);
        // And once it settles, nothing is left running.
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        elm.settle().unwrap();
        assert_eq!(elm.link().elm.interrupted, 1);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
    }

    #[test]
    fn a_quiet_channel_isnt_a_hung_adapter() {
        // The adapter's silence watchdog (its timeout and a margin, about 7 s) bounds a request
        // that should print its prompt. A monitor prints none, and is bounded by the caller.
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        let channel = request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(7600)),
            Err(Error::Timeout)
        ));
        elm.send(
            &Policy::read_only()
                .approve_tp20_disconnect(&channel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xA8]);
    }

    #[test]
    fn frames_printed_between_reads_are_reported_not_returned() {
        // The module's data arrives while the caller isn't reading; the stop that comes with the
        // next frame reads it on the way (the adapter prints in 3-byte pieces) and logs it. The
        // frames are due 200 ms after the request, not 10: under load the test thread can reach its
        // 2 ms recv more than 10 ms late, and a recv that starts after the frames are due reads them.
        use obdcracker_transport::LinkEvent;
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_millis(200)));
        let channel = request_sent(&mut elm);
        elm.link_mut().chunk = 3;
        assert!(matches!(
            elm.recv(Duration::from_millis(2)),
            Err(Error::Timeout)
        ));
        elm.take_events();
        // Wait until the module's frames have reached the fake adapter and been printed, not for a
        // fixed time that a loaded runner can outlast.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            elm.link_mut().elm.poll();
            if elm.link().elm.next_frame_at().is_none() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the fake adapter never printed the module's frames"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let policy = Policy::read_only();
        elm.send(&policy.approve_tp20_ack(&channel, 1).unwrap())
            .unwrap();
        assert_eq!(elm.link().elm.sent.last(), Some(&(0x740, vec![0xB1])));
        let unread: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect();
        assert!(
            unread.iter().any(|l| l == "300 20 00 0E 5A 9B 41 42 43"),
            "{unread:?}"
        );
        assert_eq!(count(&elm, "XX"), 0);
    }

    #[test]
    fn a_monitor_that_ended_before_the_stop_byte_is_refused_not_run() {
        // The prompt comes first, so `X` starts a line: ended as `XX`, which the adapter refuses.
        let mut car = one_frame_stn(Duration::from_secs(60));
        car.listen_ends_on_write = true;
        let mut elm = with_echo_shown(car);
        let channel = request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        let sent = elm.link().elm.sent.len();
        elm.send(
            &Policy::read_only()
                .approve_tp20_disconnect(&channel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xA8]);
        assert_eq!(count(&elm, "XX"), 1);
        assert_eq!(elm.link().elm.interrupted, 0);
        assert_eq!(elm.link().elm.sent[sent..], [(0x740, vec![0xA8])]);
    }

    #[test]
    fn a_monitor_that_prompts_on_its_own_fails_the_adapter_closed_on_every_path() {
        // The prompt arrives between the caller's `recv` and whatever comes next: nothing the
        // driver wrote could have caused it, so the cached adapter state can't be trusted and
        // nothing more is written, whichever call finds it (#227, Codex).
        type Next =
            fn(&mut Elm<FakeLink>, &obdcracker_safety::OpenTp20Channel) -> Result<(), Error>;
        let nexts: [(&str, Next); 5] = [
            ("a channel frame", |elm, channel| {
                let frame = Policy::read_only()
                    .approve_tp20_disconnect(channel)
                    .unwrap();
                elm.send(&frame)
            }),
            ("an ISO-TP request", |elm, _| {
                elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            }),
            ("a command", |elm, _| elm.info().map(|_| ())),
            ("settle", |elm, _| elm.settle()),
            ("a wait", |elm, _| {
                elm.recv(Duration::from_secs(1)).map(|_| ())
            }),
        ];
        for (name, next) in nexts {
            let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
            let channel = request_sent(&mut elm);
            assert!(matches!(
                elm.recv(Duration::from_millis(20)),
                Err(Error::Timeout)
            ));
            elm.link_mut().inject = b"\r>".to_vec();
            let written = elm.link().written.len();
            let err = next(&mut elm, &channel).unwrap_err();
            assert!(err.to_string().contains("monitoring"), "{name}: {err}");
            // Failed closed: it stays failed, and nothing was written.
            let frame = approve(Target::Physical(0x7E0), &[0x09, 0x02]);
            assert!(elm.send(&frame).is_err(), "{name}");
            assert_eq!(elm.link().written.len(), written, "{name}");
        }
    }

    #[test]
    fn buffer_full_while_monitoring_fails_the_wait_and_the_stop() {
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        let channel = request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        // In a wait.
        elm.link_mut().inject = b"BUFFER FULL\r".to_vec();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("BUFFER FULL"), "{err}");
        // While stopping, before a frame goes out: that frame isn't sent.
        let mut elm = with_echo_shown(one_frame_stn(Duration::from_secs(60)));
        let channel2 = request_sent(&mut elm);
        assert!(matches!(
            elm.recv(Duration::from_millis(20)),
            Err(Error::Timeout)
        ));
        let sent = elm.link().elm.sent.len();
        elm.link_mut().inject = b"BUFFER FULL\r".to_vec();
        let disconnect = Policy::read_only()
            .approve_tp20_disconnect(&channel2)
            .unwrap();
        let err = elm.send(&disconnect).unwrap_err();
        assert!(err.to_string().contains("BUFFER FULL"), "{err}");
        assert_eq!(elm.link().elm.sent.len(), sent);
        // The monitor was stopped, and the adapter can still be used.
        assert_eq!(elm.link().elm.interrupted, 1);
        elm.send(&disconnect).unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, [0xA8]);
        let _ = channel;
    }

    #[test]
    fn a_misheard_monitor_command_never_reaches_the_bus() {
        // Every bit of every character of `STM` and `ATMA`: the echo shows the flip before the
        // carriage return, so the line is ended with `XX` and the adapter refuses it. A flip of a
        // letter's case is the same command to the adapter.
        for (stn, command) in [(true, "STM"), (false, "ATMA")] {
            for index in 0..command.len() {
                for bit in 0..8 {
                    let mut car = one_frame_stn(Duration::from_secs(60));
                    if !stn {
                        car.sti = None;
                    }
                    let mut elm = with_echo_shown(car);
                    request_sent(&mut elm);
                    let sent = elm.link().elm.sent.len();
                    elm.link_mut().corrupt_write_of =
                        Some((command.as_bytes().to_vec(), index, 1 << bit));
                    let result = elm.recv(Duration::from_millis(20));
                    assert!(elm.link().corrupt_write_of.is_none(), "{command}");
                    assert_eq!(elm.link().elm.sent[sent..], [], "{command} {index} {bit}");
                    if bit == 5 {
                        assert!(matches!(result, Err(Error::Timeout)), "{command} {index}");
                    } else {
                        let err = result.unwrap_err();
                        assert!(matches!(err, Error::Adapter(_)), "{command} {index} {bit}");
                    }
                }
            }
        }
    }

    // The A7's passenger door module on session 9: it refuses `1A 9B` with `7F 1A 11` in one
    // frame (`300 10 00 03 7F 1A 11`), due 5 ms after the adapter starts monitoring. The module
    // sends a frame again until someone acknowledges it (#301).
    fn refusing_stn() -> FakeElm {
        let mut car = one_frame_stn_from_monitor(Duration::from_millis(5));
        car.delayed = Some(Box::new(|header, request| match (header, request) {
            (0x740, [0x10, 0x00, 0x02, 0x1A, 0x9B]) => vec![(
                Duration::from_millis(5),
                0x300,
                vec![0x10, 0x00, 0x03, 0x7F, 0x1A, 0x11],
            )],
            _ => Vec::new(),
        }));
        car
    }

    const REFUSAL: [u8; 6] = [0x10, 0x00, 0x03, 0x7F, 0x1A, 0x11];

    fn unread_lines(elm: &mut Elm<FakeLink>) -> Vec<String> {
        use obdcracker_transport::LinkEvent;
        elm.take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_silent_monitor_gets_session_9s_can_error_instead_of_the_answer() {
        // An adapter that takes the ACK setting but stays silent anyway: the module repeats its
        // frame, nothing acknowledges it, and the adapter says `CAN ERROR`. The wait fails with
        // that, as it did on the car, and no repeat is returned as an answer.
        let mut car = refusing_stn();
        car.monitor_ignores_ack = true;
        let mut elm = with_echo_shown(car);
        request_sent(&mut elm);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("CAN ERROR"), "{err}");
        elm.settle().unwrap();
        let repeats = unread_lines(&mut elm);
        assert_eq!(repeats.len(), support::fake_elm::UNACKED_REPEATS);
        assert!(
            repeats
                .iter()
                .all(|l| l.trim_end() == "300 10 00 03 7F 1A 11"),
            "{repeats:?}"
        );
    }

    #[test]
    fn the_monitor_acknowledges_so_the_module_s_answer_arrives_once() {
        let mut elm = with_echo_shown(refusing_stn());
        request_sent(&mut elm);
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, REFUSAL);
        assert!(matches!(
            elm.recv(Duration::from_millis(50)),
            Err(Error::Timeout)
        ));
        elm.settle().unwrap();
        assert_eq!(unread_lines(&mut elm), Vec::<String>::new());
        assert_eq!(elm.link().elm.lost_frames, []);
        // `STCMM1` went out with raw mode, long before the first `STM`: nothing but the monitor
        // itself sits between the module's ACK and the answer.
        let log = commands(&elm);
        let ack = log.iter().position(|c| c == "STCMM1").unwrap();
        let monitor = log.iter().position(|c| c == "STM").unwrap();
        assert!(ack < monitor, "{log:?}");
        assert_eq!(log[monitor - 1], "1000021A9B");
    }

    #[test]
    fn a_plain_elm_acknowledges_with_atcsm0_and_the_answer_arrives_once() {
        let mut car = refusing_stn();
        car.sti = None;
        let mut elm = with_echo_shown(car);
        request_sent(&mut elm);
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().payload, REFUSAL);
        assert!(matches!(
            elm.recv(Duration::from_millis(50)),
            Err(Error::Timeout)
        ));
        let log = commands(&elm);
        let ack = log.iter().position(|c| c == "ATCSM0").unwrap();
        let monitor = log.iter().position(|c| c == "ATMA").unwrap();
        assert!(ack < monitor, "{log:?}");
        assert_eq!(count(&elm, "STCMM1"), 0);
    }

    #[test]
    fn the_ack_setting_follows_raw_mode_once_in_and_once_out() {
        for (stn, on, off) in [(true, "STCMM1", "STCMM0"), (false, "ATCSM0", "ATCSM1")] {
            let mut car = tp20_car();
            if stn {
                car.sti = Some("STN2232 v5.12.4".into());
            }
            let mut elm = with_echo_shown(car);
            let before = commands(&elm).len();
            open_tp20(&mut elm);
            // A second channel finds raw mode on already.
            open_tp20(&mut elm);
            let entered = &commands(&elm)[before..];
            assert_eq!(
                entered.iter().filter(|c| *c == on).count(),
                1,
                "{entered:?}"
            );
            assert_eq!(entered.iter().filter(|c| *c == off).count(), 0);
            // Right after the third switch, ahead of the header and anything a frame needs.
            let at = entered.iter().position(|c| c == on).unwrap();
            assert_eq!(entered[at - 1], "ATCAF0", "{entered:?}");
            assert!(elm.link().elm.settings.monitor_ack);
            // Leaving raw mode puts the silent default back, once.
            let before = commands(&elm).len();
            read_vin(&mut elm);
            let left = &commands(&elm)[before..];
            assert_eq!(left.iter().filter(|c| *c == off).count(), 1, "{left:?}");
            assert_eq!(left.iter().filter(|c| *c == on).count(), 0);
            assert!(!elm.link().elm.settings.monitor_ack);
        }
    }

    #[test]
    fn the_ack_setting_is_an_adapter_command_in_the_audit_events() {
        use obdcracker_transport::LinkEvent;
        let mut elm = with_echo_shown(unpaced_tp20_car());
        elm.take_events();
        open_tp20(&mut elm);
        let logged: Vec<(String, Vec<String>)> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Command {
                    command, answer, ..
                } => Some((command, answer)),
                _ => None,
            })
            .collect();
        assert!(
            logged.contains(&("STCMM1".to_owned(), vec!["OK".to_owned()])),
            "{logged:?}"
        );
    }

    #[test]
    fn an_adapter_that_refuses_the_ack_setting_fails_closed_before_any_channel_frame() {
        // A clone without `AT CSM`, or an STN that doesn't know `STCMM`: a silent monitor would
        // hear nothing but `CAN ERROR`, so the setup isn't sent and nothing more is written.
        for (stn, command) in [(true, "STCMM1"), (false, "ATCSM0")] {
            let mut car = tp20_car();
            if stn {
                car.sti = Some("STN2232 v5.12.4".into());
            }
            car.unsupported.push(command.to_owned());
            let mut elm = with_echo_shown(car);
            let sent = elm.link().elm.sent.len();
            let setup = Policy::read_only().approve_tp20_setup(0x5F).unwrap();
            let err = elm.send(&setup).unwrap_err();
            let shown = err.to_string();
            assert!(shown.contains(command), "{shown}");
            assert!(shown.contains("doesn't support"), "{shown}");
            assert_eq!(elm.link().elm.sent.len(), sent, "{command}");
            let written = elm.link().written.len();
            assert!(elm.send(&setup).is_err());
            assert_eq!(elm.link().written.len(), written);
            assert_eq!(elm.link().elm.sent.len(), sent);
        }
    }

    #[test]
    fn a_refused_restore_of_the_silent_default_fails_the_switch_back() {
        let mut car = tp20_car();
        car.sti = Some("STN2232 v5.12.4".into());
        car.unsupported.push("STCMM0".to_owned());
        let mut elm = with_echo_shown(car);
        open_tp20(&mut elm);
        let sent = elm.link().elm.sent.len();
        let err = elm
            .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap_err();
        assert!(err.to_string().contains("STCMM0"), "{err}");
        assert_eq!(elm.link().elm.sent.len(), sent);
    }

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
            .approve(Protocol::Uds, Target::Physical(0x710), &[0x22, 0xF1, 0x87])
            .unwrap();
        let mut elm = connect(busy_bus());
        elm.send(&request).unwrap();
        let mut sources = Vec::new();
        while let Ok(reply) = elm.recv(Duration::from_secs(1)) {
            sources.push(reply.source);
        }
        assert_eq!(sources, [0x77A]);
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
        // `17 FE 00 76 21 xx xx xx xx xx xx xx \r` with a 29-bit ID: 37 characters. At 9600 baud
        // (the slowest an ELM327 starts at), 8-N-1, that's 10 bits a character.
        let lines = 1 + (4095 - 6_u32).div_ceil(7);
        let printing = Duration::from_secs_f64(f64::from(lines * 37 * 10) / 9600.0);
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
        let printing = Duration::from_secs_f64(f64::from(lines * 37 * 10) / 9600.0);
        let p2_star = Elm::<FakeLink>::timing().p2_star;
        assert!(
            p2_star > obdcracker_transport::Timing::default().p2_star + printing * 16,
            "{p2_star:?} vs {printing:?}"
        );
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
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x7E8);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.link().elm.interrupted, 0);
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!((reply.source, reply.payload.as_slice()), (0x7E8, VIN));
        assert_eq!(elm.recv(Duration::from_secs(1)), Err(Error::Timeout));
    }
}

mod stpx {
    use super::*;

    const FOUR_DIDS: [u8; 9] = [0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1, 0x89, 0xF1, 0x91];
    const LINE: &[u8] = b"STPX d:22F187F188F189F191";

    // An STN whose engine ECU answers the four-DID read with a multi-frame reply.
    fn stn() -> FakeElm {
        let mut adapter = FakeElm::new(Box::new(|header, request| {
            if header == 0x7E0 && request == FOUR_DIDS {
                let mut reply = vec![0x62, 0xF1, 0x87];
                reply.extend((0..20).map(|n| 0x30 + n));
                vec![(0x7E8, reply)]
            } else {
                Vec::new()
            }
        }));
        adapter.sti = Some("STN2232 v5.12.4".into());
        adapter
    }

    // Connected to `adapter` and past a first request, so the driver has seen it echo each
    // character as it arrives.
    fn warmed(adapter: FakeElm) -> Elm<FakeLink> {
        let mut elm = connect(adapter);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm
    }

    fn four_dids() -> Approved {
        approve(Target::Physical(0x7E0), &FOUR_DIDS)
    }

    // A `22` read of `dids` distinct DIDs: 1 + 2 * dids bytes, so always odd.
    fn long_request(dids: u8) -> Approved {
        let mut payload = vec![0x22];
        for did in 0..dids {
            payload.extend([0xF1, 0x80 + did]);
        }
        approve(Target::Physical(0x7E0), &payload)
    }

    // A `19` read of `len` bytes. The policy takes any length of it, so it reaches the even
    // lengths a `22` read can't.
    fn long_dtc_read(len: usize) -> Approved {
        let mut payload = vec![0x19, 0x02, 0xFF];
        payload.resize(len, 0x00);
        approve(Target::Physical(0x7E0), &payload)
    }

    #[test]
    fn an_stn_sends_a_request_of_several_frames_and_reads_the_answer() {
        let mut elm = warmed(stn());
        elm.send(&four_dids()).unwrap();
        let reply = elm.recv(Duration::from_secs(1)).unwrap();
        assert_eq!(reply.source, 0x7E8);
        assert_eq!(reply.payload.len(), 23);
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(elm.link().elm.sent.len(), 2);
        assert_eq!(elm.link().elm.sent[1], (0x7E0, FOUR_DIDS.to_vec()));
    }

    #[test]
    fn the_carriage_return_waits_for_the_echo_of_the_stpx_line() {
        let mut elm = warmed(stn());
        elm.link_mut().writes.clear();
        elm.send(&four_dids()).unwrap();
        assert_eq!(elm.link().writes, [LINE.to_vec(), b"\r".to_vec()]);
    }

    #[test]
    fn an_stn_that_has_not_shown_it_echoes_as_it_reads_refuses_and_writes_nothing() {
        // Before any request, and after one an adapter echoed only as whole lines.
        let mut fresh = connect(stn());
        let written = fresh.link().written.len();
        assert!(fresh.send(&four_dids()).is_err());
        assert_eq!(fresh.link().written.len(), written);

        let mut late = stn();
        late.echo_at_line_end = true;
        let mut elm = warmed(late);
        let written = elm.link().written.len();
        assert!(elm.send(&four_dids()).is_err());
        assert_eq!(elm.link().written.len(), written);
        assert_eq!(elm.link().elm.sent.len(), 1);
    }

    #[test]
    fn no_single_bit_error_in_the_stpx_line_sends_a_different_request() {
        // The line is written without its carriage return and its echo checked first, so a bit
        // flipped on the way in is caught before the adapter acts on it. A flip that only changes
        // a letter's case is the same command and sends the same request.
        let mut same = 0;
        for index in 0..LINE.len() {
            for bit in 0..8 {
                let mut elm = warmed(stn());
                elm.link_mut().corrupt_write_of = Some((LINE.to_vec(), index, 1 << bit));
                let result = elm.send(&four_dids());
                let sent = &elm.link().elm.sent[1..];
                if result.is_ok() {
                    same += 1;
                    assert_eq!(
                        sent,
                        [(0x7E0, FOUR_DIDS.to_vec())],
                        "byte {index} bit {bit}"
                    );
                } else {
                    assert_eq!(sent, [], "byte {index} bit {bit}");
                    let written = elm.link().written.len();
                    assert!(elm.send(&four_dids()).is_err());
                    assert_eq!(elm.link().written.len(), written);
                }
            }
        }
        // Only the flips of bit 5 of a letter (its case), so the check isn't passing vacuously.
        assert!(same > 0 && same < 30, "{same}");
    }

    #[test]
    fn a_misheard_stpx_line_is_killed_and_the_driver_stops() {
        let mut elm = warmed(stn());
        elm.link_mut().corrupt_write_of = Some((LINE.to_vec(), 9, 0x01));
        let err = elm.send(&four_dids()).unwrap_err();
        assert!(err.to_string().contains("echoed"), "{err}");
        assert_eq!(elm.link().elm.sent.len(), 1);
        assert!(commands(&elm).last().unwrap().ends_with("XX"));
    }

    #[test]
    fn a_module_that_sends_no_flow_control_fails_only_that_request() {
        // The STN sent the first frame, the engine ECU sent no flow control, and the adapter
        // printed the echo and then `FC RX TIMEOUT` (OBDLink EX, STN2232 v5.12.4, #215).
        let mut adapter = stn();
        adapter.no_flow_control = true;
        let mut elm = warmed(adapter);
        elm.send(&four_dids()).unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
        assert!(err.to_string().contains("FC RX TIMEOUT"), "{err}");
        assert!(!err.to_string().contains("unexpected output"), "{err}");

        // The adapter is back at its prompt with its settings, so the driver goes on.
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(elm.link().elm.sent.len(), 3);
        assert_eq!(elm.link().elm.sent[2], (0x7E0, vec![0x09, 0x02]));
    }

    #[test]
    fn the_fc_rx_timeout_reaches_the_audit_log() {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-fc-rx-timeout.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let mut adapter = stn();
        adapter.no_flow_control = true;
        let mut elm = Audited::open(&log, warmed(adapter), "fake").unwrap();
        elm.send(&four_dids()).unwrap();
        assert!(elm.recv(Duration::from_secs(1)).is_err());
        let audit = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        assert!(audit.contains("FC RX TIMEOUT"), "{audit}");
    }

    #[test]
    fn a_line_that_only_looks_like_fc_rx_timeout_still_breaks_the_driver_down() {
        let mut elm = warmed(stn());
        elm.link_mut().elm.after_echo = b"FC RX TIMEOUTX\r".to_vec();
        elm.send(&four_dids()).unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "{err}");
        let written = elm.link().written.len();
        assert!(elm.send(&four_dids()).is_err());
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn the_adapters_refusal_of_a_killed_line_is_not_an_answer() {
        // The kill's `XX` makes the STN refuse the whole line with `?` (#215). The fake prints it
        // the same way; the driver has stopped, reads none of it and sends nothing.
        let mut elm = warmed(stn());
        elm.link_mut().corrupt_write_of = Some((LINE.to_vec(), 9, 0x01));
        let err = elm.send(&four_dids()).unwrap_err();
        assert!(err.to_string().contains("echoed"), "{err}");
        let heard = elm.link_mut().elm.read(usize::MAX);
        assert!(heard.windows(2).any(|w| w == b"?\r"), "{heard:?}");
        assert_eq!(elm.link().elm.sent.len(), 1);
        let written = elm.link().written.len();
        assert!(elm.send(&four_dids()).is_err());
        assert!(elm.recv(Duration::from_millis(50)).is_err());
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn the_longest_request_is_sent_and_one_byte_more_is_refused() {
        // The echoed line has to fit the line splitter: `STPX d:` and up to 44 bytes of digits
        // are 95 characters, and 45 bytes would be 97 over its 96. A `22` read reaches 43 bytes
        // (21 DIDs), so the exact limit is pinned with a `19` read, whose length is free.
        let mut elm = warmed(stn());
        elm.send(&long_dtc_read(44)).unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        assert_eq!(elm.link().elm.sent.len(), 2);
        let (_, sent) = &elm.link().elm.sent[1];
        assert_eq!(sent.len(), 44);
        let mut line = b"STPX d:".to_vec();
        line.extend(sent.iter().flat_map(|b| format!("{b:02X}").into_bytes()));
        assert_eq!(line.len(), 95);
        assert!(
            elm.link().written.windows(line.len()).any(|w| w == line),
            "the {}-character STPX line was not written",
            line.len()
        );
        let written = elm.link().written.len();
        for refused in [long_dtc_read(45), long_request(22)] {
            let err = elm.send(&refused).unwrap_err();
            assert!(matches!(err, Error::Adapter(_)), "{err}");
            assert_eq!(elm.link().written.len(), written);
        }
        elm.send(&long_request(21)).unwrap();
        assert_eq!(elm.link().elm.sent.last().unwrap().1.len(), 43);
    }

    #[test]
    fn an_audited_stn_logs_the_whole_request_before_sending_it() {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-stpx.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let mut elm = Audited::open(&log, warmed(stn()), "fake").unwrap();
        elm.send(&four_dids()).unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        let audit = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        let lines: Vec<serde_json::Value> = audit
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let tx = lines.iter().position(|v| v["dir"] == "tx").unwrap();
        assert_eq!(
            lines[tx]["payload"], "22 F1 87 F1 88 F1 89 F1 91",
            "{audit}"
        );
        assert!(!audit.contains("STPX"), "{audit}");
    }
}

// A plain ELM327 sends a request of 8 to 44 bytes as raw frames written with `AT CAF0`
// (docs/design/elm-caf0-segmenting.md). The fake's `Module` receives them as an ECU does.
mod caf0 {
    use obdcracker_transport::LinkEvent;
    use obdcracker_transport::elm::{
        SEGMENT_GAP, SEGMENT_HOLD, SEGMENT_MAX_WAITS, SEGMENT_TRANSFER,
    };
    use support::fake_elm::{Module, flow_control_frame};

    use super::*;

    const REQUEST_ID: u32 = 0x7E1;
    const REPLY_ID: u32 = 0x7E9;
    const ANSWER: [u8; 3] = [0x59, 0x02, 0xFF];
    const FOUR_DIDS: [u8; 9] = [0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1, 0x89, 0xF1, 0x91];

    // `len` bytes of a `19` read, which the policy takes at any length: after its third byte,
    // byte n is n.
    fn read_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|n| match n {
                0 => 0x19,
                1 => 0x02,
                2 => 0xFF,
                n => u8::try_from(n).unwrap(),
            })
            .collect()
    }

    fn request(len: usize) -> Approved {
        approve(Target::Physical(REQUEST_ID), &read_of(len))
    }

    fn module() -> Module {
        Module::new(REQUEST_ID, REPLY_ID)
    }

    // A plain ELM327 with `module`, which answers every request it receives whole with `answer`
    // (nothing, if that's empty).
    fn adapter(module: Module, answer: &[u8]) -> FakeElm {
        let answer = answer.to_vec();
        FakeElm::new(Box::new(move |header, _| {
            if header == REQUEST_ID && !answer.is_empty() {
                vec![(REPLY_ID, answer.clone())]
            } else {
                Vec::new()
            }
        }))
        .with_module(module)
    }

    // Connected and past a first request, so the driver has seen the adapter echo each character
    // as it reads it.
    fn warmed(adapter: FakeElm) -> Elm<FakeLink> {
        let mut elm = connect(adapter);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm
    }

    fn standard() -> Elm<FakeLink> {
        warmed(adapter(module(), &ANSWER))
    }

    fn module_of(elm: &Elm<FakeLink>) -> &Module {
        elm.link().elm.module.as_ref().unwrap()
    }

    fn module_mut(elm: &mut Elm<FakeLink>) -> &mut Module {
        elm.link_mut().elm.module.as_mut().unwrap()
    }

    // Every frame the module received.
    fn received(elm: &Elm<FakeLink>) -> Vec<Vec<u8>> {
        module_of(elm)
            .frames
            .iter()
            .map(|(_, data)| data.clone())
            .collect()
    }

    // `payload` as frames, from ISO 15765-2 and not from core's `Segmenter`: a first frame with
    // the length and 6 bytes, then 7 bytes a frame numbered from 1, each padded with `filler`.
    fn golden(payload: &[u8], filler: u8) -> Vec<Vec<u8>> {
        let len = payload.len();
        let mut first = vec![0x10 | u8::try_from(len >> 8).unwrap(), len.to_le_bytes()[0]];
        first.extend(&payload[..6]);
        let mut frames = vec![first];
        for (n, chunk) in payload[6..].chunks(7).enumerate() {
            let mut frame = vec![0x20 | u8::try_from((n + 1) & 0x0F).unwrap()];
            frame.extend(chunk);
            frame.resize(8, filler);
            frames.push(frame);
        }
        frames
    }

    // The line the driver writes for a frame: 16 digits.
    fn line(frame: &[u8]) -> Vec<u8> {
        hex(frame).replace(' ', "").into_bytes()
    }

    // Sends `request`, reads the answer and what follows it.
    fn exchange_one(elm: &mut Elm<FakeLink>, request: &Approved) -> Response {
        elm.send(request).unwrap();
        let answer = elm.recv(Duration::from_secs(1)).unwrap();
        while elm.recv(Duration::from_millis(100)).is_ok() {}
        answer
    }

    fn since(elm: &Elm<FakeLink>, before: usize) -> Vec<String> {
        commands(elm)[before..].to_vec()
    }

    fn count(commands: &[String], command: &str) -> usize {
        commands.iter().filter(|c| *c == command).count()
    }

    fn gaps(elm: &Elm<FakeLink>) -> Vec<Duration> {
        let times: Vec<Instant> = module_of(elm).frames.iter().map(|(at, _)| *at).collect();
        times.windows(2).map(|w| w[1] - w[0]).collect()
    }

    // ---- what is refused, with nothing written -------------------------------------------

    #[test]
    fn refuses_what_it_cant_send_in_segments_and_writes_nothing() {
        let cases: Vec<(&str, Elm<FakeLink>, Approved, &str)> = vec![
            (
                "before any request showed the adapter echoes as it reads",
                connect(adapter(module(), &ANSWER)),
                request(9),
                "echoes each character",
            ),
            (
                "an adapter that echoes whole lines",
                {
                    let mut late = adapter(module(), &ANSWER);
                    late.echo_at_line_end = true;
                    warmed(late)
                },
                request(9),
                "echoes each character",
            ),
            ("45 bytes", standard(), request(45), "doesn't fit"),
            (
                "a module whose reply ID isn't known",
                standard(),
                approve(Target::Physical(0x710), &read_of(9)),
                "no one module's flow control",
            ),
            (
                "PP 26 missing from the summary",
                {
                    let mut elm = adapter(module(), &ANSWER);
                    elm.pps = Some(vec!["09:00 F  24:00 F  25:00 F  29:FF F".to_owned()]);
                    warmed(elm)
                },
                request(9),
                "PP 26",
            ),
        ];
        for (what, mut elm, refused, says) in cases {
            let written = elm.link().written.len();
            let sent = elm.link().elm.sent.len();
            let err = elm.send(&refused).unwrap_err();
            assert!(matches!(err, Error::Adapter(_)), "{what}: {err}");
            assert!(err.to_string().contains(says), "{what}: {err}");
            assert_eq!(elm.link().written.len(), written, "{what} wrote");
            assert_eq!(elm.link().elm.sent.len(), sent, "{what} sent");
            // Still usable.
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .unwrap();
        }
    }

    #[test]
    fn a_request_of_up_to_7_bytes_stays_one_frame() {
        let mut elm = standard();
        let seven = approve(Target::Physical(REQUEST_ID), &read_of(7));
        let before = commands(&elm).len();
        elm.send(&seven).unwrap();
        assert_eq!(elm.link().elm.sent.last(), Some(&(REQUEST_ID, read_of(7))));
        assert!(!since(&elm, before).iter().any(|c| c.starts_with("ATCAF")));
    }

    // ---- the frames -----------------------------------------------------------------------

    #[test]
    fn writes_the_frames_of_the_golden_table() {
        for payload in [
            read_of(8),
            FOUR_DIDS.to_vec(),
            read_of(13),
            read_of(14),
            read_of(44),
        ] {
            let mut elm = standard();
            let answer = exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &payload));
            assert_eq!(answer, Response::new(REPLY_ID, ANSWER.to_vec()));
            assert_eq!(
                received(&elm),
                golden(&payload, 0x00),
                "{}-byte request",
                payload.len()
            );
            assert_eq!(module_of(&elm).received, std::slice::from_ref(&payload));
            // Each frame is a line of 16 digits, written with no carriage return and then that.
            let writes = &elm.link().writes;
            for frame in golden(&payload, 0x00) {
                let at = writes.iter().position(|w| *w == line(&frame)).unwrap();
                assert_eq!(writes[at + 1], b"\r", "{frame:02X?}");
            }
        }
        let mut elm = standard();
        exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &FOUR_DIDS));
        assert_eq!(
            received(&elm),
            [
                [0x10, 0x09, 0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1],
                [0x21, 0x89, 0xF1, 0x91, 0x00, 0x00, 0x00, 0x00]
            ]
        );
        let mut elm = standard();
        exchange_one(&mut elm, &request(14));
        assert_eq!(
            received(&elm)[2],
            [0x22, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn writes_the_commands_of_the_design_in_order() {
        // 14 bytes: a first frame, a consecutive frame inside the block, and the last one.
        let mut elm = standard();
        let before = commands(&elm).len();
        exchange_one(&mut elm, &request(14));
        assert_eq!(
            since(&elm, before),
            [
                "ATCAF0",
                "ATSH7E1",
                "ATFCSH7E1",
                "ATFCSD300003",
                "ATFCSM1",
                "ATCRA7E9",
                "100E1902FF030405",
                "ATR0",
                "21060708090A0B0C",
                "ATR1",
                "220D000000000000",
            ]
        );
        // One `X` stopped the listen after the first frame.
        assert_eq!(elm.link().elm.interrupted, 1);
        assert!(elm.link().elm.settings.responses);

        // 8 to 13 bytes have no frame inside a block: no `AT R0` or `AT R1`.
        let mut elm = standard();
        let before = commands(&elm).len();
        exchange_one(&mut elm, &request(9));
        let sent = since(&elm, before);
        assert_eq!(count(&sent, "ATR0") + count(&sent, "ATR1"), 0, "{sent:?}");
        assert_eq!(sent.iter().filter(|c| c.starts_with("ATCAF")).count(), 1);
    }

    #[test]
    fn pads_with_the_adapters_filler_byte() {
        // PP 26 on, `AA`.
        let mut on = adapter(module(), &ANSWER);
        on.pp.push((0x26, 0xAA));
        let mut elm = warmed(on);
        exchange_one(&mut elm, &request(14));
        assert_eq!(received(&elm), golden(&read_of(14), 0xAA));
        assert_eq!(received(&elm)[2][7], 0xAA);

        // PP 26 listed but off, at its factory value `00`, and an adapter with no parameters.
        let mut off = adapter(module(), &ANSWER);
        off.pps = Some(vec![
            "09:00 F  24:00 F  25:00 F  26:55 F  29:FF F".to_owned(),
        ]);
        let mut clone = adapter(module(), &ANSWER);
        clone.unsupported.push("ATPPS".into());
        for adapter in [off, clone] {
            let mut elm = warmed(adapter);
            exchange_one(&mut elm, &request(14));
            assert_eq!(received(&elm), golden(&read_of(14), 0x00));
        }
    }

    #[test]
    fn a_29_bit_request_goes_in_frames_too() {
        let ids = ModuleIds {
            request: 0x17FC_0076,
            reply: 0x17FE_0076,
        };
        let adapter = FakeElm::new(Box::new(|header, _| {
            if header == 0x17FC_0076 {
                vec![(0x17FE_0076, ANSWER.to_vec())]
            } else {
                Vec::new()
            }
        }))
        .with_module(Module::new(0x17FC_0076, 0x17FE_0076));
        let mut elm = warmed(adapter);
        let policy = Policy::read_only().narrowed_to(&[ids]).unwrap();
        let payload = read_of(14);
        let approved = policy
            .approve(Protocol::Uds, Target::Physical29(ids.request), &payload)
            .unwrap();
        let answer = exchange_one(&mut elm, &approved);
        assert_eq!(answer, Response::new(0x17FE_0076, ANSWER.to_vec()));
        assert_eq!(received(&elm), golden(&payload, 0x00));
        assert!(elm.link().elm.settings.bits29());
    }

    // ---- a misheard line never reaches the bus ---------------------------------------------

    // Flips bit `bit` of byte `index` of the next write of `bytes`, and sends `payload`.
    fn flipped(
        payload: &[u8],
        bytes: &[u8],
        index: usize,
        bit: u8,
    ) -> (Elm<FakeLink>, Result<(), Error>) {
        let mut elm = standard();
        elm.link_mut().corrupt_write_of = Some((bytes.to_vec(), index, 1 << bit));
        let result = elm.send(&approve(Target::Physical(REQUEST_ID), payload));
        assert!(elm.link().corrupt_write_of.is_none(), "{bytes:02X?}");
        (elm, result)
    }

    #[test]
    fn no_single_bit_error_in_a_frame_line_puts_another_frame_on_the_bus() {
        // Every bit of every digit of every frame line of a 14-byte request: the echo shows the
        // flip before the carriage return, so the line is ended with `XX`, the adapter refuses
        // it, and the driver stops. A flip of a letter's case is the same digit.
        let payload = read_of(14);
        let frames = golden(&payload, 0x00);
        std::thread::scope(|scope| {
            for (k, frame) in frames.iter().enumerate() {
                let (payload, frames) = (&payload, &frames);
                scope.spawn(move || {
                    let bytes = line(frame);
                    for index in 0..bytes.len() {
                        for bit in 0..8 {
                            let (mut elm, result) = flipped(payload, &bytes, index, bit);
                            let what = format!("frame {k} digit {index} bit {bit}");
                            if result.is_ok() {
                                assert!(bit == 5 && bytes[index].is_ascii_alphabetic(), "{what}");
                                assert_eq!(received(&elm), *frames, "{what}");
                            } else {
                                // The frames before it, and nothing from it on.
                                assert_eq!(received(&elm), frames[..k], "{what}");
                                assert_eq!(elm.link().elm.sent.len(), 1 + k, "{what}");
                                assert!(commands(&elm).last().unwrap().ends_with("XX"), "{what}");
                                let written = elm.link().written.len();
                                assert!(elm.send(&request(14)).is_err(), "{what}");
                                assert_eq!(elm.link().written.len(), written, "{what}");
                            }
                        }
                    }
                });
            }
        });
    }

    // Where the writes of a clean 14-byte request are: the index among the writes since the
    // request began of each frame's digits.
    fn write_positions() -> Vec<usize> {
        let mut elm = standard();
        let before = elm.link().writes.len();
        exchange_one(&mut elm, &request(14));
        let writes = &elm.link().writes[before..];
        golden(&read_of(14), 0x00)
            .iter()
            .map(|f| writes.iter().position(|w| *w == line(f)).unwrap())
            .collect()
    }

    #[test]
    fn a_flipped_carriage_return_leaves_the_frame_unsent() {
        // The line is held in the adapter, unsent, and the driver gives up on it: after 7 s of
        // silence for the first frame, 2 s for one inside a block. The last frame's send
        // returns, and its answer never comes.
        let frames = golden(&read_of(14), 0x00);
        let positions = write_positions();
        std::thread::scope(|scope| {
            for k in 0..frames.len() {
                for bit in 0..8 {
                    let (frames, positions) = (&frames, &positions);
                    scope.spawn(move || {
                        let mut elm = standard();
                        let at = elm.link().writes.len() + positions[k] + 1;
                        elm.link_mut().corrupt_write_at = Some((at, 0, 1 << bit));
                        let result = elm.send(&request(14));
                        assert!(elm.link().corrupt_write_at.is_none());
                        assert_eq!(result.is_ok(), k == 2, "frame {k} bit {bit}");
                        assert_eq!(received(&elm), frames[..k], "frame {k} bit {bit}");
                        assert!(elm.recv(Duration::from_millis(300)).is_err());
                        assert_eq!(received(&elm), frames[..k], "frame {k} bit {bit}");
                    });
                }
            }
        });
    }

    #[test]
    fn a_clone_that_ignores_caf0_sends_no_consecutive_frame() {
        // It answers `OK` to `AT CAF0` and stays in `AT CAF1`. A real ELM327 refuses the 8-byte
        // line with `?`, which stops the driver; a clone that sends the 8 bytes sends one frame
        // of service 0x10 (diagnostic session control) with the length as its session, which the
        // module answers with something that isn't flow control. Either way no consecutive frame
        // is sent, and nothing but that one frame is on the bus.
        for sends_it in [false, true] {
            let mut clone = adapter(module(), &ANSWER);
            clone.ignores_caf0 = true;
            clone.takes_eight_bytes_in_caf1 = sends_it;
            let mut elm = warmed(clone);
            let sent = elm.link().elm.sent.len();
            let err = elm.send(&request(14)).unwrap_err();
            assert!(matches!(err, Error::Adapter(_)), "{err}");
            let on_bus = &elm.link().elm.sent[sent..];
            assert_eq!(on_bus.len(), usize::from(sends_it), "{on_bus:02X?}");
            assert_eq!(module_of(&elm).frames, []);
            // A `?` leaves the driver stopped; the other is only that request's failure, so the
            // next request is tried (and fails the same way).
            let written = elm.link().written.len();
            assert!(elm.send(&request(9)).is_err());
            assert_eq!(elm.link().written.len() > written, sends_it);
        }
    }

    #[test]
    fn a_misheard_switch_of_caf0_never_reaches_the_bus() {
        // `ATCAF0` going in and `ATCAF1` coming out are written like a request, their echo checked
        // before the carriage return.
        let single = approve(Target::Physical(0x7E0), &[0x09, 0x02]);
        for (command, leaving) in [("ATCAF0", false), ("ATCAF1", true)] {
            for index in 0..command.len() {
                for bit in 0..8 {
                    let mut elm = standard();
                    if leaving {
                        exchange_one(&mut elm, &request(9));
                    }
                    let sent = elm.link().elm.sent.len();
                    elm.link_mut().corrupt_write_of =
                        Some((command.as_bytes().to_vec(), index, 1 << bit));
                    let result = if leaving {
                        elm.send(&single)
                    } else {
                        elm.send(&request(9))
                    };
                    assert!(elm.link().corrupt_write_of.is_none(), "{command}");
                    let on_bus = &elm.link().elm.sent[sent..];
                    if result.is_ok() {
                        assert_eq!(bit, 5, "{command} {index}");
                    } else {
                        assert_eq!(on_bus, [], "{command} {index} {bit}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_misheard_r0_r1_or_x_never_puts_another_frame_on_the_bus() {
        let payload = read_of(14);
        let frames = golden(&payload, 0x00);
        // `ATR0` goes in before frame 2 and `ATR1` before frame 3: after either flip only the
        // frames already sent are on the bus. Its carriage return is part of the line.
        std::thread::scope(|scope| {
            for (command, before) in [("ATR0\r", 1), ("ATR1\r", 2)] {
                for index in 0..command.len() {
                    for bit in 0..8 {
                        let (payload, frames) = (&payload, &frames);
                        scope.spawn(move || {
                            let (elm, result) = flipped(payload, command.as_bytes(), index, bit);
                            let what = format!("{command:?} byte {index} bit {bit}");
                            if result.is_ok() {
                                // Only the case of a letter is a flip the adapter takes as the
                                // same command.
                                assert_eq!(bit, 5, "{what}");
                                assert_eq!(received(&elm), *frames, "{what}");
                            } else {
                                assert_eq!(received(&elm), frames[..before], "{what}");
                            }
                        });
                    }
                }
            }
        });
        // `X` is any byte to the adapter, which stops listening for it whatever it is.
        for bit in 0..8 {
            let (mut elm, result) = flipped(&payload, b"X", 0, bit);
            assert!(result.is_ok(), "bit {bit}");
            assert_eq!(received(&elm), frames, "bit {bit}");
            assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, REPLY_ID);
        }
    }

    // ---- a link that fails mid-transfer ----------------------------------------------------

    #[test]
    fn a_link_that_fails_mid_transfer_stops_the_driver_and_writes_nothing_more() {
        let positions = write_positions();
        // After the carriage return of frame 2, and after the echo of frame 3 (its digits are
        // written, its carriage return isn't): the first two frames are on the bus either way.
        for allowed in [positions[1] + 2, positions[2] + 1] {
            let mut elm = standard();
            let writes = elm.link().writes.len();
            elm.link_mut().kill_after_writes = Some(allowed);
            let err = elm.send(&request(14)).unwrap_err();
            assert!(err.to_string().contains("link"), "{err}");
            assert_eq!(received(&elm), golden(&read_of(14), 0x00)[..2]);
            assert_eq!(elm.link().writes.len() - writes, allowed);
            // The driver is stopped, and there is no link to put `AT R1` back on.
            let written = elm.link().written.len();
            assert!(elm.send(&request(9)).is_err());
            assert_eq!(elm.link().written.len(), written);
        }
    }

    // ---- flow control ----------------------------------------------------------------------

    // The adapter after `frames` as the module's flow control.
    fn answering_with(frames: Vec<Vec<u8>>) -> Elm<FakeLink> {
        warmed(adapter(module().with_flow_frames(frames), &ANSWER))
    }

    fn waits(n: usize) -> Vec<Vec<u8>> {
        let mut frames = vec![flow_control_frame(1, 0, 0); n];
        frames.push(flow_control_frame(0, 0, 0));
        frames
    }

    #[test]
    fn only_a_clean_flow_control_lets_the_transfer_go_on() {
        let single_frame = vec![0x03, 0x7F, 0x10, 0x12, 0, 0, 0, 0];
        let first_frame = vec![0x10, 0x09, 0x62, 0xF1, 0x87, 0xF1, 0x88, 0xF1];
        let consecutive = vec![0x21, 0x89, 0xF1, 0x91, 0, 0, 0, 0];
        let extra = vec![0x03, 0x7F, 0x19, 0x78, 0, 0, 0, 0];
        let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
            ("none", vec![], "NO DATA"),
            (
                "a single frame",
                vec![single_frame],
                "instead of flow control",
            ),
            (
                "a first frame",
                vec![first_frame],
                "instead of flow control",
            ),
            (
                "a consecutive frame",
                vec![consecutive],
                "instead of flow control",
            ),
            ("status 3", vec![flow_control_frame(3, 0, 0)], "can't use"),
            ("status 8", vec![flow_control_frame(8, 0, 0)], "can't use"),
            ("status 15", vec![flow_control_frame(15, 0, 0)], "can't use"),
            ("2 bytes", vec![vec![0x30, 0x00]], "can't use"),
            ("overflow", vec![flow_control_frame(2, 0, 0)], "overflow"),
            ("11 waits", waits(11), "more than 10 wait"),
            (
                "continue then another frame",
                vec![flow_control_frame(0, 0, 0), extra],
                "after its flow control",
            ),
            (
                "two continues",
                vec![flow_control_frame(0, 0, 0), flow_control_frame(0, 0, 0)],
                "after its flow control",
            ),
        ];
        for (what, script, says) in cases {
            let mut elm = answering_with(script);
            let Err(err) = elm.send(&request(14)) else {
                panic!("{what}: the request was sent");
            };
            assert!(matches!(err, Error::Adapter(_)), "{what}: {err}");
            assert!(err.to_string().contains(says), "{what}: {err}");
            // Only the first frame went out, and the adapter is back at its prompt.
            assert_eq!(received(&elm).len(), 1, "{what}");
            assert!(!elm.link().elm.has_output(), "{what}");
            assert!(elm.link().elm.settings.responses, "{what}");
        }
    }

    // The unread and status lines among the events taken.
    fn heard_besides_frames(elm: &mut Elm<FakeLink>) -> Vec<String> {
        elm.take_events()
            .into_iter()
            .filter_map(|event| match event {
                LinkEvent::Unread { line, .. } => Some(format!("unread {line}")),
                LinkEvent::Status { line, .. } => Some(format!("status {line}")),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_line_that_fails_the_request_is_still_in_the_events() {
        // After the flow control, before the adapter's `STOPPED`: the frame is evidence of what
        // the module did, so it is reported as unread though the request fails on it.
        let extra = vec![0x03, 0x7F, 0x19, 0x78, 0, 0, 0, 0];
        let mut elm = answering_with(vec![flow_control_frame(0, 0, 0), extra]);
        elm.take_events();
        assert!(elm.send(&request(14)).is_err());
        assert_eq!(
            heard_besides_frames(&mut elm),
            ["unread 7E9 03 7F 19 78 00 00 00 00"]
        );
        // No flow control: the adapter's `NO DATA` is the answer.
        let mut elm = answering_with(vec![]);
        elm.take_events();
        assert!(elm.send(&request(14)).is_err());
        assert_eq!(heard_besides_frames(&mut elm), ["status NO DATA"]);
        // In `AT R0`, where the adapter listens for nothing, a status and a frame.
        for (printed, logged) in [
            ("BUS BUSY", "status BUS BUSY"),
            (
                "7E9 03 7F 19 78 00 00 00 00",
                "unread 7E9 03 7F 19 78 00 00 00 00",
            ),
        ] {
            let mut stopped = module();
            stopped.status_on_frame = Some((3, printed.to_owned()));
            let mut elm = warmed(adapter(stopped, &ANSWER));
            elm.take_events();
            assert!(elm.send(&request(21)).is_err());
            assert_eq!(heard_besides_frames(&mut elm), [logged]);
        }
    }

    #[test]
    fn the_hold_counts_from_the_flow_control_not_the_first_frame() {
        // The flow control comes 900 ms after the first frame, with an extra frame behind it that
        // fails the request. The module keeps the half transfer for 1 s from the flow control, so
        // the next request waits 1.25 s from it, not from the first frame.
        let positions = write_positions();
        let extra = vec![0x03, 0x7F, 0x19, 0x78, 0, 0, 0, 0];
        let mut elm = answering_with(vec![flow_control_frame(0, 0, 0), extra]);
        let at = elm.link().writes.len() + positions[0] + 1;
        elm.link_mut().slow_reads_after = Some((at, [Duration::from_millis(900)].into()));
        assert!(elm.send(&request(14)).is_err());
        let first_frame = module_of(&elm).frames[0].0;
        module_mut(&mut elm).flow_control = vec![(REPLY_ID, flow_control_frame(0, 0, 0))];
        exchange_one(&mut elm, &request(14));
        assert!(first_frame.elapsed() >= Duration::from_millis(2100));
    }

    #[test]
    fn a_status_whose_prompt_comes_after_the_limit_is_still_a_failure_of_that_request() {
        // `BUS BUSY` is read, and the transfer limit passes before the adapter's prompt is read.
        // The wait ends at the limit, and the prompt is read while the listen is stopped.
        let positions = write_positions();
        let mut busy = module();
        busy.status_on_frame = Some((1, "BUS BUSY".to_owned()));
        let mut elm = warmed(adapter(busy, &ANSWER));
        elm.tighten_segment_bounds(SEGMENT_GAP, Duration::from_millis(200));
        elm.link_mut().chunk = 10;
        let at = elm.link().writes.len() + positions[0] + 1;
        elm.link_mut().slow_reads_after = Some((at, [Duration::from_millis(400)].into()));
        let started = Instant::now();
        let err = elm.send(&request(14)).unwrap_err();
        assert!(err.to_string().contains("BUS BUSY"), "{err}");
        // Not the 7 s of silence that breaks the driver down.
        assert!(started.elapsed() < Duration::from_secs(3));
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
    }

    #[test]
    fn one_to_ten_waits_before_continue_to_send_are_taken() {
        assert_eq!(SEGMENT_MAX_WAITS, 10);
        for n in [0, 1, 10] {
            let mut elm = answering_with(waits(n));
            let answer = exchange_one(&mut elm, &request(14));
            assert_eq!(answer.source, REPLY_ID, "{n} waits");
            assert_eq!(received(&elm), golden(&read_of(14), 0x00), "{n} waits");
        }
    }

    #[test]
    fn a_flow_control_from_the_wrong_id_breaks_the_driver_down() {
        // An adapter that lost its filter prints a frame from outside it.
        let mut stray = module();
        stray.flow_control = vec![(0x7EA, flow_control_frame(0, 0, 0))];
        stray.unfiltered = true;
        let mut elm = warmed(adapter(stray, &ANSWER));
        let err = elm.send(&request(14)).unwrap_err();
        assert!(err.to_string().contains("receive filter"), "{err}");
        assert_eq!(received(&elm).len(), 1);
        let written = elm.link().written.len();
        assert!(elm.send(&request(9)).is_err());
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn another_nodes_frames_are_hidden_by_the_receive_filter() {
        let mut busy = module();
        busy.other_nodes = vec![
            (0x7EA, flow_control_frame(2, 0, 0)),
            (0x7E8, flow_control_frame(0, 0, 0)),
        ];
        let mut elm = warmed(adapter(busy, &ANSWER));
        let answer = exchange_one(&mut elm, &request(14));
        assert_eq!(answer.source, REPLY_ID);
        assert_eq!(received(&elm), golden(&read_of(14), 0x00));
    }

    #[test]
    fn an_adapter_that_ends_its_listen_with_the_flow_control_is_handled() {
        // An STN-like listen that ends at its prompt after one frame: the `X` then has nothing
        // to stop. And a timeout that runs out just as the `X` is written: the prompt comes first
        // and the byte starts a line, which is ended so the adapter refuses it.
        for ends_on_write in [false, true] {
            let mut fake = adapter(module(), &ANSWER);
            fake.listen_one_frame = !ends_on_write;
            fake.listen_ends_on_write = ends_on_write;
            let mut elm = warmed(fake);
            let before = commands(&elm).len();
            let answer = exchange_one(&mut elm, &request(14));
            assert_eq!(answer.source, REPLY_ID, "{ends_on_write}");
            assert_eq!(received(&elm), golden(&read_of(14), 0x00));
            let sent = since(&elm, before);
            assert_eq!(count(&sent, "XX"), usize::from(ends_on_write), "{sent:?}");
            assert_eq!(elm.link().elm.interrupted, 0);
        }
    }

    // ---- block size and STmin ---------------------------------------------------------------

    #[test]
    fn follows_the_block_size_of_the_flow_control() {
        // 41 bytes: a first frame and 5 consecutive ones.
        let payload = read_of(41);
        for (block_size, flow_controls, r0) in [(0, 1, 1), (1, 5, 0), (2, 3, 2)] {
            let mut elm = warmed(adapter(module().with_flow(block_size, 0), &ANSWER));
            let before = commands(&elm).len();
            let answer = exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &payload));
            assert_eq!(answer.source, REPLY_ID);
            assert_eq!(
                received(&elm),
                golden(&payload, 0x00),
                "block size {block_size}"
            );
            let sent = since(&elm, before);
            // One `X` for each flow control; `AT R0` before each run of frames inside a block.
            assert_eq!(elm.link().elm.interrupted, flow_controls, "{block_size}");
            assert_eq!(
                count(&sent, "ATR0"),
                r0,
                "block size {block_size}: {sent:?}"
            );
            assert_eq!(
                count(&sent, "ATR1"),
                r0,
                "block size {block_size}: {sent:?}"
            );
        }
    }

    #[test]
    fn keeps_the_gap_the_flow_control_asks_for() {
        // 27 bytes: a first frame and 3 consecutive ones, so two gaps between consecutive frames.
        for (st_min, least) in [
            (0x00, Duration::ZERO),
            (0x05, Duration::from_millis(5)),
            (0x7F, Duration::from_millis(127)),
            // 500 µs is rounded up to the 1 ms the driver can keep.
            (0xF5, Duration::from_millis(1)),
            // Reserved values are the longest gap.
            (0x80, Duration::from_millis(127)),
            (0xFA, Duration::from_millis(127)),
        ] {
            let mut elm = warmed(adapter(module().with_flow(0, st_min), &ANSWER));
            exchange_one(&mut elm, &request(27));
            let gaps = gaps(&elm);
            assert_eq!(gaps.len(), 3);
            for gap in &gaps[1..] {
                assert!(*gap >= least, "STmin {st_min:#04X}: {gaps:?}");
            }
        }
    }

    #[test]
    fn keeps_the_gap_across_every_flow_control_wait() {
        // Block size 1: each consecutive frame is the last of its block and waits for a flow
        // control, but is still 127 ms after the one before it, which on a fast link the `X` and
        // the write would otherwise use up.
        let mut elm = warmed(adapter(module().with_flow(1, 0x7F), &ANSWER));
        exchange_one(&mut elm, &request(27));
        let gaps = gaps(&elm);
        assert_eq!(gaps.len(), 3);
        for gap in &gaps[1..] {
            assert!(*gap >= Duration::from_millis(127), "{gaps:?}");
        }
    }

    // ---- bounds ----------------------------------------------------------------------------

    #[test]
    fn the_bounds_are_the_designs() {
        assert_eq!(SEGMENT_GAP, Duration::from_millis(500));
        assert_eq!(SEGMENT_TRANSFER, Duration::from_secs(30));
        assert_eq!(SEGMENT_HOLD, Duration::from_millis(1250));
    }

    // The digits of frame `k` (counting from 0) of a request of `len` bytes.
    fn digits(len: usize, k: usize) -> Vec<u8> {
        line(&golden(&read_of(len), 0x00)[k])
    }

    #[test]
    fn a_frame_that_would_go_more_than_500_ms_after_the_last_is_killed() {
        // 21 bytes: a first frame and 3 consecutive ones, the first two inside the block (`AT
        // R0`). Each case delays the digits of one consecutive frame on a slow link, so the
        // gap before it has passed by the time its echo is checked.
        for slow in [1, 2, 3] {
            let mut elm = warmed(adapter(module(), &ANSWER));
            // A longer bound can't be set.
            elm.tighten_segment_bounds(Duration::from_secs(10), Duration::from_secs(100));
            elm.link_mut().slow_write_of = Some((digits(21, slow), Duration::from_millis(600)));
            let err = elm.send(&request(21)).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("before frame {} of 4", slow + 1)),
                "{err}"
            );
            // The slow frame never reached the bus; the line was ended with `XX`.
            assert_eq!(
                received(&elm),
                golden(&read_of(21), 0x00)[..slow],
                "frame {slow}"
            );
            let killed = format!("{}XX", String::from_utf8(digits(21, slow)).unwrap());
            assert!(commands(&elm).contains(&killed), "{:?}", commands(&elm));
            // `AT R1` is back whatever the state it was in, and the adapter is at its prompt.
            assert!(elm.link().elm.settings.responses);
            assert!(!elm.link().elm.has_output());
        }
    }

    #[test]
    fn a_transfer_that_takes_longer_than_its_limit_stops() {
        // Each consecutive frame waits 127 ms for the one before, so the fifth is due after
        // 381 ms: past a shortened limit of 330 ms, which the fourth, due after 254 ms, meets.
        let mut elm = warmed(adapter(module().with_flow(0, 0x7F), &ANSWER));
        elm.tighten_segment_bounds(SEGMENT_GAP, Duration::from_millis(330));
        let err = elm.send(&request(41)).unwrap_err();
        assert!(err.to_string().contains("took more than 330 ms"), "{err}");
        // The first four frames went out, and the adapter was put back to waiting for replies.
        assert_eq!(received(&elm), golden(&read_of(41), 0x00)[..4]);
        assert!(elm.link().elm.settings.responses);
    }

    #[test]
    fn the_next_request_waits_out_a_stopped_transfer_and_one_after_a_success_doesnt() {
        // A first frame the module accepted and a flow control that never lets the rest go: the
        // module keeps the half transfer and ignores a first frame until it drops it after 1 s.
        let mut stuck = module().with_flow_frames(waits(11));
        stuck.ignores_first_frame_while_receiving = true;
        let mut elm = warmed(adapter(stuck, &ANSWER));
        assert!(elm.send(&request(14)).is_err());
        let first_frame = module_of(&elm).frames[0].0;
        module_mut(&mut elm).flow_control = vec![(REPLY_ID, flow_control_frame(0, 0, 0))];
        // It waits, then its first frame meets a module that has dropped the old one.
        let answer = exchange_one(&mut elm, &request(14));
        assert!(first_frame.elapsed() >= SEGMENT_HOLD);
        assert_eq!(answer.source, REPLY_ID);
        assert_eq!(module_of(&elm).dropped, 1);

        // Nothing is held after a success.
        let started = Instant::now();
        exchange_one(&mut elm, &request(14));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    // ---- `AT R0` is put back ---------------------------------------------------------------

    #[test]
    fn at_r1_is_back_after_every_failure_with_at_r0_on() {
        // 21 bytes: frames 2 and 3 are inside a block, so `AT R0` is on when the 3rd is
        // written. Each status ends the request, leaves the driver usable, and `AT R1` is back.
        for status in ["BUS BUSY", "BUFFER FULL", "DATA ERROR"] {
            let mut broken = module();
            broken.status_on_frame = Some((3, status.to_owned()));
            let mut elm = warmed(adapter(broken, &ANSWER));
            let before = commands(&elm).len();
            let err = elm.send(&request(21)).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("{status} while sending frame 3 of 4")),
                "{err}"
            );
            let sent = since(&elm, before);
            assert_eq!(sent.last().map(String::as_str), Some("ATR1"), "{sent:?}");
            assert!(elm.link().elm.settings.responses, "{status}");
            assert_eq!(received(&elm).len(), 2, "{status}");
        }
        // Anything else leaves the adapter in an unknown state.
        let mut can_error = module();
        can_error.status_on_frame = Some((3, "CAN ERROR".to_owned()));
        let mut elm = warmed(adapter(can_error, &ANSWER));
        assert!(elm.send(&request(21)).is_err());
        let written = elm.link().written.len();
        assert!(elm.send(&request(9)).is_err());
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn a_frame_in_at_r0_is_not_the_modules_to_send() {
        // The adapter isn't listening in `AT R0`, so a module that prints a frame anyway has
        // broken the transfer.
        let mut chatty = module();
        chatty.status_on_frame = Some((3, "7E9 03 7F 19 78 00 00 00 00".to_owned()));
        let mut elm = warmed(adapter(chatty, &ANSWER));
        let err = elm.send(&request(21)).unwrap_err();
        assert!(err.to_string().contains("after its flow control"), "{err}");
        assert!(elm.link().elm.settings.responses);
    }

    #[test]
    fn a_refused_at_r1_breaks_the_driver_down() {
        let mut elm = warmed(adapter(module(), &ANSWER));
        elm.link_mut().slow_write_of = Some((digits(21, 2), Duration::from_millis(600)));
        elm.link_mut().elm.unsupported.push("ATR1".into());
        let err = elm.send(&request(21)).unwrap_err();
        assert!(
            err.to_string().contains("wouldn't go back to waiting"),
            "{err}"
        );
        let written = elm.link().written.len();
        assert!(elm.send(&request(9)).is_err());
        assert_eq!(elm.link().written.len(), written);
    }

    // ---- the answer ------------------------------------------------------------------------

    #[test]
    fn a_multi_frame_answer_gets_the_adapters_flow_control_to_the_request_id() {
        let answer: Vec<u8> = (0..20).map(|n| 0x40 + n).collect();
        let mut elm = warmed(adapter(module(), &answer));
        let got = exchange_one(&mut elm, &request(14));
        assert_eq!(got, Response::new(REPLY_ID, answer));
        // The module goes on only if the flow control came to its own request ID.
        assert_eq!(elm.link().elm.flow_control_ids, [REQUEST_ID]);
    }

    #[test]
    fn a_negative_response_and_a_single_frame_answer_are_read_as_always() {
        for answer in [vec![0x7F, 0x19, 0x31], vec![0x59, 0x02, 0xFF, 0x01]] {
            let mut elm = warmed(adapter(module(), &answer));
            assert_eq!(
                exchange_one(&mut elm, &request(14)),
                Response::new(REPLY_ID, answer)
            );
        }
    }

    #[test]
    fn what_a_clone_in_caf0_prints_in_an_answer_is_dealt_with() {
        // `CAF0` prints a frame whose PCI byte is invalid, which `CAF1` would hide: dropped, so
        // the request times out as it would have.
        let mut invalid = module();
        invalid.after_answer = vec!["7E9 40 00 00 00 00 00 00 00".to_owned()];
        let mut elm = warmed(adapter(invalid, &[]));
        elm.send(&request(14)).unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)), Err(Error::Timeout));
        // A remote frame is text, and unexpected output stops the driver.
        let mut remote = module();
        remote.after_answer = vec!["7E9 RTR".to_owned()];
        let mut elm = warmed(adapter(remote, &[]));
        elm.send(&request(14)).unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "{err}");
        let written = elm.link().written.len();
        assert!(elm.send(&request(9)).is_err());
        assert_eq!(elm.link().written.len(), written);
        // A reply marked `<DATA ERROR` fails that request only.
        let mut data_error = module();
        data_error.after_answer = vec!["7E9 59 02 FF <DATA ERROR".to_owned()];
        let mut elm = warmed(adapter(data_error, &[]));
        elm.send(&request(14)).unwrap();
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("DATA ERROR"), "{err}");
    }

    // ---- modes -----------------------------------------------------------------------------

    #[test]
    fn a_single_frame_request_after_a_segmented_one_switches_back_first() {
        let mut elm = standard();
        exchange_one(&mut elm, &request(9));
        // Lazily: nothing was written right after the request.
        assert!(!commands(&elm).last().unwrap().starts_with("ATCAF"));
        assert!(!elm.link().elm.settings.caf);
        let before = commands(&elm).len();
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let sent = since(&elm, before);
        assert_eq!(sent.first().map(String::as_str), Some("ATCAF1"), "{sent:?}");
        assert!(elm.link().elm.settings.caf);
        // The single frame went out with its PCI byte.
        assert_eq!(elm.link().elm.sent.last(), Some(&(0x7E0, vec![0x09, 0x02])));
    }

    #[test]
    fn two_segmented_requests_in_a_row_switch_once() {
        let mut elm = standard();
        let before = commands(&elm).len();
        exchange_one(&mut elm, &request(9));
        exchange_one(&mut elm, &request(14));
        exchange_one(&mut elm, &request(44));
        let sent = since(&elm, before);
        assert_eq!(count(&sent, "ATCAF0"), 1, "{sent:?}");
        assert_eq!(count(&sent, "ATCAF1"), 0, "{sent:?}");
        // A plain ELM327 is paced, so adaptive timing is never on to be switched.
        assert!(!sent.iter().any(|c| c.starts_with("ATAT")), "{sent:?}");
    }

    // A module for the segmented request and one for a TP2.0 channel setup.
    fn mixed() -> FakeElm {
        FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x200, [0x5F, 0xC0, ..]) => {
                vec![(0x25F, vec![0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])]
            }
            (REQUEST_ID, _) => vec![(REPLY_ID, ANSWER.to_vec())],
            _ => Vec::new(),
        }))
        .with_module(module())
    }

    fn open_tp20(elm: &mut Elm<FakeLink>) {
        elm.send(&Policy::read_only().approve_tp20_setup(0x5F).unwrap())
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
    }

    #[test]
    fn a_tp20_session_and_a_segmented_request_pass_through_plain_iso_tp() {
        // Segmented, then TP2.0: `ATCAF1` first, then the raw mode switch.
        let mut elm = warmed(mixed());
        let start = commands(&elm).len();
        exchange_one(&mut elm, &request(9));
        let before = commands(&elm).len();
        open_tp20(&mut elm);
        let sent = since(&elm, before);
        assert_eq!(
            sent[..5],
            ["ATCAF1", "ATCFC0", "ATV1", "ATCAF0", "ATCSM0"],
            "{sent:?}"
        );
        assert!(!elm.link().elm.settings.caf && !elm.link().elm.settings.cfc);
        // And back: the raw mode is left, then `ATCAF0` for the segments.
        let before = commands(&elm).len();
        let answer = exchange_one(&mut elm, &request(9));
        assert_eq!(answer.source, REPLY_ID);
        let sent = since(&elm, before);
        assert_eq!(
            sent[..5],
            ["ATCAF1", "ATV0", "ATCFC1", "ATCSM1", "ATCAF0"],
            "{sent:?}"
        );
        let settings = &elm.link().elm.settings;
        // Segmenting needs the adapter's own flow control and no variable DLC, as it is.
        assert!(!settings.caf && settings.cfc && !settings.variable_dlc);
        assert_eq!(received(&elm).len(), 4);
        // Adaptive timing is off on a paced adapter all along, so no switch is written.
        assert!(!since(&elm, start).iter().any(|c| c.starts_with("ATAT")));
    }

    // ---- the audit log ---------------------------------------------------------------------

    fn audit_of(
        elm: Elm<FakeLink>,
        name: &str,
        run: impl FnOnce(&mut Audited<Elm<FakeLink>>),
    ) -> Vec<serde_json::Value> {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-caf0-{name}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        {
            let mut audited = Audited::open(&log, elm, "fake").unwrap();
            run(&mut audited);
        }
        let audit = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        audit
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    // What each line of the log says after the request: the command, or the direction and payload.
    fn story(lines: &[serde_json::Value]) -> Vec<String> {
        let tx = lines.iter().position(|v| v["dir"] == "tx").unwrap();
        lines[tx..]
            .iter()
            .map(|v| match v["dir"].as_str().unwrap() {
                "cmd" => format!("cmd {}", v["cmd"].as_str().unwrap()),
                dir => format!("{dir} {}", v["payload"].as_str().unwrap_or("")),
            })
            .collect()
    }

    #[test]
    fn the_audit_log_shows_the_request_once_then_every_frame_and_flow_control() {
        let lines = audit_of(standard(), "order", |elm| {
            elm.send(&request(14)).unwrap();
            while elm.recv(Duration::from_secs(1)).is_ok() {}
        });
        let story = story(&lines);
        let frames: Vec<String> = golden(&read_of(14), 0x00).iter().map(|f| hex(f)).collect();
        // The request comes first, once, with the payload; the frames follow it.
        assert_eq!(story[0], format!("tx {}", hex(&read_of(14))));
        assert_eq!(story.iter().filter(|s| s.starts_with("tx ")).count(), 1);
        // The commands, frames and flow control, in the order they happened.
        let expected = [
            "cmd ATCAF0".to_owned(),
            format!("tx_frame {}", frames[0]),
            format!("rx_frame {}", hex(&flow_control_frame(0, 0, 0))),
            "cmd X".to_owned(),
            "cmd ATR0".to_owned(),
            format!("tx_frame {}", frames[1]),
            "cmd ATR1".to_owned(),
            format!("tx_frame {}", frames[2]),
            format!("rx {}", hex(&ANSWER)),
        ];
        let mut rest = story.iter();
        for event in &expected {
            assert!(
                rest.any(|s| s == event),
                "{event} not in order in {story:?}"
            );
        }
        let ids: Vec<&str> = lines
            .iter()
            .filter(|v| v["dir"].as_str().is_some_and(|d| d.ends_with("_frame")))
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["7E1", "7E9", "7E1", "7E1"]);
    }

    #[test]
    fn a_stopped_transfer_leaves_every_frame_in_the_log() {
        let lines = audit_of(answering_with(waits(11)), "partial", |elm| {
            assert!(elm.send(&request(14)).is_err());
        });
        let story = story(&lines);
        let tx_frames = story.iter().filter(|s| s.starts_with("tx_frame")).count();
        let rx_frames = story.iter().filter(|s| s.starts_with("rx_frame")).count();
        assert_eq!((tx_frames, rx_frames), (1, 11), "{story:?}");
        assert!(lines.iter().any(|v| v["dir"] == "err"), "{story:?}");
    }

    #[test]
    fn a_killed_line_is_logged_as_a_command_not_a_frame() {
        let mut elm = standard();
        let bytes = digits(14, 1);
        elm.link_mut().corrupt_write_of = Some((bytes.clone(), 3, 0x01));
        let lines = audit_of(elm, "killed", |elm| {
            assert!(elm.send(&request(14)).is_err());
        });
        let story = story(&lines);
        // The first frame is a frame; the second was written as digits and never sent.
        assert_eq!(
            story.iter().filter(|s| s.starts_with("tx_frame")).count(),
            1
        );
        // What the driver wrote, which the adapter heard differently.
        let written = String::from_utf8(bytes).unwrap();
        assert!(story.contains(&format!("cmd {written}")), "{story:?}");
    }

    // An event as text, without the time it happened at (which differs between runs).
    fn untimed(event: &LinkEvent) -> String {
        match event {
            LinkEvent::Command {
                command, answer, ..
            } => format!("command {command} {answer:?}"),
            LinkEvent::Unread { line, .. } => format!("unread {line}"),
            LinkEvent::Status { line, .. } => format!("status {line}"),
            LinkEvent::Frame { sent, id, data, .. } => format!("frame {sent} {id:X} {data:02X?}"),
            LinkEvent::Setting { name, value, .. } => format!("setting {name} {value}"),
            LinkEvent::Lost(count) => format!("lost {count}"),
            other => panic!("an event this test doesn't know: {other:?}"),
        }
    }

    #[test]
    fn events_past_the_limit_are_counted_lost_in_order() {
        const MAX: usize = obdcracker_transport::elm::MAX_EVENTS;
        // Block size 1 gives a 44-byte request about 20 events.
        let fresh = || warmed(adapter(module().with_flow(1, 0), &ANSWER));

        // Taken after every exchange, nothing is dropped: everything the driver produced, in order.
        let mut reference = fresh();
        let mut everything: Vec<String> = reference.take_events().iter().map(untimed).collect();
        for _ in 0..250 {
            exchange_one(&mut reference, &request(44));
            everything.extend(reference.take_events().iter().map(untimed));
        }
        assert!(
            everything.iter().all(|e| !e.starts_with("lost")),
            "the reference run lost events"
        );
        assert!(everything.len() > MAX + 1, "{}", everything.len());

        // Never taken, it keeps the first `MAX` and counts the rest as lost, once, at the end.
        let mut elm = fresh();
        for _ in 0..250 {
            exchange_one(&mut elm, &request(44));
        }
        let events: Vec<String> = elm.take_events().iter().map(untimed).collect();
        assert_eq!(events.len(), MAX + 1);
        assert_eq!(events[..MAX], everything[..MAX]);
        assert_eq!(events[MAX], format!("lost {}", everything.len() - MAX));
    }
}

// An STN's long request goes as `STPX`, unless the driver is told to segment it with `AT CAF0`
// like a plain ELM327's (docs/design/elm-caf0-segmenting.md, section 13).
mod forced_caf0 {
    use obdcracker_transport::LinkEvent;
    use support::fake_elm::Module;

    use super::*;

    const REQUEST_ID: u32 = 0x7E1;
    const REPLY_ID: u32 = 0x7E9;
    const ANSWER: [u8; 3] = [0x59, 0x02, 0xFF];
    const FOUR_DIDS: [u8; 9] = [0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1, 0x89, 0xF1, 0x91];
    // The line the fake records for the 4-DID read sent with `STPX`.
    const STPX_LINE: &str = "STPXD:22F187F188F189F191";

    // `len` bytes of a `19` read, which the policy takes at any length.
    fn read_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|n| match n {
                0 => 0x19,
                1 => 0x02,
                2 => 0xFF,
                n => u8::try_from(n).unwrap(),
            })
            .collect()
    }

    fn request(len: usize) -> Approved {
        approve(Target::Physical(REQUEST_ID), &read_of(len))
    }

    // An adapter with a module that answers every request it receives whole; an STN if `stn`.
    fn adapter(stn: bool) -> FakeElm {
        let mut adapter = FakeElm::new(Box::new(|header, _| {
            if header == REQUEST_ID {
                vec![(REPLY_ID, ANSWER.to_vec())]
            } else {
                Vec::new()
            }
        }))
        .with_module(Module::new(REQUEST_ID, REPLY_ID));
        if stn {
            adapter.sti = Some("STN1155 v5.6.19".into());
        }
        adapter
    }

    // Connected, with the option as `forced` says, and past a first request, so the driver has
    // seen the adapter echo each character as it reads it.
    fn warmed(adapter: FakeElm, forced: bool) -> Elm<FakeLink> {
        let mut elm = connect(adapter);
        elm.segment_on_stn(forced);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        while elm.recv(Duration::from_secs(1)).is_ok() {}
        elm
    }

    // Every frame the module received.
    fn frames_received(elm: &Elm<FakeLink>) -> Vec<Vec<u8>> {
        elm.link()
            .elm
            .module
            .as_ref()
            .unwrap()
            .frames
            .iter()
            .map(|(_, frame)| frame.clone())
            .collect()
    }

    fn exchange_one(elm: &mut Elm<FakeLink>, request: &Approved) -> Response {
        elm.send(request).unwrap();
        let answer = elm.recv(Duration::from_secs(1)).unwrap();
        while elm.recv(Duration::from_millis(100)).is_ok() {}
        answer
    }

    fn since(elm: &Elm<FakeLink>, before: usize) -> Vec<String> {
        commands(elm)[before..].to_vec()
    }

    #[test]
    fn an_stn_sends_a_long_request_as_stpx_unless_told_to_segment_it() {
        let mut elm = warmed(adapter(true), false);
        let before = commands(&elm).len();
        let answer = exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &FOUR_DIDS));
        assert_eq!(answer, Response::new(REPLY_ID, ANSWER.to_vec()));
        let sent = since(&elm, before);
        assert!(sent.iter().any(|c| c == STPX_LINE), "{sent:?}");
        assert!(!sent.iter().any(|c| c.starts_with("ATCAF")), "{sent:?}");
        assert_eq!(frames_received(&elm).len(), 0);
    }

    #[test]
    fn an_stn_told_to_segment_sends_the_same_request_as_caf0_frames() {
        let mut elm = warmed(adapter(true), true);
        let before = commands(&elm).len();
        let answer = exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &FOUR_DIDS));
        assert_eq!(answer, Response::new(REPLY_ID, ANSWER.to_vec()));
        let sent = since(&elm, before);
        assert!(!sent.iter().any(|c| c.starts_with("STPX")), "{sent:?}");
        assert!(sent.iter().any(|c| c == "ATCAF0"), "{sent:?}");
        assert_eq!(
            frames_received(&elm),
            [
                vec![0x10, 0x09, 0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1],
                vec![0x21, 0x89, 0xF1, 0x91, 0x00, 0x00, 0x00, 0x00]
            ]
        );
        assert_eq!(
            elm.link().elm.module.as_ref().unwrap().received,
            [FOUR_DIDS.to_vec()]
        );
    }

    #[test]
    fn a_request_of_7_bytes_or_less_stays_one_frame_when_forced() {
        let mut elm = warmed(adapter(true), true);
        let before = commands(&elm).len();
        elm.send(&request(7)).unwrap();
        assert_eq!(elm.link().elm.sent.last(), Some(&(REQUEST_ID, read_of(7))));
        let sent = since(&elm, before);
        assert!(
            !sent
                .iter()
                .any(|c| c.starts_with("ATCAF") || c.starts_with("STPX")),
            "{sent:?}"
        );
    }

    #[test]
    fn the_longest_request_goes_in_segments_and_one_byte_more_is_refused() {
        let mut elm = warmed(adapter(true), true);
        let answer = exchange_one(&mut elm, &request(44));
        assert_eq!(answer, Response::new(REPLY_ID, ANSWER.to_vec()));
        assert_eq!(frames_received(&elm).len(), 7);
        let written = elm.link().written.len();
        let err = elm.send(&request(45)).unwrap_err();
        assert!(err.to_string().contains("doesn't fit"), "{err}");
        assert_eq!(elm.link().written.len(), written);
    }

    #[test]
    fn every_check_of_segmenting_applies_to_an_stn_too() {
        // Nothing is written, though `STPX` would have taken each of these (the first one needs
        // an early echo, too).
        let mut no_pp26 = adapter(true);
        no_pp26.pps = Some(vec!["09:00 F  24:00 F  25:00 F  29:FF F".to_owned()]);
        let mut cold = connect(adapter(true));
        cold.segment_on_stn(true);
        let cases: Vec<(&str, Elm<FakeLink>, Approved, &str)> = vec![
            (
                "no early echo seen yet",
                cold,
                request(9),
                "echoes each character",
            ),
            (
                "a module whose reply ID isn't known",
                warmed(adapter(true), true),
                approve(Target::Physical(0x710), &read_of(9)),
                "no one module's flow control",
            ),
            ("PP 26 missing", warmed(no_pp26, true), request(9), "PP 26"),
        ];
        for (what, mut elm, refused, says) in cases {
            let written = elm.link().written.len();
            let err = elm.send(&refused).unwrap_err();
            assert!(matches!(err, Error::Adapter(_)), "{what}: {err}");
            assert!(err.to_string().contains(says), "{what}: {err}");
            assert_eq!(elm.link().written.len(), written, "{what} wrote");
        }
    }

    #[test]
    fn turning_the_option_off_goes_back_to_stpx_after_caf1() {
        let mut elm = warmed(adapter(true), true);
        exchange_one(&mut elm, &request(9));
        elm.segment_on_stn(false);
        let before = commands(&elm).len();
        exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &FOUR_DIDS));
        let sent = since(&elm, before);
        let caf1 = sent.iter().position(|c| c == "ATCAF1").expect("ATCAF1");
        let stpx = sent.iter().position(|c| c == STPX_LINE).expect("STPX");
        assert!(caf1 < stpx, "{sent:?}");
    }

    #[test]
    fn a_plain_elm327_segments_whether_or_not_the_option_is_set() {
        for forced in [false, true] {
            let mut elm = warmed(adapter(false), forced);
            exchange_one(&mut elm, &approve(Target::Physical(REQUEST_ID), &FOUR_DIDS));
            assert_eq!(frames_received(&elm).len(), 2, "forced {forced}");
        }
    }

    // ---- the audit log ----------------------------------------------------------------------

    fn settings(events: &[LinkEvent]) -> Vec<(&str, &str)> {
        events
            .iter()
            .filter_map(|event| match event {
                LinkEvent::Setting { name, value, .. } => Some((name.as_str(), value.as_str())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn setting_the_option_is_an_event_on_an_stn_and_on_a_plain_elm327() {
        for stn in [true, false] {
            let mut elm = connect(adapter(stn));
            elm.take_events();
            elm.segment_on_stn(true);
            let events = elm.take_events();
            assert_eq!(settings(&events), [("segment-on-stn", "on")], "stn {stn}");
            elm.segment_on_stn(false);
            let events = elm.take_events();
            assert_eq!(settings(&events), [("segment-on-stn", "off")], "stn {stn}");
        }
    }

    #[test]
    fn the_audit_log_says_the_option_was_set_before_the_first_request() {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-forced-caf0.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        {
            let mut elm = connect(adapter(true));
            elm.segment_on_stn(true);
            let mut audited = Audited::open(&log, elm, "fake").unwrap();
            audited
                .send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .unwrap();
            while audited.recv(Duration::from_secs(1)).is_ok() {}
        }
        let audit = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        let lines: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let setting = lines
            .iter()
            .position(|v| v["dir"] == "setting")
            .expect("a setting line");
        let tx = lines.iter().position(|v| v["dir"] == "tx").unwrap();
        assert!(setting < tx, "{lines:?}");
        assert_eq!(lines[setting]["name"], "segment-on-stn");
        assert_eq!(lines[setting]["value"], "on");
        assert_eq!(lines.iter().filter(|v| v["dir"] == "setting").count(), 1);
    }
}

mod response_pending {
    use super::*;

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

    // The driver interrupts the adapter only to stop a listen or a monitor, reading that STOPPED
    // itself. Here nothing was stopped, so STOPPED means something else wrote to it, and the
    // interrupting byte may start the next line it reads.
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
                0x17FC_0076 => vec![(0x17FE_0076, payload)],
                _ => Vec::new(),
            }
        }))
    }

    // The instruments' reply ID comes from a profile, so the receive filter shows only it.
    fn read_long(elm: &mut Elm<FakeLink>, target: Target) -> Result<Response, Error> {
        let policy = if target == Target::Physical(0x714) {
            Policy::read_only().narrowed_to(&[INSTRUMENTS]).unwrap()
        } else if target == Target::Physical29(VAG29.request) {
            Policy::read_only().narrowed_to(&[VAG29]).unwrap()
        } else {
            Policy::read_only()
        };
        elm.send(
            &policy
                .approve(Protocol::Uds, target, &[0x22, 0xF1, 0x87])
                .unwrap(),
        )?;
        elm.recv(Duration::from_secs(30))
    }

    #[test]
    fn the_fake_adapter_overflows_without_pacing() {
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
            assert_eq!(elm.link().elm.flow_control_ids, [0x7E0, 0x714], "{baud}");
        }
    }

    #[test]
    fn the_longest_29_bit_reply_reads_on_a_plain_elm327_at_every_common_baud_rate() {
        // A 29-bit frame line is 37 characters, `17 FE 00 76 21 41 41 41 41 41 41 41 \r`, so
        // the gap an 11-bit line needs is too short (PR #147, Codex).
        for baud in [9600, 38_400, 115_200] {
            let mut elm = Elm::connect(FakeLink::at_baud(long_replies(), baud)).unwrap();
            let reply = read_long(&mut elm, Target::Physical29(VAG29.request))
                .unwrap_or_else(|e| panic!("{baud} baud: {e}"));
            assert_eq!(reply.payload.len(), 4095, "{baud} baud");
        }
    }

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
    fn a_broadcast_gets_the_adapters_own_flow_control_to_each_ecu() {
        // Only the adapter's ISO 15765-4 handling (mode 0) reaches each answering ECU's own
        // request ID, so a broadcast isn't paced, even on a plain ELM327 (PR #70, Codex).
        let mut elm = Elm::connect(FakeLink::new(eight_long_replies())).unwrap();
        let setup = commands(&elm).len();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let mut sources = Vec::new();
        while let Ok(reply) = elm.recv(Duration::from_secs(5)) {
            assert_eq!(reply.payload.len(), 4095);
            sources.push(reply.source);
        }
        sources.sort_unstable();
        assert_eq!(sources, (0x7E8..=0x7EF).collect::<Vec<_>>());
        assert_eq!(commands(&elm)[setup..setup + 2], ["ATSH7DF", "ATFCSM0"]);
        let mut to = elm.link().elm.flow_control_ids.clone();
        to.sort_unstable();
        assert_eq!(to, (0x7E0..=0x7E7).collect::<Vec<_>>());
    }

    #[test]
    fn flow_control_mode_2_would_stall_every_reply() {
        // Mode 2 keeps the First Frame's own ID (datasheet p. 48): flow control for 7E8's
        // reply goes to 7E8, not 7E0, and the ECU never sends the rest.
        let mut elm = eight_long_replies();
        elm.settings.headers = true;
        elm.settings.protocol = Some("6".into());
        let mut out = Vec::new();
        for line in ["ATFCSD300003", "ATFCSM2", "0902"] {
            elm.write(format!("{line}\r").as_bytes());
            out.extend(elm.read(usize::MAX));
        }
        assert_eq!(elm.flow_control_ids, (0x7E8..=0x7EF).collect::<Vec<_>>());
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains(" 21 "), "{out}");
    }

    #[test]
    fn a_broadcast_that_overflows_a_slow_link_says_so() {
        // Eight ECUs' long replies at once are too much for 9600 baud.
        let mut elm = Elm::connect(FakeLink::at_baud(eight_long_replies(), 9600)).unwrap();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let err = loop {
            if let Err(e) = elm.recv(Duration::from_secs(5)) {
                break e.to_string();
            }
        };
        assert!(
            err.contains("BUFFER FULL") && err.contains("faster baud rate"),
            "{err}"
        );
    }

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
                    "ATFCSH7E0".to_owned(),
                    format!("ATFCSD3000{st_min}"),
                    "ATFCSM1".to_owned(),
                    "ATFCSH714".to_owned(),
                    format!("ATFCSD3000{st_min}"),
                    "ATFCSM1".to_owned(),
                ],
                "{rate:?}"
            );
        }
    }

    #[test]
    fn adaptive_timing_is_off_only_when_pacing() {
        // A learned timeout shorter than the gap would end a paced reply early (PR #70, Codex).
        let elm = Elm::connect(FakeLink::at_baud(long_replies(), 9600)).unwrap();
        assert_eq!(commands(&elm).last().map(String::as_str), Some("ATAT0"));
        let mut stn = long_replies();
        stn.sti = Some("STN2232 v5.12.4".into());
        let elm = Elm::connect(FakeLink::new(stn)).unwrap();
        assert!(!commands(&elm).iter().any(|c| c == "ATAT0"));
    }

    #[test]
    fn patience_raises_an_stns_timeout_and_restores_it() {
        // An STN always waits its whole timeout for a first reply (STN1100 FRPM), so turning
        // adaptive timing off alone never made a silent ID's wait longer: every discovery pass in
        // #86 waited about 1.09 s (#87). `STPTO` sets the timeout in milliseconds, up to 65535.
        let mut stn = car();
        stn.sti = Some("STN2232 v5.12.4".into());
        let mut elm = connect(stn);
        let new_commands = |elm: &Elm<FakeLink>, before: usize| commands(elm)[before..].to_vec();
        let before = commands(&elm).len();
        assert_eq!(
            elm.patient(Some(Duration::from_secs(5))).unwrap(),
            Some(Duration::from_secs(5))
        );
        assert_eq!(new_commands(&elm, before), ["ATAT0", "STPTO5000"]);
        let before = commands(&elm).len();
        assert_eq!(elm.patient(None).unwrap(), None);
        assert_eq!(new_commands(&elm, before), ["ATSTFF", "ATAT1"]);
        assert_eq!(
            elm.patient(Some(Duration::from_secs(100))).unwrap(),
            Some(Duration::from_millis(65_535))
        );
        assert_eq!(
            commands(&elm).last().map(String::as_str),
            Some("STPTO65535")
        );
        elm.patient(None).unwrap();
        let before = commands(&elm).len();
        assert_eq!(
            elm.patient(Some(Duration::from_millis(500))).unwrap(),
            Some(ADAPTER_TIMEOUT)
        );
        assert_eq!(new_commands(&elm, before), ["ATAT0"]);
        let before = commands(&elm).len();
        elm.patient(None).unwrap();
        assert_eq!(new_commands(&elm, before), ["ATAT1"]);
    }

    #[test]
    fn patience_sets_the_wait_each_call_asks_for() {
        let mut stn = car();
        stn.sti = Some("STN2232 v5.12.4".into());
        let mut elm = connect(stn);
        elm.patient(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(
            elm.patient(Some(Duration::from_secs(2))).unwrap(),
            Some(Duration::from_secs(2))
        );
        assert_eq!(commands(&elm).last().map(String::as_str), Some("STPTO2000"));
        assert_eq!(
            elm.patient(Some(Duration::from_millis(500))).unwrap(),
            Some(ADAPTER_TIMEOUT)
        );
        assert_eq!(commands(&elm).last().map(String::as_str), Some("ATSTFF"));
        let before = commands(&elm).len();
        elm.patient(None).unwrap();
        assert_eq!(commands(&elm)[before..], ["ATAT1"]);
    }

    #[test]
    fn a_failed_stpto_leaves_the_adapter_unusable() {
        // An answer that isn't OK doesn't prove the adapter didn't apply it, so its timeout is
        // unknown: nothing more is sent until it's connected (and reset) again.
        let mut stn = car();
        stn.sti = Some("STN2232 v5.12.4".into());
        stn.unsupported = vec!["STPTO5000".into()];
        let mut elm = connect(stn);
        assert!(elm.patient(Some(Duration::from_secs(5))).is_err());
        let before = commands(&elm).len();
        let err = elm.patient(None).unwrap_err();
        assert!(err.to_string().contains("connect again"), "{err}");
        assert!(
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .is_err()
        );
        assert_eq!(commands(&elm).len(), before);
    }

    #[test]
    fn a_plain_elm327_waits_no_longer_than_at_st_ff() {
        // `AT ST FF` is the most an ELM327 waits, so patience says that's how long the wait
        // really is. A plain ELM327 is paced, so adaptive timing is already off and nothing is
        // sent: a learned timeout shorter than the gap would end a paced reply early (PR #70).
        for elm in [car(), long_replies()] {
            let mut elm = Elm::connect(FakeLink::new(elm)).unwrap();
            let before = commands(&elm).len();
            assert_eq!(
                elm.patient(Some(Duration::from_secs(5))).unwrap(),
                Some(ADAPTER_TIMEOUT)
            );
            assert_eq!(elm.patient(None).unwrap(), None);
            assert_eq!(commands(&elm).len(), before);
        }
    }

    #[test]
    fn a_patient_stn_may_stay_quiet_for_its_whole_timeout() {
        // With a 9 s timeout, 8 s without a byte is the adapter waiting, not a hang.
        let mut stn = car();
        stn.sti = Some("STN2232 v5.12.4".into());
        let mut elm = connect(stn);
        elm.patient(Some(Duration::from_secs(9))).unwrap();
        elm.link_mut().elm.hang_after_request = true;
        elm.send(&approve(Target::Physical(0x7E5), &[0x09, 0x02]))
            .unwrap();
        let start = Instant::now();
        elm.link_mut().scheduled = [(start + Duration::from_secs(8), b"\r>".to_vec())].into();
        assert_eq!(elm.recv(Duration::from_secs(60)), Err(Error::Timeout));
        assert!(start.elapsed() >= Duration::from_secs(8));
        elm.patient(None).unwrap();
        elm.send(&approve(Target::Physical(0x7E5), &[0x09, 0x02]))
            .unwrap();
        let start = Instant::now();
        let err = loop {
            match elm.recv(Duration::from_secs(60)) {
                Ok(_) | Err(Error::Timeout) => {}
                Err(err) => break err,
            }
            assert!(start.elapsed() < Duration::from_secs(15), "never tripped");
        };
        assert!(err.to_string().contains("quiet"), "{err}");
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
        let mut clone = long_replies();
        clone.sti = Some("OK".into());
        assert_eq!(
            flow_commands(FakeLink::at_baud(clone, 115_200))[1],
            "ATFCSD300003"
        );
        // Untested any slower, so it's paced like any other adapter.
        let mut stn = long_replies();
        stn.sti = Some("STN2232 v5.12.4".into());
        assert_eq!(
            flow_commands(FakeLink::at_baud(stn, 38_400))[1],
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

mod events {
    use super::*;
    use obdcracker_transport::LinkEvent;

    fn commands_in(events: &[LinkEvent]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|e| match e {
                LinkEvent::Command { command, .. } => Some(command.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_adapter_command_is_reported_with_its_answer() {
        let mut elm = connect(car());
        let events = elm.take_events();
        assert_eq!(commands_in(&events), commands(&elm));
        assert!(
            events.iter().any(|e| matches!(
                e,
                LinkEvent::Command { command, answer, .. }
                    if command == "ATSP6" && answer == &["OK".to_owned()]
            )),
            "{events:?}"
        );
        assert_eq!(elm.take_events(), []);
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let events = elm.take_events();
        assert!(commands_in(&events).contains(&"ATSH7E0"), "{events:?}");
    }

    #[test]
    fn reply_lines_nobody_read_are_reported_not_lost() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let first = elm.recv(Duration::from_secs(1)).unwrap();
        elm.take_events();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let unread: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect();
        let other = if first.source == 0x7E8 { "7E9" } else { "7E8" };
        assert_ne!(unread, Vec::<String>::new());
        assert!(
            unread.iter().all(|line| line.starts_with(other)),
            "{unread:?}"
        );
    }

    #[test]
    fn frames_of_a_reply_left_incomplete_are_reported() {
        // Paced, the two ECUs' frames interleave, so the second's first frames are read (and
        // fed to its reassembler) before the first's reply completes. Abandoning that reply
        // must still report every one of its lines.
        let mut elm = Elm::connect(FakeLink::at_baud(car(), 115_200)).unwrap();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let first = elm.recv(Duration::from_secs(1)).unwrap();
        elm.take_events();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let other = if first.source == 0x7E8 { "7E9" } else { "7E8" };
        let unread: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect();
        let expected: Vec<String> = frames(VIN)
            .iter()
            .map(|frame| format!("{other} {}", hex(frame)))
            .collect();
        assert_eq!(unread, expected);
    }

    fn unread_in(events: Vec<LinkEvent>) -> Vec<String> {
        events
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect()
    }

    fn three_ecus() -> FakeElm {
        FakeElm::new(Box::new(|header, request| {
            if header == 0x7DF && request == [0x09, 0x02] {
                [0x7E8, 0x7E9, 0x7EA]
                    .into_iter()
                    .map(|source| (source, VIN.to_vec()))
                    .collect()
            } else {
                Vec::new()
            }
        }))
    }

    #[test]
    fn unfinished_replies_are_reported_in_the_order_they_arrived() {
        // Paced, the ECUs' frames interleave: the first's reply completes on its third frame,
        // by when the other two have sent two frames each, and their last frames follow.
        let mut elm = Elm::connect(FakeLink::at_baud(three_ecus(), 115_200)).unwrap();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x7E8);
        elm.take_events();
        elm.settle().unwrap();
        let frames = frames(VIN);
        let expected: Vec<String> = frames
            .iter()
            .flat_map(|frame| ["7E9", "7EA"].map(|source| format!("{source} {}", hex(frame))))
            .collect();
        assert_eq!(unread_in(elm.take_events()), expected);
    }

    #[test]
    fn a_broken_adapter_still_reports_what_it_had_heard() {
        let mut elm = Elm::connect(FakeLink::at_baud(
            FakeElm::new(Box::new(|header, _| {
                if header == 0x7DF {
                    vec![(0x7E8, VIN.to_vec()), (0x7E9, [VIN, VIN].concat())]
                } else {
                    Vec::new()
                }
            })),
            115_200,
        ))
        .unwrap();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)).unwrap().source, 0x7E8);
        elm.take_events();
        elm.link_mut().closed = true;
        assert!(matches!(
            elm.recv(Duration::from_secs(1)),
            Err(Error::Adapter(_))
        ));
        assert!(elm.settle().is_err());
        let unread = unread_in(elm.take_events());
        let sent: Vec<String> = frames(&[VIN, VIN].concat())
            .iter()
            .map(|frame| format!("7E9 {}", hex(frame)))
            .collect();
        assert!(unread.len() >= 2 && sent.starts_with(&unread), "{unread:?}");
    }

    fn statuses_in(events: &[LinkEvent]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|e| match e {
                LinkEvent::Status { line, .. } => Some(line.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_status_line_that_ends_a_request_is_reported_as_a_status() {
        // NO DATA was read: it's the adapter's answer that ended the request (#88).
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x01, 0x00]))
            .unwrap();
        assert_eq!(elm.recv(Duration::from_secs(1)), Err(Error::Timeout));
        let events = elm.take_events();
        assert_eq!(statuses_in(&events), ["NO DATA"]);
        assert_eq!(unread_in(events), Vec::<String>::new());
    }

    #[test]
    fn a_status_line_nobody_waited_for_is_still_a_status() {
        let mut elm = connect(car());
        elm.send(&approve(Target::Physical(0x7E0), &[0x01, 0x00]))
            .unwrap();
        elm.take_events();
        elm.send(&approve(Target::Physical(0x7E0), &[0x01, 0x00]))
            .unwrap();
        let events = elm.take_events();
        assert_eq!(statuses_in(&events), ["NO DATA"]);
        assert_eq!(unread_in(events), Vec::<String>::new());
    }

    #[test]
    fn reset_output_past_the_answer_cap_is_counted_as_lost() {
        // A noisy clone prints 40 lines before its banner (#85). The answer keeps the first 32
        // lines (the echo and 31 of them); the other 9 and the banner are counted, not dropped
        // silently.
        let mut fake = car();
        fake.reset_noise = b"NOISE\r".repeat(40);
        let mut elm = connect(fake);
        let events = elm.take_events();
        let answer = events
            .iter()
            .find_map(|e| match e {
                LinkEvent::Command {
                    command, answer, ..
                } if command == "ATZ" => Some(answer),
                _ => None,
            })
            .unwrap();
        assert_eq!(answer.len(), 32);
        assert_eq!(answer[0], "ATZ");
        assert!(answer[1..].iter().all(|line| line == "NOISE"), "{answer:?}");
        let reset = events
            .iter()
            .position(|e| matches!(e, LinkEvent::Command { command, .. } if command == "ATZ"))
            .unwrap();
        assert_eq!(
            events.get(reset + 1),
            Some(&LinkEvent::Lost(10)),
            "{events:?}"
        );
        assert_eq!(lost_in(&events), 10);
    }

    // Eight ECUs answer a broadcast at once with the longest single transfer, 586 frames each,
    // interleaved: more frame lines are in flight than the driver keeps (`MAX_EVENTS`, 4096)
    // before the first reply completes.
    fn eight_long_replies() -> (Elm<FakeLink>, usize) {
        eight_replies_first_shorter_by(0)
    }

    // The same, but 0x7E8's reply is `cut` bytes shorter, so it completes while the others'
    // lines are still arriving.
    fn eight_replies_first_shorter_by(cut: usize) -> (Elm<FakeLink>, usize) {
        let payload: Vec<u8> = [0x49, 0x02]
            .into_iter()
            .chain((0..=250u8).cycle().take(4093))
            .collect();
        let per_ecu = frames(&payload).len();
        let mut fake = FakeElm::new(Box::new(move |header, request| {
            if header == 0x7DF && request == [0x09, 0x02] {
                (0x7E8..=0x7EF)
                    .map(|id| {
                        let end = if id == 0x7E8 {
                            payload.len() - cut
                        } else {
                            payload.len()
                        };
                        (id, payload[..end].to_vec())
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }));
        fake.drain_rate = Some(u32::MAX);
        let mut elm = connect(fake);
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        (elm, per_ecu)
    }

    fn lost_in(events: &[LinkEvent]) -> usize {
        events
            .iter()
            .map(|e| match e {
                LinkEvent::Lost(n) => *n,
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn lines_past_the_cap_that_end_up_in_replies_are_not_lost() {
        let (mut elm, _) = eight_long_replies();
        for _ in 0..8 {
            assert_eq!(
                elm.recv(Duration::from_secs(5)).unwrap().payload.len(),
                4095
            );
        }
        elm.settle().unwrap();
        let events = elm.take_events();
        assert_eq!(lost_in(&events), 0, "{:?}", events.last());
        assert_eq!(unread_in(events), Vec::<String>::new());
    }

    #[test]
    fn lines_past_the_cap_in_abandoned_replies_are_each_counted_once() {
        // Only the first reply is read: every line of the other seven is reported as unread or
        // counted as lost, and nothing else is.
        let (mut elm, per_ecu) = eight_long_replies();
        elm.recv(Duration::from_secs(5)).unwrap();
        elm.take_events();
        elm.settle().unwrap();
        elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
            .unwrap();
        let events = elm.take_events();
        let lost = lost_in(&events);
        let at = events.iter().position(|e| matches!(e, LinkEvent::Lost(_)));
        let first_command = events
            .iter()
            .position(|e| matches!(e, LinkEvent::Command { .. }));
        assert!(at < first_command, "{at:?} {first_command:?}");
        let unread = unread_in(events).len();
        assert!(lost > 0, "{unread} unread");
        assert_eq!(unread + lost, 7 * per_ecu);
    }

    #[test]
    fn lines_read_after_one_is_lost_are_lost_too() {
        // 0x7E8's reply completes after the cap is hit, freeing the room its lines held, and
        // 0x7E9's completes later still. Lines read after the first loss must not be kept, or
        // `Lost` would be reported after lines read later than the ones it counts.
        let (mut elm, per_ecu) = eight_replies_first_shorter_by(300);
        let first = elm.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(first.source, 0x7E8);
        let second = elm.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(second.source, 0x7E9);
        elm.take_events();
        elm.settle().unwrap();
        let events = elm.take_events();
        // The modules' frames arrive in rounds of eight, so the 4096 lines kept are 512 rounds,
        // 512 from each module; the two replies took theirs back.
        let kept = 4096 - 2 * 512;
        // The other six modules' last frames are only read by `settle`, after the loss.
        let late = ["7EA", "7EB", "7EC", "7ED", "7EE", "7EF"];
        let lost = 6 * per_ecu - late.len() - kept;
        let marker = events
            .iter()
            .position(|e| matches!(e, LinkEvent::Lost(_)))
            .unwrap();
        assert_eq!(marker, kept, "{:?}", &events[marker.saturating_sub(2)..]);
        assert_eq!(events[marker], LinkEvent::Lost(lost));
        assert!(
            events[..marker]
                .iter()
                .all(|e| matches!(e, LinkEvent::Unread { .. }))
        );
        let after: Vec<&str> = events[marker + 1..]
            .iter()
            .map(|e| match e {
                LinkEvent::Unread { line, .. } => &line[..3],
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(after, late);
    }

    #[test]
    fn unread_lines_keep_the_time_they_arrived() {
        // The second ECU's reply starts arriving with the first: its first line is read and
        // queued but unused while the caller waits, then dropped by the next request. Its time
        // is when it was read, not when it was dropped. (Lines still in the link's buffer are
        // read, and timed, only then.)
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.recv(Duration::from_secs(1)).unwrap();
        let arrived_by = std::time::SystemTime::now();
        std::thread::sleep(Duration::from_millis(50));
        elm.take_events();
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let times: Vec<_> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { at, .. } => Some(at),
                _ => None,
            })
            .collect();
        assert!(
            times.first().is_some_and(|at| *at <= arrived_by),
            "{times:?}"
        );
    }

    #[test]
    fn settling_reports_what_is_left_of_the_last_request() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        let first = elm.recv(Duration::from_secs(1)).unwrap();
        elm.take_events();
        elm.settle().unwrap();
        let other = if first.source == 0x7E8 { "7E9" } else { "7E8" };
        let unread: Vec<String> = elm
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                LinkEvent::Unread { line, .. } => Some(line),
                _ => None,
            })
            .collect();
        assert_ne!(unread, Vec::<String>::new());
        assert!(unread.iter().all(|l| l.starts_with(other)), "{unread:?}");
        let written = elm.link().elm.commands.len();
        elm.settle().unwrap();
        assert_eq!(elm.take_events(), []);
        assert_eq!(elm.link().elm.commands.len(), written);
    }

    #[test]
    fn a_failed_setup_still_reports_the_commands_it_sent() {
        // The adapter refuses `AT SP 6` mid-setup: the commands up to it, and its answer, come
        // back with the error, as nothing else can take them.
        let mut adapter = FakeElm::silent();
        adapter.unsupported.push("ATSP6".into());
        let Err(failed) = Elm::connect_reporting(FakeLink::new(adapter)) else {
            panic!("connected");
        };
        assert!(
            failed.error.to_string().contains("ATSP6"),
            "{}",
            failed.error
        );
        assert_eq!(
            commands_in(&failed.events),
            ["ATZ", "ATPPS", "ATL0", "ATS1", "ATH1", "ATSP6"]
        );
        assert!(
            matches!(
                failed.events.last(),
                Some(LinkEvent::Command { answer, .. }) if answer == &["?".to_owned()]
            ),
            "{:?}",
            failed.events.last()
        );
    }

    #[test]
    fn a_reset_whose_write_fails_is_still_reported() {
        // Part of `ATZ` may have reached the adapter before the link failed.
        let mut link = FakeLink::new(FakeElm::silent());
        link.fail_writes = true;
        let Err(failed) = Elm::connect_reporting(link) else {
            panic!("connected");
        };
        assert_eq!(commands_in(&failed.events), ["ATZ"], "{:?}", failed.events);
    }

    #[test]
    fn an_untaken_report_is_bounded() {
        let mut elm = connect(car());
        for _ in 0..1500 {
            elm.send(&approve(Target::Physical(0x7E0), &[0x09, 0x02]))
                .unwrap();
            elm.send(&approve(Target::Physical(0x7E1), &[0x09, 0x02]))
                .unwrap();
        }
        let events = elm.take_events();
        assert!(events.len() <= obdcracker_transport::elm::MAX_EVENTS + 1);
        assert!(
            matches!(events.last(), Some(LinkEvent::Lost(n)) if *n > 0),
            "{:?}",
            events.last()
        );
    }
}

// `scan` and `fingerprint` through the real driver on links it paces (#71): eight ECUs' long
// replies to one broadcast overflow a plain ELM327's buffer at 9600 baud.
mod paced_reads {
    use super::*;
    use obdcracker_core::obd::{Cvn, Dtc, Unit};
    use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
    use obdcracker_transport::Timing;
    use obdcracker_transport::fingerprint::{Calibration, ReadError, fingerprint, read_vin};
    use obdcracker_transport::scan::{ObdEcu, PidValue, scan};

    // ECU `n` listens on 0x7E0 + n and answers on 0x7E8 + n.
    #[derive(Clone, Copy)]
    struct Fleet {
        ecus: u32,
        // Hears a physical request but never answers it (broadcasts still get answered).
        silent_on: Option<u32>,
        // Refuses every physical request with NRC 0x31.
        refuses_on: Option<u32>,
        // Whether anyone answers `01 00`.
        answers_01_00: bool,
    }

    impl Fleet {
        fn of(ecus: u32) -> Self {
            Self {
                ecus,
                silent_on: None,
                refuses_on: None,
                answers_01_00: true,
            }
        }
    }

    // ECU `n`'s VIN, 17 characters.
    fn vin(n: u32) -> String {
        format!("WAUZZZ4G1EN00000{n}")
    }

    fn ecu_reply(n: u32, request: &[u8]) -> Option<Vec<u8>> {
        let tag = u8::try_from(n).unwrap();
        match request {
            [0x01, 0x00] => Some(vec![0x41, 0x00, 0x00, 0x10, 0x00, 0x00]),
            [0x01, 0x0C] => Some(vec![0x41, 0x0C, tag + 1, 0x00]),
            [0x09, 0x00] => Some(vec![0x49, 0x00, 0x14, 0x40, 0x00, 0x00]),
            [0x09, 0x02] => {
                let mut reply = vec![0x49, 0x02, 0x01];
                reply.extend(vin(n).bytes());
                Some(reply)
            }
            [0x09, 0x04] => {
                let mut reply = vec![0x49, 0x04, 0x03];
                for slot in 0..3 {
                    let mut calid = format!("CAL{n}-{slot}").into_bytes();
                    calid.resize(16, 0);
                    reply.extend(calid);
                }
                Some(reply)
            }
            [0x09, 0x06] => {
                let mut reply = vec![0x49, 0x06, 0x03];
                for slot in 0..3 {
                    reply.extend([tag, slot, 0xAA, 0xBB]);
                }
                Some(reply)
            }
            [0x09, 0x0A] => {
                let mut reply = vec![0x49, 0x0A, 0x01];
                let mut name = format!("ECU{n}-Engine").into_bytes();
                name.resize(20, 0);
                reply.extend(name);
                Some(reply)
            }
            [0x03] => Some(vec![0x43, 0x03, 0x01, tag, 0x02, tag, 0x03, tag]),
            _ => None,
        }
    }

    fn adapter(fleet: Fleet) -> FakeElm {
        FakeElm::new(Box::new(move |header, request| {
            let asked: Vec<u32> = if header == 0x7DF {
                (0..fleet.ecus).collect()
            } else if (0x7E0..0x7E0 + fleet.ecus).contains(&header) {
                vec![header - 0x7E0]
            } else {
                Vec::new()
            };
            let physical = header != 0x7DF;
            asked
                .into_iter()
                .filter_map(|n| {
                    if request == [0x01, 0x00] && !fleet.answers_01_00 {
                        return None;
                    }
                    let reply = ecu_reply(n, request)?;
                    if physical && fleet.silent_on == Some(n) {
                        None
                    } else if physical && fleet.refuses_on == Some(n) {
                        Some((0x7E8 + n, vec![0x7F, request[0], 0x31]))
                    } else {
                        Some((0x7E8 + n, reply))
                    }
                })
                .collect()
        }))
    }

    fn plain_elm(fleet: Fleet, baud: u32) -> Elm<FakeLink> {
        Elm::connect(FakeLink::at_baud(adapter(fleet), baud)).unwrap()
    }

    fn stn_at(fleet: Fleet, byte_rate: Option<u32>) -> Elm<FakeLink> {
        let mut stn = adapter(fleet);
        stn.sti = Some("STN2232 v5.12.4".into());
        let mut link = FakeLink::new(stn);
        link.byte_rate = byte_rate;
        Elm::connect(link).unwrap()
    }

    // An STN's buffer isn't modelled, so it never overflows here, as the real one doesn't at
    // this speed.
    fn fast_stn(fleet: Fleet) -> Elm<FakeLink> {
        stn_at(fleet, Some(11_520))
    }

    fn timing() -> Timing {
        Elm::<FakeLink>::timing()
    }

    type Sent = Vec<(u32, Vec<u8>)>;

    fn sent(elm: &Elm<FakeLink>) -> Sent {
        elm.link().elm.sent.clone()
    }

    fn broadcasts(requests: &[&[u8]]) -> Sent {
        requests.iter().map(|r| (0x7DF, r.to_vec())).collect()
    }

    fn physical_reads(of: &[u8], ecus: u32) -> Sent {
        (0..ecus).map(|n| (0x7E0 + n, of.to_vec())).collect()
    }

    fn scanned(n: u32) -> ObdEcu {
        let tag = u16::try_from(n).unwrap();
        ObdEcu {
            source: 0x7E8 + n,
            pids: Ok(vec![(
                0x0C,
                Ok(PidValue::Quantity {
                    value: f32::from(tag + 1) * 64.0,
                    unit: Unit::Rpm,
                }),
            )]),
            pids_cut_short: None,
            supported_info: Ok(vec![0x04, 0x06, 0x0A]),
            ecu_name: Ok(format!("ECU{n}-Engine")),
            stored_dtcs: Ok(vec![
                Dtc::new(0x0100 | tag),
                Dtc::new(0x0200 | tag),
                Dtc::new(0x0300 | tag),
            ]),
        }
    }

    fn calibrated(n: u32) -> Calibration {
        let tag = u8::try_from(n).unwrap();
        Calibration {
            source: 0x7E8 + n,
            calids: Ok((0..3).map(|slot| Some(format!("CAL{n}-{slot}"))).collect()),
            cvns: Ok((0..3).map(|slot| Cvn([tag, slot, 0xAA, 0xBB])).collect()),
        }
    }

    // Flow control went to each ECU's own request ID, and to nothing else.
    fn assert_flow_control_per_ecu(elm: &Elm<FakeLink>, ecus: u32) {
        let mut to = elm.link().elm.flow_control_ids.clone();
        to.sort_unstable();
        to.dedup();
        assert_eq!(to, (0x7E0..0x7E0 + ecus).collect::<Vec<_>>());
        assert!(commands(elm).iter().any(|c| c == "ATFCSM1"));
    }

    #[test]
    fn a_plain_elm327_at_9600_baud_scans_eight_ecus() {
        let mut elm = plain_elm(Fleet::of(8), 9600);
        let result = scan(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(scanned).collect::<Vec<_>>());
        // The long reads go to each ECU in turn, after the broadcasts that name the ECUs.
        let mut expected = broadcasts(&[&[0x01, 0x00], &[0x01, 0x0C], &[0x09, 0x00]]);
        expected.extend(physical_reads(&[0x09, 0x0A], 8));
        expected.extend(physical_reads(&[0x03], 8));
        assert_eq!(sent(&elm), expected);
        assert_flow_control_per_ecu(&elm, 8);
    }

    #[test]
    fn a_plain_elm327_at_9600_baud_fingerprints_eight_ecus() {
        let mut elm = plain_elm(Fleet::of(8), 9600);
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(calibrated).collect::<Vec<_>>());
        let mut expected = broadcasts(&[&[0x01, 0x00]]);
        expected.extend(physical_reads(&[0x09, 0x04], 8));
        expected.extend(physical_reads(&[0x09, 0x06], 8));
        assert_eq!(sent(&elm), expected);
        assert_flow_control_per_ecu(&elm, 8);
    }

    #[test]
    fn an_stn_at_115200_baud_sends_the_same_broadcasts_as_before() {
        let mut elm = fast_stn(Fleet::of(8));
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(calibrated).collect::<Vec<_>>());
        // No `01 00` to learn the ECUs, and no physical request.
        assert_eq!(sent(&elm), broadcasts(&[&[0x09, 0x04], &[0x09, 0x06]]));

        let mut elm = fast_stn(Fleet::of(8));
        let result = scan(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(scanned).collect::<Vec<_>>());
        assert_eq!(
            sent(&elm),
            broadcasts(&[
                &[0x01, 0x00],
                &[0x01, 0x0C],
                &[0x09, 0x00],
                &[0x09, 0x0A],
                &[0x03],
            ])
        );
    }

    #[test]
    fn an_ecu_silent_on_its_physical_request_has_no_reply_and_the_others_are_complete() {
        let fleet = Fleet {
            silent_on: Some(3),
            ..Fleet::of(8)
        };
        let mut elm = plain_elm(fleet, 9600);
        let result = scan(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus.len(), 8);
        for (n, ecu) in (0..8).zip(&result.ecus) {
            if n == 3 {
                // Still listed: it answered the broadcasts.
                assert_eq!(ecu.source, 0x7EB);
                assert_eq!(ecu.ecu_name, Err(ReadError::NoReply));
                assert_eq!(ecu.stored_dtcs, Err(ReadError::NoReply));
                assert_eq!(ecu.pids, scanned(3).pids);
            } else {
                assert_eq!(*ecu, scanned(n));
            }
        }

        let mut elm = plain_elm(fleet, 9600);
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        // It answered neither 09 04 nor 09 06, so it isn't listed, as with a broadcast.
        assert_eq!(
            result.ecus,
            [0, 1, 2, 4, 5, 6, 7].map(calibrated).to_vec(),
            "{:?}",
            result.ecus
        );
    }

    #[test]
    fn an_ecu_refusing_its_physical_request_is_reported_as_a_refusal() {
        let fleet = Fleet {
            refuses_on: Some(5),
            ..Fleet::of(8)
        };
        let refusal = |sid| {
            ReadError::Reply(ReplyError::Negative(NegativeResponse {
                sid,
                nrc: Nrc::RequestOutOfRange,
            }))
        };
        let mut elm = plain_elm(fleet, 9600);
        let result = scan(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        for (n, ecu) in (0..8).zip(&result.ecus) {
            if n == 5 {
                assert_eq!(ecu.ecu_name, Err(refusal(0x09)));
                assert_eq!(ecu.stored_dtcs, Err(refusal(0x03)));
            } else {
                assert_eq!(*ecu, scanned(n));
            }
        }

        let mut elm = plain_elm(fleet, 9600);
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus.len(), 8);
        for (n, ecu) in (0..8).zip(&result.ecus) {
            if n == 5 {
                assert_eq!(ecu.calids, Err(refusal(0x09)));
                assert_eq!(ecu.cvns, Err(refusal(0x09)));
            } else {
                assert_eq!(*ecu, calibrated(n));
            }
        }
    }

    // Two ECUs fit a broadcast even at 9600 baud, so a read that has to fall back works.
    #[test]
    fn a_read_falls_back_to_the_broadcast_when_the_policy_refuses_an_ecus_physical_id() {
        let module = |request, reply| ModuleIds { request, reply };
        for narrowed in [
            // 0x7E1 isn't in the profile.
            vec![module(0x7E0, 0x7E8)],
            // 0x7E1 would be answered on an ID the ECU doesn't use.
            vec![module(0x7E0, 0x7E8), module(0x7E1, 0x7EA)],
        ] {
            let policy = Policy::read_only().narrowed_to(&narrowed).unwrap();
            let mut elm = plain_elm(Fleet::of(2), 9600);
            let result = fingerprint(&mut elm, &policy, &[], timing()).unwrap();
            assert_eq!(result.ecus, (0..2).map(calibrated).collect::<Vec<_>>());
            assert_eq!(
                sent(&elm),
                broadcasts(&[&[0x01, 0x00], &[0x09, 0x04], &[0x09, 0x06]]),
                "{narrowed:?}"
            );

            let mut elm = plain_elm(Fleet::of(2), 9600);
            let result = scan(&mut elm, &policy, &[], timing()).unwrap();
            assert_eq!(result.ecus, (0..2).map(scanned).collect::<Vec<_>>());
            assert!(
                sent(&elm).iter().all(|(header, _)| *header == 0x7DF),
                "{:?}",
                sent(&elm)
            );
        }
    }

    #[test]
    fn a_narrowed_policy_still_reads_the_ecus_it_lists_physically() {
        let all: Vec<_> = (0..8)
            .map(|n| ModuleIds {
                request: 0x7E0 + n,
                reply: 0x7E8 + n,
            })
            .collect();
        let policy = Policy::read_only().narrowed_to(&all).unwrap();
        let mut elm = plain_elm(Fleet::of(8), 9600);
        let result = fingerprint(&mut elm, &policy, &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(calibrated).collect::<Vec<_>>());
        assert_eq!(sent(&elm).len(), 17);
    }

    #[test]
    fn audited_forwards_that_the_adapter_paces() {
        let log = std::env::temp_dir().join(format!(
            "obdcracker-transport-{}-paced-fingerprint.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let mut elm = Audited::open(&log, plain_elm(Fleet::of(8), 9600), "fake").unwrap();
        assert!(elm.broadcasts_can_overflow());
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, (0..8).map(calibrated).collect::<Vec<_>>());

        let audit = std::fs::read_to_string(&log).unwrap();
        let entries: Vec<(String, String, String)> = audit
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|entry| entry["dir"] == "tx" || entry["dir"] == "rx")
            .map(|entry| {
                let text = |key: &str| entry[key].as_str().unwrap().to_owned();
                (text("dir"), text("id"), text("payload"))
            })
            .collect();
        let sends: Vec<_> = entries
            .iter()
            .filter(|(dir, ..)| dir == "tx")
            .map(|(_, id, payload)| (id.as_str(), payload.as_str()))
            .collect();
        let mut expected = vec![("7DF".to_owned(), "01 00")];
        for pid in ["09 04", "09 06"] {
            expected.extend((0..8).map(|n| (format!("7E{n}"), pid)));
        }
        assert_eq!(
            sends,
            expected
                .iter()
                .map(|(id, payload)| (id.as_str(), *payload))
                .collect::<Vec<_>>(),
            "{audit}"
        );
        // Each physical request is logged before its ECU's reply, and that reply before the
        // next request.
        let order: Vec<_> = entries
            .iter()
            .map(|(dir, id, _)| format!("{dir} {id}"))
            .collect();
        let in_turn = (0..8)
            .flat_map(|n| {
                [
                    format!("tx {:03X}", 0x7E0 + n),
                    format!("rx {:03X}", 0x7E8 + n),
                ]
            })
            .collect::<Vec<_>>();
        assert!(
            order.windows(in_turn.len()).any(|w| w == in_turn),
            "{order:?}"
        );
    }

    #[test]
    fn no_ecu_answering_01_00_reads_as_before() {
        let fleet = Fleet {
            answers_01_00: false,
            ..Fleet::of(2)
        };
        let mut elm = plain_elm(fleet, 9600);
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        // Nothing to read per ECU, so the broadcasts are asked and answered as ever.
        assert_eq!(result.ecus, (0..2).map(calibrated).collect::<Vec<_>>());
        assert_eq!(
            sent(&elm),
            broadcasts(&[&[0x01, 0x00], &[0x09, 0x04], &[0x09, 0x06]])
        );

        let mut elm = plain_elm(Fleet::of(0), 9600);
        let result = fingerprint(&mut elm, &Policy::read_only(), &[], timing()).unwrap();
        assert_eq!(result.ecus, Vec::<Calibration>::new());
        assert!(!result.anything_answered());
    }

    #[test]
    fn the_adapter_says_whether_its_broadcasts_can_overflow() {
        // Every plain ELM327 is paced, at any speed and with no known speed.
        for baud in [9600, 38_400, 115_200] {
            assert!(
                plain_elm(Fleet::of(1), baud).broadcasts_can_overflow(),
                "{baud}"
            );
        }
        let mut link = FakeLink::new(adapter(Fleet::of(1)));
        link.byte_rate = None;
        assert!(Elm::connect(link).unwrap().broadcasts_can_overflow());
        // An STN is paced only on a slow link.
        for (rate, paced) in [(Some(960), true), (Some(3840), true), (Some(11_520), false)] {
            assert_eq!(
                stn_at(Fleet::of(1), rate).broadcasts_can_overflow(),
                paced,
                "{rate:?}"
            );
        }
    }

    fn vins(replies: &[obdcracker_transport::Response]) -> Vec<(u32, Vec<u8>)> {
        replies
            .iter()
            .map(|r| (r.source, r.payload.clone()))
            .collect()
    }

    fn vin_reply(n: u32) -> (u32, Vec<u8>) {
        let mut payload = vec![0x49, 0x02, 0x01];
        payload.extend(vin(n).bytes());
        (0x7E8 + n, payload)
    }

    #[test]
    fn a_plain_elm327_at_9600_baud_reads_eight_vins() {
        let mut elm = plain_elm(Fleet::of(8), 9600);
        let replies = read_vin(&mut elm, &Policy::read_only(), timing()).unwrap();
        assert_eq!(vins(&replies), (0..8).map(vin_reply).collect::<Vec<_>>());
        // `01 00` names the ECUs, then each is asked alone: no broadcast of `09 02`.
        let mut expected = broadcasts(&[&[0x01, 0x00]]);
        expected.extend(physical_reads(&[0x09, 0x02], 8));
        assert_eq!(sent(&elm), expected);
        assert_flow_control_per_ecu(&elm, 8);
    }

    #[test]
    fn an_ecu_that_stays_silent_on_its_own_vin_request_is_left_out() {
        let fleet = Fleet {
            silent_on: Some(3),
            ..Fleet::of(8)
        };
        let mut elm = plain_elm(fleet, 9600);
        let replies = read_vin(&mut elm, &Policy::read_only(), timing()).unwrap();
        let expected: Vec<_> = (0..8).filter(|&n| n != 3).map(vin_reply).collect();
        assert_eq!(vins(&replies), expected);
        let mut asked = broadcasts(&[&[0x01, 0x00]]);
        asked.extend(physical_reads(&[0x09, 0x02], 8));
        assert_eq!(sent(&elm), asked);
    }

    #[test]
    fn an_ecu_that_refuses_its_own_vin_request_is_returned_as_the_refusal() {
        let fleet = Fleet {
            refuses_on: Some(5),
            ..Fleet::of(8)
        };
        let mut elm = plain_elm(fleet, 9600);
        let replies = read_vin(&mut elm, &Policy::read_only(), timing()).unwrap();
        let mut expected: Vec<_> = (0..8).map(vin_reply).collect();
        expected[5] = (0x7ED, vec![0x7F, 0x09, 0x31]);
        assert_eq!(vins(&replies), expected);
    }

    #[test]
    fn no_vin_read_asks_each_ecu_when_nothing_answers_01_00() {
        let fleet = Fleet {
            answers_01_00: false,
            ..Fleet::of(2)
        };
        let mut elm = plain_elm(fleet, 9600);
        let replies = read_vin(&mut elm, &Policy::read_only(), timing()).unwrap();
        let mut got = vins(&replies);
        got.sort_unstable();
        assert_eq!(got, (0..2).map(vin_reply).collect::<Vec<_>>());
        assert_eq!(sent(&elm), broadcasts(&[&[0x01, 0x00], &[0x09, 0x02]]));
    }

    #[test]
    fn a_vin_read_broadcasts_when_the_policy_refuses_an_ecus_physical_id() {
        let narrowed = [ModuleIds {
            request: 0x7E0,
            reply: 0x7E8,
        }];
        let policy = Policy::read_only().narrowed_to(&narrowed).unwrap();
        let mut elm = plain_elm(Fleet::of(2), 9600);
        let replies = read_vin(&mut elm, &policy, timing()).unwrap();
        let mut got = vins(&replies);
        got.sort_unstable();
        assert_eq!(got, (0..2).map(vin_reply).collect::<Vec<_>>());
        assert_eq!(sent(&elm), broadcasts(&[&[0x01, 0x00], &[0x09, 0x02]]));
    }

    #[test]
    fn an_stn_at_115200_baud_reads_the_vin_with_one_broadcast() {
        let mut elm = fast_stn(Fleet::of(8));
        let replies = read_vin(&mut elm, &Policy::read_only(), timing()).unwrap();
        let mut got = vins(&replies);
        got.sort_unstable();
        assert_eq!(got, (0..8).map(vin_reply).collect::<Vec<_>>());
        assert_eq!(sent(&elm), broadcasts(&[&[0x09, 0x02]]));
    }

    #[test]
    fn a_broadcast_sent_directly_still_overflows_a_slow_link() {
        // Only `scan`, `fingerprint` and `read_vin` read per ECU; any other broadcast of a long
        // request is the caller's to split (#71).
        let mut elm = plain_elm(Fleet::of(8), 9600);
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x04]))
            .unwrap();
        let err = loop {
            if let Err(e) = elm.recv(Duration::from_secs(5)) {
                break e.to_string();
            }
        };
        assert!(err.contains("BUFFER FULL"), "{err}");
    }
}

// When a reply left the bus, bounded from when the adapter finished printing it
// (docs/elm327.md#when-a-reply-left-the-bus).
mod bus_time {
    use std::collections::VecDeque;

    use obdcracker_transport::{ExtendedSession, S3};

    use super::*;

    const ENGINE: Target = Target::Physical(0x7E0);
    const SLOW_READ: &[u8] = &[0x22, 0xF1, 0x87];
    const QUICK_READ: &[u8] = &[0x22, 0xF1, 0x88];

    // A link that prints at `rate` bytes a second, as a serial line does, and says its byte rate
    // is `declared`. The adapter's modules put their answer to a request in `slow` on the bus
    // `delay` after it was sent; every other request is answered at once. `host_delay` is added
    // to every byte, as USB latency would.
    struct Throttled {
        inner: FakeLink,
        declared: Option<u32>,
        rate: u32,
        host_delay: Duration,
        // The most bytes one read hands over.
        chunk: usize,
        slow: Vec<(Vec<u8>, Duration)>,
        line: Vec<u8>,
        queue: VecDeque<(Instant, u8)>,
        bus_left: Option<Instant>,
    }

    impl Throttled {
        fn new(elm: FakeElm, declared: Option<u32>, rate: u32) -> Self {
            Self {
                inner: FakeLink::new(elm),
                declared,
                rate,
                host_delay: Duration::ZERO,
                chunk: usize::MAX,
                slow: Vec::new(),
                line: Vec::new(),
                queue: VecDeque::new(),
                bus_left: None,
            }
        }

        // The answer to `request` leaves the bus `delay` after it is sent.
        fn answering_after(mut self, request: &[u8], delay: Duration) -> Self {
            self.slow
                .push((hex(request).replace(' ', "").into_bytes(), delay));
            self
        }
    }

    impl Link for Throttled {
        fn write_all(&mut self, bytes: &[u8], driver: Driver) -> io::Result<()> {
            self.inner.write_all(bytes, driver)?;
            let now = Instant::now();
            let printed = self.inner.elm.read(usize::MAX);
            self.line.extend_from_slice(bytes);
            if !bytes.contains(&b'\r') {
                self.queue
                    .extend(printed.into_iter().map(|byte| (now, byte)));
                return Ok(());
            }
            let line = std::mem::take(&mut self.line);
            let delay = self
                .slow
                .iter()
                .find(|(request, _)| line.strip_suffix(b"\r") == Some(request))
                .map(|&(_, delay)| delay);
            let left = now + delay.unwrap_or_default();
            if delay.is_some() {
                self.bus_left = Some(left);
            }
            for (n, byte) in printed.into_iter().enumerate() {
                let bytes = u64::try_from(n + 1).unwrap();
                let print_time = Duration::from_nanos(1_000_000_000 * bytes / u64::from(self.rate));
                self.queue
                    .push_back((left + self.host_delay + print_time, byte));
            }
            Ok(())
        }

        fn read(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            _driver: Driver,
        ) -> io::Result<usize> {
            let give_up = Instant::now() + timeout;
            loop {
                let now = Instant::now();
                let mut n = 0;
                while n < buf.len().min(self.chunk)
                    && self.queue.front().is_some_and(|&(at, _)| at <= now)
                {
                    buf[n] = self.queue.pop_front().unwrap().1;
                    n += 1;
                }
                if n > 0 || now >= give_up {
                    return Ok(n);
                }
                let next = self
                    .queue
                    .front()
                    .map_or(give_up, |&(at, _)| at.min(give_up));
                std::thread::sleep(
                    next.saturating_duration_since(now)
                        .max(Duration::from_millis(1)),
                );
            }
        }

        fn kind(&self) -> LinkKind {
            LinkKind::UsbSerial
        }

        fn byte_rate(&self) -> Option<u32> {
            self.declared
        }
    }

    impl std::fmt::Debug for Throttled {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Throttled").finish_non_exhaustive()
        }
    }

    // An engine that answers a read of F187 with `answer` filler bytes, after response-pending
    // if `pending`.
    fn engine(answer: usize, pending: bool) -> FakeElm {
        FakeElm::new(Box::new(move |header, request| {
            if header != 0x7E0 {
                return Vec::new();
            }
            let reply = match request {
                [0x10, 0x03] => vec![0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
                [0x10, 0x01] => vec![0x50, 0x01, 0x00, 0x32, 0x01, 0xF4],
                [0x3E, 0x00] => vec![0x7E, 0x00],
                [0x22, 0xF1, 0x87] => {
                    let mut reply = vec![0x62, 0xF1, 0x87];
                    reply.extend(std::iter::repeat_n(0x41, answer));
                    let mut replies = Vec::new();
                    if pending {
                        replies.push((0x7E8, vec![0x7F, 0x22, 0x78]));
                    }
                    replies.push((0x7E8, reply));
                    return replies;
                }
                [0x22, 0xF1, 0x88] => vec![0x62, 0xF1, 0x88, 0x42],
                _ => return Vec::new(),
            };
            vec![(0x7E8, reply)]
        }))
    }

    // Connects at full speed, so setup doesn't take as long as the test's replies, then prints at
    // the link's rate.
    fn connect_throttled(mut link: Throttled) -> Elm<Throttled> {
        let rate = std::mem::replace(&mut link.rate, 1_000_000);
        let mut elm = Elm::connect(link).unwrap();
        elm.link_mut().rate = rate;
        elm
    }

    // The answer to a read of F187, when the request was sent, and when the answer left the bus.
    fn one_read(link: Throttled) -> (Response, Instant, Instant) {
        let mut elm = connect_throttled(link);
        let sent = Instant::now();
        let replies = exchange(
            &mut elm,
            &approve(ENGINE, SLOW_READ),
            Expect::Module(0x7E8),
            Elm::<Throttled>::timing(),
        )
        .unwrap();
        let left = elm.link().bus_left.unwrap();
        (replies.into_iter().next().unwrap(), sent, left)
    }

    const S3_BOUNDS: S3 = S3 {
        keepalive: Duration::from_millis(500),
        timeout: Duration::from_millis(1500),
    };

    // Reads F187, then F188 straight after, through a session that trusts the module for 1 s, and
    // returns what was sent.
    fn reads_in_a_session(link: Throttled) -> Vec<Vec<u8>> {
        let mut elm = connect_throttled(link);
        let mut session = ExtendedSession::enter(
            &mut elm,
            &Policy::read_only(),
            ENGINE,
            Elm::<Throttled>::timing(),
            S3_BOUNDS,
        )
        .unwrap();
        session.exchange(&approve(ENGINE, SLOW_READ)).unwrap();
        session.exchange(&approve(ENGINE, QUICK_READ)).unwrap();
        drop(session);
        elm.link()
            .inner
            .elm
            .sent
            .iter()
            .map(|(_, payload)| payload.clone())
            .collect()
    }

    #[test]
    fn a_slow_module_on_a_fast_link_keeps_the_session() {
        // The answer left the bus 1.4 s after the request and printed within milliseconds: the
        // session was restarted a moment ago, not 1.4 s ago.
        let link = Throttled::new(engine(8, false), Some(11_520), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(1400));
        assert_eq!(
            reads_in_a_session(link),
            [
                vec![0x10, 0x03],
                SLOW_READ.to_vec(),
                QUICK_READ.to_vec(),
                vec![0x10, 0x01]
            ]
        );
    }

    #[test]
    fn a_long_answer_printed_at_the_links_full_speed_enters_the_session_again() {
        // The answer left the bus at once and took 1.4 s to print: the module's S3 ran from the
        // start, so trusting it from the end of the print would be wrong.
        let link = Throttled::new(engine(700, false), Some(2000), 2000)
            .answering_after(SLOW_READ, Duration::from_millis(1));
        assert_eq!(
            reads_in_a_session(link),
            [
                vec![0x10, 0x03],
                SLOW_READ.to_vec(),
                vec![0x10, 0x03],
                QUICK_READ.to_vec(),
                vec![0x10, 0x01]
            ]
        );
    }

    // A read of F187 whose answer has `filler` bytes, left the bus `wait_ms` after the request,
    // and is printed at `rate` bytes a second by a link that says it carries `declared`, with
    // `host_ms` of USB latency: the bus time is between the request and the answer leaving.
    fn assert_bus_time_bounded(
        declared: u32,
        rate: u32,
        host_ms: u64,
        filler: usize,
        wait_ms: u64,
    ) {
        let mut link = Throttled::new(engine(filler, false), Some(declared), rate)
            .answering_after(SLOW_READ, Duration::from_millis(wait_ms));
        link.host_delay = Duration::from_millis(host_ms);
        let (reply, sent, left) = one_read(link);
        let bus_time = reply.bus_time.unwrap();
        assert!(bus_time <= left, "after it left the bus");
        assert!(bus_time >= sent, "before the request was sent");
    }

    #[test]
    fn a_slow_module_on_a_fast_link_is_timed_before_it_left_the_bus() {
        assert_bus_time_bounded(11_520, 11_520, 0, 8, 300);
    }

    #[test]
    fn usb_latency_doesnt_push_the_bus_time_past_when_it_left() {
        assert_bus_time_bounded(11_520, 11_520, 60, 8, 300);
        assert_bus_time_bounded(11_520, 11_520, 60, 8, 1);
    }

    #[test]
    fn a_long_answer_printed_at_full_speed_is_timed_no_earlier_than_the_request() {
        assert_bus_time_bounded(2000, 2000, 0, 300, 1);
    }

    #[test]
    fn an_adapter_printing_at_half_its_rate_is_still_timed_before_it_left_the_bus() {
        assert_bus_time_bounded(2000, 1000, 0, 300, 1);
        assert_bus_time_bounded(2000, 1000, 0, 300, 300);
    }

    #[test]
    fn a_short_answer_on_a_slow_link_is_timed_before_it_left_the_bus() {
        assert_bus_time_bounded(960, 960, 0, 8, 1);
    }

    #[test]
    fn a_byte_rate_of_one_is_timed_no_earlier_than_the_request() {
        assert_bus_time_bounded(1, 11_520, 0, 8, 1);
    }

    #[test]
    fn a_reply_read_late_is_timed_from_when_it_could_have_arrived() {
        // The module answered at once, but nothing read the link for 600 ms: the bytes sat in the
        // port's buffer, so when they were read says nothing about when they arrived.
        let link = Throttled::new(engine(8, false), Some(11_520), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(1));
        let mut elm = connect_throttled(link);
        let sent = Instant::now();
        elm.send(&approve(ENGINE, SLOW_READ)).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let reply = elm.recv(Duration::from_secs(5)).unwrap();
        let left = elm.link().bus_left.unwrap();
        let bus_time = reply.bus_time.unwrap();
        assert!(bus_time <= left, "after it left the bus");
        assert!(bus_time >= sent);
    }

    #[test]
    fn a_reply_read_late_in_small_pieces_is_timed_from_when_it_could_have_arrived() {
        // Every read hands over 16 bytes, so the first read of the late caller leaves older bytes
        // in the buffer: it doesn't show that nothing is left.
        let mut link = Throttled::new(engine(100, false), Some(11_520), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(1));
        link.chunk = 16;
        let mut elm = connect_throttled(link);
        let sent = Instant::now();
        elm.send(&approve(ENGINE, SLOW_READ)).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let reply = elm.recv(Duration::from_secs(5)).unwrap();
        let left = elm.link().bus_left.unwrap();
        let bus_time = reply.bus_time.unwrap();
        assert!(bus_time <= left, "after it left the bus");
        assert!(bus_time >= sent);
    }

    #[test]
    fn a_short_answer_is_timed_close_to_when_it_left_the_bus() {
        let link = Throttled::new(engine(8, false), Some(11_520), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(600));
        let (reply, _, left) = one_read(link);
        let bus_time = reply.bus_time.unwrap();
        assert!(bus_time <= left);
        assert!(
            left - bus_time < Duration::from_millis(400),
            "{:?}",
            left - bus_time
        );
    }

    #[test]
    fn the_answer_after_response_pending_is_the_one_timed() {
        let link = Throttled::new(engine(8, true), Some(11_520), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(600));
        let (reply, _, left) = one_read(link);
        assert_eq!(reply.payload[0], 0x62);
        assert!(reply.bus_time.unwrap() <= left);
    }

    #[test]
    fn a_link_with_no_known_byte_rate_gives_no_bus_time() {
        let link = Throttled::new(engine(8, false), None, 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(1));
        let (reply, _, _) = one_read(link);
        assert_eq!(reply.bus_time, None);
    }

    #[test]
    fn a_zero_byte_rate_gives_no_bus_time() {
        let link = Throttled::new(engine(8, false), Some(0), 11_520)
            .answering_after(SLOW_READ, Duration::from_millis(1));
        let (reply, _, _) = one_read(link);
        assert_eq!(reply.bus_time, None);
    }
}
