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
                "ATZ", "ATE0", "ATL0", "ATS1", "ATH1", "ATSP6", "ATCAF1", "ATCFC1", "ATR1",
                "ATCF700", "ATCM700", "ATAT1", "ATSTFF"
            ]
        );
        let settings = &elm.link().elm.settings;
        assert!(!settings.echo && settings.headers && settings.spaces && !settings.linefeeds);
        assert_eq!(settings.protocol.as_deref(), Some("6"));
        assert!(
            elm.link().elm.sent.is_empty(),
            "setup put a frame on the bus"
        );
    }

    #[test]
    fn every_setup_command_contains_a_letter_that_isnt_hex() {
        // An ELM327 sends any all-hex line to the bus, so a mangled AT command must never be one.
        let elm = connect(FakeElm::silent());
        for command in commands(&elm) {
            assert!(command.bytes().any(|b| !b.is_ascii_hexdigit()), "{command}");
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
        for missing in ["ATSP6", "ATH1", "ATCF700", "ATSTFF"] {
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
        // Replace the adapter's output with an endless stream of first frames.
        elm.link_mut().flood = Some(b"7E8 10 14 49 02 01 57 41 55\r".to_vec());
        let start = Instant::now();
        assert_eq!(elm.recv(Duration::from_millis(200)), Err(Error::Timeout));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(elm.link().flooded > 0);
    }

    #[test]
    fn an_overlong_line_is_an_adapter_error() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.link_mut().flood = Some(vec![b'7'; 1000]);
        let err = elm.recv(Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "{err}");
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
            let mut elm = connect(car());
            elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
                .unwrap();
            elm.link_mut().inject = output.to_vec();
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
            elm.link_mut().inject = output.to_vec();
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
        // The adapter resets just as it answers ATSH: a banner comes before the OK.
        elm.link_mut().inject = b"\rELM327 v2.0\r".to_vec();
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
    fn a_bus_error_leaves_the_adapter_usable() {
        let mut elm = connect(car());
        elm.send(&approve(Target::ObdFunctional, &[0x09, 0x02]))
            .unwrap();
        elm.link_mut().inject = b"CAN ERROR\r".to_vec();
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

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
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
            return then.read(buf, timeout);
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
