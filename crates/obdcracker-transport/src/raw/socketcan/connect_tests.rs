//! The checks made before the socket is used, and the session they make, over the fake interface.

use std::time::Duration;

use obdcracker_core::obd;
use obdcracker_safety::{Policy, Protocol, Target};

use super::connect::{self, check_name, plan};
use super::device::{BusState, Device, Iface, KernelFilter, Modes};
use super::fake::{FakeDevice, Reaction, after_drops, bus_off, heard, heard29};
use super::{BitrateCheck, ConnectFailure, Mode, Options, Session};
use crate::{Error, Expect, LinkEvent, Timing, Transport, exchange};

fn options(interface: &str, bitrate: Option<u32>, mode: Mode) -> Options {
    let mut options = Options::new(interface);
    options.bitrate = bitrate;
    options.mode = mode;
    options
}

fn open(fake: &FakeDevice, options: &Options) -> Result<Session<FakeDevice>, ConnectFailure> {
    connect::connect(fake.clone(), options)
}

fn refusal(result: Result<Session<FakeDevice>, ConnectFailure>) -> String {
    match result {
        Ok(_) => panic!("connected"),
        Err(failure) => failure.error.to_string(),
    }
}

fn iface(change: impl FnOnce(&mut Iface)) -> FakeDevice {
    let mut iface = FakeDevice::can0(500_000).state().iface.clone();
    change(&mut iface);
    FakeDevice::with(iface)
}

fn modes(change: impl FnOnce(&mut Modes)) -> Modes {
    let mut modes = Modes::default();
    change(&mut modes);
    modes
}

fn read_did() -> obdcracker_safety::Approved {
    Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x22, 0xF1, 0x87])
        .unwrap()
}

// --- Names and options ---

#[test]
fn interface_names_are_what_the_kernel_allows_and_safe_in_a_path() {
    for good in [
        "can0",
        "vcan0",
        "slcan0",
        "can-1",
        "a",
        "123456789012345",
        "PCAN_1",
    ] {
        assert_eq!(check_name(good), Ok(()), "{good}");
    }
    for bad in [
        "",
        ".",
        "..",
        "../can0",
        "can0/..",
        "a/b",
        "can:0",
        "can 0",
        "can0\n",
        "can\t0",
        "\u{e9}can",
        "can\u{0}",
        "can\x1b[2J",
        "1234567890123456",
        "\u{202e}can0",
    ] {
        let err = check_name(bad).unwrap_err();
        assert!(
            err.contains("isn't a network interface name"),
            "{bad:?}: {err}"
        );
        // What is said back is safe to print.
        assert!(
            err.chars().all(|c| c.is_ascii() && !c.is_ascii_control()),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn a_bad_name_or_bitrate_is_refused_before_the_interface_is_read() {
    let fake = FakeDevice::can0(500_000);
    for options in [
        options("../etc", None, Mode::Active),
        options("can0", Some(125_000), Mode::Active),
        options("can0", Some(0), Mode::Active),
        options("can0", Some(500_001), Mode::ListenOnly),
    ] {
        assert!(open(&fake, &options).is_err());
    }
    assert_eq!(fake.state().describes, 0);
    assert_eq!(fake.state().opened, None);
}

#[test]
fn the_link_name_has_the_interface_and_the_mode() {
    let fake = FakeDevice::can0(500_000);
    let session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    assert_eq!(session.link_name(), "socketcan:can0:active");
    assert_eq!(
        options("vcan0", None, Mode::ListenOnly).link_name(),
        "socketcan:vcan0:listen-only"
    );
}

// --- What an interface must be ---

#[test]
fn an_interface_that_is_up_at_the_asked_bitrate_connects() {
    let fake = FakeDevice::can0(500_000);
    let session = open(&fake, &options("can0", Some(500_000), Mode::Active)).unwrap();
    assert_eq!(session.check, BitrateCheck::Matched);
    assert_eq!(session.bitrate, Some(500_000));
    assert_eq!(
        fake.state().opened,
        Some(true),
        "the driver echoes, so the socket hears itself"
    );
}

#[test]
fn with_no_bitrate_asked_none_is_checked() {
    let fake = FakeDevice::can0(250_000);
    let session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    assert_eq!(session.check, BitrateCheck::NotChecked);
    assert_eq!(session.bitrate, Some(250_000));
}

#[test]
fn another_bitrate_than_the_one_asked_for_is_refused_and_not_changed() {
    for mode in [Mode::Active, Mode::ListenOnly] {
        let fake = FakeDevice::can0(250_000);
        let message = refusal(open(&fake, &options("can0", Some(500_000), mode)));
        assert!(
            message.contains("250000") && message.contains("500000"),
            "{message}"
        );
        assert!(message.contains("never changes"), "{message}");
        // Nothing was opened, so nothing could have been sent.
        assert_eq!(fake.state().opened, None);
        assert_eq!(fake.state().filter_history.len(), 0);
        assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
    }
}

// #42 requirement 5: the bitrate is checked from what the interface reports, and checking writes
// nothing.
#[test]
fn the_bitrate_check_writes_nothing_and_reads_the_interface_once() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        let session = open(&fake, &options("can0", Some(500_000), Mode::Active)).unwrap();
        assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
        assert_eq!(fake.state().counter, 0);
        assert_eq!(fake.state().describes, 1);
        drop(session);
    }
}

#[test]
fn an_interface_that_reports_no_bitrate_is_unconfirmed_with_a_note() {
    let fake = FakeDevice::vcan();
    let mut session = open(&fake, &options("vcan0", Some(500_000), Mode::Active)).unwrap();
    assert_eq!(session.check, BitrateCheck::Unconfirmed);
    assert_eq!(session.bitrate, None);
    let notes = status_lines(session.take_events());
    assert!(
        notes
            .iter()
            .any(|n| n.contains("500000 bit/s is not confirmed")),
        "{notes:?}"
    );
}

fn status_lines(events: Vec<LinkEvent>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|e| match e {
            LinkEvent::Status { line, .. } => Some(line),
            _ => None,
        })
        .collect()
}

#[test]
fn what_was_read_from_the_interface_is_in_the_audit_log() {
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    let lines = status_lines(session.take_events());
    assert_eq!(
        lines[0],
        "interface can0: CAN, up, state error-active, bitrate 500000 bit/s, listen-only off, \
         loopback off, presume-ack off, one-shot off, the driver echoes sent frames"
    );
    let fake = FakeDevice::vcan();
    let mut session = open(&fake, &options("vcan0", None, Mode::Active)).unwrap();
    let lines = status_lines(session.take_events());
    assert_eq!(
        lines[0],
        "interface vcan0: CAN, up, state not reported, no bitrate configured, modes not \
         reported, the driver doesn't echo sent frames"
    );
}

#[test]
fn a_refusal_carries_what_was_read_for_the_audit_log() {
    let fake = iface(|i| i.up = false);
    let failure = open(&fake, &options("can0", None, Mode::Active))
        .err()
        .unwrap();
    let lines = status_lines(failure.events);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].starts_with("interface can0: CAN, down"),
        "{lines:?}"
    );
}

#[test]
fn an_interface_that_is_down_or_not_can_is_refused() {
    let message = refusal(open(
        &iface(|i| i.up = false),
        &options("can0", None, Mode::Active),
    ));
    assert!(message.contains("can0 is down"), "{message}");
    assert!(message.contains("never changes"), "{message}");
    let message = refusal(open(
        &iface(|i| i.is_can = false),
        &options("eth0", None, Mode::Active),
    ));
    assert!(message.contains("isn't a CAN interface"), "{message}");
}

#[test]
fn a_faulted_or_stopped_controller_is_refused() {
    for state in [
        BusState::BusOff,
        BusState::ErrorPassive,
        BusState::Stopped,
        BusState::Sleeping,
    ] {
        for mode in [Mode::Active, Mode::ListenOnly] {
            let fake = iface(|i| i.state = Some(state));
            let message = refusal(open(&fake, &options("can0", None, mode)));
            assert!(message.contains(state.name()), "{message}");
            assert_eq!(fake.state().opened, None);
        }
    }
}

#[test]
fn error_warning_connects_with_a_note() {
    let fake = iface(|i| i.state = Some(BusState::ErrorWarning));
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    assert!(
        status_lines(session.take_events())
            .iter()
            .any(|n| n.contains("error-warning"))
    );
}

#[test]
fn an_active_session_on_a_listen_only_interface_is_refused() {
    let fake = iface(|i| i.modes = Some(modes(|m| m.listen_only = true)));
    let message = refusal(open(&fake, &options("can0", None, Mode::Active)));
    assert!(message.contains("listen-only mode"), "{message}");
    assert!(message.contains("--listen-only"), "{message}");
    assert_eq!(fake.state().opened, None);
}

#[test]
fn a_listen_only_session_on_a_listen_only_interface_connects() {
    let fake = iface(|i| i.modes = Some(modes(|m| m.listen_only = true)));
    let session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
    assert_eq!(session.mode, Mode::ListenOnly);
}

#[test]
fn a_listen_only_session_says_when_the_controller_would_still_acknowledge() {
    // The kernel's listen-only mode is what keeps a controller from acknowledging frames: without
    // it, a session that writes nothing still puts a dominant bit on the bus for each frame.
    let acknowledges = |notes: &[String]| notes.iter().any(|n| n.contains("acknowledges"));
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
    assert_eq!(session.controller_listen_only, Some(false));
    assert!(acknowledges(&status_lines(session.take_events())));
    // An interface that doesn't report its modes: unknown, and said so.
    let fake = iface(|i| i.modes = None);
    let mut session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
    assert_eq!(session.controller_listen_only, None);
    assert!(acknowledges(&status_lines(session.take_events())));
    // The controller in listen-only mode is silent: nothing to say.
    let fake = iface(|i| i.modes = Some(modes(|m| m.listen_only = true)));
    let mut session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
    assert_eq!(session.controller_listen_only, Some(true));
    assert!(!acknowledges(&status_lines(session.take_events())));
    // An active session acknowledges as any node does, and has no such note.
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    assert!(!acknowledges(&status_lines(session.take_events())));
}

#[test]
fn a_loopback_interface_is_refused_for_an_active_session_only() {
    let fake = iface(|i| i.modes = Some(modes(|m| m.loopback = true)));
    let message = refusal(open(&fake, &options("can0", None, Mode::Active)));
    assert!(message.contains("loopback"), "{message}");
    assert!(open(&fake, &options("can0", None, Mode::ListenOnly)).is_ok());
}

#[test]
fn presumed_acknowledgements_and_one_shot_are_noted() {
    let fake = iface(|i| {
        i.modes = Some(modes(|m| {
            m.presume_ack = true;
            m.one_shot = true;
        }));
    });
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    let notes = status_lines(session.take_events());
    assert!(
        notes
            .iter()
            .any(|n| n.contains("presumes acknowledgements")),
        "{notes:?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("never retries")),
        "{notes:?}"
    );
}

#[test]
fn without_an_echo_an_unreadable_counter_refuses_an_active_session_only() {
    let fake = FakeDevice::vcan();
    fake.state().counter_fails = true;
    let message = refusal(open(&fake, &options("vcan0", None, Mode::Active)));
    assert!(message.contains("transmit counter"), "{message}");
    assert_eq!(fake.state().opened, None);
    // A session that never writes needs no confirmation.
    assert!(open(&fake, &options("vcan0", None, Mode::ListenOnly)).is_ok());
    // With an echo the counter isn't used.
    let fake = FakeDevice::can0(500_000);
    fake.state().counter_fails = true;
    assert!(open(&fake, &options("can0", None, Mode::Active)).is_ok());
}

#[test]
fn an_interface_that_cant_be_read_or_opened_is_an_error() {
    let fake = FakeDevice::can0(500_000);
    fake.state().describe_fails = Some("no interface can0: No such device".to_owned());
    let message = refusal(open(&fake, &options("can0", None, Mode::Active)));
    assert!(message.contains("No such device"), "{message}");
    let fake = FakeDevice::can0(500_000);
    fake.state().open_fails = Some("can't open a CAN socket".to_owned());
    let failure = open(&fake, &options("can0", None, Mode::Active))
        .err()
        .unwrap();
    assert!(failure.error.to_string().contains("can't open"));
    // It still says what it had read.
    assert_eq!(status_lines(failure.events).len(), 1);
}

#[test]
fn the_plan_is_decided_from_the_report_alone() {
    let ok = FakeDevice::can0(500_000).state().iface.clone();
    let wanted = options("can0", Some(500_000), Mode::Active);
    assert_eq!(
        plan("can0", &ok, &wanted).unwrap().check,
        BitrateCheck::Matched
    );
    let mut other = ok;
    other.bitrate = Some(250_000);
    assert!(plan("can0", &other, &wanted).is_err());
}

// The refusal for an interface at another bitrate than the one asked for, decided by the session's
// mode and what the controller reports about its own listen-only mode.
fn refused_at_wrong_bitrate(mode: Mode, controller_listen_only: Option<bool>) -> String {
    let mut report = FakeDevice::can0(250_000).state().iface.clone();
    report.modes = controller_listen_only.map(|listen_only| modes(|m| m.listen_only = listen_only));
    plan("can0", &report, &options("can0", Some(500_000), mode)).unwrap_err()
}

#[test]
fn a_wrong_bitrate_is_refused_saying_what_it_does_in_an_active_session() {
    let message = refused_at_wrong_bitrate(Mode::Active, Some(false));
    assert!(
        message.contains("Sending at the wrong bitrate disturbs the car's bus"),
        "{message}"
    );
    assert!(
        message.contains("250000") && message.contains("500000"),
        "{message}"
    );
    assert!(message.contains("ask for 250000"), "{message}");
    assert!(message.contains("never changes"), "{message}");
    assert!(!message.contains("missed or misread"), "{message}");
}

#[test]
fn a_wrong_bitrate_in_a_listen_only_session_only_misses_frames_when_the_controller_is_listen_only()
{
    let message = refused_at_wrong_bitrate(Mode::ListenOnly, Some(true));
    assert!(
        message.contains("frames would be missed or misread"),
        "{message}"
    );
    assert!(message.contains("ask for 250000"), "{message}");
    assert!(message.contains("never changes"), "{message}");
    assert!(!message.contains("Sending"), "{message}");
    assert!(!message.contains("error frames"), "{message}");
    assert!(!message.contains("disturb"), "{message}");
}

#[test]
fn a_wrong_bitrate_in_a_listen_only_session_says_the_controller_can_disturb_the_bus() {
    let message = refused_at_wrong_bitrate(Mode::ListenOnly, Some(false));
    assert!(
        message.contains("frames would be missed or misread"),
        "{message}"
    );
    assert!(
        message.contains("the controller can send error frames and disturb the bus"),
        "{message}"
    );
    assert!(
        message.contains("since it isn't in listen-only mode"),
        "{message}"
    );
    assert!(!message.contains("(or doesn't say)"), "{message}");
    assert!(!message.contains("Sending"), "{message}");
    assert!(message.contains("ask for 250000"), "{message}");
    assert!(message.contains("never changes"), "{message}");
}

#[test]
fn a_wrong_bitrate_with_an_unreported_controller_mode_does_not_state_it_as_fact() {
    let message = refused_at_wrong_bitrate(Mode::ListenOnly, None);
    assert!(
        message.contains("frames would be missed or misread"),
        "{message}"
    );
    assert!(
        message.contains("the controller can send error frames and disturb the bus"),
        "{message}"
    );
    assert!(
        message.contains("since it isn't in listen-only mode (or doesn't say)"),
        "{message}"
    );
    assert!(!message.contains("Sending"), "{message}");
    assert!(message.contains("ask for 250000"), "{message}");
}

// --- A session carrying requests ---

// Reads the frame's CAN ID and first data byte.
fn id_and_pci(frame: &[u8; 16]) -> (u32, u8) {
    (u32::from_ne_bytes(frame[..4].try_into().unwrap()), frame[8])
}

fn car(fake: &FakeDevice) {
    fake.state().on_send = Some(Box::new(|frame| match id_and_pci(frame) {
        (0x7E0, 0x03) => Reaction::reply(vec![heard(0x7E8, &[0x05, 0x62, 0xF1, 0x87, 0x11, 0x22])]),
        // The broadcast `09 02`: the VIN, as a first frame.
        (0x7DF, 0x02) => Reaction::reply(vec![heard(
            0x7E8,
            &[0x10, 0x14, 0x49, 0x02, 0x01, 0x57, 0x41, 0x55],
        )]),
        // The flow control the transport sends to the ECU's physical ID.
        (0x7E0, 0x30) => Reaction::reply(vec![
            heard(0x7E8, &[0x21, 0x5A, 0x5A, 0x5A, 0x34, 0x47, 0x31, 0x45]),
            heard(0x7E8, &[0x22, 0x4E, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]),
        ]),
        // A first frame of a request: the ECU lets the rest come.
        (0x7E0, 0x10) => Reaction::reply(vec![heard(
            0x7E8,
            &[0x30, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
        )]),
        _ => Reaction::confirm(),
    }));
}

#[test]
fn a_request_goes_out_padded_and_its_reply_comes_back_with_or_without_an_echo() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        car(&fake);
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        let replies = crate::exchange(
            &mut session,
            &read_did(),
            Expect::Module(0x7E8),
            Timing::default(),
        )
        .unwrap();
        assert_eq!(replies[0].payload, [0x62, 0xF1, 0x87, 0x11, 0x22]);
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(id_and_pci(&sent[0]).0, 0x7E0);
        assert_eq!(sent[0][4], 8, "DLC 8");
        assert_eq!(
            sent[0][8..],
            [0x03, 0x22, 0xF1, 0x87, 0xAA, 0xAA, 0xAA, 0xAA]
        );
    }
}

#[test]
fn flow_control_after_a_broadcast_goes_to_the_physical_id_and_the_reply_completes() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        car(&fake);
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        let vin = Policy::read_only()
            .approve(
                Protocol::Uds,
                Target::ObdFunctional,
                &obd::vehicle_info(0x02),
            )
            .unwrap();
        let replies = exchange(&mut session, &vin, Expect::ObdEcus, Timing::default()).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            obd::decode_vin(&replies[0].payload).unwrap(),
            "WAUZZZ4G1EN000000"
        );
        let sent = fake.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(id_and_pci(&sent[0]).0, 0x7DF);
        // Not the broadcast ID: the ECU that answered (0x7E8 - 8).
        assert_eq!(id_and_pci(&sent[1]).0, 0x7E0);
        assert_eq!(sent[1][8], 0x30);
        assert_eq!(sent[1][4], 8);
    }
}

#[test]
fn the_kernel_is_asked_for_the_replies_of_the_request_only() {
    let fake = FakeDevice::vcan();
    car(&fake);
    let mut session = open(&fake, &options("vcan0", None, Mode::Active)).unwrap();
    session.send(&read_did()).unwrap();
    let filters = fake.filters();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].id, 0x7E8);
}

#[test]
fn a_multi_frame_request_sends_each_frame_after_the_last_was_confirmed() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        car(&fake);
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        // `19` takes any length: ten bytes need a first frame and a consecutive frame.
        let mut payload = vec![0x19, 0x02, 0xAF];
        payload.extend_from_slice(&[0; 7]);
        let request = Policy::read_only()
            .approve(Protocol::Uds, Target::Physical(0x7E0), &payload)
            .unwrap();
        session.send(&request).unwrap();
        let sent = fake.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0][8] & 0xF0, 0x10);
        assert_eq!(sent[1][8], 0x21);
        // The last, short frame is padded.
        assert_eq!(sent[1][13..], [0xAA, 0xAA, 0xAA]);
        // Each was counted or echoed before the next went out.
        assert_eq!(fake.state().counter, 2);
        assert_eq!(fake.state().overlapped, 0);
    }
}

// #42 requirement 2: a long transfer, so a port that let the next frame go before the last one was
// confirmed would show (the fake counts a write made while a confirmation was still unread).
#[test]
fn every_frame_of_a_long_request_is_padded_and_confirmed_before_the_next() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        car(&fake);
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        let mut payload = vec![0x19, 0x02, 0xAF];
        payload.resize(100, 0);
        let request = Policy::read_only()
            .approve(Protocol::Uds, Target::Physical(0x7E0), &payload)
            .unwrap();
        session.send(&request).unwrap();
        let sent = fake.sent();
        // a first frame of 6 bytes, then 94 bytes in sevens
        assert_eq!(sent.len(), 1 + 94usize.div_ceil(7));
        for (n, frame) in sent.iter().enumerate() {
            assert_eq!(frame[4], 8, "DLC 8 on frame {n}");
            if n > 0 {
                assert_eq!(frame[8], 0x20 | (u8::try_from(n).unwrap() & 0x0F), "{n}");
            }
        }
        assert_eq!(fake.state().overlapped, 0);
    }
}

// Guards the test above: the fake must see a confirmation nobody read as an overlap.
#[test]
fn the_fake_counts_a_write_made_before_the_last_confirmation_was_read() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        let mut device = fake.clone();
        let echo = fake.state().iface.echo;
        device.open(echo).unwrap();
        device
            .set_filters(&[KernelFilter { id: 0, mask: 0 }])
            .unwrap();
        device.send(&[0; 16]).unwrap();
        assert_eq!(fake.state().overlapped, 0);
        device.send(&[1; 16]).unwrap();
        assert_eq!(fake.state().overlapped, 1);
    }
}

// #42 requirement 3: the kernel is given the replies of each request, at their width, and a frame
// outside them never reaches the socket.
#[test]
fn the_kernel_filter_follows_each_request_and_keeps_to_its_width() {
    let fake = FakeDevice::vcan();
    car(&fake);
    let mut session = open(&fake, &options("vcan0", None, Mode::Active)).unwrap();
    let broadcast = Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::ObdFunctional,
            &obd::vehicle_info(0x02),
        )
        .unwrap();
    session.send(&broadcast).unwrap();
    for (packet, reaches) in [
        (heard(0x7E8, &[1]), true),
        (heard(0x7EF, &[2]), true),
        (heard(0x7F0, &[3]), false),
        (heard(0x7E7, &[3]), false),
        (heard(0x7DF, &[4]), false),
        (heard29(0x7E8, &[5]), false),
    ] {
        let queued = fake.state().inbox.len();
        fake.deliver(packet);
        assert_eq!(fake.state().inbox.len() - queued, usize::from(reaches));
    }
    session.send(&read_did()).unwrap();
    for (packet, reaches) in [
        (heard(0x7E8, &[1]), true),
        (heard(0x7E9, &[2]), false),
        (heard(0x7E0, &[3]), false),
    ] {
        let queued = fake.state().inbox.len();
        fake.deliver(packet);
        assert_eq!(fake.state().inbox.len() - queued, usize::from(reaches));
    }
    let extended = Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::Physical29(0x18DA_10F1),
            &[0x22, 0xF1, 0x87],
        )
        .unwrap();
    session.send(&extended).unwrap();
    for (packet, reaches) in [
        (heard29(0x18DA_F110, &[1]), true),
        (heard(0x7E8, &[2]), false),
        (heard(0x18DA_F110 & 0x7FF, &[3]), false),
    ] {
        let queued = fake.state().inbox.len();
        fake.deliver(packet);
        assert_eq!(fake.state().inbox.len() - queued, usize::from(reaches));
    }
}

// #42 requirement 3: a receive overrun is an error, never a gap in a reply.
#[test]
fn a_receive_overrun_in_a_reply_is_an_error_and_the_half_reply_is_dropped() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        fake.state().on_send = Some(Box::new(|frame| match id_and_pci(frame) {
            (0x7E0, 0x03) => Reaction::reply(vec![heard(
                0x7E8,
                &[0x10, 0x0A, 0x62, 0xF1, 0x87, 0x01, 0x02, 0x03],
            )]),
            // The socket's queue overflowed: the drop counter rides on the next frame.
            (0x7E0, 0x30) => Reaction::reply(vec![after_drops(
                heard(0x7E8, &[0x21, 0x04, 0x05, 0x06, 0x07]),
                2,
            )]),
            _ => Reaction::confirm(),
        }));
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        session.send(&read_did()).unwrap();
        match session.recv(Duration::from_millis(50)) {
            Err(Error::Adapter(message)) => assert!(message.contains("overrun"), "{message}"),
            other => panic!("{other:?}"),
        }
        // What came after the loss is not the rest of that reply, and nothing was glued together.
        assert_eq!(session.recv(Duration::from_millis(5)), Err(Error::Timeout));
        // The bus is fine: the session goes on.
        session.send(&read_did()).unwrap();
    }
}

#[test]
fn a_listen_only_session_writes_nothing_not_even_what_the_policy_approves() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        let mut session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
        let recvs = fake.state().recvs;
        let err = session.send(&read_did()).unwrap_err();
        assert!(err.to_string().contains("listen-only"), "{err}");
        // The guard comes before the transport touches the socket at all.
        assert_eq!(fake.state().recvs, recvs);
        assert_eq!(fake.state().filter_history.len(), 1, "only the open's own");
        let broadcast = Policy::read_only()
            .approve(
                Protocol::Uds,
                Target::ObdFunctional,
                &obd::vehicle_info(0x02),
            )
            .unwrap();
        assert!(session.send(&broadcast).is_err());
        assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
        assert_eq!(fake.state().counter, 0);
    }
}

#[test]
fn a_listen_only_session_can_receive_and_still_writes_nothing() {
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::ListenOnly)).unwrap();
    // Nothing was asked, so a lone reply frame has no window to belong to: it is dropped.
    fake.deliver(heard(0x7E8, &[0x04, 0x62, 0xF1, 0x87, 0x99]));
    assert_eq!(session.recv(Duration::from_millis(5)), Err(Error::Timeout));
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

#[test]
fn an_unacknowledged_request_is_an_error_that_stops_later_sends() {
    let fake = FakeDevice::can0(500_000);
    fake.state().on_send = Some(Box::new(|_| Reaction {
        echo: super::fake::Echo::Never,
        ..Reaction::confirm()
    }));
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    let err = session.send(&read_did()).unwrap_err();
    assert!(err.to_string().contains("no confirmation"), "{err}");
    let sent = fake.sent().len();
    assert!(session.send(&read_did()).is_err());
    assert!(session.recv(Duration::from_millis(5)).is_err());
    assert_eq!(fake.sent().len(), sent);
}

#[test]
fn a_bus_off_latches_and_nothing_more_is_written() {
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    fake.deliver(bus_off());
    let err = session.send(&read_did()).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert!(session.send(&read_did()).is_err());
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

#[test]
fn an_interface_that_went_away_is_an_error_not_a_hang() {
    let fake = FakeDevice::can0(500_000);
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    fake.state().fail_recv = Some("Network is down".to_owned());
    fake.state().fail_send = true;
    assert!(session.send(&read_did()).is_err());
    assert!(session.recv(Duration::from_millis(5)).is_err());
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

// --- The interface is only ever read ---

// What this backend may call on the kernel's side. `describe` reads; the rest act on the
// backend's own socket. A call that sets an interface's bitrate or mode, brings it up or down,
// restarts it, creates or deletes one is not in this list, and the backend's source may not
// contain one: nothing could undo it on a car's bus.
#[test]
fn the_backend_never_changes_an_interface() {
    let sources = [
        ("linux.rs", include_str!("linux.rs")),
        ("connect.rs", include_str!("connect.rs")),
        ("can_port.rs", include_str!("can_port.rs")),
        ("mod.rs", include_str!("mod.rs")),
        ("device.rs", include_str!("device.rs")),
    ];
    for (file, source) in sources {
        for forbidden in [
            "set_bitrate",
            "set_bit_timing",
            "set_data_bit",
            "set_ctrlmode",
            "set_can_param",
            "set_can_params",
            "set_mtu",
            "set_restart",
            "set_termination",
            "bring_up",
            "bring_down",
            "create_vcan",
            ".create(",
            ".delete(",
            ".restart(",
            "IsoTp",
            "CAN_ISOTP",
            "TemporaryInterface",
        ] {
            assert!(
                !source.contains(forbidden),
                "{file} mentions {forbidden}: this backend may not change an interface"
            );
        }
    }
}

// --- VW TP2.0 (#259) ---

use super::fake::heard_len;
use crate::raw::tests::tp20::{Car, IDENTIFICATION, SETUP_REQUEST, channel, policy, setup};
use crate::tp20::{ChannelSession, Disconnect};

// A car with one TP2.0 module that answers the identification read; every frame it sends is as
// long as the module made it, as on a real bus.
fn tp20_car(fake: &FakeDevice) {
    let mut car = Car::with(vec![(IDENTIFICATION.to_vec(), vec![0x5A, 0x9B, 1, 2])]);
    fake.state().on_send = Some(Box::new(move |frame| {
        let id = u32::from_ne_bytes(frame[..4].try_into().unwrap());
        let data = &frame[8..8 + usize::from(frame[4])];
        Reaction::reply(
            car.hear_frame(id, data)
                .into_iter()
                .map(|(id, payload)| heard_len(id, u8::try_from(payload.len()).unwrap(), &payload))
                .collect(),
        )
    }));
}

#[test]
fn a_tp20_session_runs_over_the_interface_with_or_without_an_echo() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        tp20_car(&fake);
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        let policy = policy();
        let mut channel =
            ChannelSession::open(&mut session, &policy, 0x01, Timing::default()).unwrap();
        assert_eq!(
            channel.request(&IDENTIFICATION).unwrap(),
            [0x5A, 0x9B, 1, 2]
        );
        assert_eq!(channel.close(), Ok(Disconnect::Closed));
        let sent = fake.sent();
        // The setup (7 bytes), the tester's parameters (6), the request (5), the ACK of the
        // answer (1) and the disconnect (1): each is confirmed (by its echo, or by the transmit
        // counter) at the DLC it was sent with.
        let dlcs: Vec<u8> = sent.iter().map(|frame| frame[4]).collect();
        assert_eq!(dlcs, [7, 6, 5, 1, 1]);
        assert_eq!(fake.state().overlapped, 0);
        assert_eq!(sent[0][8..], [0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01, 0]);
        assert_eq!(u32::from_ne_bytes(sent[0][..4].try_into().unwrap()), 0x200);
        assert_eq!(u32::from_ne_bytes(sent[4][..4].try_into().unwrap()), 0x740);
        assert_eq!(sent[4][8..], [0xA8, 0, 0, 0, 0, 0, 0, 0]);
    }
}

#[test]
fn a_tp20_frame_nobody_acknowledges_is_an_error_that_stops_later_sends() {
    for fake in [FakeDevice::can0(500_000), FakeDevice::vcan()] {
        fake.state().on_send = Some(Box::new(|_| Reaction {
            echo: super::fake::Echo::Never,
            counts: false,
            ..Reaction::confirm()
        }));
        let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
        let err = session.send(&setup()).unwrap_err();
        assert!(err.to_string().contains("no confirmation"), "{err}");
        assert!(session.send(&setup()).is_err());
        assert_eq!(fake.sent().len(), 1);
    }
}

#[test]
fn a_listen_only_session_writes_no_tp2_0_frame() {
    let fake = FakeDevice::vcan();
    let mut session = open(&fake, &options("vcan0", None, Mode::ListenOnly)).unwrap();
    let policy = policy();
    let channel = channel();
    let requests = [
        setup(),
        policy.approve_tp20_parameters(&channel).unwrap(),
        policy.approve_tp20_keep_alive(&channel).unwrap(),
        policy.approve_tp20_ack(&channel, 1).unwrap(),
        policy.approve_tp20_disconnect(&channel).unwrap(),
        policy
            .approve_tp20_request(&channel, 0, &IDENTIFICATION)
            .unwrap(),
    ];
    for request in &requests {
        let err = session.send(request).unwrap_err();
        assert!(err.to_string().contains("listen-only"), "{err}");
    }
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

#[test]
fn a_bus_off_before_a_channel_frame_latches_and_nothing_more_is_written() {
    let fake = FakeDevice::can0(500_000);
    tp20_car(&fake);
    let mut session = open(&fake, &options("can0", None, Mode::Active)).unwrap();
    session.send(&setup()).unwrap();
    assert_eq!(fake.sent().len(), 1);
    fake.deliver(bus_off());
    let request = policy().approve_tp20_disconnect(&channel()).unwrap();
    let err = session.send(&request).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert!(session.send(&request).is_err());
    assert_eq!(fake.sent().len(), 1);
    assert_eq!(fake.sent()[0][8..15], SETUP_REQUEST);
}
