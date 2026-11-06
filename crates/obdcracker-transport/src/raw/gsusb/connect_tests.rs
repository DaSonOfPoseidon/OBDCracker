//! The connect state machine and the session it makes, over the fake USB layer.

use std::time::Duration;

use obdcracker_core::obd;
use obdcracker_safety::{Policy, Protocol, Target};

use super::connect::{self, ConnectFailure};
use super::fake::{
    BUS_OFF, Echo, FEATURES, FakeUsb, PASSIVE, Reaction, candlelight_const, error_frame, heard,
    raw_frame,
};
use super::usb::Usb;
use super::wire;
use super::{BitrateCheck, BitrateSource, Mode, Options, Session};
use crate::raw::port::Filter;
use crate::{Error, Expect, LinkEvent, Timing, Transport, exchange};

const LISTEN: u32 = wire::FLAG_LISTEN_ONLY | wire::FLAG_BERR_REPORTING;
const ACTIVE: u32 = wire::FLAG_BERR_REPORTING;

fn options(mode: Mode) -> Options {
    let mut options = Options::new(500_000);
    options.mode = mode;
    options.listen_window = Duration::from_millis(20);
    options
}

fn open(fake: &FakeUsb, options: &Options) -> Result<Session<FakeUsb>, ConnectFailure> {
    connect::connect(fake.clone(), options)
}

// A bus that is up: the controller hears a frame as soon as it listens.
fn busy_bus(fake: &FakeUsb) {
    fake.on_start(|flags| {
        if flags & wire::FLAG_LISTEN_ONLY != 0 {
            vec![heard(0x7E8, &[0x04, 0x62, 0xF1, 0x87, 0x99])]
        } else {
            vec![]
        }
    });
}

fn started_active(modes: &[(u32, u32)]) -> bool {
    modes
        .iter()
        .any(|&(mode, flags)| mode == wire::MODE_START && flags & wire::FLAG_LISTEN_ONLY == 0)
}

fn read_did() -> obdcracker_safety::Approved {
    Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &[0x22, 0xF1, 0x87])
        .unwrap()
}

#[test]
fn connect_checks_the_bitrate_listening_before_it_goes_active() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let session = open(&fake, &options(Mode::Active)).unwrap();
    assert_eq!(session.bitrate_check(), BitrateCheck::Confirmed);
    assert_eq!(
        fake.requests(),
        [
            wire::BREQ_HOST_FORMAT,
            wire::BREQ_DEVICE_CONFIG,
            wire::BREQ_BT_CONST,
            // Whatever an earlier program left running is stopped first.
            wire::BREQ_MODE,
            wire::BREQ_BITTIMING,
            wire::BREQ_MODE,
            // The listen window ends with the controller in reset, before it is started again.
            wire::BREQ_MODE,
            wire::BREQ_BITTIMING,
            wire::BREQ_MODE,
        ]
    );
    assert_eq!(
        fake.modes(),
        [
            (wire::MODE_RESET, 0),
            (wire::MODE_START, LISTEN),
            (wire::MODE_RESET, 0),
            (wire::MODE_START, ACTIVE),
        ]
    );
    fake.assert_nothing_written();
}

#[test]
fn each_control_message_is_what_the_device_expects() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let _session = open(&fake, &options(Mode::Active)).unwrap();
    let controls = fake.0.borrow().controls.clone();
    assert_eq!(controls[0].data, [0xEF, 0xBE, 0, 0]);
    assert_eq!((controls[0].value, controls[0].inbound), (1, false));
    assert_eq!((controls[1].value, controls[1].inbound), (1, true));
    assert_eq!((controls[2].value, controls[2].inbound), (0, true));
    // 48 MHz at 500 kbit/s.
    assert_eq!(
        controls[4].data,
        [6, 0, 0, 0, 7, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0]
    );
    assert_eq!(controls[4].value, 0);
    assert_eq!(controls[5].data, [1, 0, 0, 0, 1, 0x10, 0, 0]);
    assert_eq!(controls[7].data, controls[4].data);
}

#[test]
fn the_bus_error_flag_is_only_asked_for_when_the_device_has_it() {
    let fake = FakeUsb::new();
    fake.0.borrow_mut().bt_const = candlelight_const(wire::FEATURE_LISTEN_ONLY, 48_000_000);
    busy_bus(&fake);
    let _session = open(&fake, &options(Mode::Active)).unwrap();
    assert_eq!(
        fake.modes()[1..],
        [
            (wire::MODE_START, wire::FLAG_LISTEN_ONLY),
            (wire::MODE_RESET, 0),
            (wire::MODE_START, 0)
        ]
    );
}

#[test]
fn listen_only_never_leaves_listen_only() {
    // Whatever the bus does and whoever says what the bitrate is.
    for source in [BitrateSource::Configured, BitrateSource::Assumed] {
        for hears in [true, false] {
            let fake = FakeUsb::new();
            if hears {
                busy_bus(&fake);
            }
            let mut options = options(Mode::ListenOnly);
            options.bitrate_source = source;
            let mut session = open(&fake, &options).unwrap();
            assert_eq!(session.bitrate_check(), BitrateCheck::NotChecked);
            assert_eq!(
                fake.modes(),
                [(wire::MODE_RESET, 0), (wire::MODE_START, LISTEN)]
            );
            assert!(!started_active(&fake.modes()));
            // Not even a request that the policy approves is written, or its flow control, and the
            // device isn't touched to find that out.
            let reads = fake.0.borrow().bulk_in_calls;
            let err = session.send(&read_did()).unwrap_err();
            assert_eq!(fake.0.borrow().bulk_in_calls, reads);
            assert!(err.to_string().contains("listen-only"), "{err}");
            let broadcast = Policy::read_only()
                .approve(
                    Protocol::Uds,
                    Target::ObdFunctional,
                    &obd::vehicle_info(0x02),
                )
                .unwrap();
            assert!(session.send(&broadcast).is_err());
            fake.assert_nothing_written();
            assert!(!started_active(&fake.modes()));
        }
    }
}

#[test]
fn a_listen_only_session_can_receive_and_still_writes_nothing() {
    let fake = FakeUsb::new();
    let mut session = open(&fake, &options(Mode::ListenOnly)).unwrap();
    // Nothing was asked, so a lone reply frame has no window to belong to: it is dropped.
    fake.queue(heard(0x7E8, &[0x04, 0x62, 0xF1, 0x87, 0x99]));
    assert_eq!(session.recv(Duration::from_millis(5)), Err(Error::Timeout));
    fake.assert_nothing_written();
}

#[test]
fn frames_heard_in_the_window_cannot_answer_a_request() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    // A reply-shaped frame is still on its way when the window ends.
    fake.0.borrow_mut().late_on_reset = vec![heard(0x7E8, &[0x04, 0x62, 0xF1, 0x87, 0x99])];
    fake.on_write(|_, can_id, data| {
        assert_eq!(
            (can_id, data[..4].to_vec()),
            (0x7E0, vec![3, 0x22, 0xF1, 0x87])
        );
        Reaction::reply(vec![heard(0x7E8, &[0x05, 0x62, 0xF1, 0x87, 0x11, 0x22])])
    });
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    // The device's queue was emptied when the window ended, not left for the first request.
    assert_eq!(fake.0.borrow().inbox.len(), 0);
    let replies = exchange(
        &mut session,
        &read_did(),
        Expect::Module(0x7E8),
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].payload, [0x62, 0xF1, 0x87, 0x11, 0x22]);
}

#[test]
fn error_frames_in_the_window_refuse_to_go_active() {
    for (class, detail) in [(BUS_OFF, 0), PASSIVE, (0x80, 0)] {
        let fake = FakeUsb::new();
        fake.on_start(move |flags| {
            if flags & wire::FLAG_LISTEN_ONLY != 0 {
                // Valid frames beside the errors don't excuse them.
                vec![heard(0x7E8, &[1]), error_frame(class, detail)]
            } else {
                vec![]
            }
        });
        let failure = open(&fake, &options(Mode::Active)).unwrap_err();
        assert!(
            failure.error.to_string().contains("bitrate"),
            "{}",
            failure.error
        );
        assert!(!started_active(&fake.modes()));
        assert_eq!(fake.modes().last(), Some(&(wire::MODE_RESET, 0)));
        assert!(fake.is_stopped());
        fake.assert_nothing_written();
    }
}

#[test]
fn silence_goes_active_with_a_warning_when_the_bitrate_was_chosen() {
    let fake = FakeUsb::new();
    let mut options = options(Mode::Active);
    options.bitrate_source = BitrateSource::Configured;
    let mut session = open(&fake, &options).unwrap();
    assert_eq!(session.bitrate_check(), BitrateCheck::Unconfirmed);
    assert!(started_active(&fake.modes()));
    let notes: Vec<String> = session
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            LinkEvent::Status { line, .. } => Some(line),
            _ => None,
        })
        .collect();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("500000") && n.contains("not confirmed")),
        "{notes:?}"
    );
}

#[test]
fn silence_with_no_chosen_bitrate_refuses_to_go_active() {
    let fake = FakeUsb::new();
    let mut options = options(Mode::Active);
    options.bitrate_source = BitrateSource::Assumed;
    let failure = open(&fake, &options).unwrap_err();
    let text = failure.error.to_string();
    assert!(
        text.contains("--bitrate") || text.contains("bitrate"),
        "{text}"
    );
    assert!(!started_active(&fake.modes()));
    assert!(fake.is_stopped());
}

#[test]
fn a_chosen_bitrate_that_hears_frames_is_confirmed_either_way() {
    for source in [BitrateSource::Configured, BitrateSource::Assumed] {
        let fake = FakeUsb::new();
        busy_bus(&fake);
        let mut options = options(Mode::Active);
        options.bitrate_source = source;
        let session = open(&fake, &options).unwrap();
        assert_eq!(session.bitrate_check(), BitrateCheck::Confirmed);
    }
}

#[test]
fn a_bitrate_the_clock_cannot_give_exactly_is_refused_before_any_mode_message() {
    let fake = FakeUsb::new();
    fake.0.borrow_mut().bt_const = candlelight_const(FEATURES, 18_500_000);
    let failure = open(&fake, &options(Mode::Active)).unwrap_err();
    assert!(
        failure.error.to_string().contains("500000"),
        "{}",
        failure.error
    );
    assert_eq!(
        fake.requests(),
        [
            wire::BREQ_HOST_FORMAT,
            wire::BREQ_DEVICE_CONFIG,
            wire::BREQ_BT_CONST
        ]
    );
}

#[test]
fn a_device_without_listen_only_is_refused_even_to_go_active() {
    for mode in [Mode::Active, Mode::ListenOnly] {
        let fake = FakeUsb::new();
        fake.0.borrow_mut().bt_const = candlelight_const(wire::FEATURE_BERR_REPORTING, 48_000_000);
        let failure = open(&fake, &options(mode)).unwrap_err();
        assert!(
            failure.error.to_string().contains("listen-only"),
            "{}",
            failure.error
        );
        assert_eq!(fake.modes().len(), 0);
    }
}

#[test]
fn a_device_that_needs_the_lpc546xx_quirk_is_refused() {
    let fake = FakeUsb::new();
    fake.0.borrow_mut().bt_const =
        candlelight_const(FEATURES | wire::FEATURE_USB_QUIRK_LPC546XX, 48_000_000);
    let failure = open(&fake, &options(Mode::Active)).unwrap_err();
    assert!(
        failure.error.to_string().contains("quirk"),
        "{}",
        failure.error
    );
    assert_eq!(fake.modes().len(), 0);
}

#[test]
fn only_the_two_obd_bitrates_are_accepted_and_nothing_is_sent_for_another() {
    for bitrate in [
        0,
        1,
        125_000,
        249_999,
        250_001,
        499_999,
        500_001,
        1_000_000,
        u32::MAX,
    ] {
        let fake = FakeUsb::new();
        let mut options = options(Mode::Active);
        options.bitrate = bitrate;
        assert!(open(&fake, &options).is_err(), "{bitrate}");
        assert!(fake.requests().is_empty(), "{bitrate}");
    }
    for bitrate in [250_000, 500_000] {
        let fake = FakeUsb::new();
        busy_bus(&fake);
        let mut options = options(Mode::Active);
        options.bitrate = bitrate;
        assert!(open(&fake, &options).is_ok(), "{bitrate}");
    }
}

#[test]
fn a_device_that_answers_with_the_wrong_sizes_is_refused() {
    let fake = FakeUsb::new();
    fake.0.borrow_mut().device_config = vec![0; 11];
    assert!(open(&fake, &options(Mode::Active)).is_err());
    assert_eq!(fake.modes().len(), 0);
    let fake = FakeUsb::new();
    fake.0.borrow_mut().bt_const = vec![0; 41];
    assert!(open(&fake, &options(Mode::Active)).is_err());
    assert_eq!(fake.modes().len(), 0);
}

#[test]
fn a_failure_after_the_controller_started_leaves_it_in_reset() {
    // The bit timing is refused the second time, with the controller already started once.
    let fake = FakeUsb::new();
    busy_bus(&fake);
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_BITTIMING, 1));
    let failure = open(&fake, &options(Mode::Active)).unwrap_err();
    assert!(fake.is_stopped());
    assert_eq!(fake.modes().last(), Some(&(wire::MODE_RESET, 0)));
    assert!(!started_active(&fake.modes()));
    // What was sent is evidence for the audit log.
    assert!(failure.events.iter().any(|e| matches!(
        e,
        LinkEvent::Command { command, .. } if command.contains("BITTIMING")
    )));
}

#[test]
fn a_reset_that_fails_is_reported_with_the_failure() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    // The first three mode messages (reset, listen, reset) pass; the active start fails.
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_MODE, 3));
    let failure = open(&fake, &options(Mode::Active)).unwrap_err();
    let text = failure.error.to_string();
    assert!(text.contains("resetting the controller failed"), "{text}");
}

#[test]
fn a_failed_start_is_reset_even_if_it_may_have_taken_effect() {
    let fake = FakeUsb::new();
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_MODE, 1));
    // Reset passes, the listen-only start fails: the controller may be running.
    let failure = open(&fake, &options(Mode::ListenOnly)).unwrap_err();
    assert!(
        failure
            .error
            .to_string()
            .contains("control transfer failed")
    );
    // Reset, the failed start, the reset after it, and a last try when the controller is dropped.
    assert_eq!(fake.modes().len(), 4);
}

#[test]
fn every_control_transfer_is_logged_for_the_audit_log() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let commands: Vec<String> = session
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            LinkEvent::Command { command, .. } => Some(command),
            _ => None,
        })
        .collect();
    for wanted in [
        "HOST_FORMAT",
        "DEVICE_CONFIG",
        "BT_CONST",
        "BITTIMING",
        "MODE RESET",
        "listen-only",
        "active",
    ] {
        assert!(
            commands.iter().any(|c| c.contains(wanted)),
            "{wanted} in {commands:?}"
        );
    }
    assert_eq!(session.take_events().len(), 0);
}

#[test]
fn the_link_names_gsusb_its_mode_and_its_bitrate() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let session = open(&fake, &options(Mode::Active)).unwrap();
    assert_eq!(session.link_name(), "gsusb:active:500000");
    let fake = FakeUsb::new();
    let mut options = options(Mode::ListenOnly);
    options.bitrate = 250_000;
    let session = open(&fake, &options).unwrap();
    assert_eq!(session.link_name(), "gsusb:listen-only:250000");
}

#[test]
fn dropping_a_session_takes_the_controller_off_the_bus() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    drop(open(&fake, &options(Mode::Active)).unwrap());
    assert!(fake.is_stopped());
    assert_eq!(fake.modes().last(), Some(&(wire::MODE_RESET, 0)));
    fake.assert_nothing_written();
}

#[test]
fn a_listen_window_too_long_to_be_one_is_refused_before_any_usb() {
    for window in [
        Duration::MAX,
        Duration::from_secs(61),
        Duration::from_secs(60) + Duration::from_nanos(1),
    ] {
        let fake = FakeUsb::new();
        let mut options = options(Mode::Active);
        options.listen_window = window;
        let failure = open(&fake, &options).unwrap_err();
        assert!(
            failure.error.to_string().contains("listen window"),
            "{}",
            failure.error
        );
        assert_eq!(fake.requests().len(), 0, "{window:?}");
    }
    for window in [Duration::ZERO, Duration::from_secs(60)] {
        let fake = FakeUsb::new();
        busy_bus(&fake);
        let mut options = options(Mode::Active);
        options.listen_window = window;
        assert!(open(&fake, &options).is_ok(), "{window:?}");
    }
}

#[test]
fn closing_hands_back_the_reset_for_the_audit_log() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let _ = session.take_events();
    let events = session.close().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        LinkEvent::Command { command, answer, .. } if command.contains("MODE RESET") && answer == &["ok"]
    )));
    // A reset that failed is in the failure's events too.
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let _ = session.take_events();
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_MODE, 0));
    let failure = session.close().unwrap_err();
    assert!(failure.events.iter().any(|e| matches!(
        e,
        LinkEvent::Command { command, answer, .. }
            if command.contains("MODE RESET") && answer[0].contains("failed")
    )));
}

#[test]
fn closing_reports_whether_the_reset_worked() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let session = open(&fake, &options(Mode::Active)).unwrap();
    assert!(session.close().is_ok());
    assert!(fake.is_stopped());
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let session = open(&fake, &options(Mode::Active)).unwrap();
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_MODE, 0));
    assert!(session.close().is_err());
}

// --- A session carrying requests ---

fn car(fake: &FakeUsb) {
    fake.on_write(|_, can_id, data| match (can_id, data[0]) {
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
    });
}

#[test]
fn a_request_goes_out_padded_and_its_reply_comes_back() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let replies = exchange(
        &mut session,
        &read_did(),
        Expect::Module(0x7E8),
        Timing::default(),
    )
    .unwrap();
    assert_eq!(replies[0].payload, [0x62, 0xF1, 0x87, 0x11, 0x22]);
    assert_eq!(
        fake.written(),
        [(0x7E0, vec![0x03, 0x22, 0xF1, 0x87, 0xAA, 0xAA, 0xAA, 0xAA])]
    );
    for out in fake.bulk_out() {
        assert_eq!(out.len(), 20);
        assert_eq!(out[8], 8, "DLC 8");
    }
}

#[test]
fn flow_control_after_a_broadcast_goes_to_the_physical_id_and_the_reply_completes() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
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
    let written = fake.written();
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].0, 0x7DF);
    // Not the broadcast ID: the ECU that answered (0x7E8 - 8).
    assert_eq!(written[1].0, 0x7E0);
    assert_eq!(written[1].1[0], 0x30);
    assert_eq!(written[1].1.len(), 8);
}

#[test]
fn a_multi_frame_request_sends_each_frame_after_the_last_was_confirmed() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    // `19` takes any length: ten bytes need a first frame and a consecutive frame.
    let mut payload = vec![0x19, 0x02, 0xAF];
    payload.extend_from_slice(&[0; 7]);
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &payload)
        .unwrap();
    session.send(&request).unwrap();
    let written = fake.written();
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].1[0] & 0xF0, 0x10);
    assert_eq!(written[1].1[0], 0x21);
    // The last, short frame is padded.
    assert_eq!(written[1].1[5..], [0xAA, 0xAA, 0xAA]);
    assert_eq!(fake.0.borrow().overlapped, 0);
}

// #42 requirement 2: a long transfer, so a port that let the next frame go before the last one was
// confirmed would show (the fake counts a write made while a confirmation was still unread).
#[test]
fn every_frame_of_a_long_request_is_padded_and_confirmed_before_the_next() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let mut payload = vec![0x19, 0x02, 0xAF];
    payload.resize(100, 0);
    let request = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x7E0), &payload)
        .unwrap();
    session.send(&request).unwrap();
    let out = fake.bulk_out();
    // a first frame of 6 bytes, then 94 bytes in sevens
    assert_eq!(out.len(), 1 + 94usize.div_ceil(7));
    for (n, frame) in out.iter().enumerate() {
        assert_eq!(frame[8], 8, "DLC 8 on frame {n}");
        if n > 0 {
            assert_eq!(frame[12], 0x20 | (u8::try_from(n).unwrap() & 0x0F), "{n}");
        }
    }
    assert_eq!(fake.0.borrow().overlapped, 0);
}

// Guards the test above: the fake must see a confirmation nobody read as an overlap.
#[test]
fn the_fake_counts_a_write_made_before_the_last_confirmation_was_read() {
    let fake = FakeUsb::new();
    let mut usb = fake.clone();
    let frame = raw_frame(
        0,
        0x7E0,
        8,
        0,
        0,
        &[0x03, 0x22, 0xF1, 0x87, 0xAA, 0xAA, 0xAA, 0xAA],
    );
    Usb::bulk_out(&mut usb, &frame).unwrap();
    assert_eq!(fake.0.borrow().overlapped, 0);
    Usb::bulk_out(&mut usb, &frame).unwrap();
    assert_eq!(fake.0.borrow().overlapped, 1);
}

// #42 requirement 3: the port is asked for the replies of each request, and nothing else.
#[test]
fn the_port_is_given_the_replies_of_the_request_only() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    assert_eq!(session.can.port.filters(), []);
    session.send(&read_did()).unwrap();
    assert_eq!(
        session.can.port.filters(),
        [Filter {
            id: 0x7E8,
            mask: 0x7FF,
            extended: false
        }]
    );
    let broadcast = Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::ObdFunctional,
            &obd::vehicle_info(0x02),
        )
        .unwrap();
    session.send(&broadcast).unwrap();
    assert_eq!(
        session.can.port.filters(),
        [Filter {
            id: 0x7E8,
            mask: 0x7F8,
            extended: false
        }]
    );
    let extended = Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::Physical29(0x18DA_10F1),
            &[0x22, 0xF1, 0x87],
        )
        .unwrap();
    session.send(&extended).unwrap();
    assert_eq!(
        session.can.port.filters(),
        [Filter {
            id: 0x18DA_F110,
            mask: 0x1FFF_FFFF,
            extended: true
        }]
    );
}

#[test]
fn a_frame_from_another_module_is_not_the_requests_reply() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    session.send(&read_did()).unwrap();
    fake.queue(heard(0x7E9, &[0x05, 0x62, 0xF1, 0x87, 0x11, 0x22]));
    assert_eq!(session.recv(Duration::from_millis(5)), Err(Error::Timeout));
    fake.queue(heard(0x7E8, &[0x05, 0x62, 0xF1, 0x87, 0x11, 0x22]));
    assert_eq!(
        session.recv(Duration::from_millis(5)).unwrap().payload,
        [0x62, 0xF1, 0x87, 0x11, 0x22]
    );
}

// #42 requirement 3: a receive overrun is an error, never a gap in a reply.
#[test]
fn a_receive_overrun_in_a_reply_is_an_error_and_the_half_reply_is_dropped() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    fake.on_write(|_, can_id, data| match (can_id, data[0]) {
        (0x7E0, 0x03) => Reaction::reply(vec![heard(
            0x7E8,
            &[0x10, 0x0A, 0x62, 0xF1, 0x87, 0x01, 0x02, 0x03],
        )]),
        // The device lost frames: its overflow flag rides on the next one.
        (0x7E0, 0x30) => Reaction::reply(vec![raw_frame(
            wire::ECHO_ID_RX,
            0x7E8,
            8,
            0,
            1,
            &[0x21, 0x04, 0x05, 0x06, 0x07, 0, 0, 0],
        )]),
        _ => Reaction::confirm(),
    });
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
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

#[test]
fn a_request_is_not_sent_while_a_stale_reply_hides_behind_a_flood() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    // The first request leaves its filter on the reply ID; then other IDs flood in ahead of a
    // late reply to it.
    session.send(&read_did()).unwrap();
    let written = fake.bulk_out().len();
    for _ in 0..5000 {
        fake.queue(heard(0x123, &[1]));
    }
    fake.queue(heard(0x7E8, &[0x05, 0x62, 0xF1, 0x87, 0x99, 0x99]));
    let err = session.send(&read_did()).unwrap_err();
    assert!(err.to_string().contains("drained"), "{err}");
    assert_eq!(fake.bulk_out().len(), written, "nothing was sent");
}

#[test]
fn an_unacknowledged_request_is_an_error_that_stops_later_sends() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    fake.on_write(|_, _, _| Reaction {
        echo: Echo::Never,
        ..Reaction::confirm()
    });
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let err = session.send(&read_did()).unwrap_err();
    assert!(err.to_string().contains("acknowledged"), "{err}");
    assert!(fake.is_stopped());
    let sent = fake.bulk_out().len();
    assert!(session.send(&read_did()).is_err());
    assert!(session.recv(Duration::from_millis(5)).is_err());
    assert_eq!(fake.bulk_out().len(), sent);
}

#[test]
fn a_bus_off_latches_and_nothing_more_is_written() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    fake.queue(error_frame(BUS_OFF, 0));
    let err = session.send(&read_did()).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert!(session.send(&read_did()).is_err());
    fake.assert_nothing_written();
}

#[test]
fn an_unplugged_device_is_an_error_not_a_hang() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    fake.0.borrow_mut().fail_bulk_in = true;
    fake.0.borrow_mut().fail_bulk_out = true;
    assert!(session.send(&read_did()).is_err());
    assert!(session.recv(Duration::from_millis(5)).is_err());
    fake.assert_nothing_written();
}

// --- VW TP2.0 (#259) ---

use crate::raw::tests::tp20::{Car, IDENTIFICATION, SETUP_REQUEST, channel, policy, setup};
use crate::tp20::{ChannelSession, Disconnect};

// A car with one TP2.0 module that answers the identification read; every frame it sends is as
// long as the module made it, as on a real bus.
fn tp20_car(fake: &FakeUsb) {
    let mut car = Car::with(vec![(IDENTIFICATION.to_vec(), vec![0x5A, 0x9B, 1, 2])]);
    fake.on_write(move |_, can_id, data| {
        Reaction::reply(
            car.hear_frame(can_id, data)
                .into_iter()
                .map(|(id, payload)| heard(id, &payload))
                .collect(),
        )
    });
}

#[test]
fn a_tp20_session_runs_over_usb_with_every_frame_at_its_own_length() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    tp20_car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let policy = policy();
    let mut channel = ChannelSession::open(&mut session, &policy, 0x01, Timing::default()).unwrap();
    assert_eq!(
        channel.request(&IDENTIFICATION).unwrap(),
        [0x5A, 0x9B, 1, 2]
    );
    assert_eq!(channel.close(), Ok(Disconnect::Closed));
    let out = fake.bulk_out();
    // The setup (7 bytes), the tester's parameters (6), the request (5), the ACK of the answer
    // (1) and the disconnect (1): the DLC on USB is the frame's own, the bytes after it zero.
    let dlcs: Vec<u8> = out.iter().map(|frame| frame[8]).collect();
    assert_eq!(dlcs, [7, 6, 5, 1, 1]);
    assert_eq!(out[0][12..], [0x01, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01, 0]);
    assert_eq!(out[0][4..8], [0x00, 0x02, 0, 0], "to 0x200");
    assert_eq!(out[4][12..], [0xA8, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(out[4][4..8], [0x40, 0x07, 0, 0], "to 0x740");
    // Each was confirmed before the next went out.
    assert_eq!(fake.0.borrow().overlapped, 0);
}

#[test]
fn a_tp20_frame_nobody_acknowledges_is_an_error_that_stops_later_sends() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    fake.on_write(|_, _, _| Reaction {
        echo: Echo::Never,
        ..Reaction::confirm()
    });
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let err = session.send(&setup()).unwrap_err();
    assert!(err.to_string().contains("acknowledged"), "{err}");
    assert!(fake.is_stopped());
    let sent = fake.bulk_out().len();
    assert!(session.send(&setup()).is_err());
    assert_eq!(fake.bulk_out().len(), sent);
}

#[test]
fn a_listen_only_session_writes_no_tp2_0_frame() {
    let fake = FakeUsb::new();
    let mut session = open(&fake, &options(Mode::ListenOnly)).unwrap();
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
    fake.assert_nothing_written();
    assert!(!started_active(&fake.modes()));
}

#[test]
fn a_bus_off_before_a_channel_frame_latches_and_nothing_more_is_written() {
    let fake = FakeUsb::new();
    busy_bus(&fake);
    tp20_car(&fake);
    let mut session = open(&fake, &options(Mode::Active)).unwrap();
    let policy = policy();
    session.send(&setup()).unwrap();
    let written = fake.bulk_out().len();
    assert_eq!(written, 1);
    fake.queue(error_frame(BUS_OFF, 0));
    let request = policy.approve_tp20_disconnect(&channel()).unwrap();
    let err = session.send(&request).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert!(session.send(&request).is_err());
    assert_eq!(fake.bulk_out().len(), written);
    assert_eq!(fake.written()[0].1[..7], SETUP_REQUEST);
}
