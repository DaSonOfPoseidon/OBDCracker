//! The CAN port over the fake USB layer.

use std::time::{Duration, Instant};

use super::can_port::GsUsbPort;
use super::fake::{
    BUS_OFF, Echo, FakeUsb, PASSIVE, Reaction, error_frame, heard, heard29, raw_frame,
};
use super::wire;
use crate::Error;
use crate::raw::port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};

fn started(fake: &FakeUsb, listen_only: bool) -> GsUsbPort<FakeUsb> {
    let mut port = GsUsbPort::new(fake.clone(), listen_only);
    port.start(!listen_only, false).unwrap();
    port
}

fn open_port(fake: &FakeUsb) -> GsUsbPort<FakeUsb> {
    let mut port = started(fake, false);
    port.set_filters(&[any11()]).unwrap();
    port
}

fn any11() -> Filter {
    Filter {
        id: 0,
        mask: 0,
        extended: false,
    }
}

fn tx(id: u32, extended: bool, data: [u8; 8]) -> TxFrame {
    TxFrame { id, extended, data }
}

fn frame(id: u32, data: &[u8]) -> PortEvent {
    PortEvent::Frame(RxFrame {
        id,
        extended: false,
        data: data.to_vec(),
        time: None,
    })
}

const MS: Duration = Duration::from_millis(1);

#[test]
fn a_frame_is_written_with_its_padding_and_confirmed_before_write_returns() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    port.write(&tx(
        0x7E0,
        false,
        [2, 0x10, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
    ))
    .unwrap();
    let out = fake.bulk_out();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].len(), 20);
    assert_eq!(out[0][8], 8, "DLC 8");
    assert_eq!(out[0][4..8], [0xE0, 0x07, 0, 0]);
    assert_eq!(out[0][12..], [2, 0x10, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
    // The confirmation was taken: nothing is left to read.
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn echo_ids_never_collide_with_the_receive_marker() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    for _ in 0..40 {
        port.write(&tx(0x7E0, false, [0; 8])).unwrap();
    }
    for out in fake.bulk_out() {
        let echo = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        assert!(echo < 10, "{echo}");
    }
}

#[test]
fn frames_that_arrive_around_the_confirmation_are_kept_in_order() {
    let fake = FakeUsb::new();
    fake.on_write(|_, _, _| Reaction {
        before: vec![heard(0x7E8, &[1, 2, 3])],
        echo: Echo::Right,
        after: vec![heard(0x7E8, &[4, 5])],
    });
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, [0; 8])).unwrap();
    assert_eq!(port.read(MS).unwrap(), frame(0x7E8, &[1, 2, 3]));
    assert_eq!(port.read(MS).unwrap(), frame(0x7E8, &[4, 5]));
}

#[test]
fn a_wrong_echo_id_is_an_error_and_stops_the_port() {
    let fake = FakeUsb::new();
    fake.on_write(|echo, _, _| Reaction {
        echo: Echo::Wrong(echo + 1),
        ..Reaction::confirm()
    });
    let mut port = open_port(&fake);
    let err = port.write(&tx(0x7E0, false, [0; 8])).unwrap_err();
    assert!(err.to_string().contains("echo"), "{err}");
    // Nothing more goes out, and the controller is left in reset.
    let before = fake.bulk_out().len();
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    assert!(port.read(Duration::ZERO).is_err());
    assert_eq!(fake.bulk_out().len(), before);
    assert!(fake.is_stopped());
}

#[test]
fn a_confirmation_with_no_frame_in_flight_is_refused() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    // A stale or spoofed echo of a frame we never sent.
    fake.queue(raw_frame(3, 0x7E0, 8, 0, 0, &[0; 8]));
    let err = port.read(MS).unwrap_err();
    assert!(err.to_string().contains("in flight"), "{err}");
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    fake.assert_nothing_written();
}

#[test]
fn a_second_confirmation_of_the_same_frame_is_refused() {
    let fake = FakeUsb::new();
    fake.on_write(|_, _, _| Reaction {
        echo: Echo::Twice,
        ..Reaction::confirm()
    });
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, [0; 8])).unwrap();
    assert!(
        port.read(MS).is_err(),
        "the duplicate has nothing in flight"
    );
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    assert_eq!(fake.bulk_out().len(), 1);
}

#[test]
fn an_unconfirmed_frame_resets_the_controller_and_stops_every_send() {
    let fake = FakeUsb::new();
    fake.on_write(|_, _, _| Reaction {
        echo: Echo::Never,
        ..Reaction::confirm()
    });
    let mut port = open_port(&fake);
    let began = Instant::now();
    let err = port.write(&tx(0x7E0, false, [0; 8])).unwrap_err();
    assert!(matches!(err, Error::Adapter(_)), "{err}");
    assert!(err.to_string().contains("confirm"), "{err}");
    assert!(began.elapsed() < Duration::from_secs(5));
    // The controller would retry the frame for ever: it is reset, not left to.
    assert!(fake.is_stopped());
    assert_eq!(fake.modes().last(), Some(&(wire::MODE_RESET, 0)));
    let before = fake.bulk_out().len();
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    assert!(port.read(Duration::ZERO).is_err());
    assert_eq!(fake.bulk_out().len(), before);
}

#[test]
fn a_bus_fault_while_waiting_for_a_confirmation_ends_the_wait() {
    let fake = FakeUsb::new();
    fake.on_write(|_, _, _| Reaction {
        before: vec![error_frame(BUS_OFF, 0)],
        echo: Echo::Never,
        after: vec![],
    });
    let mut port = open_port(&fake);
    let began = Instant::now();
    let err = port.write(&tx(0x7E0, false, [0; 8])).unwrap_err();
    assert!(err.to_string().contains("bus-off"), "{err}");
    assert!(fake.is_stopped());
    assert!(began.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_failed_bulk_write_stops_the_port() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.0.borrow_mut().fail_bulk_out = true;
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    fake.0.borrow_mut().fail_bulk_out = false;
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    fake.assert_nothing_written();
    assert!(fake.is_stopped());
}

#[test]
fn listen_only_never_writes() {
    let fake = FakeUsb::new();
    let mut port = started(&fake, true);
    let err = port.write(&tx(0x7E0, false, [0; 8])).unwrap_err();
    assert!(err.to_string().contains("listen-only"), "{err}");
    fake.assert_nothing_written();
    // That isn't a fault of the port: it still listens.
    fake.queue(heard(0x7E8, &[1]));
    port.set_filters(&[any11()]).unwrap();
    assert_eq!(port.read(MS).unwrap(), frame(0x7E8, &[1]));
}

#[test]
fn a_port_in_listen_only_cannot_be_started_active() {
    let fake = FakeUsb::new();
    let mut port = GsUsbPort::new(fake.clone(), true);
    assert!(port.start(true, false).is_err());
    assert_eq!(fake.modes().len(), 0);
}

#[test]
fn filters_pick_by_id_mask_and_width() {
    let fake = FakeUsb::new();
    let mut port = started(&fake, false);
    port.set_filters(&[
        Filter {
            id: 0x7E8,
            mask: 0x7F8,
            extended: false,
        },
        Filter {
            id: 0x18DA_F110,
            mask: 0x1FFF_FFFF,
            extended: true,
        },
    ])
    .unwrap();
    for packet in [
        heard(0x7DF, &[1]),
        heard(0x7E8, &[2]),
        heard(0x7EF, &[3]),
        heard(0x7F0, &[4]),
        // The same bits at the other width are another module's.
        heard29(0x7E8, &[5]),
        heard29(0x18DA_F110, &[6]),
        heard(0x110, &[7]),
    ] {
        fake.queue(packet);
    }
    let mut ids = vec![];
    while let Ok(event) = port.read(Duration::ZERO) {
        match event {
            PortEvent::Frame(f) => ids.push((f.id, f.extended)),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(ids, [(0x7E8, false), (0x7EF, false), (0x18DA_F110, true)]);
}

#[test]
fn a_port_with_no_filters_hands_over_no_frames() {
    let fake = FakeUsb::new();
    let mut port = started(&fake, false);
    fake.queue(heard(0x7E8, &[1]));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
    port.set_filters(&[any11()]).unwrap();
    fake.queue(heard(0x7E8, &[1]));
    assert!(port.read(Duration::ZERO).is_ok());
    port.set_filters(&[]).unwrap();
    fake.queue(heard(0x7E8, &[2]));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn bus_events_get_through_every_filter() {
    let fake = FakeUsb::new();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    fake.queue(heard(0x123, &[1]));
    fake.queue(error_frame(BUS_OFF, 0));
    fake.queue(error_frame(PASSIVE.0, PASSIVE.1));
    fake.queue(error_frame(0x80, 0));
    fake.queue(error_frame(0x04, 0x01));
    let events: Vec<PortEvent> = std::iter::from_fn(|| port.read(Duration::ZERO).ok()).collect();
    assert_eq!(
        events,
        [
            PortEvent::BusOff,
            PortEvent::ErrorPassive,
            PortEvent::ErrorFrame,
            PortEvent::Overrun
        ]
    );
}

#[test]
fn the_overflow_flag_is_an_overrun_before_the_frame_it_rode_on() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.queue(raw_frame(wire::ECHO_ID_RX, 0x7E8, 1, 0, 1, &[9]));
    assert_eq!(port.read(MS).unwrap(), PortEvent::Overrun);
    assert_eq!(port.read(MS).unwrap(), frame(0x7E8, &[9]));
}

#[test]
fn the_overflow_flag_on_a_confirmation_is_an_overrun_too() {
    let fake = FakeUsb::new();
    fake.on_write(|echo, _, _| Reaction {
        before: vec![],
        echo: Echo::Never,
        after: vec![raw_frame(echo, 0x7E0, 8, 0, 1, &[0; 8])],
    });
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, [0; 8])).unwrap();
    assert_eq!(port.read(MS).unwrap(), PortEvent::Overrun);
}

#[test]
fn remote_frames_and_other_channels_are_never_delivered() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.queue(raw_frame(
        wire::ECHO_ID_RX,
        0x4000_0000 | 0x7E8,
        0,
        0,
        0,
        &[],
    ));
    fake.queue(raw_frame(wire::ECHO_ID_RX, 0x7E8, 1, 1, 0, &[5]));
    fake.queue(raw_frame(wire::ECHO_ID_RX, 0x7E8, 1, 0, 0, &[6]));
    assert_eq!(port.read(MS).unwrap(), frame(0x7E8, &[6]));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn a_malformed_frame_stops_the_port() {
    for packet in [
        vec![0; 19],
        vec![0; 24],
        raw_frame(wire::ECHO_ID_RX, 0x7E8, 9, 0, 0, &[]),
        raw_frame(wire::ECHO_ID_RX, 0x7E8, 8, 0, 2, &[]),
    ] {
        let fake = FakeUsb::new();
        let mut port = open_port(&fake);
        fake.queue(packet);
        assert!(port.read(MS).is_err());
        assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
        fake.assert_nothing_written();
        assert!(fake.is_stopped());
    }
}

#[test]
fn a_failing_usb_read_is_the_ports_error() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.0.borrow_mut().fail_bulk_in = true;
    let err = port.read(MS).unwrap_err();
    assert!(err.to_string().contains("went away"), "{err}");
    assert!(port.write(&tx(0x7E0, false, [0; 8])).is_err());
    fake.assert_nothing_written();
}

#[test]
fn a_flood_of_other_ids_cannot_hold_a_read_past_its_deadline() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    fake.0.borrow_mut().flood = Some(heard(0x123, &[1]));
    let began = Instant::now();
    assert_eq!(port.read(Duration::from_millis(30)), Err(Error::Timeout));
    assert!(began.elapsed() < Duration::from_secs(2));
    // A read that must not wait still comes back.
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn a_flood_of_matching_frames_is_read_one_at_a_time() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.0.borrow_mut().flood = Some(heard(0x7E8, &[1]));
    for _ in 0..3000 {
        assert_eq!(port.read(Duration::ZERO).unwrap(), frame(0x7E8, &[1]));
    }
}

#[test]
fn a_flood_while_waiting_for_a_confirmation_overruns_instead_of_growing() {
    let fake = FakeUsb::new();
    fake.on_write(|_, _, _| Reaction {
        before: (0..5000)
            .map(|i| heard(0x7E8, &[u8::try_from(i % 256).unwrap()]))
            .collect(),
        echo: Echo::Right,
        after: vec![],
    });
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, [0; 8])).unwrap();
    let mut frames = 0;
    let mut overran = false;
    while let Ok(event) = port.read(Duration::ZERO) {
        match event {
            PortEvent::Frame(_) => frames += 1,
            PortEvent::Overrun => overran = true,
            other => panic!("{other:?}"),
        }
    }
    assert!(frames <= 1024, "{frames}");
    assert!(overran, "frames were dropped, so an overrun is reported");
}

#[test]
fn dropping_a_started_port_resets_the_controller_and_writes_nothing_else() {
    let fake = FakeUsb::new();
    {
        let _port = open_port(&fake);
    }
    assert!(fake.is_stopped());
    assert_eq!(fake.modes().last(), Some(&(wire::MODE_RESET, 0)));
    fake.assert_nothing_written();
}

#[test]
fn dropping_a_stopped_port_sends_nothing() {
    let fake = FakeUsb::new();
    {
        let _port = GsUsbPort::new(fake.clone(), false);
    }
    assert_eq!(fake.requests().len(), 0);
}

#[test]
fn unwinding_resets_the_controller_and_does_nothing_more() {
    let fake = FakeUsb::new();
    let kept = fake.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let mut port = open_port(&fake);
        port.write(&tx(0x7E0, false, [0; 8])).unwrap();
        panic!("a bug elsewhere");
    }));
    assert!(result.is_err());
    assert_eq!(
        kept.bulk_out().len(),
        1,
        "only the frame sent before the panic"
    );
    assert!(kept.is_stopped());
    assert_eq!(kept.modes().last(), Some(&(wire::MODE_RESET, 0)));
}

#[test]
fn closing_reports_a_failed_reset_and_drop_tries_again() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    fake.0.borrow_mut().fail_control = Some((wire::BREQ_MODE, 0));
    assert!(port.close().is_err());
    fake.0.borrow_mut().fail_control = None;
    let resets = fake.modes().len();
    drop(port);
    assert_eq!(fake.modes().len(), resets + 1, "a last try");
    assert!(fake.is_stopped());
}

#[test]
fn closing_twice_resets_once() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    port.close().unwrap();
    port.close().unwrap();
    drop(port);
    let resets = fake
        .modes()
        .iter()
        .filter(|m| m.0 == wire::MODE_RESET)
        .count();
    assert_eq!(resets, 1);
}

#[test]
fn an_id_wider_than_its_width_is_refused_before_any_write() {
    let fake = FakeUsb::new();
    let mut port = open_port(&fake);
    assert!(port.write(&tx(0x800, false, [0; 8])).is_err());
    assert!(port.write(&tx(0x2000_0000, true, [0; 8])).is_err());
    fake.assert_nothing_written();
    // A bad request isn't a fault of the port.
    port.write(&tx(0x7FF, false, [0; 8])).unwrap();
    port.write(&tx(0x1FFF_FFFF, true, [0; 8])).unwrap();
}

#[test]
fn what_the_port_does_is_logged_for_the_audit_log() {
    let fake = FakeUsb::new();
    let mut port = started(&fake, false);
    let events = port.take_events();
    assert!(events.iter().any(|e| matches!(
        e,
        crate::LinkEvent::Command { command, .. } if command.contains("START")
    )));
    assert_eq!(port.take_events().len(), 0);
}
