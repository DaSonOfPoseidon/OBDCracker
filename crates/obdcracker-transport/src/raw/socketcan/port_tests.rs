//! The CAN port over the fake interface.

use std::time::{Duration, Instant};

use super::can_port::SocketCanPort;
use super::device::{Device, KernelFilter};
use super::fake::{
    Echo, FakeDevice, Reaction, after_drops, bus_error, bus_off, error_frame, heard, heard_len,
    heard29, passive, remote, rx_overflow,
};
use super::wire::{EFF_FLAG, RTR_FLAG};
use crate::raw::port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};
use crate::{Error, LinkEvent};

fn started(fake: &FakeDevice, listen_only: bool) -> SocketCanPort<FakeDevice> {
    let echo = fake.state().iface.echo;
    let mut dev = fake.clone();
    dev.open(echo).unwrap();
    SocketCanPort::new(dev, listen_only, echo)
}

// A port on a driver that echoes, with every 11-bit frame let through.
fn open_port(fake: &FakeDevice) -> SocketCanPort<FakeDevice> {
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
const REQUEST: [u8; 8] = [2, 0x10, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];

fn echoing() -> FakeDevice {
    FakeDevice::can0(500_000)
}

fn silent_driver() -> FakeDevice {
    FakeDevice::vcan()
}

#[test]
fn a_frame_is_written_with_its_padding_and_confirmed_before_write_returns() {
    let fake = echoing();
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), 16);
    assert_eq!(sent[0][4], 8, "DLC 8");
    assert_eq!(u32::from_ne_bytes(sent[0][..4].try_into().unwrap()), 0x7E0);
    assert_eq!(sent[0][8..], REQUEST);
    // The echo was taken: it is not left to be read as a frame from the bus.
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn an_extended_frame_is_written_with_its_flag() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0,
        mask: 0,
        extended: true,
    }])
    .unwrap();
    port.write(&tx(0x17FC_0010, true, REQUEST)).unwrap();
    let id = u32::from_ne_bytes(fake.sent()[0][..4].try_into().unwrap());
    assert_eq!(id, 0x17FC_0010 | EFF_FLAG);
}

#[test]
fn the_echo_only_comes_back_through_a_filter_that_lets_it_in() {
    // The transport's filter is for replies only, so without the port adding the request's own
    // ID the kernel would never deliver the echo and every write would time out.
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    let during = fake.state().filter_history.last().cloned().unwrap();
    assert!(
        during.contains(&KernelFilter {
            id: 0x7E0,
            mask: 0x7FF | EFF_FLAG | RTR_FLAG
        }),
        "{during:x?}"
    );
    assert!(
        during.contains(&KernelFilter {
            id: 0x7E8,
            mask: 0x7FF | EFF_FLAG | RTR_FLAG
        }),
        "the reply filter stays"
    );
}

#[test]
fn frames_that_arrive_around_the_echo_are_kept_in_order() {
    let fake = echoing();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        before: vec![heard(0x7E8, &[1]), heard(0x7E9, &[2])],
        echo: Echo::Right,
        after: vec![heard(0x7EA, &[3])],
        counts: true,
    }));
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    for (id, byte) in [(0x7E8, 1), (0x7E9, 2), (0x7EA, 3)] {
        let PortEvent::Frame(f) = port.read(Duration::ZERO).unwrap() else {
            panic!("not a frame");
        };
        assert_eq!((f.id, f.data[0]), (id, byte));
    }
}

#[test]
fn another_nodes_frame_with_the_same_id_and_other_data_is_not_the_echo() {
    let fake = echoing();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        before: vec![],
        echo: Echo::WrongData,
        after: vec![],
        counts: true,
    }));
    let mut port = open_port(&fake);
    let started = Instant::now();
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(450));
    assert!(err.to_string().contains("no confirmation"), "{err}");
}

#[test]
fn an_unconfirmed_frame_stops_the_port_and_says_how_to_take_the_interface_down() {
    let fake = echoing();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        echo: Echo::Never,
        ..Reaction::confirm()
    }));
    let mut port = open_port(&fake);
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("no confirmation"), "{text}");
    assert!(text.contains("ip link set <interface> down"), "{text}");
    let sent = fake.sent().len();
    let recvs = fake.state().recvs;
    // Nothing more goes out, and nothing more is read.
    assert_eq!(port.write(&tx(0x7E0, false, REQUEST)).unwrap_err(), err);
    assert_eq!(port.read(Duration::ZERO).unwrap_err(), err);
    assert_eq!(port.set_filters(&[any11()]).unwrap_err(), err);
    assert_eq!(fake.sent().len(), sent);
    assert_eq!(fake.state().recvs, recvs);
}

#[test]
fn a_second_echo_of_the_same_frame_is_received_data_not_a_confirmation() {
    let fake = echoing();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        echo: Echo::Twice,
        ..Reaction::confirm()
    }));
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    // The extra copy is on the socket like any frame; with the reply filter it is dropped.
    assert_eq!(port.read(Duration::ZERO), Ok(frame(0x7E0, &REQUEST)));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn a_bus_fault_while_waiting_for_the_echo_ends_the_wait() {
    for (fault, text) in [
        (bus_off(), "bus-off"),
        (passive(), "error-passive"),
        (bus_error(), "error frame"),
    ] {
        let fake = echoing();
        let packet = fault.clone();
        fake.state().on_send = Some(Box::new(move |_| Reaction {
            before: vec![packet.clone()],
            echo: Echo::Never,
            after: vec![],
            counts: true,
        }));
        let mut port = open_port(&fake);
        let started = Instant::now();
        let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(300));
        assert!(err.to_string().contains(text), "{err}");
        assert_eq!(port.write(&tx(0x7E0, false, REQUEST)).unwrap_err(), err);
    }
}

#[test]
fn a_failed_send_stops_the_port() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.state().fail_send = true;
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(err.to_string().contains("writing a frame failed"), "{err}");
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
    fake.state().fail_send = false;
    assert_eq!(port.write(&tx(0x7E0, false, REQUEST)).unwrap_err(), err);
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

#[test]
fn listen_only_never_writes() {
    let fake = echoing();
    let mut port = started(&fake, true);
    port.set_filters(&[any11()]).unwrap();
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(err.to_string().contains("listen-only"), "{err}");
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
    // It still listens.
    fake.deliver(heard(0x7E8, &[1]));
    assert_eq!(
        port.read(Duration::ZERO),
        Ok(frame(0x7E8, &[1, 0, 0, 0, 0, 0, 0, 0]))
    );
}

#[test]
fn without_an_echo_the_transmit_counter_confirms_each_frame() {
    let fake = silent_driver();
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    assert_eq!(fake.sent().len(), 2);
    assert_eq!(fake.state().counter, 2);
    // No echo was asked of the socket, so none is expected, and the kernel filter is only the
    // transport's.
    assert_eq!(fake.state().opened, Some(false));
    assert_eq!(
        fake.state().filter_history.len(),
        2,
        "open, then the transport's"
    );
}

#[test]
fn without_an_echo_a_counter_that_does_not_move_stops_the_port() {
    let fake = silent_driver();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        counts: false,
        ..Reaction::confirm()
    }));
    let mut port = open_port(&fake);
    let started = Instant::now();
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(450));
    assert!(err.to_string().contains("transmit counter"), "{err}");
    assert_eq!(port.write(&tx(0x7E0, false, REQUEST)).unwrap_err(), err);
    assert_eq!(fake.sent().len(), 1);
}

#[test]
fn without_an_echo_an_unreadable_counter_writes_nothing() {
    let fake = silent_driver();
    let mut port = open_port(&fake);
    fake.state().counter_fails = true;
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(err.to_string().contains("transmit counter"), "{err}");
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
}

#[test]
fn without_an_echo_a_bus_fault_ends_the_wait() {
    let fake = silent_driver();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        before: vec![bus_off()],
        counts: false,
        ..Reaction::confirm()
    }));
    let mut port = open_port(&fake);
    let started = Instant::now();
    let err = port.write(&tx(0x7E0, false, REQUEST)).unwrap_err();
    assert!(started.elapsed() < Duration::from_millis(300));
    assert!(err.to_string().contains("bus-off"), "{err}");
}

#[test]
fn an_id_wider_than_its_width_is_refused_before_any_write() {
    let fake = echoing();
    let mut port = open_port(&fake);
    assert!(port.write(&tx(0x800, false, REQUEST)).is_err());
    assert!(port.write(&tx(0x2000_0000, true, REQUEST)).is_err());
    assert_eq!(fake.sent(), Vec::<[u8; 16]>::new());
    // A refusal for a bad request is not a fault of the port.
    port.write(&tx(0x7FF, false, REQUEST)).unwrap();
    port.write(&tx(0x1FFF_FFFF, true, REQUEST)).unwrap();
}

#[test]
fn filters_pick_by_id_mask_and_width() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[
        Filter {
            id: 0x7E8,
            mask: 0x7F8,
            extended: false,
        },
        Filter {
            id: 0x17FE_0010,
            mask: 0x1FFF_FFFF,
            extended: true,
        },
    ])
    .unwrap();
    fake.deliver(heard(0x7E9, &[1]));
    fake.deliver(heard(0x7F0, &[2]));
    fake.deliver(heard29(0x17FE_0010, &[3]));
    // Same low bits as an accepted 11-bit ID, wrong width; and an 11-bit frame whose ID is an
    // accepted 29-bit one's low bits.
    fake.deliver(heard29(0x7E8, &[4]));
    fake.deliver(heard29(0x17FE_0011, &[5]));
    let mut got = Vec::new();
    while let Ok(PortEvent::Frame(f)) = port.read(Duration::ZERO) {
        got.push((f.id, f.extended, f.data[0]));
    }
    assert_eq!(got, [(0x7E9, false, 1), (0x17FE_0010, true, 3)]);
}

#[test]
fn the_kernel_is_given_the_transports_filters_with_their_flags() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[
        Filter {
            id: 0x7E8,
            mask: 0x7F8,
            extended: false,
        },
        Filter {
            id: 0x17FE_0010,
            mask: 0x1FFF_FFFF,
            extended: true,
        },
    ])
    .unwrap();
    assert_eq!(
        fake.filters(),
        [
            KernelFilter {
                id: 0x7E8,
                mask: 0x7F8 | EFF_FLAG | RTR_FLAG
            },
            KernelFilter {
                id: 0x17FE_0010 | EFF_FLAG,
                mask: 0x1FFF_FFFF | EFF_FLAG | RTR_FLAG
            }
        ]
    );
}

#[test]
fn a_port_with_no_filters_hands_over_no_frames() {
    let fake = echoing();
    let mut port = started(&fake, false);
    fake.deliver(heard(0x7E8, &[1]));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
    port.set_filters(&[]).unwrap();
    fake.deliver(heard(0x7E8, &[1]));
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn remote_frames_are_never_delivered() {
    let fake = echoing();
    let mut port = open_port(&fake);
    // The kernel's filters already refuse them; a port that was handed one anyway drops it.
    let mut state = fake.state();
    state.inbox.push_back(remote(0x7E8));
    state.inbox.push_back(heard(0x7E8, &[1]));
    drop(state);
    let PortEvent::Frame(f) = port.read(Duration::ZERO).unwrap() else {
        panic!("not a frame");
    };
    assert_eq!(f.data[0], 1);
}

#[test]
fn bus_events_get_through_every_filter() {
    for (packet, event) in [
        (bus_off(), PortEvent::BusOff),
        (passive(), PortEvent::ErrorPassive),
        (rx_overflow(), PortEvent::Overrun),
        (bus_error(), PortEvent::ErrorFrame),
        (error_frame(0x100, 0), PortEvent::ErrorFrame),
        (error_frame(0x001, 0), PortEvent::ErrorFrame),
    ] {
        let fake = echoing();
        let mut port = started(&fake, false);
        port.set_filters(&[]).unwrap();
        fake.deliver(packet);
        assert_eq!(port.read(Duration::ZERO), Ok(event));
    }
}

#[test]
fn the_sockets_drop_counter_is_an_overrun_before_the_frame_it_rode_on() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.deliver(after_drops(heard(0x7E8, &[1]), 3));
    assert_eq!(port.read(Duration::ZERO), Ok(PortEvent::Overrun));
    assert_eq!(
        port.read(Duration::ZERO),
        Ok(frame(0x7E8, &[1, 0, 0, 0, 0, 0, 0, 0]))
    );
    // The same count again is not a new loss; a higher one is.
    fake.deliver(after_drops(heard(0x7E8, &[2]), 3));
    fake.deliver(after_drops(heard(0x7E8, &[3]), 4));
    assert!(matches!(port.read(Duration::ZERO), Ok(PortEvent::Frame(_))));
    assert_eq!(port.read(Duration::ZERO), Ok(PortEvent::Overrun));
    assert!(matches!(port.read(Duration::ZERO), Ok(PortEvent::Frame(_))));
}

#[test]
fn the_drop_counter_on_a_frame_the_filter_refuses_is_an_overrun_too() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    fake.state()
        .inbox
        .push_back(after_drops(heard(0x123, &[1]), 1));
    assert_eq!(port.read(Duration::ZERO), Ok(PortEvent::Overrun));
}

#[test]
fn a_malformed_frame_stops_the_port() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.state().inbox.push_back(heard_len(0x7E8, 9, &[0; 8]));
    let err = port.read(Duration::ZERO).unwrap_err();
    assert!(err.to_string().contains("DLC 9"), "{err}");
    assert_eq!(port.read(Duration::ZERO).unwrap_err(), err);
    assert_eq!(port.write(&tx(0x7E0, false, REQUEST)).unwrap_err(), err);

    // An 11-bit frame with ID bits above 11, and a datagram of the wrong size.
    for bad in [
        heard_len(0x0001_07E8, 8, &[0; 8]),
        super::device::Packet {
            frame: vec![0; 72],
            dropped: 0,
        },
        super::device::Packet {
            frame: vec![0; 15],
            dropped: 0,
        },
    ] {
        let fake = echoing();
        let mut port = open_port(&fake);
        fake.state().inbox.push_back(bad);
        assert!(port.read(Duration::ZERO).is_err());
    }
}

#[test]
fn a_failing_read_is_the_ports_error_and_stops_it() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.state().fail_recv = Some("Network is down".to_owned());
    let err = port.read(Duration::ZERO).unwrap_err();
    assert!(
        matches!(&err, Error::Adapter(m) if m.contains("Network is down")),
        "{err}"
    );
    fake.state().fail_recv = None;
    assert_eq!(port.read(Duration::ZERO).unwrap_err(), err);
}

#[test]
fn a_flood_of_other_ids_cannot_hold_a_read_past_its_deadline() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    fake.state().flood = Some(heard(0x123, &[0]));
    let started = Instant::now();
    assert_eq!(port.read(20 * MS), Err(Error::Timeout));
    let took = started.elapsed();
    assert!(took >= 20 * MS && took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn a_drain_that_gives_up_is_not_an_empty_queue() {
    let fake = echoing();
    let mut port = started(&fake, false);
    port.set_filters(&[Filter {
        id: 0x7E8,
        mask: 0x7FF,
        extended: false,
    }])
    .unwrap();
    fake.state().flood = Some(heard(0x123, &[0]));
    let err = port.read(Duration::ZERO).unwrap_err();
    assert!(
        matches!(&err, Error::Adapter(m) if m.contains("can't be drained")),
        "{err}"
    );
    // Not a fault of the port: once the flood stops, it reads again.
    fake.state().flood = None;
    assert_eq!(port.read(Duration::ZERO), Err(Error::Timeout));
}

#[test]
fn a_flood_of_matching_frames_is_read_one_at_a_time() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.state().flood = Some(heard(0x7E8, &[7]));
    for _ in 0..10 {
        assert!(matches!(port.read(Duration::ZERO), Ok(PortEvent::Frame(_))));
    }
}

#[test]
fn a_flood_while_waiting_for_the_echo_overruns_instead_of_growing() {
    let fake = echoing();
    fake.state().on_send = Some(Box::new(|_| Reaction {
        before: (0..3000)
            .map(|i| heard(0x7E8, &[u8::try_from(i % 256).unwrap()]))
            .collect(),
        ..Reaction::confirm()
    }));
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    let mut frames = 0;
    let mut overruns = 0;
    loop {
        match port.read(Duration::ZERO) {
            Ok(PortEvent::Frame(_)) => frames += 1,
            Ok(PortEvent::Overrun) => overruns += 1,
            Err(Error::Timeout) => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(frames <= 1024, "{frames}");
    assert_eq!(overruns, 1);
}

#[test]
fn the_ports_own_settings_are_logged_for_the_audit_log() {
    let fake = echoing();
    let mut port = open_port(&fake);
    port.write(&tx(0x7E0, false, REQUEST)).unwrap();
    let events = port.take_events();
    let commands: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Command {
                command, answer, ..
            } => {
                assert_eq!(answer, &["ok".to_owned()]);
                Some(command.as_str())
            }
            _ => None,
        })
        .collect();
    assert!(
        commands.iter().all(|c| c.starts_with("CAN_RAW_FILTER ")),
        "{commands:?}"
    );
    assert_eq!(
        commands.len(),
        2,
        "the transport's filters, then the echo's"
    );
    assert_eq!(port.take_events(), Vec::<LinkEvent>::new());
}

#[test]
fn the_reason_a_port_stopped_is_logged() {
    let fake = echoing();
    let mut port = open_port(&fake);
    fake.state().inbox.push_back(heard_len(0x7E8, 9, &[0; 8]));
    port.read(Duration::ZERO).unwrap_err();
    let events = port.take_events();
    assert!(events.iter().any(|e| matches!(
        e,
        LinkEvent::Status { line, .. } if line.starts_with("stopped: ") && line.contains("DLC 9")
    )));
}

#[test]
fn the_audit_log_is_bounded() {
    let fake = echoing();
    let mut port = open_port(&fake);
    for i in 0..200u32 {
        port.set_filters(&[Filter {
            id: i,
            mask: 0x7FF,
            extended: false,
        }])
        .unwrap();
    }
    let events = port.take_events();
    assert!(events.len() <= 65, "{}", events.len());
    assert!(matches!(events.last(), Some(LinkEvent::Lost(n)) if *n > 100));
}
