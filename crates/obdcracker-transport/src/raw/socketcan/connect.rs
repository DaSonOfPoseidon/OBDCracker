//! Checking a SocketCAN interface before the socket is opened. Everything here reads: it never
//! changes the interface's state, bitrate or mode. See `docs/socketcan.md#connecting`.

use std::time::SystemTime;

use super::can_port::SocketCanPort;
use super::device::{BusState, Device, Iface};
use super::{BitrateCheck, Mode, Options, Session};
use crate::raw::{BITRATES, ConnectFailure, RawCan, printable};
use crate::{Error, LinkEvent};

/// The longest an interface name can be: the kernel's `IFNAMSIZ` less the terminating NUL.
const MAX_NAME: usize = 15;

/// Refuses an interface name that can't be one. The name is typed by a user and goes into a path
/// under `/sys/class/net`, so it is a plain run of printable ASCII with none of the characters
/// the kernel itself refuses (`/`, `:` and whitespace) and not `.` or `..`.
pub(super) fn check_name(name: &str) -> Result<(), String> {
    let bad = name.is_empty()
        || name.len() > MAX_NAME
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':');
    if bad {
        return Err(format!(
            "{:?} isn't a network interface name: use up to {MAX_NAME} printable characters, \
             without / or : (for example can0 or vcan0)",
            printable(name)
        ));
    }
    Ok(())
}

/// Refuses options that can't be right, before anything is read: a name that isn't one, or a
/// bitrate that no car's diagnostic bus uses.
pub(super) fn check_options(options: &Options) -> Result<(), ConnectFailure> {
    check_name(&options.interface).map_err(ConnectFailure::before_device)?;
    if let Some(bitrate) = options.bitrate
        && !BITRATES.contains(&bitrate)
    {
        return Err(ConnectFailure::before_device(format!(
            "{bitrate} bit/s isn't a diagnostic CAN bitrate: use 250000 or 500000"
        )));
    }
    Ok(())
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// What the kernel said, as one line for the audit log.
fn describe(name: &str, iface: &Iface) -> String {
    let mut line = format!(
        "interface {name}: {}, {}",
        if iface.is_can {
            "CAN"
        } else {
            "not a CAN interface"
        },
        if iface.up { "up" } else { "down" },
    );
    line.push_str(&match iface.state {
        Some(state) => format!(", state {}", state.name()),
        None => ", state not reported".to_owned(),
    });
    line.push_str(&match iface.bitrate {
        Some(bitrate) => format!(", bitrate {bitrate} bit/s"),
        None => ", no bitrate configured".to_owned(),
    });
    line.push_str(&match iface.modes {
        Some(modes) => format!(
            ", listen-only {}, loopback {}, presume-ack {}, one-shot {}",
            on_off(modes.listen_only),
            on_off(modes.loopback),
            on_off(modes.presume_ack),
            on_off(modes.one_shot),
        ),
        None => ", modes not reported".to_owned(),
    });
    line.push_str(if iface.echo {
        ", the driver echoes sent frames"
    } else {
        ", the driver doesn't echo sent frames"
    });
    line
}

/// What the interface allows, decided from what the kernel reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) check: BitrateCheck,
    /// Notes for the audit log and the user: things that don't stop the session.
    pub(super) notes: Vec<String>,
}

const HOW_TO_SET_UP: &str = "This tool never changes an interface's bitrate or mode: set it up yourself, \
     for example `sudo ip link set can0 up type can bitrate 500000`";

/// Decides whether a session may use `iface`, or says why not.
pub(super) fn plan(name: &str, iface: &Iface, options: &Options) -> Result<Plan, String> {
    if !iface.is_can {
        return Err(format!("{name} isn't a CAN interface"));
    }
    if !iface.up {
        return Err(format!("{name} is down. {HOW_TO_SET_UP}"));
    }
    if let Some(state @ (BusState::BusOff | BusState::ErrorPassive)) = iface.state {
        return Err(format!(
            "{name} is {}: the CAN controller is faulted, so the car's bus is disturbed or the \
             bitrate is wrong. Not using it",
            state.name()
        ));
    }
    if let Some(state @ (BusState::Stopped | BusState::Sleeping)) = iface.state {
        return Err(format!(
            "{name} is {}, not on the bus. {HOW_TO_SET_UP}",
            state.name()
        ));
    }
    let mut notes = Vec::new();
    if options.mode == Mode::Active
        && let Some(modes) = iface.modes
    {
        if modes.listen_only {
            return Err(format!(
                "{name} is in listen-only mode, so the kernel drops everything sent to it without \
                 saying so. Use --listen-only to monitor it, or take it out of listen-only mode \
                 yourself (`sudo ip link set {name} down`, then `ip link set {name} type can \
                 listen-only off`, then up). This tool never changes an interface's mode"
            ));
        }
        if modes.loopback {
            return Err(format!(
                "{name} is in loopback mode: its frames never reach the bus. This tool never \
                 changes an interface's mode"
            ));
        }
    }
    if let Some(modes) = iface.modes {
        if modes.presume_ack {
            notes.push(format!(
                "{name} presumes acknowledgements, so a frame nobody heard still counts as sent"
            ));
        }
        if modes.one_shot {
            notes.push(format!("{name} sends each frame once and never retries it"));
        }
    }
    if iface.state == Some(BusState::ErrorWarning) {
        notes.push(format!(
            "{name} is in error-warning: its error counters are high"
        ));
    }
    let check = match (options.bitrate, iface.bitrate) {
        (Some(expected), Some(actual)) if expected == actual => BitrateCheck::Matched,
        (Some(expected), Some(actual)) => {
            return Err(format!(
                "{name} runs at {actual} bit/s but {expected} bit/s was asked for (--bitrate or \
                 the vehicle profile). Sending at the wrong bitrate disturbs the car's bus, and \
                 this tool never changes an interface's bitrate: set it yourself, or ask for \
                 {actual}"
            ));
        }
        (Some(expected), None) => {
            notes.push(format!(
                "{name} reports no bitrate (a virtual interface, or a driver that doesn't say), \
                 so {expected} bit/s is not confirmed"
            ));
            BitrateCheck::Unconfirmed
        }
        (None, _) => BitrateCheck::NotChecked,
    };
    Ok(Plan { check, notes })
}

fn status(line: String) -> LinkEvent {
    LinkEvent::Status {
        at: SystemTime::now(),
        line,
    }
}

/// Reads the interface, decides, and opens the socket.
pub(super) fn connect<D: Device>(
    mut dev: D,
    options: &Options,
) -> Result<Session<D>, ConnectFailure> {
    check_options(options)?;
    let name = options.interface.as_str();
    let iface = dev.describe().map_err(|error| ConnectFailure {
        error,
        events: Vec::new(),
    })?;
    let described = describe(name, &iface);
    let mut events = vec![status(described.clone())];
    let plan = match plan(name, &iface, options) {
        Ok(plan) => plan,
        Err(message) => {
            return Err(ConnectFailure {
                error: Error::Adapter(message),
                events,
            });
        }
    };
    // Without an echo the transmit counter is all that tells a frame went out: if it can't be
    // read, an active session could not order a transfer's frames.
    if options.mode == Mode::Active
        && !iface.echo
        && let Err(e) = dev.tx_packets()
    {
        events.push(status(format!("can't read the transmit counter: {e}")));
        return Err(ConnectFailure {
            error: Error::Adapter(format!(
                "{name} doesn't echo sent frames and its transmit counter can't be read, so \
                 nothing could tell when a frame went out: {e}"
            )),
            events,
        });
    }
    if let Err(error) = dev.open(iface.echo) {
        return Err(ConnectFailure { error, events });
    }
    let mut port = SocketCanPort::new(dev, options.mode == Mode::ListenOnly, iface.echo);
    port.status(described);
    for note in plan.notes {
        port.status(note);
    }
    Ok(Session {
        can: RawCan::new(port),
        mode: options.mode,
        interface: options.interface.clone(),
        bitrate: iface.bitrate,
        check: plan.check,
    })
}
