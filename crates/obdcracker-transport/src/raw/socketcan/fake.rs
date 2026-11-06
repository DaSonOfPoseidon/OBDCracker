//! A fake interface for the tests: it keeps the kernel's filter rules, records everything the port
//! does and plays the bus.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use super::device::{BusState, Device, Iface, KernelFilter, Modes, Packet};
use super::wire::{EFF_FLAG, EFF_MASK, FRAME_LEN, RTR_FLAG, SFF_MASK};
use crate::Error;

/// How the fake answers a frame written to it.
pub(super) struct Reaction {
    /// Frames the bus delivers before the echo.
    pub(super) before: Vec<Packet>,
    pub(super) echo: Echo,
    /// Frames the bus delivers after it: the modules' replies.
    pub(super) after: Vec<Packet>,
    /// Whether the driver's transmit counter moves.
    pub(super) counts: bool,
}

impl Reaction {
    pub(super) fn confirm() -> Self {
        Self {
            before: vec![],
            echo: Echo::Right,
            after: vec![],
            counts: true,
        }
    }

    pub(super) fn reply(frames: Vec<Packet>) -> Self {
        Self {
            after: frames,
            ..Self::confirm()
        }
    }
}

pub(super) enum Echo {
    Right,
    /// The driver never sends the frame back (nobody ACKs it).
    Never,
    /// The same ID with other data.
    WrongData,
    /// The right echo, twice.
    Twice,
}

type OnSend = Box<dyn FnMut(&[u8; 16]) -> Reaction>;

pub(super) struct State {
    pub(super) iface: Iface,
    pub(super) describe_fails: Option<String>,
    pub(super) open_fails: Option<String>,
    /// `Some(echo)` once the socket is open.
    pub(super) opened: Option<bool>,
    /// Every set of filters the socket was given, oldest first.
    pub(super) filter_history: Vec<Vec<KernelFilter>>,
    pub(super) sent: Vec<[u8; 16]>,
    pub(super) inbox: VecDeque<Packet>,
    /// Called with each frame written, if set. Without it every frame is confirmed.
    pub(super) on_send: Option<OnSend>,
    pub(super) fail_send: bool,
    pub(super) fail_recv: Option<String>,
    pub(super) counter: u64,
    pub(super) counter_fails: bool,
    /// The transmit counter reads one behind until the socket has been read this many times.
    pub(super) counter_lag_recvs: usize,
    /// Every read finds this packet.
    pub(super) flood: Option<Packet>,
    pub(super) recvs: usize,
    pub(super) describes: usize,
}

#[derive(Clone)]
pub(super) struct FakeDevice(pub(super) Rc<RefCell<State>>);

impl FakeDevice {
    /// A `vcan`: up, a CAN interface, no controller to report, no echo.
    pub(super) fn vcan() -> Self {
        Self::with(Iface {
            is_can: true,
            up: true,
            echo: false,
            state: None,
            bitrate: None,
            modes: None,
        })
    }

    /// A real controller at `bitrate`, active, with the driver echoing frames.
    pub(super) fn can0(bitrate: u32) -> Self {
        Self::with(Iface {
            is_can: true,
            up: true,
            echo: true,
            state: Some(BusState::ErrorActive),
            bitrate: Some(bitrate),
            modes: Some(Modes::default()),
        })
    }

    pub(super) fn with(iface: Iface) -> Self {
        Self(Rc::new(RefCell::new(State {
            iface,
            describe_fails: None,
            open_fails: None,
            opened: None,
            filter_history: Vec::new(),
            sent: Vec::new(),
            inbox: VecDeque::new(),
            on_send: None,
            fail_send: false,
            fail_recv: None,
            counter: 0,
            counter_fails: false,
            counter_lag_recvs: 0,
            flood: None,
            recvs: 0,
            describes: 0,
        })))
    }

    pub(super) fn state(&self) -> std::cell::RefMut<'_, State> {
        self.0.borrow_mut()
    }

    pub(super) fn sent(&self) -> Vec<[u8; 16]> {
        self.0.borrow().sent.clone()
    }

    pub(super) fn filters(&self) -> Vec<KernelFilter> {
        self.0
            .borrow()
            .filter_history
            .last()
            .cloned()
            .unwrap_or_default()
    }

    /// Puts a packet where the kernel would, if the socket's filters let it through. Error
    /// frames are not filtered by ID.
    pub(super) fn deliver(&self, packet: Packet) {
        let mut state = self.0.borrow_mut();
        deliver(&mut state, packet);
    }
}

fn can_id(packet: &Packet) -> Option<u32> {
    let bytes: [u8; 4] = packet.frame.get(..4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

fn passes(filters: &[KernelFilter], id: u32) -> bool {
    filters.iter().any(|f| id & f.mask == f.id & f.mask)
}

fn deliver(state: &mut State, packet: Packet) {
    // The kernel delivers error frames by the error mask, and everything else by the filters. A
    // malformed packet is delivered as is: that is the point of sending one.
    let wanted = match can_id(&packet) {
        Some(id) if id & 0x2000_0000 != 0 => true,
        Some(id) => passes(
            state.filter_history.last().map_or(&[][..], Vec::as_slice),
            id,
        ),
        None => true,
    };
    if wanted {
        state.inbox.push_back(packet);
    }
}

impl Device for FakeDevice {
    fn describe(&mut self) -> Result<Iface, Error> {
        let mut state = self.0.borrow_mut();
        state.describes += 1;
        match &state.describe_fails {
            Some(why) => Err(Error::Adapter(why.clone())),
            None => Ok(state.iface.clone()),
        }
    }

    fn open(&mut self, echo: bool) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        if let Some(why) = &state.open_fails {
            return Err(Error::Adapter(why.clone()));
        }
        state.opened = Some(echo);
        // A new socket receives nothing until it is given filters.
        state.filter_history.push(Vec::new());
        Ok(())
    }

    fn set_filters(&mut self, filters: &[KernelFilter]) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        assert!(
            state.opened.is_some(),
            "filters set before the socket was open"
        );
        state.filter_history.push(filters.to_vec());
        Ok(())
    }

    fn send(&mut self, frame: &[u8; 16]) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        let echo = state
            .opened
            .expect("a frame sent before the socket was open");
        if state.fail_send {
            return Err(Error::Adapter("Network is down".to_owned()));
        }
        state.sent.push(*frame);
        let reaction = match state.on_send.as_mut() {
            Some(on_send) => on_send(frame),
            None => Reaction::confirm(),
        };
        for packet in reaction.before {
            deliver(&mut state, packet);
        }
        if echo {
            let own = Packet {
                frame: frame.to_vec(),
                dropped: 0,
            };
            match reaction.echo {
                Echo::Right => deliver(&mut state, own),
                Echo::Never => {}
                Echo::WrongData => {
                    let mut other = own;
                    other.frame[8] ^= 0xFF;
                    deliver(&mut state, other);
                }
                Echo::Twice => {
                    deliver(&mut state, own.clone());
                    deliver(&mut state, own);
                }
            }
        }
        if reaction.counts {
            state.counter += 1;
        }
        for packet in reaction.after {
            deliver(&mut state, packet);
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Packet>, Error> {
        let mut state = self.0.borrow_mut();
        state.recvs += 1;
        if let Some(why) = &state.fail_recv {
            return Err(Error::Adapter(why.clone()));
        }
        if let Some(flood) = &state.flood {
            return Ok(Some(flood.clone()));
        }
        if let Some(packet) = state.inbox.pop_front() {
            return Ok(Some(packet));
        }
        drop(state);
        // Nothing is coming: a real socket waits out the timeout, and so does the fake.
        assert!(
            timeout <= Duration::from_secs(2),
            "a test waited {timeout:?}"
        );
        std::thread::sleep(timeout);
        Ok(None)
    }

    fn tx_packets(&mut self) -> Result<u64, Error> {
        let state = self.0.borrow();
        if state.counter_fails {
            Err(Error::Adapter("no such file".to_owned()))
        } else if state.recvs < state.counter_lag_recvs {
            Ok(state.counter.saturating_sub(1))
        } else {
            Ok(state.counter)
        }
    }
}

// --- Packet builders ---

fn frame(can_id: u32, dlc: u8, data: &[u8]) -> Packet {
    let mut bytes = vec![0; FRAME_LEN];
    bytes[0..4].copy_from_slice(&can_id.to_ne_bytes());
    bytes[4] = dlc;
    bytes[8..8 + data.len()].copy_from_slice(data);
    Packet {
        frame: bytes,
        dropped: 0,
    }
}

/// A frame heard on the bus: an 11-bit ID, 8 data bytes (padded with zeros if shorter).
pub(super) fn heard(id: u32, data: &[u8]) -> Packet {
    frame(id & SFF_MASK, 8, data)
}

/// The same with a 29-bit ID.
pub(super) fn heard29(id: u32, data: &[u8]) -> Packet {
    frame((id & EFF_MASK) | EFF_FLAG, 8, data)
}

/// A frame with an exact length, for the parser's edge cases.
pub(super) fn heard_len(id: u32, dlc: u8, data: &[u8]) -> Packet {
    frame(id, dlc, data)
}

pub(super) fn remote(id: u32) -> Packet {
    frame((id & SFF_MASK) | RTR_FLAG, 0, &[])
}

pub(super) const BUS_OFF: u32 = 0x040;
const CRTL: u32 = 0x004;
const PROT: u32 = 0x008;

pub(super) fn error_frame(class: u32, detail: u8) -> Packet {
    frame(0x2000_0000 | class, 8, &[0, detail])
}

pub(super) fn bus_off() -> Packet {
    error_frame(BUS_OFF, 0)
}

pub(super) fn passive() -> Packet {
    error_frame(CRTL, 0x10)
}

pub(super) fn rx_overflow() -> Packet {
    error_frame(CRTL, 0x01)
}

pub(super) fn bus_error() -> Packet {
    error_frame(PROT, 0)
}

/// A packet the socket's queue lost frames before.
pub(super) fn after_drops(mut packet: Packet, dropped: u32) -> Packet {
    packet.dropped = dropped;
    packet
}
