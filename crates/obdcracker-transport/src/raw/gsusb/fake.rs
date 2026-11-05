//! A fake `gs_usb` device for the tests: it records every transfer and plays the controller.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use super::usb::Usb;
use super::wire::{self, ECHO_ID_RX};
use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Control {
    pub(super) request: u8,
    pub(super) value: u16,
    pub(super) data: Vec<u8>,
    pub(super) inbound: bool,
}

/// How the fake answers a frame written to it.
pub(super) struct Reaction {
    /// Frames the bus delivers before the confirmation.
    pub(super) before: Vec<Vec<u8>>,
    pub(super) echo: Echo,
    /// Frames the bus delivers after it: the modules' replies.
    pub(super) after: Vec<Vec<u8>>,
}

impl Reaction {
    pub(super) fn confirm() -> Self {
        Self {
            before: vec![],
            echo: Echo::Right,
            after: vec![],
        }
    }

    pub(super) fn reply(frames: Vec<Vec<u8>>) -> Self {
        Self {
            after: frames,
            ..Self::confirm()
        }
    }
}

pub(super) enum Echo {
    Right,
    /// The controller never sends the frame (nobody ACKs it).
    Never,
    /// A confirmation with this echo ID instead.
    Wrong(u32),
    /// The right confirmation, twice.
    Twice,
}

type OnWrite = Box<dyn FnMut(u32, u32, [u8; 8]) -> Reaction>;
type OnStart = Box<dyn FnMut(u32) -> Vec<Vec<u8>>>;

pub(super) struct State {
    pub(super) controls: Vec<Control>,
    pub(super) bulk_out: Vec<Vec<u8>>,
    pub(super) inbox: VecDeque<Vec<u8>>,
    pub(super) device_config: Vec<u8>,
    pub(super) bt_const: Vec<u8>,
    /// Called with (echo ID, CAN ID, data) for each frame written.
    pub(super) on_write: Option<OnWrite>,
    /// Called with the flags when the controller is started: the frames it hears.
    pub(super) on_start: Option<OnStart>,
    /// The mode flags the controller was started with, `None` while it is in reset.
    pub(super) started: Option<u32>,
    /// A request that fails, as (request, how many of its transfers to let through first).
    pub(super) fail_control: Option<(u8, usize)>,
    pub(super) fail_bulk_out: bool,
    pub(super) fail_bulk_in: bool,
    /// Every read finds this packet.
    pub(super) flood: Option<Vec<u8>>,
    /// Frames still on their way when the controller is reset: they arrive just after it.
    pub(super) late_on_reset: Vec<Vec<u8>>,
    /// Frames written while the controller was in reset.
    pub(super) written_while_stopped: usize,
    /// Frames written while an earlier one was still unconfirmed.
    pub(super) overlapped: usize,
    unconfirmed: usize,
    pub(super) bulk_in_calls: usize,
}

/// A handle on the fake that the test keeps while the code under test owns the other.
#[derive(Clone)]
pub(super) struct FakeUsb(pub(super) Rc<RefCell<State>>);

impl std::fmt::Debug for FakeUsb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeUsb")
    }
}

/// A candleLight on an STM32F072, reporting listen-only and bus-error reporting.
pub(super) fn candlelight_const(feature: u32, fclk: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [feature, fclk, 1, 16, 1, 8, 4, 1, 1024, 1] {
        bytes.extend_from_slice(&u32::to_le_bytes(word));
    }
    bytes
}

pub(super) const FEATURES: u32 = wire::FEATURE_LISTEN_ONLY | wire::FEATURE_BERR_REPORTING | 0x6;

impl FakeUsb {
    pub(super) fn new() -> Self {
        Self(Rc::new(RefCell::new(State {
            controls: vec![],
            bulk_out: vec![],
            inbox: VecDeque::new(),
            device_config: vec![0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0],
            bt_const: candlelight_const(FEATURES, 48_000_000),
            on_write: None,
            on_start: None,
            started: None,
            fail_control: None,
            fail_bulk_out: false,
            fail_bulk_in: false,
            flood: None,
            late_on_reset: vec![],
            written_while_stopped: 0,
            overlapped: 0,
            unconfirmed: 0,
            bulk_in_calls: 0,
        })))
    }

    pub(super) fn queue(&self, frame: Vec<u8>) {
        self.0.borrow_mut().inbox.push_back(frame);
    }

    pub(super) fn on_write(&self, f: impl FnMut(u32, u32, [u8; 8]) -> Reaction + 'static) {
        self.0.borrow_mut().on_write = Some(Box::new(f));
    }

    pub(super) fn on_start(&self, f: impl FnMut(u32) -> Vec<Vec<u8>> + 'static) {
        self.0.borrow_mut().on_start = Some(Box::new(f));
    }

    /// Every mode message sent, as (mode, flags).
    pub(super) fn modes(&self) -> Vec<(u32, u32)> {
        self.0
            .borrow()
            .controls
            .iter()
            .filter(|c| c.request == wire::BREQ_MODE && !c.inbound)
            .map(|c| {
                let word = |at: usize| {
                    u32::from_le_bytes([c.data[at], c.data[at + 1], c.data[at + 2], c.data[at + 3]])
                };
                (word(0), word(4))
            })
            .collect()
    }

    pub(super) fn requests(&self) -> Vec<u8> {
        self.0.borrow().controls.iter().map(|c| c.request).collect()
    }

    pub(super) fn bulk_out(&self) -> Vec<Vec<u8>> {
        self.0.borrow().bulk_out.clone()
    }

    /// The (CAN ID, data) of every frame written.
    pub(super) fn written(&self) -> Vec<(u32, Vec<u8>)> {
        self.bulk_out()
            .iter()
            .map(|b| {
                (
                    u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                    b[12..].to_vec(),
                )
            })
            .collect()
    }

    pub(super) fn assert_nothing_written(&self) {
        assert_eq!(self.bulk_out().len(), 0, "a frame reached the bus");
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.0.borrow().started.is_none()
    }
}

impl Usb for FakeUsb {
    fn control_out(&mut self, request: u8, value: u16, data: &[u8]) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.controls.push(Control {
            request,
            value,
            data: data.to_vec(),
            inbound: false,
        });
        if let Some((fail, skip)) = s.fail_control.as_mut()
            && *fail == request
        {
            if *skip == 0 {
                return Err(Error::Adapter("control transfer failed".to_owned()));
            }
            *skip -= 1;
        }
        if request == wire::BREQ_MODE {
            let mode = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            if mode == wire::MODE_START {
                s.started = Some(flags);
                if let Some(mut on_start) = s.on_start.take() {
                    let heard = on_start(flags);
                    s.inbox.extend(heard);
                    s.on_start = Some(on_start);
                }
            } else {
                let was_running = s.started.take().is_some();
                s.unconfirmed = 0;
                if was_running {
                    let late = std::mem::take(&mut s.late_on_reset);
                    s.inbox.extend(late);
                }
            }
        }
        Ok(())
    }

    fn control_in(&mut self, request: u8, value: u16, _length: u16) -> Result<Vec<u8>, Error> {
        let mut s = self.0.borrow_mut();
        s.controls.push(Control {
            request,
            value,
            data: vec![],
            inbound: true,
        });
        if let Some((fail, skip)) = s.fail_control.as_mut()
            && *fail == request
        {
            if *skip == 0 {
                return Err(Error::Adapter("control transfer failed".to_owned()));
            }
            *skip -= 1;
        }
        match request {
            wire::BREQ_DEVICE_CONFIG => Ok(s.device_config.clone()),
            wire::BREQ_BT_CONST => Ok(s.bt_const.clone()),
            other => Err(Error::Adapter(format!("no such request {other}"))),
        }
    }

    fn bulk_out(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        if s.fail_bulk_out {
            return Err(Error::Adapter("bulk write failed".to_owned()));
        }
        s.bulk_out.push(data.to_vec());
        if s.started.is_none() {
            s.written_while_stopped += 1;
        }
        if s.unconfirmed > 0 {
            s.overlapped += 1;
        }
        let echo_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let can_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let mut payload = [0; 8];
        payload.copy_from_slice(&data[12..20]);
        let mut reaction = match s.on_write.take() {
            Some(mut f) => {
                let reaction = f(echo_id, can_id, payload);
                s.on_write = Some(f);
                reaction
            }
            None => Reaction::confirm(),
        };
        s.inbox.extend(std::mem::take(&mut reaction.before));
        let mut echo = data.to_vec();
        match reaction.echo {
            Echo::Right => {
                s.inbox.push_back(echo);
            }
            Echo::Never => s.unconfirmed += 1,
            Echo::Wrong(id) => {
                echo[..4].copy_from_slice(&id.to_le_bytes());
                s.inbox.push_back(echo);
            }
            Echo::Twice => {
                s.inbox.push_back(echo.clone());
                s.inbox.push_back(echo);
            }
        }
        s.inbox.extend(reaction.after);
        Ok(())
    }

    fn bulk_in(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, Error> {
        let mut s = self.0.borrow_mut();
        s.bulk_in_calls += 1;
        if s.fail_bulk_in {
            return Err(Error::Adapter("the device went away".to_owned()));
        }
        if let Some(packet) = s.inbox.pop_front() {
            return Ok(Some(packet));
        }
        Ok(s.flood.clone())
    }
}

// --- Frames as the device sends them ---

pub(super) fn raw_frame(
    echo_id: u32,
    can_id: u32,
    dlc: u8,
    channel: u8,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&echo_id.to_le_bytes());
    bytes.extend_from_slice(&can_id.to_le_bytes());
    bytes.extend_from_slice(&[dlc, channel, flags, 0]);
    let mut padded = [0; 8];
    padded[..data.len()].copy_from_slice(data);
    bytes.extend_from_slice(&padded);
    bytes
}

/// A frame heard on the bus with an 11-bit ID.
pub(super) fn heard(id: u32, data: &[u8]) -> Vec<u8> {
    raw_frame(
        ECHO_ID_RX,
        id,
        u8::try_from(data.len()).unwrap(),
        0,
        0,
        data,
    )
}

/// A frame heard on the bus with a 29-bit ID.
pub(super) fn heard29(id: u32, data: &[u8]) -> Vec<u8> {
    raw_frame(
        ECHO_ID_RX,
        id | 0x8000_0000,
        u8::try_from(data.len()).unwrap(),
        0,
        0,
        data,
    )
}

/// An error frame: the class bits and the controller detail byte.
pub(super) fn error_frame(class: u32, detail: u8) -> Vec<u8> {
    raw_frame(ECHO_ID_RX, 0x2000_0000 | class, 8, 0, 0, &[0, detail])
}

pub(super) const BUS_OFF: u32 = 0x40;
pub(super) const PASSIVE: (u32, u8) = (0x04, 0x10);
