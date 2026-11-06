use std::time::{Duration, Instant};

use obdcracker_core::isotp::CAN_DLC;

use crate::Error;

// Padding for a frame shorter than a classic CAN frame (docs/raw-can.md#frames).
const PAD: u8 = 0xAA;

/// Which CAN IDs a port should hand over: those whose bits under `mask` equal `id`'s, at the
/// given width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Filter {
    pub(crate) id: u32,
    pub(crate) mask: u32,
    pub(crate) extended: bool,
}

/// A frame to put on the bus: `len` data bytes (DLC `len`), of which `data` holds the first.
/// ISO-TP frames are always 8 ([`TxFrame::padded`]); VW TP2.0 frames go out at their own length
/// ([`TxFrame::exact`]). A port must send DLC `len`, not 8: use [`TxFrame::bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxFrame {
    pub(crate) id: u32,
    pub(crate) extended: bool,
    pub(crate) data: [u8; CAN_DLC],
    pub(crate) len: usize,
}

impl TxFrame {
    // Only `RawCan` builds one, from an ISO-TP frame the core produced or a token the policy
    // minted.
    pub(super) fn padded(id: u32, extended: bool, bytes: &[u8]) -> Self {
        let mut data = [PAD; CAN_DLC];
        for (slot, byte) in data.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        Self {
            id,
            extended,
            data,
            len: CAN_DLC,
        }
    }

    // A frame of exactly `bytes`, with no padding: VW TP2.0's setup is 7 bytes and a disconnect
    // 1 (docs/raw-can.md#vw-tp20). Refuses what a classic CAN frame can't carry.
    pub(super) fn exact(id: u32, extended: bool, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > CAN_DLC {
            return Err(Error::Adapter(format!(
                "a {}-byte frame doesn't fit a classic CAN frame (1 to {CAN_DLC} bytes)",
                bytes.len()
            )));
        }
        let mut data = [0; CAN_DLC];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            id,
            extended,
            data,
            len: bytes.len(),
        })
    }

    /// The data bytes that go on the bus.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// A data frame a port received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxFrame {
    pub(crate) id: u32,
    pub(crate) extended: bool,
    pub(crate) data: Vec<u8>,
    /// A time no later than when the frame left the bus, if the port can bound it, else `None`.
    pub(crate) time: Option<Instant>,
}

/// What a port saw on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortEvent {
    Frame(RxFrame),
    /// The controller went bus-off.
    BusOff,
    /// The controller's error counters passed the error-passive limit.
    ErrorPassive,
    /// An error frame was seen on the bus.
    ErrorFrame,
    /// The port dropped received frames because nothing read them in time.
    Overrun,
}

/// One CAN controller, as far as the raw-CAN core needs it. Crate-private on purpose: the only
/// code that can call `write` is `RawCan`, which sends nothing but approved requests and the flow
/// control the policy minted. See docs/raw-can.md.
pub(crate) trait CanPort {
    /// Accepts only frames that match one of `filters` from now on. A port with no hardware
    /// filter may filter in software, or hand over more: `RawCan` checks every frame itself.
    fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error>;

    /// Puts one frame on the bus and returns once the controller has confirmed it went out, so
    /// the next frame can't pass it. A port that can't confirm (no echo) waits as long as it
    /// takes to be sure, or fails. An unconfirmed frame is an error, never `Ok`.
    fn write(&mut self, frame: &TxFrame) -> Result<(), Error>;

    /// Waits up to `timeout` for the next frame or bus event. Remote frames are never delivered.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] if nothing came; any other error is the port failing.
    fn read(&mut self, timeout: Duration) -> Result<PortEvent, Error>;
}
