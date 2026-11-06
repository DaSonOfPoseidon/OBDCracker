//! What the SocketCAN port needs from the operating system, so the port can be tested against a
//! fake. The real one is `linux::LinuxDevice`.
//!
//! Nothing here can change the interface: it describes it, and moves frames through a socket
//! bound to it. See `docs/socketcan.md`.

use std::time::Duration;

use crate::Error;

/// Where an interface's CAN controller is, as the kernel reports it. `None` where the driver
/// doesn't say (a `vcan` has no controller at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BusState {
    ErrorActive,
    ErrorWarning,
    ErrorPassive,
    BusOff,
    Stopped,
    Sleeping,
}

impl BusState {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::ErrorActive => "error-active",
            Self::ErrorWarning => "error-warning",
            Self::ErrorPassive => "error-passive",
            Self::BusOff => "bus-off",
            Self::Stopped => "stopped",
            Self::Sleeping => "sleeping",
        }
    }
}

/// The controller modes the kernel reports as set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per kernel control mode"
)]
pub(super) struct Modes {
    pub(super) listen_only: bool,
    /// Frames are looped back inside the controller and never reach the bus.
    pub(super) loopback: bool,
    /// Missing acknowledgements are ignored, so a frame nobody heard still counts as sent.
    pub(super) presume_ack: bool,
    /// A frame is sent once, never retried.
    pub(super) one_shot: bool,
}

/// What the kernel says about an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Iface {
    /// Its hardware type is CAN (`ARPHRD_CAN`).
    pub(super) is_can: bool,
    pub(super) up: bool,
    /// The driver confirms each frame once it has gone out (`IFF_ECHO`).
    pub(super) echo: bool,
    pub(super) state: Option<BusState>,
    /// The bitrate it was configured with, if it has one.
    pub(super) bitrate: Option<u32>,
    pub(super) modes: Option<Modes>,
}

/// A frame filter for the kernel, as `can_id` and `can_mask` with the flag bits in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KernelFilter {
    pub(super) id: u32,
    pub(super) mask: u32,
}

/// One datagram from the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Packet {
    /// The `struct can_frame`, as the kernel wrote it.
    pub(super) frame: Vec<u8>,
    /// How many frames the socket's queue has dropped since it was made, as the kernel counted
    /// them when this one was queued (0 until one is).
    pub(super) dropped: u32,
}

/// One SocketCAN interface and a raw socket on it.
pub(super) trait Device {
    /// What the kernel says about the interface. Reads only.
    fn describe(&mut self) -> Result<Iface, Error>;

    /// Opens the socket. Nothing is received until [`Device::set_filters`] says what: it starts
    /// out receiving nothing. Error frames are always delivered. With `echo`, the socket also
    /// receives the frames it sends itself.
    fn open(&mut self, echo: bool) -> Result<(), Error>;

    /// Replaces the socket's filters. An empty list receives no data frames.
    fn set_filters(&mut self, filters: &[KernelFilter]) -> Result<(), Error>;

    /// Queues one `struct can_frame` on the interface. Blocks for a bounded time at most.
    fn send(&mut self, frame: &[u8; 16]) -> Result<(), Error>;

    /// Waits up to `timeout` for the next datagram. `None` if none came by then; never before.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Packet>, Error>;

    /// How many frames the driver says it has sent (`tx_packets`).
    fn tx_packets(&mut self) -> Result<u64, Error>;
}
