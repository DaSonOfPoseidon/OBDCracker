//! SocketCAN interfaces (Linux): any CAN adapter the kernel has a driver for, and `vcan`. The bus
//! framing is the shared raw-CAN transport
//! ([`docs/raw-can.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/raw-can.md));
//! this module adds a raw socket on the interface and the checks made before it is used. It never
//! changes the interface's bitrate or mode. See
//! [`docs/socketcan.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/socketcan.md).

use std::time::Duration;

use obdcracker_safety::{Approved, ApprovedFlowControl};

use crate::raw::RawCan;
pub use crate::raw::{ConnectFailure, Mode};
use crate::{Error, LinkEvent, Response, Transport};
use can_port::SocketCanPort;
use linux::LinuxDevice;

mod can_port;
mod connect;
mod device;
mod linux;
mod wire;

#[cfg(test)]
mod connect_tests;
#[cfg(test)]
mod fake;
#[cfg(test)]
mod port_tests;
#[cfg(test)]
mod wire_tests;

/// What the bitrate check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitrateCheck {
    /// A bitrate was asked for and the interface reports exactly that.
    Matched,
    /// A bitrate was asked for, but the interface reports none (a virtual interface, or a driver
    /// that doesn't say), so it could not be confirmed.
    Unconfirmed,
    /// No bitrate was asked for, so none was checked.
    NotChecked,
}

/// How to connect.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The interface, such as `can0` or `vcan0`.
    pub interface: String,
    /// The bitrate the car's bus runs at (250000 or 500000), if known. The interface must be
    /// configured to it already; it is never set.
    pub bitrate: Option<u32>,
    /// Whether the session may transmit.
    pub mode: Mode,
}

impl Options {
    /// An active session on `interface`, with no bitrate to check.
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            bitrate: None,
            mode: Mode::Active,
        }
    }

    /// How to name this link in the audit log: `socketcan:<interface>:<mode>`.
    #[must_use]
    pub fn link_name(&self) -> String {
        format!("socketcan:{}:{}", self.interface, self.mode.name())
    }
}

/// A connected interface. Everything it does on the bus is a request the policy approved.
#[derive(Debug)]
struct Session<D: device::Device> {
    can: RawCan<SocketCanPort<D>>,
    mode: Mode,
    interface: String,
    // What the kernel reports, if it does.
    bitrate: Option<u32>,
    check: BitrateCheck,
}

impl<D: device::Device> Session<D> {
    fn link_name(&self) -> String {
        format!("socketcan:{}:{}", self.interface, self.mode.name())
    }
}

impl<D: device::Device> Transport for Session<D> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        // Before the transport frames or filters anything: a listen-only session writes nothing.
        if self.mode == Mode::ListenOnly {
            return Err(Error::Adapter(
                "the session is listen-only: nothing is written to the bus".to_owned(),
            ));
        }
        self.can.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.can.recv(timeout)
    }

    fn recv_logged(
        &mut self,
        timeout: Duration,
        before_send: &mut dyn FnMut(&ApprovedFlowControl) -> Result<(), Error>,
    ) -> Result<Response, Error> {
        self.can.recv_logged(timeout, before_send)
    }

    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        self.can.patient(wait)
    }

    fn broadcasts_can_overflow(&self) -> bool {
        self.can.broadcasts_can_overflow()
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        let mut events = self.can.port.take_events();
        events.extend(self.can.take_events());
        events
    }

    fn settle(&mut self) -> Result<(), Error> {
        self.can.settle()
    }
}

/// A SocketCAN interface carrying ISO-TP requests to a car.
///
/// It is a [`Transport`], and that is all: it takes requests only as [`Approved`], and sends the
/// flow control frames that `obdcracker-safety` mints for a multi-frame reply. It has no way to
/// write a frame of the caller's own, in either [`Mode`]:
///
/// ```compile_fail,E0599
/// use obdcracker_transport::socketcan::SocketCan;
/// fn put_a_frame_on_the_bus(interface: &mut SocketCan) {
///     interface.write(&[0x7E0, 0x02, 0x10, 0x02]);
/// }
/// ```
///
/// Nor can its parts be reached, or one be made around a socket of the caller's:
///
/// ```compile_fail,E0432
/// use obdcracker_transport::socketcan::SocketCanPort;
/// ```
///
/// ```compile_fail,E0423
/// use obdcracker_transport::socketcan::SocketCan;
/// fn make() -> SocketCan {
///     SocketCan(())
/// }
/// ```
///
/// [`SocketCan::open`] reads the interface first, as `docs/socketcan.md` describes, and refuses
/// one that is down, faulted, in a mode that would drop what is sent, or at another bitrate than
/// the one asked for. It never sets the interface's bitrate or mode, and it never uses the
/// kernel's own ISO-TP sockets.
#[derive(Debug)]
pub struct SocketCan(Session<LinuxDevice>);

impl SocketCan {
    /// Reads the interface, checks it, and opens a raw socket on it.
    ///
    /// # Errors
    ///
    /// [`ConnectFailure`]: the interface can't be used, with what was read from it for the
    /// audit log. Nothing is written to the bus.
    pub fn open(options: &Options) -> Result<Self, ConnectFailure> {
        connect::connect(LinuxDevice::new(&options.interface), options).map(Self)
    }

    /// What the bitrate check found.
    #[must_use]
    pub fn bitrate_check(&self) -> BitrateCheck {
        self.0.check
    }

    /// Whether this session may transmit.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.0.mode
    }

    /// The interface's name.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.0.interface
    }

    /// The bitrate in bit/s the interface reports, if it reports one.
    #[must_use]
    pub fn bitrate(&self) -> Option<u32> {
        self.0.bitrate
    }

    /// How to name this link in the audit log: `socketcan:<interface>:<mode>`.
    #[must_use]
    pub fn link_name(&self) -> String {
        self.0.link_name()
    }
}

impl Transport for SocketCan {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.0.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.0.recv(timeout)
    }

    fn recv_logged(
        &mut self,
        timeout: Duration,
        before_send: &mut dyn FnMut(&ApprovedFlowControl) -> Result<(), Error>,
    ) -> Result<Response, Error> {
        self.0.recv_logged(timeout, before_send)
    }

    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        self.0.patient(wait)
    }

    fn broadcasts_can_overflow(&self) -> bool {
        self.0.broadcasts_can_overflow()
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        self.0.take_events()
    }

    fn settle(&mut self) -> Result<(), Error> {
        self.0.settle()
    }
}
