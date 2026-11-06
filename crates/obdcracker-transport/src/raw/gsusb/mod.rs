//! `gs_usb` adapters (`CANable`, candleLight): a CAN controller on USB, driven without a vendor
//! library on Linux, Windows and macOS. The bus framing is the shared raw-CAN transport
//! ([`docs/raw-can.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/raw-can.md));
//! this module adds the controller's USB protocol and the connect step that checks the bitrate
//! before the controller goes on the bus. See
//! [`docs/gsusb.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/gsusb.md).

use std::fmt;
use std::time::Duration;

use obdcracker_safety::{Approved, ApprovedFlowControl};

use crate::raw::RawCan;
pub use crate::raw::{ConnectFailure, Mode};
use crate::{Error, LinkEvent, Response, Transport};
use can_port::GsUsbPort;
use nusb::MaybeFuture;
use nusb_usb::NusbUsb;
pub use select::DeviceSummary;
use select::{KNOWN, Unchosen, printable};
use usb::Usb;

mod can_port;
mod connect;
#[cfg(test)]
mod fake;
mod nusb_usb;
mod select;
mod timing;
mod usb;
mod wire;

#[cfg(test)]
mod connect_tests;
#[cfg(test)]
mod port_tests;
#[cfg(test)]
mod select_tests;
#[cfg(test)]
mod tests;

/// Where the bitrate came from. It decides what silence during the bitrate check means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitrateSource {
    /// The user, or the vehicle profile, said what the car's bus runs at. A bus that stays silent
    /// for the whole listen window then goes active with a warning.
    Configured,
    /// A guess. A bus that stays silent can't be told apart from one at another rate, so going
    /// active is refused.
    Assumed,
}

/// What the bitrate check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitrateCheck {
    /// Frames were decoded at the bitrate while listening only.
    Confirmed,
    /// The bus was silent for the whole window, and the bitrate was chosen by the user or a
    /// profile, so the controller went active anyway.
    Unconfirmed,
    /// A listen-only session: it never goes active, so there was nothing to check.
    NotChecked,
}

/// How to connect.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The serial number of the device to use. With none, exactly one known device must be
    /// plugged in.
    pub serial: Option<String>,
    /// The bus's bitrate in bit/s: 250000 or 500000.
    pub bitrate: u32,
    /// Where `bitrate` came from.
    pub bitrate_source: BitrateSource,
    /// Whether the controller may transmit.
    pub mode: Mode,
    /// How long to listen at `bitrate` before going active: at most 60 s.
    pub listen_window: Duration,
}

impl Options {
    /// How to name this link in the audit log: `gsusb:<mode>:<bitrate>`.
    #[must_use]
    pub fn link_name(&self) -> String {
        format!("gsusb:{}:{}", self.mode.name(), self.bitrate)
    }

    /// An active session at `bitrate`, which the caller chose, on the only `gs_usb` device
    /// plugged in, listening for 1 s first.
    #[must_use]
    pub fn new(bitrate: u32) -> Self {
        Self {
            serial: None,
            bitrate,
            bitrate_source: BitrateSource::Configured,
            mode: Mode::Active,
            listen_window: Duration::from_secs(1),
        }
    }
}

/// A connected controller. Everything it does on the bus is a request the policy approved.
#[derive(Debug)]
struct Session<U: Usb> {
    can: RawCan<GsUsbPort<U>>,
    mode: Mode,
    bitrate: u32,
    check: BitrateCheck,
}

impl<U: Usb> Session<U> {
    fn bitrate_check(&self) -> BitrateCheck {
        self.check
    }

    fn link_name(&self) -> String {
        format!("gsusb:{}:{}", self.mode.name(), self.bitrate)
    }

    fn close(mut self) -> Result<Vec<LinkEvent>, ConnectFailure> {
        let closed = self.can.port.close();
        let mut events = self.can.port.take_events();
        events.extend(self.can.take_events());
        match closed {
            Ok(()) => Ok(events),
            Err(error) => Err(ConnectFailure { error, events }),
        }
    }
}

impl<U: Usb> Transport for Session<U> {
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

/// Why [`GsUsb::open`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// No known `gs_usb` device is plugged in, or none has the serial number asked for.
    NotFound {
        /// The serial number asked for.
        serial: Option<String>,
    },
    /// Several devices fit and none was named. Nothing was written to any of them.
    Many(Vec<DeviceSummary>),
    /// The device was found but couldn't be brought up, or the options were refused.
    Failed(ConnectFailure),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { serial: None } => {
                f.write_str("no gs_usb adapter (CANable, candleLight) found")
            }
            Self::NotFound {
                serial: Some(serial),
            } => {
                write!(
                    f,
                    "no gs_usb adapter with serial number {} found",
                    printable(serial)
                )
            }
            Self::Many(devices) => {
                f.write_str(
                    "several gs_usb adapters are plugged in; pick one by its serial number:",
                )?;
                for device in devices {
                    write!(f, "\n  {device}")?;
                }
                Ok(())
            }
            Self::Failed(failure) => failure.error.fmt(f),
        }
    }
}

impl std::error::Error for ConnectError {}

/// A `gs_usb` adapter (`CANable`, candleLight) carrying ISO-TP requests to a car.
///
/// It is a [`Transport`], and that is all: it takes requests only as [`Approved`], and sends the
/// flow control frames that `obdcracker-safety` mints for a multi-frame reply. It has no way to
/// write a frame of the caller's own, in either [`Mode`]:
///
/// ```compile_fail,E0599
/// use obdcracker_transport::gsusb::GsUsb;
/// fn put_a_frame_on_the_bus(adapter: &mut GsUsb) {
///     adapter.write(&[0x7E0, 0x02, 0x10, 0x02]);
/// }
/// ```
///
/// Nor can its parts be reached, or one be made around a USB handle of the caller's:
///
/// ```compile_fail,E0432
/// use obdcracker_transport::gsusb::GsUsbPort;
/// ```
///
/// ```compile_fail,E0423
/// use obdcracker_transport::gsusb::GsUsb;
/// fn make() -> GsUsb {
///     GsUsb(())
/// }
/// ```
///
/// [`GsUsb::open`] brings the controller up the way `docs/gsusb.md` describes: in listen-only
/// mode first, to check the bitrate, and only then (unless [`Mode::ListenOnly`] was asked for)
/// active. Dropping it takes the controller off the bus; [`GsUsb::close`] does the same and
/// reports a failure.
#[derive(Debug)]
pub struct GsUsb(Session<NusbUsb>);

impl GsUsb {
    /// Finds the device, brings the controller up and checks the bitrate.
    ///
    /// # Errors
    ///
    /// [`ConnectError`]. Nothing is written to a device unless exactly one known device fits.
    pub fn open(options: &Options) -> Result<Self, ConnectError> {
        connect::check_options(options).map_err(ConnectError::Failed)?;
        let devices = nusb::list_devices().wait().map_err(|e| {
            ConnectError::Failed(ConnectFailure::before_device(format!(
                "can't list the USB devices: {e}"
            )))
        })?;
        let candidates: Vec<_> = devices
            .filter(|d| KNOWN.contains(&(d.vendor_id(), d.product_id())))
            .map(|d| {
                let summary = DeviceSummary::new(
                    d.vendor_id(),
                    d.product_id(),
                    d.serial_number(),
                    d.product_string(),
                );
                (summary, d)
            })
            .collect();
        let info = select::choose(candidates, options.serial.as_deref()).map_err(|e| match e {
            Unchosen::None | Unchosen::NoSuchSerial => ConnectError::NotFound {
                serial: options.serial.clone(),
            },
            Unchosen::Many(devices) => ConnectError::Many(devices),
        })?;
        let usb = NusbUsb::open(&info).map_err(|error| {
            ConnectError::Failed(ConnectFailure {
                error,
                events: Vec::new(),
            })
        })?;
        connect::connect(usb, options)
            .map(Self)
            .map_err(ConnectError::Failed)
    }

    /// What the bitrate check found.
    #[must_use]
    pub fn bitrate_check(&self) -> BitrateCheck {
        self.0.bitrate_check()
    }

    /// Whether this session may transmit.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.0.mode
    }

    /// The bitrate in bit/s.
    #[must_use]
    pub fn bitrate(&self) -> u32 {
        self.0.bitrate
    }

    /// How to name this link in the audit log: `gsusb:<mode>:<bitrate>`.
    #[must_use]
    pub fn link_name(&self) -> String {
        self.0.link_name()
    }

    /// Takes the controller off the bus, and reports it if that failed. A controller that is
    /// still on the bus keeps acknowledging frames, so a caller that can't be sure should unplug
    /// the adapter. Returns the control transfers it sent that nobody has taken yet
    /// ([`Transport::take_events`]), for the audit log ([`crate::log_events`]).
    ///
    /// # Errors
    ///
    /// The reset didn't reach the device. The failure carries the same events.
    pub fn close(self) -> Result<Vec<LinkEvent>, ConnectFailure> {
        self.0.close()
    }
}

impl Transport for GsUsb {
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
