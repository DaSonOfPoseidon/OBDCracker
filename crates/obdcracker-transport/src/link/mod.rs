//! Byte streams that carry an adapter's command set: USB serial, TCP, and later Bluetooth. A
//! driver such as [`crate::elm::Elm`] runs over any of them.
//!
//! Anyone can implement [`Link`] for their own byte stream, but only a driver in this crate can
//! write to one: [`Link::write_all`] takes a [`Driver`] token that nothing else can make. An
//! adapter turns some of what it's sent into CAN frames, so writing to a link directly would
//! skip the safety policy.
//!
//! ```compile_fail
//! use obdcracker_transport::link::{Driver, Link};
//! fn send_raw(link: &mut impl Link) {
//!     // Driver has a private field, so this doesn't compile.
//!     link.write_all(b"3101FF00\r", Driver(())).unwrap();
//! }
//! ```

use std::io;
use std::time::Duration;

/// Proof that the caller is one of this crate's drivers, which only send approved requests.
/// Nothing outside this crate can make one.
#[derive(Debug)]
pub struct Driver(());

impl Driver {
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// A two-way byte stream to an adapter.
pub trait Link {
    /// Writes every byte, or fails. Only a driver can call it.
    fn write_all(&mut self, bytes: &[u8], driver: Driver) -> io::Result<()>;
    /// Waits up to `timeout` for bytes and reads what has arrived into `buf`. Returns how many
    /// bytes were read: 0 means none arrived in time. A closed stream is an error.
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize>;
    /// How the adapter is connected.
    fn kind(&self) -> LinkKind;
}

impl<L: Link + ?Sized> Link for Box<L> {
    fn write_all(&mut self, bytes: &[u8], driver: Driver) -> io::Result<()> {
        (**self).write_all(bytes, driver)
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        (**self).read(buf, timeout)
    }

    fn kind(&self) -> LinkKind {
        (**self).kind()
    }
}

/// How an adapter is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkKind {
    /// A USB serial port (a USB adapter such as the `OBDLink EX`), or an RS-232 port.
    UsbSerial,
    /// TCP, which for an OBD adapter means Wi-Fi.
    Tcp,
}

impl LinkKind {
    /// A fixed name for logs: `usb-serial` or `tcp`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UsbSerial => "usb-serial",
            Self::Tcp => "tcp",
        }
    }

    /// Whether the adapter is reached over radio. A wireless adapter left plugged in drains the
    /// battery, and anyone in range can connect to it.
    #[must_use]
    pub fn is_wireless(self) -> bool {
        match self {
            Self::UsbSerial => false,
            Self::Tcp => true,
        }
    }
}

#[cfg(feature = "serial")]
mod serial;

#[cfg(feature = "serial")]
pub use serial::SerialLink;
