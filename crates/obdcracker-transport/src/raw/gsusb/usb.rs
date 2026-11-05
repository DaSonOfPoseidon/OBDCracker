//! What the backend needs from USB, so a fake can stand in for a device in tests.

use std::fmt::Debug;
use std::time::Duration;

use crate::Error;

/// The longest a control transfer may take (the kernel's `gs_usb` driver waits as long).
pub(super) const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
/// The longest a bulk write may take.
pub(super) const BULK_TIMEOUT: Duration = Duration::from_secs(1);

/// One `gs_usb` device's interface: vendor control transfers addressed to the interface, and its two
/// bulk endpoints. Private, and implemented by nothing but the `nusb` layer and a test fake, so
/// the only code that writes a frame is the CAN port behind `RawCan`.
pub(super) trait Usb: Debug {
    /// A vendor request to the interface, with `value` as wValue.
    fn control_out(&mut self, request: u8, value: u16, data: &[u8]) -> Result<(), Error>;

    /// A vendor request from the interface, asking for `length` bytes. Returns what came back,
    /// which may be shorter or longer than asked; the caller checks.
    fn control_in(&mut self, request: u8, value: u16, length: u16) -> Result<Vec<u8>, Error>;

    /// Writes one packet to the bulk OUT endpoint, or fails after [`BULK_TIMEOUT`].
    fn bulk_out(&mut self, data: &[u8]) -> Result<(), Error>;

    /// The next packet from the bulk IN endpoint, `None` once `timeout` has passed with none.
    /// Packets are never lost between calls: the device's frames queue up in the OS meanwhile.
    fn bulk_in(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, Error>;
}
