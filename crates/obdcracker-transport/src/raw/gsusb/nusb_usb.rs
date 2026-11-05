//! The real USB layer, on `nusb`: pure Rust, with no libusb, on Linux, Windows and macOS.

use std::fmt;
use std::time::Duration;

use nusb::descriptors::TransferType;
use nusb::transfer::{
    Buffer, Bulk, ControlIn, ControlOut, ControlType, Direction, In, Out, Recipient, TransferError,
};
use nusb::{Device, DeviceInfo, Endpoint, ErrorKind, Interface, MaybeFuture};

use super::usb::{BULK_TIMEOUT, CONTROL_TIMEOUT, Usb};
use crate::Error;

// Every gs_usb device has its one vendor interface at number 0.
const INTERFACE: u8 = 0;
// Transfers kept submitted on the IN endpoint, so the OS queues the device's frames while the
// host is busy elsewhere.
const PENDING_IN: usize = 16;

pub(super) struct NusbUsb {
    interface: Interface,
    ep_in: Endpoint<Bulk, In>,
    ep_out: Endpoint<Bulk, Out>,
    in_len: usize,
}

impl fmt::Debug for NusbUsb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NusbUsb")
    }
}

impl NusbUsb {
    /// Opens the device and claims its interface. Never detaches a kernel driver: a device the
    /// Linux `gs_usb` driver holds is somebody else's (use `SocketCAN` for it).
    pub(super) fn open(info: &DeviceInfo) -> Result<Self, Error> {
        let device: Device = info
            .open()
            .wait()
            .map_err(|e| Error::Adapter(open_error_text(e.kind(), &e.to_string())))?;
        let interface = device
            .claim_interface(INTERFACE)
            .wait()
            .map_err(|e| Error::Adapter(open_error_text(e.kind(), &e.to_string())))?;
        let (mut ep_in_addr, mut ep_out_addr) = (None, None);
        for endpoint in interface
            .descriptor()
            .ok_or_else(|| Error::Adapter("the device has no interface 0 descriptor".to_owned()))?
            .endpoints()
        {
            if endpoint.transfer_type() == TransferType::Bulk {
                let slot = match endpoint.direction() {
                    Direction::In => &mut ep_in_addr,
                    Direction::Out => &mut ep_out_addr,
                };
                slot.get_or_insert(endpoint.address());
            }
        }
        let (Some(in_addr), Some(out_addr)) = (ep_in_addr, ep_out_addr) else {
            return Err(Error::Adapter(
                "the device's interface 0 has no bulk IN and OUT endpoints, so it isn't a gs_usb \
                 device"
                    .to_owned(),
            ));
        };
        let io = |e: nusb::Error| Error::Adapter(format!("can't open the bulk endpoints: {e}"));
        let ep_in = interface.endpoint::<Bulk, In>(in_addr).map_err(io)?;
        let ep_out = interface.endpoint::<Bulk, Out>(out_addr).map_err(io)?;
        let in_len = ep_in.max_packet_size();
        if in_len == 0 {
            return Err(Error::Adapter(
                "the bulk IN endpoint has no packet size".to_owned(),
            ));
        }
        Ok(Self {
            interface,
            ep_in,
            ep_out,
            in_len,
        })
    }
}

/// What to tell the user when the device or its interface can't be opened.
pub(super) fn open_error_text(kind: ErrorKind, detail: &str) -> String {
    match kind {
        ErrorKind::Busy => "the device is in use by another driver or program. On Linux the \
             kernel's gs_usb driver holds it whenever that is loaded; this backend never detaches \
             a kernel driver, so use --socketcan with the interface it creates, or unload the \
             driver (`sudo rmmod gs_usb`)"
            .to_owned(),
        ErrorKind::PermissionDenied => format!(
            "no permission to open the USB device ({detail}). On Linux add a udev rule for it \
             (docs/install.md); on Windows the device needs the WinUSB driver"
        ),
        ErrorKind::Disconnected => "the USB device was unplugged".to_owned(),
        _ => format!(
            "can't open the USB device ({detail}). On Windows it needs the WinUSB driver \
             (docs/install.md)"
        ),
    }
}

fn transfer_error(what: &str, e: TransferError) -> Error {
    Error::Adapter(match e {
        TransferError::Disconnected => "the USB device was unplugged".to_owned(),
        other => format!("{what}: {other}"),
    })
}

impl Usb for NusbUsb {
    fn control_out(&mut self, request: u8, value: u16, data: &[u8]) -> Result<(), Error> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Interface,
                    request,
                    value,
                    index: u16::from(INTERFACE),
                    data,
                },
                CONTROL_TIMEOUT,
            )
            .wait()
            .map_err(|e| transfer_error("USB control transfer", e))
    }

    fn control_in(&mut self, request: u8, value: u16, length: u16) -> Result<Vec<u8>, Error> {
        self.interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Interface,
                    request,
                    value,
                    index: u16::from(INTERFACE),
                    length,
                },
                CONTROL_TIMEOUT,
            )
            .wait()
            .map_err(|e| transfer_error("USB control transfer", e))
    }

    fn bulk_out(&mut self, data: &[u8]) -> Result<(), Error> {
        let done = self
            .ep_out
            .transfer_blocking(Buffer::from(data), BULK_TIMEOUT);
        done.status
            .map_err(|e| transfer_error("USB bulk write", e))?;
        if done.actual_len != data.len() {
            return Err(Error::Adapter(format!(
                "USB bulk write sent {} of {} bytes",
                done.actual_len,
                data.len()
            )));
        }
        Ok(())
    }

    fn bulk_in(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, Error> {
        while self.ep_in.pending() < PENDING_IN {
            let buffer = self.ep_in.allocate(self.in_len);
            self.ep_in.submit(buffer);
        }
        let Some(done) = self.ep_in.wait_next_complete(timeout) else {
            return Ok(None);
        };
        done.status
            .map_err(|e| transfer_error("USB bulk read", e))?;
        let mut buffer = done.buffer;
        let len = done.actual_len.min(buffer.len());
        let packet = buffer[..len].to_vec();
        buffer.clear();
        self.ep_in.submit(buffer);
        Ok(Some(packet))
    }
}
