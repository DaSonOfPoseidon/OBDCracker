//! Which USB device to open: only ones on the list of known `gs_usb` devices, and only one.

use std::fmt;

/// Vendor and product IDs of devices that speak `gs_usb`: Geschwister Schneider and candleLight
/// (`CANable`), and boards with the same firmware. A device not on the list is never opened.
pub(super) const KNOWN: [(u16, u16); 6] = [
    (0x1D50, 0x606F),
    (0x1209, 0x2323),
    (0x1CD2, 0x606F),
    (0x16D0, 0x10B8),
    (0x16D0, 0x0F30),
    (0x1209, 0xCA01),
];

/// A `gs_usb` device that is plugged in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceSummary {
    /// The USB vendor ID.
    pub vendor_id: u16,
    /// The USB product ID.
    pub product_id: u16,
    /// The serial number string, if the device has one, with anything but printable ASCII
    /// replaced: the device wrote it.
    pub serial: Option<String>,
    /// The product name string, cleaned the same way.
    pub product: Option<String>,
}

impl DeviceSummary {
    pub(super) fn new(
        vendor_id: u16,
        product_id: u16,
        serial: Option<&str>,
        product: Option<&str>,
    ) -> Self {
        Self {
            vendor_id,
            product_id,
            serial: serial.map(printable),
            product: product.map(printable),
        }
    }
}

impl fmt::Display for DeviceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.vendor_id, self.product_id)?;
        if let Some(product) = &self.product {
            write!(f, " {product}")?;
        }
        match &self.serial {
            Some(serial) => write!(f, " (serial {serial})"),
            None => f.write_str(" (no serial number)"),
        }
    }
}

// The longest a device-supplied string is shown.
const MAX_SHOWN: usize = 64;

/// A string a device wrote, made safe to print on a terminal: anything but printable ASCII is
/// replaced (an escape sequence in a product string must not reach the user's screen).
pub(super) fn printable(text: &str) -> String {
    text.chars()
        .take(MAX_SHOWN)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Why no single device was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unchosen {
    None,
    NoSuchSerial,
    Many(Vec<DeviceSummary>),
}

/// The one device to open: the only one plugged in, or the one with `serial`.
pub(super) fn choose<T>(
    candidates: Vec<(DeviceSummary, T)>,
    serial: Option<&str>,
) -> Result<T, Unchosen> {
    if candidates.is_empty() {
        return Err(Unchosen::None);
    }
    let wanted = serial.map(printable);
    let mut matching: Vec<(DeviceSummary, T)> = candidates
        .into_iter()
        .filter(|(summary, _)| match &wanted {
            Some(wanted) => summary.serial.as_ref() == Some(wanted),
            None => true,
        })
        .collect();
    match matching.len() {
        0 => Err(Unchosen::NoSuchSerial),
        1 => Ok(matching.remove(0).1),
        _ => Err(Unchosen::Many(
            matching.into_iter().map(|(summary, _)| summary).collect(),
        )),
    }
}
