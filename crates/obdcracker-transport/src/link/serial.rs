use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serial2::SerialPort;

use super::{Driver, Link, LinkKind, WRITE_TIMEOUT};

/// A USB serial (or RS-232) port, 8 data bits, no parity, 1 stop bit.
#[derive(Debug)]
pub struct SerialLink {
    port: SerialPort,
    baud: u32,
}

impl SerialLink {
    /// Opens a port, such as `/dev/ttyUSB0`, `/dev/cu.usbserial-…` or `COM3`, at `baud` bits
    /// per second. `OBDLink` USB adapters use 115200; many ELM327 clones use 38400.
    pub fn open(path: impl AsRef<Path>, baud: u32) -> io::Result<Self> {
        let mut port = SerialPort::open(path, baud)?;
        // An adapter holding off the host could otherwise block a write forever.
        port.set_write_timeout(WRITE_TIMEOUT)?;
        Ok(Self { port, baud })
    }

    /// The serial ports this computer has. Not every OS can list them.
    pub fn available_ports() -> io::Result<Vec<PathBuf>> {
        SerialPort::available_ports()
    }
}

/// Why [`find_adapter`] and [`find_adapter_in`] chose no port.
#[derive(Debug)]
#[non_exhaustive]
pub enum FindAdapterError {
    /// This computer's serial ports couldn't be listed.
    List(io::Error),
    /// No port looks like a USB adapter.
    NotFound,
    /// Several ports look like USB adapters, sorted. Pick one by name.
    Many(Vec<PathBuf>),
}

impl fmt::Display for FindAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List(e) => write!(f, "can't list serial ports: {e}"),
            Self::NotFound => f.write_str("no USB serial adapter found"),
            Self::Many(ports) => {
                let names: Vec<_> = ports.iter().map(|p| p.display().to_string()).collect();
                write!(f, "found {} adapters ({})", ports.len(), names.join(", "))
            }
        }
    }
}

impl std::error::Error for FindAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::List(e) => Some(e),
            _ => None,
        }
    }
}

/// Finds the serial port of the one USB adapter plugged in, for [`SerialLink::open`].
///
/// Ports that can't be an adapter are ignored: on Linux only `ttyUSB*` and `ttyACM*` count, on
/// macOS only the `cu.*` side of `usbserial`, `usbmodem`, `SLAB_USBtoUART` and `wchusbserial`
/// devices, so built-in UARTs and Bluetooth ports are never picked. Windows lists only COM names,
/// which can't tell USB from built-in or Bluetooth ports, so every COM port counts there and a
/// lone built-in port would be chosen; the ELM initialization then fails on it. Nothing is sent
/// to find a port: it is chosen by name alone.
///
/// # Errors
///
/// [`FindAdapterError::NotFound`] when no port qualifies, [`FindAdapterError::Many`] when more
/// than one does, and [`FindAdapterError::List`] when the ports can't be listed.
pub fn find_adapter() -> Result<PathBuf, FindAdapterError> {
    find_adapter_in(SerialLink::available_ports().map_err(FindAdapterError::List)?)
}

/// The same choice as [`find_adapter`] over a given list of ports, such as one from
/// [`SerialLink::available_ports`]. Duplicates count once.
///
/// # Errors
///
/// [`FindAdapterError::NotFound`] or [`FindAdapterError::Many`], as for [`find_adapter`].
pub fn find_adapter_in(ports: Vec<PathBuf>) -> Result<PathBuf, FindAdapterError> {
    let mut found = adapter_ports(ports, Os::current());
    match found.len() {
        0 => Err(FindAdapterError::NotFound),
        1 => Ok(found.remove(0)),
        _ => Err(FindAdapterError::Many(found)),
    }
}

#[derive(Clone, Copy)]
enum Os {
    Linux,
    Apple,
    Windows,
    Other,
}

impl Os {
    fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Apple
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

// Takes the OS as a value so every OS's rule is tested on every OS.
fn adapter_ports(ports: Vec<PathBuf>, os: Os) -> Vec<PathBuf> {
    let mut kept: Vec<PathBuf> = ports
        .into_iter()
        .filter(|port| {
            let name = port
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            match os {
                Os::Linux => name.starts_with("ttyUSB") || name.starts_with("ttyACM"),
                // The `tty.*` twin of each device waits for a carrier signal when opened.
                Os::Apple => name.strip_prefix("cu.").is_some_and(|rest| {
                    ["usbserial", "usbmodem", "SLAB_USBtoUART", "wchusbserial"]
                        .iter()
                        .any(|prefix| rest.starts_with(prefix))
                }),
                Os::Windows | Os::Other => true,
            }
        })
        .collect();
    kept.sort();
    kept.dedup();
    kept
}

impl Link for SerialLink {
    fn write_all(&mut self, bytes: &[u8], _driver: Driver) -> io::Result<()> {
        // No flush: it waits for the OS to finish transmitting, with no timeout, so an adapter
        // that stops draining could block it forever. The adapter's answer shows the line got
        // there.
        self.port.write_all(bytes)
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration, _driver: Driver) -> io::Result<usize> {
        self.port.set_read_timeout(timeout)?;
        match self.port.read(buf) {
            // A port with nothing more to read has gone, such as an unplugged adapter.
            Ok(0) if !buf.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn kind(&self) -> LinkKind {
        LinkKind::UsbSerial
    }

    fn byte_rate(&self) -> Option<u32> {
        // 10 bits a byte: a start bit, 8 data bits and a stop bit.
        Some(self.baud / 10)
    }
}

#[cfg(test)]
mod find_tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn linux_keeps_usb_and_acm_ports_only() {
        let ports = paths(&[
            "/dev/ttyS0",
            "/dev/ttyS4",
            "/dev/ttyUSB0",
            "/dev/ttyACM1",
            "/dev/ttyAMA0",
        ]);
        assert_eq!(
            adapter_ports(ports, Os::Linux),
            paths(&["/dev/ttyACM1", "/dev/ttyUSB0"])
        );
    }

    #[test]
    fn macos_keeps_the_cu_side_of_usb_devices_only() {
        let ports = paths(&[
            "/dev/tty.usbserial-A1",
            "/dev/cu.usbserial-A1",
            "/dev/tty.usbmodem14101",
            "/dev/cu.usbmodem14101",
            "/dev/cu.Bluetooth-Incoming-Port",
            "/dev/cu.debug-console",
        ]);
        assert_eq!(
            adapter_ports(ports, Os::Apple),
            paths(&["/dev/cu.usbmodem14101", "/dev/cu.usbserial-A1"])
        );
    }

    #[test]
    fn macos_knows_the_common_usb_serial_chips() {
        let ports = paths(&["/dev/cu.SLAB_USBtoUART", "/dev/cu.wchusbserial1410"]);
        assert_eq!(adapter_ports(ports, Os::Apple).len(), 2);
    }

    #[test]
    fn windows_keeps_every_port_sorted() {
        assert_eq!(
            adapter_ports(paths(&["COM3", "COM1"]), Os::Windows),
            paths(&["COM1", "COM3"])
        );
    }

    #[test]
    fn other_systems_keep_every_port() {
        let ports = paths(&["/dev/x", "/dev/y"]);
        assert_eq!(adapter_ports(ports, Os::Other).len(), 2);
    }

    // A port the current OS's rule keeps, so these hold on whichever OS runs them.
    fn usb_port(n: u32) -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            format!("COM{n}")
        } else if cfg!(target_os = "macos") {
            format!("/dev/cu.usbserial-{n}")
        } else {
            format!("/dev/ttyUSB{n}")
        })
    }

    #[test]
    fn no_ports_is_not_found() {
        assert!(matches!(
            find_adapter_in(Vec::new()),
            Err(FindAdapterError::NotFound)
        ));
    }

    #[test]
    #[cfg(not(windows))]
    fn ports_that_cannot_be_adapters_are_not_found() {
        assert!(matches!(
            find_adapter_in(paths(&["/dev/ttyS0", "/dev/cu.debug-console"])),
            Err(FindAdapterError::NotFound)
        ));
    }

    #[test]
    fn one_port_is_chosen() {
        assert_eq!(find_adapter_in(vec![usb_port(7)]).unwrap(), usb_port(7));
    }

    #[test]
    fn two_ports_are_many_and_sorted() {
        match find_adapter_in(vec![usb_port(9), usb_port(2)]) {
            Err(FindAdapterError::Many(ports)) => assert_eq!(ports, [usb_port(2), usb_port(9)]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_port_listed_twice_is_one_port() {
        assert_eq!(
            find_adapter_in(vec![usb_port(1), usb_port(1)]).unwrap(),
            usb_port(1)
        );
    }

    #[test]
    fn errors_say_what_happened() {
        let list = FindAdapterError::List(io::Error::other("boom"));
        assert_eq!(list.to_string(), "can't list serial ports: boom");
        assert!(std::error::Error::source(&list).is_some());
        assert_eq!(
            FindAdapterError::NotFound.to_string(),
            "no USB serial adapter found"
        );
        assert!(std::error::Error::source(&FindAdapterError::NotFound).is_none());
        let many = FindAdapterError::Many(paths(&["/dev/a", "/dev/b"]));
        assert_eq!(many.to_string(), "found 2 adapters (/dev/a, /dev/b)");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn pair() -> (SerialLink, SerialPort) {
        let (ours, theirs) = SerialPort::pair().unwrap();
        (
            SerialLink {
                port: ours,
                baud: 115_200,
            },
            theirs,
        )
    }

    #[test]
    fn writes_reach_the_other_end() {
        let (mut link, mut adapter) = pair();
        link.write_all(b"ATZ\r", Driver::new()).unwrap();
        adapter.set_read_timeout(Duration::from_secs(1)).unwrap();
        let mut buf = [0; 16];
        let n = adapter.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ATZ\r");
    }

    #[test]
    fn reads_what_arrived() {
        let (mut link, adapter) = pair();
        adapter.write_all(b"OK\r>").unwrap();
        let mut buf = [0; 16];
        let n = link
            .read(&mut buf, Duration::from_secs(1), Driver::new())
            .unwrap();
        assert_eq!(&buf[..n], b"OK\r>");
    }

    #[test]
    fn a_read_with_nothing_to_read_times_out_with_zero_bytes() {
        let (mut link, _adapter) = pair();
        let mut buf = [0; 16];
        let start = std::time::Instant::now();
        assert_eq!(
            link.read(&mut buf, Duration::from_millis(50), Driver::new())
                .unwrap(),
            0
        );
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn is_a_wired_link() {
        let (link, _adapter) = pair();
        assert_eq!(link.kind(), LinkKind::UsbSerial);
        assert!(!link.kind().is_wireless());
    }
}
