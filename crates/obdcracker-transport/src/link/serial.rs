use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serial2::SerialPort;

use super::{Driver, Link, LinkKind};

/// A USB serial (or RS-232) port, 8 data bits, no parity, 1 stop bit.
#[derive(Debug)]
pub struct SerialLink {
    port: SerialPort,
}

impl SerialLink {
    /// Opens a port, such as `/dev/ttyUSB0`, `/dev/cu.usbserial-…` or `COM3`, at `baud` bits
    /// per second. `OBDLink` USB adapters use 115200; many ELM327 clones use 38400.
    pub fn open(path: impl AsRef<Path>, baud: u32) -> io::Result<Self> {
        Ok(Self {
            port: SerialPort::open(path, baud)?,
        })
    }

    /// The serial ports this computer has. Not every OS can list them.
    pub fn available_ports() -> io::Result<Vec<PathBuf>> {
        SerialPort::available_ports()
    }
}

impl Link for SerialLink {
    fn write_all(&mut self, bytes: &[u8], _driver: Driver) -> io::Result<()> {
        self.port.write_all(bytes)?;
        self.port.flush()
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
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
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn pair() -> (SerialLink, SerialPort) {
        let (ours, theirs) = SerialPort::pair().unwrap();
        (SerialLink { port: ours }, theirs)
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
        let n = link.read(&mut buf, Duration::from_secs(1)).unwrap();
        assert_eq!(&buf[..n], b"OK\r>");
    }

    #[test]
    fn a_read_with_nothing_to_read_times_out_with_zero_bytes() {
        let (mut link, _adapter) = pair();
        let mut buf = [0; 16];
        let start = std::time::Instant::now();
        assert_eq!(link.read(&mut buf, Duration::from_millis(50)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn is_a_wired_link() {
        let (link, _adapter) = pair();
        assert_eq!(link.kind(), LinkKind::UsbSerial);
        assert!(!link.kind().is_wireless());
    }
}
