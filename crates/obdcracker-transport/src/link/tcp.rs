use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{Driver, Link, LinkKind, WRITE_TIMEOUT};

/// A TCP connection, as Wi-Fi adapters offer (often at `192.168.0.10:35000`).
#[derive(Debug)]
pub struct TcpLink {
    stream: TcpStream,
}

impl TcpLink {
    /// Connects to `addr`, `host:port` or `ip:port`, within `timeout` in all: looking the host
    /// up, then trying each address it has.
    pub fn connect(addr: &str, timeout: Duration) -> io::Result<Self> {
        // Capped, so a huge timeout can't overflow the clock.
        let timeout = timeout.min(Duration::from_secs(3600));
        let deadline = Instant::now() + timeout;
        let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
        for addr in resolve_with(addr, timeout, |host| {
            host.to_socket_addrs().map(Iterator::collect)
        })? {
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Err(io::ErrorKind::TimedOut.into());
            };
            match Self::connect_one(addr, left) {
                Ok(link) => return Ok(link),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn connect_one(addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout.max(Duration::from_millis(1)))?;
        // Commands are a few bytes each; send them at once.
        stream.set_nodelay(true)?;
        // A peer that stops reading would otherwise block a write forever once buffers fill.
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(Self { stream })
    }
}

// The addresses `addr` names: an `ip:port` as it is, and a `host:port` looked up with `lookup`
// on another thread, so a lookup that hangs can't hold the caller past `timeout`. The thread of
// a lookup that runs out ends whenever the lookup does.
fn resolve_with(
    addr: &str,
    timeout: Duration,
    lookup: impl FnOnce(String) -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(addr) = addr.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let (tx, rx) = mpsc::channel();
    let host = addr.to_owned();
    std::thread::spawn(move || {
        // The receiver may have given up already.
        let _ = tx.send(lookup(host));
    });
    rx.recv_timeout(timeout).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("looking up {addr} took too long"),
        )
    })?
}

impl Link for TcpLink {
    fn write_all(&mut self, bytes: &[u8], _driver: Driver) -> io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration, _driver: Driver) -> io::Result<usize> {
        // A zero timeout means "block forever" to the OS, so wait at least a millisecond.
        self.stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        match self.stream.read(buf) {
            Ok(0) if !buf.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => Ok(n),
            // Unix reports a read timeout as WouldBlock, Windows as TimedOut.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    fn kind(&self) -> LinkKind {
        LinkKind::Tcp
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Instant;

    use super::*;

    fn pair() -> (TcpLink, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let link = TcpLink::connect(
            &listener.local_addr().unwrap().to_string(),
            Duration::from_secs(1),
        )
        .unwrap();
        let (adapter, _) = listener.accept().unwrap();
        (link, adapter)
    }

    #[test]
    fn writes_reach_the_other_end() {
        let (mut link, mut adapter) = pair();
        link.write_all(b"ATZ\r", Driver::new()).unwrap();
        let mut buf = [0; 4];
        adapter.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ATZ\r");
    }

    #[test]
    fn reads_what_arrived() {
        let (mut link, mut adapter) = pair();
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
        let start = Instant::now();
        assert_eq!(
            link.read(&mut buf, Duration::from_millis(50), Driver::new())
                .unwrap(),
            0
        );
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert_eq!(
            link.read(&mut buf, Duration::ZERO, Driver::new()).unwrap(),
            0
        );
    }

    #[test]
    fn a_hostname_is_looked_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        TcpLink::connect(&format!("localhost:{port}"), Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn a_slow_lookup_counts_against_the_timeout() {
        let start = Instant::now();
        let err = resolve_with("adapter.local:35000", Duration::from_millis(100), |_| {
            std::thread::sleep(Duration::from_secs(2));
            Ok(Vec::new())
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn an_address_needs_no_lookup() {
        let addrs = resolve_with("192.168.0.10:35000", Duration::ZERO, |_| {
            panic!("looked up an IP address")
        })
        .unwrap();
        assert_eq!(addrs, ["192.168.0.10:35000".parse().unwrap()]);
    }

    #[test]
    fn writes_have_a_deadline() {
        // A peer that stops reading would otherwise block a write forever once buffers fill.
        let (link, _adapter) = pair();
        assert_eq!(link.stream.write_timeout().unwrap(), Some(WRITE_TIMEOUT));
    }

    #[test]
    fn a_closed_connection_is_an_error() {
        let (mut link, adapter) = pair();
        drop(adapter);
        let mut buf = [0; 16];
        assert_eq!(
            link.read(&mut buf, Duration::from_secs(1), Driver::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn nothing_listening_is_an_error() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(TcpLink::connect(&addr.to_string(), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn is_a_wireless_link() {
        let (link, _adapter) = pair();
        assert_eq!(link.kind(), LinkKind::Tcp);
        assert!(link.kind().is_wireless());
    }
}
