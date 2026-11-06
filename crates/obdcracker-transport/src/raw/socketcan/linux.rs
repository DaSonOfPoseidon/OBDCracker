//! The real [`Device`]: a raw SocketCAN socket, and reads of the interface through netlink and
//! sysfs. It sets nothing on the interface; the only things it configures are its own socket's
//! options. See `docs/socketcan.md#what-it-never-does`.

use std::fs::File;
use std::io::{IoSliceMut, Read};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use nix::cmsg_space;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg, send, setsockopt, sockopt};
use socketcan::nl::CanState;
use socketcan::{CanCtrlMode, CanFilter, CanInterface, CanSocket, Socket, SocketOptions};

use super::device::{BusState, Device, Iface, KernelFilter, Modes, Packet};
use super::wire::{ERROR_MASK, FRAME_LEN};
use crate::Error;

/// How long a send may wait for room in the interface's queue.
const SEND_TIMEOUT: Duration = Duration::from_millis(500);
// The kernel's numbers: `ARPHRD_CAN`, and the interface flags `IFF_UP` and `IFF_ECHO`.
const ARPHRD_CAN: u32 = 280;
const IFF_ECHO: u32 = 0x4_0000;
// Longest a sysfs value is read: they are a number and a newline.
const MAX_SYSFS: u64 = 64;

/// One interface and, once opened, a raw socket on it.
#[derive(Debug)]
pub(super) struct LinuxDevice {
    name: String,
    socket: Option<CanSocket>,
    // Room for the one control message a datagram carries: the socket's drop counter.
    control: Vec<u8>,
}

impl LinuxDevice {
    /// The name must already have passed `connect::check_name`: it becomes part of a path.
    pub(super) fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            socket: None,
            control: cmsg_space!(u32),
        }
    }

    fn sysfs(&self, file: &str) -> Result<String, Error> {
        read_sysfs(&format!("/sys/class/net/{}/{file}", self.name))
    }

    fn socket(&self) -> Result<&CanSocket, Error> {
        self.socket
            .as_ref()
            .ok_or_else(|| Error::Adapter("the CAN socket isn't open".to_owned()))
    }
}

fn read_sysfs(path: &str) -> Result<String, Error> {
    let file = File::open(path).map_err(|e| Error::Adapter(format!("can't read {path}: {e}")))?;
    let mut text = String::new();
    let read = file
        .take(MAX_SYSFS + 1)
        .read_to_string(&mut text)
        .map_err(|e| Error::Adapter(format!("can't read {path}: {e}")))?;
    if read as u64 > MAX_SYSFS {
        return Err(Error::Adapter(format!(
            "{path} is longer than it should be"
        )));
    }
    Ok(text)
}

/// A number the kernel prints in decimal and a newline.
pub(super) fn parse_decimal(text: &str) -> Option<u64> {
    let digits = text.strip_suffix('\n')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The interface flags as sysfs prints them: `0x` and hex digits and a newline.
pub(super) fn parse_flags(text: &str) -> Option<u32> {
    let digits = text.strip_suffix('\n')?.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn bus_state(state: CanState) -> BusState {
    match state {
        CanState::ErrorActive => BusState::ErrorActive,
        CanState::ErrorWarning => BusState::ErrorWarning,
        CanState::ErrorPassive => BusState::ErrorPassive,
        CanState::BusOff => BusState::BusOff,
        CanState::Stopped => BusState::Stopped,
        CanState::Sleeping => BusState::Sleeping,
    }
}

fn io(what: &str, e: &std::io::Error) -> Error {
    Error::Adapter(format!("{what}: {e}"))
}

impl Device for LinuxDevice {
    fn describe(&mut self) -> Result<Iface, Error> {
        let name = &self.name;
        let flags = parse_flags(&self.sysfs("flags")?)
            .ok_or_else(|| Error::Adapter(format!("{name}: unreadable interface flags")))?;
        let hardware = parse_decimal(&self.sysfs("type")?)
            .ok_or_else(|| Error::Adapter(format!("{name}: unreadable interface type")))?;
        let interface = CanInterface::open(name)
            .map_err(|e| Error::Adapter(format!("no interface {name}: {e}")))?;
        // A read of the link, not a change: netlink's RTM_GETLINK.
        let details = interface
            .details()
            .map_err(|e| Error::Adapter(format!("can't read {name}'s settings: {e}")))?;
        let can = &details.can;
        Ok(Iface {
            is_can: hardware == u64::from(ARPHRD_CAN),
            up: details.is_up,
            echo: flags & IFF_ECHO != 0,
            state: can.state.map(bus_state),
            bitrate: can
                .bit_timing
                .map(|timing| timing.bitrate)
                .filter(|bitrate| *bitrate != 0),
            modes: can.ctrl_mode.map(|modes| Modes {
                listen_only: modes.has_mode(CanCtrlMode::ListenOnly),
                loopback: modes.has_mode(CanCtrlMode::Loopback),
                presume_ack: modes.has_mode(CanCtrlMode::PresumeAck),
                one_shot: modes.has_mode(CanCtrlMode::OneShot),
            }),
        })
    }

    fn open(&mut self, echo: bool) -> Result<(), Error> {
        let socket = CanSocket::open(&self.name)
            .map_err(|e| io(&format!("can't open a CAN socket on {}", self.name), &e))?;
        // Nothing is received until the transport says what it wants.
        socket
            .set_filter_drop_all()
            .map_err(|e| io("can't set the socket's filters", &e))?;
        socket
            .set_error_filter(ERROR_MASK)
            .map_err(|e| io("can't ask for error frames", &e))?;
        // Frames sent here are looped back to other sockets on this host, which is how the
        // car's other tools (and a simulator in a test) see them.
        socket
            .set_loopback(true)
            .map_err(|e| io("can't set loopback", &e))?;
        socket
            .set_recv_own_msgs(echo)
            .map_err(|e| io("can't set receiving the socket's own frames", &e))?;
        socket
            .set_write_timeout(Some(SEND_TIMEOUT))
            .map_err(|e| io("can't set the send timeout", &e))?;
        setsockopt(&socket, sockopt::RxqOvfl, &1)
            .map_err(|e| Error::Adapter(format!("can't ask for the socket's drop counter: {e}")))?;
        self.socket = Some(socket);
        Ok(())
    }

    fn set_filters(&mut self, filters: &[KernelFilter]) -> Result<(), Error> {
        let socket = self.socket()?;
        let filters: Vec<CanFilter> = filters
            .iter()
            .map(|f| CanFilter::new(f.id, f.mask))
            .collect();
        socket
            .set_filters(&filters)
            .map_err(|e| io("can't set the socket's filters", &e))
    }

    fn send(&mut self, frame: &[u8; 16]) -> Result<(), Error> {
        let fd = self.socket()?.as_raw_fd();
        match send(fd, frame, MsgFlags::empty()) {
            Ok(n) if n == FRAME_LEN => Ok(()),
            Ok(n) => Err(Error::Adapter(format!(
                "the kernel took {n} bytes of a {FRAME_LEN}-byte frame"
            ))),
            Err(Errno::EAGAIN) => Err(Error::Adapter(format!(
                "the interface's queue stayed full for {SEND_TIMEOUT:?}"
            ))),
            Err(e) => Err(Error::Adapter(e.to_string())),
        }
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Packet>, Error> {
        let started = Instant::now();
        let Some(socket) = self.socket.as_ref() else {
            return Err(Error::Adapter("the CAN socket isn't open".to_owned()));
        };
        let fd = socket.as_raw_fd();
        loop {
            let left = timeout.saturating_sub(started.elapsed());
            // Whole milliseconds, rounded up: poll never returns early, and a wait of 0 asks
            // only what is there.
            let millis = i32::try_from(left.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
            let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
            match poll(
                &mut fds,
                PollTimeout::try_from(millis).unwrap_or(PollTimeout::MAX),
            ) {
                Ok(0) => {
                    if left.is_zero() || started.elapsed() >= timeout {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(_) => {}
                Err(Errno::EINTR) => {
                    if started.elapsed() >= timeout {
                        return Ok(None);
                    }
                    continue;
                }
                Err(e) => return Err(Error::Adapter(format!("waiting for a frame: {e}"))),
            }
            let mut buffer = [0u8; FRAME_LEN];
            let mut io_slices = [IoSliceMut::new(&mut buffer)];
            // MSG_TRUNC makes the length the datagram's real one, so a longer frame (CAN FD) is
            // seen as longer rather than cut to fit.
            let received = recvmsg::<()>(
                fd,
                &mut io_slices,
                Some(&mut self.control),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            );
            let message = match received {
                Ok(message) => message,
                Err(Errno::EAGAIN | Errno::EINTR) => {
                    if started.elapsed() >= timeout {
                        return Ok(None);
                    }
                    continue;
                }
                Err(e) => return Err(Error::Adapter(format!("reading a frame: {e}"))),
            };
            if message.bytes != FRAME_LEN {
                return Err(Error::Adapter(format!(
                    "the kernel delivered a frame of {} bytes, not {FRAME_LEN}",
                    message.bytes
                )));
            }
            let mut dropped = 0;
            let controls = message
                .cmsgs()
                .map_err(|e| Error::Adapter(format!("reading the socket's drop counter: {e}")))?;
            for control in controls {
                if let ControlMessageOwned::RxqOvfl(count) = control {
                    dropped = count;
                }
            }
            return Ok(Some(Packet {
                frame: buffer.to_vec(),
                dropped,
            }));
        }
    }

    fn tx_packets(&mut self) -> Result<u64, Error> {
        parse_decimal(&self.sysfs("statistics/tx_packets")?)
            .ok_or_else(|| Error::Adapter(format!("{}: unreadable transmit counter", self.name)))
    }
}
