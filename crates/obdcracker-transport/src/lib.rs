//! Adapter backends. Every send takes a request approved by `obdcracker-safety`, so no backend can put
//! anything on the bus that the policy hasn't allowed.

use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use obdcracker_safety::{Approved, ApprovedFlowControl, SupplyVoltage};

mod audit;
pub mod discover;
mod dry_run;
pub mod dtc;
pub mod elm;
mod exchange;
pub mod fingerprint;
pub mod gateway;
#[cfg(feature = "serde")]
pub mod json;
pub mod link;
mod mock;
/// The gs_usb and SocketCAN backends (M6) are its users. Crate-private, so no importer can put a
/// frame on the bus:
///
/// ```compile_fail,E0603
/// use obdcracker_transport::raw::CanPort;
/// ```
#[cfg_attr(
    not(any(
        test,
        feature = "gsusb",
        all(feature = "socketcan", target_os = "linux")
    )),
    expect(dead_code, reason = "no backend uses it without a feature")
)]
mod raw;
pub mod read_dids;
pub mod scan;
mod session;
pub mod sweep;
pub mod tp20;
pub mod voltage;

pub use audit::{Audited, log_events, log_failure};
pub use dry_run::DryRun;
pub use exchange::{Expect, Timing, exchange};
pub use mock::Mock;
#[cfg(feature = "gsusb")]
pub use raw::gsusb;
#[cfg(all(feature = "socketcan", target_os = "linux"))]
pub use raw::socketcan;
pub use session::{ExtendedSession, Left, S3, SessionError};

/// A reply from one module: the CAN ID it came from and its reassembled payload.
///
/// Build one with [`Response::new`]; the struct is `#[non_exhaustive]` so it can gain fields.
/// Two replies are equal when their `source` and `payload` are: [`Response::bus_time`] is a
/// measurement of when the reply was heard, not part of what was said.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The CAN ID the reply came from.
    #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
    pub source: u32,
    /// The reassembled reply, service ID first.
    #[cfg_attr(feature = "serde", serde(with = "crate::json::bytes"))]
    pub payload: Vec<u8>,
    /// A time no later than when the reply's last frame left the bus, if the transport can bound
    /// it, else `None`. Never later: a caller trusting a module's state from this time (such as
    /// [`ExtendedSession`] timing S3) would otherwise trust it for too long. A transport that
    /// only knows when the reply reached the host leaves it `None`. See
    /// [`docs/elm327.md#when-a-reply-left-the-bus`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#when-a-reply-left-the-bus).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub bus_time: Option<Instant>,
}

impl Response {
    /// A reply with no bus time.
    #[must_use]
    pub fn new(source: u32, payload: Vec<u8>) -> Self {
        Self {
            source,
            payload,
            bus_time: None,
        }
    }

    /// This reply with [`Response::bus_time`] set.
    #[must_use]
    pub fn at_bus_time(mut self, bus_time: Option<Instant>) -> Self {
        self.bus_time = bus_time;
        self
    }
}

impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.payload == other.payload
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
/// Why a send or receive failed.
pub enum Error {
    /// No reply arrived in time.
    Timeout,
    /// The module said it was busy (response-pending, NRC 0x78) but didn't answer before its
    /// wait ended: P2* ran out, it went over [`Timing::max_pending`], or the adapter stopped
    /// listening (a plain ELM327 may not wait P2*). Returned by [`exchange`] for one module.
    StillPending,
    /// The adapter or its driver failed.
    Adapter(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response before the timeout"),
            Self::StillPending => f.write_str(
                "the module said it was busy (response-pending) but didn't answer in time",
            ),
            Self::Adapter(message) => write!(f, "adapter error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// A connection to the bus through one adapter.
pub trait Transport {
    /// Sends one approved request. Unapproved bytes can't be passed in.
    fn send(&mut self, request: &Approved) -> Result<(), Error>;
    /// Waits up to `timeout` for the next reply.
    fn recv(&mut self, timeout: Duration) -> Result<Response, Error>;
    /// Like [`Transport::recv`], for a backend that puts frames on the bus while it receives:
    /// the ISO-TP flow control frames that a multi-frame reply needs ([`ApprovedFlowControl`]).
    /// The backend **must** call `before_send` with each token before it sends that frame, and
    /// send it only if that returns `Ok`. [`Audited`] logs the frame there, so an
    /// unwritable log stops it, as for a request. Whatever `before_send` returns as an error
    /// must be returned as the error of this call.
    ///
    /// The default ignores `before_send` and calls [`Transport::recv`], for a transport that
    /// sends nothing under `recv`, such as the ELM327 driver, whose adapter sends its own flow
    /// control. A transport that wraps another must forward this to it.
    ///
    /// # Errors
    ///
    /// As for [`Transport::recv`], or the error `before_send` returned.
    fn recv_logged(
        &mut self,
        timeout: Duration,
        before_send: &mut dyn FnMut(&ApprovedFlowControl) -> Result<(), Error>,
    ) -> Result<Response, Error> {
        let _ = before_send;
        self.recv(timeout)
    }
    /// With `Some(wait)`, waits up to `wait` for each reply, or as near to it as the adapter
    /// can, until called again with `None`, which restores the usual wait. An adapter that
    /// learns shorter waits from how fast modules answer (the ELM327's adaptive timing) stops
    /// doing so, so a module slow to answer isn't missed. Sends nothing on the bus.
    ///
    /// Returns how long the adapter now waits for a reply (`None` after `None`), which can be
    /// less than `wait` (an ELM327 waits at most about 1 s) or more (it never waits less than
    /// usual). The default does nothing and returns `wait`, for a transport that waits for
    /// whatever timeout `recv` is given.
    ///
    /// # Errors
    ///
    /// The adapter refused the setting or failed.
    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        Ok(wait)
    }
    /// Whether replies to one broadcast can overflow the adapter, so a caller that wants several
    /// ECUs' long (multi-frame) replies should ask each ECU by its own request ID instead. True
    /// for an ELM327-compatible adapter whose driver paces its replies ([`elm::Elm`]): the ELM327's
    /// 512-byte buffer can't hold eight ECUs' replies at once on a slow link. The default is
    /// false, for a transport that reads every reply as it arrives.
    ///
    /// `scan`, `fingerprint` and [`fingerprint::read_vin`] use it to choose between a broadcast
    /// and one physical request per ECU. A caller that broadcasts a long request of its own
    /// (such as mode 09 PID 02) should check it too, and ask each ECU by its own request ID
    /// where it is true: the ECUs' replies can overflow the adapter and fail with `BUFFER FULL`.
    /// A wrapper of a `Transport` must forward it.
    fn broadcasts_can_overflow(&self) -> bool {
        false
    }
    /// The voltage the adapter sees on the OBD port, for [`obdcracker_safety::Precondition`]s
    /// and the low-battery guard. Sends nothing on the bus: an adapter-local
    /// command, such as the ELM327's `ATRV`, that [`Audited`] logs.
    ///
    /// The default is [`SupplyVoltage::Unknown`], for a transport that can't measure it
    /// (`gs_usb`, SocketCAN, a dry run). An answer that isn't one clean voltage is `Unknown`
    /// too, not an error, and `Unknown` never passes a precondition. A transport that wraps
    /// another must forward this.
    ///
    /// # Errors
    ///
    /// The adapter failed or didn't answer. A caller that only wants to know the voltage may
    /// treat that as `Unknown`; the adapter's next call fails too if it can no longer be trusted.
    fn supply_voltage(&mut self) -> Result<SupplyVoltage, Error> {
        Ok(SupplyVoltage::Unknown)
    }
    /// What the adapter did besides carrying requests and replies since this was last called,
    /// oldest first, for the audit log ([`Audited`] takes them after every call). The default
    /// has none.
    fn take_events(&mut self) -> Vec<LinkEvent> {
        Vec::new()
    }
    /// Reads whatever is left of the last request's replies, so it can be reported
    /// ([`LinkEvent::Unread`]) before the session ends: [`Audited`] calls it when dropped. Sends
    /// nothing on the bus. The default does nothing.
    ///
    /// # Errors
    ///
    /// The adapter failed while finishing the request.
    fn settle(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Something an adapter did besides carrying a request or a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEvent {
    /// A command to the adapter itself, such as an ELM327's `AT SH 7E0`, and the lines it
    /// answered with (as many as were read, if it failed). Commands never reach the bus.
    Command {
        /// When it was sent.
        at: SystemTime,
        /// The command, as written.
        command: String,
        /// Its answer's lines, such as `OK`.
        answer: Vec<String>,
    },
    /// A line the adapter printed for a request after nothing read it any more, dropped before
    /// the next request: such as a late reply, or one from a module nobody waited for.
    Unread {
        /// When the driver read it from the link, which may be before it was dropped.
        at: SystemTime,
        /// The line as the adapter printed it.
        line: String,
    },
    /// A status line the adapter printed for a request instead of a reply, such as an ELM327's
    /// `NO DATA` when nothing answered. One that fails a request the caller is waiting on, such
    /// as `CAN ERROR`, is returned as an error instead.
    Status {
        /// When the driver read it from the link.
        at: SystemTime,
        /// The line as the adapter printed it.
        line: String,
    },
    /// A CAN frame an adapter driver wrote itself, or read as a module's flow control, while it
    /// sent a request in segments (`docs/design/elm-caf0-segmenting.md`, section 9). The request
    /// is logged once, as the payload; these show the frames that went out for it.
    Frame {
        /// When the frame's carriage return was written, or when the driver read the frame.
        at: SystemTime,
        /// Whether the driver wrote the frame (it may be on the bus) rather than read it.
        sent: bool,
        /// The frame's CAN ID.
        id: u32,
        /// The frame's 8 data bytes, as written or read.
        data: Vec<u8>,
    },
    /// A setting of the driver that changes how it sends requests, such as forcing a segmenting
    /// path on an adapter that has its own. Logged so a log can say how a frame was sent.
    Setting {
        /// When it was set.
        at: SystemTime,
        /// The setting's name, such as `segment-on-stn`.
        name: String,
        /// What it was set to, such as `on`.
        value: String,
    },
    /// How many events, or lines the adapter printed, were dropped because there was no room to
    /// keep them until something took them.
    Lost(usize),
}

/// Bytes as space-separated upper-case hex, the way CAN tools print them: `02 09 02`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
