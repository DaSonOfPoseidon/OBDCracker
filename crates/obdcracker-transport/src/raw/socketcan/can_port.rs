//! A SocketCAN interface as a [`CanPort`]: frames in and out of a raw socket, with the driver's
//! echo (or, without one, its transmit counter) confirming each frame sent.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use super::device::{Device, KernelFilter, Packet};
use super::wire::{self, Body, BusError};
use crate::raw::port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};
use crate::{Error, LinkEvent};

/// How long a frame may go unconfirmed before the port stops. A classic frame takes well under a
/// millisecond on the bus, so this covers the driver's queue with room to spare.
pub(super) const TX_CONFIRM_TIMEOUT: Duration = Duration::from_millis(500);

// Received frames kept while a write waits for its confirmation. Past it the rest are dropped,
// and a receive overrun is reported when they would have been read.
const MAX_QUEUED: usize = 1024;
// Packets read after a deadline has passed, so a read that must not wait still sees what is
// already queued, but a flood can't keep it going.
const MAX_POLLED_PAST_DEADLINE: usize = 4096;
// The most notes kept for the audit log between `take_events` calls.
const MAX_EVENTS: usize = 64;
const LONGEST_WAIT: Duration = Duration::from_secs(3600);
// Without a driver echo the transmit counter is read this often while a write waits.
const COUNTER_STEP: Duration = Duration::from_micros(200);

// The frame a write is waiting to see come back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    id: u32,
    extended: bool,
    data: [u8; 8],
}

/// One SocketCAN interface. See `docs/socketcan.md`.
#[derive(Debug)]
pub(super) struct SocketCanPort<D: Device> {
    dev: D,
    // The session may never write. Fixed when the port is made.
    listen_only: bool,
    // The driver echoes each frame once it has gone out, so the socket can see it come back.
    echo: bool,
    // Why the port stopped for good. Nothing more is written or read after.
    broken: Option<String>,
    // What the transport asked for, which the port also applies itself.
    filters: Vec<Filter>,
    // The ID the kernel filter lets through besides `filters`, to see an echo come back.
    echo_filter: Option<KernelFilter>,
    queue: VecDeque<PortEvent>,
    lost: bool,
    in_flight: Option<InFlight>,
    last_dropped: u32,
    events: Vec<LinkEvent>,
    lost_events: usize,
}

impl<D: Device> SocketCanPort<D> {
    pub(super) fn new(dev: D, listen_only: bool, echo: bool) -> Self {
        Self {
            dev,
            listen_only,
            echo,
            broken: None,
            filters: Vec::new(),
            echo_filter: None,
            queue: VecDeque::new(),
            lost: false,
            in_flight: None,
            last_dropped: 0,
            events: Vec::new(),
            lost_events: 0,
        }
    }

    /// Adds a status line to what the audit log gets.
    pub(super) fn status(&mut self, line: String) {
        self.push(LinkEvent::Status {
            at: SystemTime::now(),
            line,
        });
    }

    fn note(&mut self, command: String, answer: String) {
        self.push(LinkEvent::Command {
            at: SystemTime::now(),
            command,
            answer: vec![answer],
        });
    }

    fn push(&mut self, event: LinkEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.lost_events += 1;
        } else {
            self.events.push(event);
        }
    }

    pub(super) fn take_events(&mut self) -> Vec<LinkEvent> {
        let mut events = std::mem::take(&mut self.events);
        if self.lost_events > 0 {
            events.push(LinkEvent::Lost(std::mem::take(&mut self.lost_events)));
        }
        events
    }

    fn check(&self) -> Result<(), Error> {
        match &self.broken {
            Some(why) => Err(Error::Adapter(why.clone())),
            None => Ok(()),
        }
    }

    // Stops the port for good. The interface is not touched: nothing in this backend may change
    // its mode, so a frame the driver still holds is left to it.
    pub(super) fn fail(&mut self, why: String) -> Error {
        if self.broken.is_none() {
            self.status(format!("stopped: {why}"));
            self.broken = Some(why.clone());
        }
        Error::Adapter(why)
    }

    // --- Filters ---

    // What the kernel is told: the transport's filters, and the one ID an echo comes back on.
    fn apply_filters(&mut self) -> Result<(), Error> {
        let mut kernel: Vec<KernelFilter> = self.filters.iter().map(wire::kernel_filter).collect();
        kernel.extend(self.echo_filter);
        let text = kernel
            .iter()
            .map(|f| format!("{:#010x}/{:#010x}", f.id, f.mask))
            .collect::<Vec<_>>()
            .join(" ");
        let result = self.dev.set_filters(&kernel);
        self.note(
            format!("CAN_RAW_FILTER {text}"),
            match &result {
                Ok(()) => "ok".to_owned(),
                Err(e) => e.to_string(),
            },
        );
        result
    }

    // The software check: the kernel may hand over more than the transport asked for (the echo's
    // ID), and a fake or an older kernel may not filter at all.
    fn accepts(&self, id: u32, extended: bool) -> bool {
        self.filters
            .iter()
            .any(|f| f.extended == extended && id & f.mask == f.id & f.mask)
    }

    // --- Receiving ---

    fn queue_frame(&mut self, frame: RxFrame) {
        if self.queue.len() >= MAX_QUEUED {
            self.lost = true;
        } else {
            self.queue.push_back(PortEvent::Frame(frame));
        }
    }

    // Bus events are rare and each tells all it can, so a repeat is dropped: the queue holds at
    // most one of each, and none is ever lost to the limit.
    fn queue_event(&mut self, event: PortEvent) {
        if !self.queue.contains(&event) {
            self.queue.push_back(event);
        }
    }

    // A bus fault waiting to be read.
    fn queued_fault(&self) -> Option<&'static str> {
        self.queue.iter().find_map(|event| match event {
            PortEvent::BusOff => Some("the CAN controller went bus-off"),
            PortEvent::ErrorPassive => Some("the CAN controller went error-passive"),
            PortEvent::ErrorFrame => Some("an error frame was seen on the CAN bus"),
            PortEvent::Frame(_) | PortEvent::Overrun => None,
        })
    }

    fn ingest(&mut self, packet: &Packet) -> Result<(), Error> {
        let body = match wire::parse_frame(&packet.frame) {
            Ok(body) => body,
            Err(e) => return Err(self.fail(format!("the kernel sent {e}"))),
        };
        // The socket's own count of frames its queue had no room for. It is cumulative, so a
        // change means frames were lost before this one.
        if packet.dropped != self.last_dropped {
            self.last_dropped = packet.dropped;
            self.queue_event(PortEvent::Overrun);
        }
        match body {
            Body::Data { id, extended, data } => {
                // The one frame this socket sent that it is waiting to see. Nothing else is taken
                // for an echo: it is the frame, byte for byte, or it is received data.
                if self.echo
                    && self.in_flight.is_some_and(|f| {
                        f.id == id && f.extended == extended && f.data[..] == data[..]
                    })
                {
                    self.in_flight = None;
                } else if self.accepts(id, extended) {
                    self.queue_frame(RxFrame {
                        id,
                        extended,
                        data,
                        time: None,
                    });
                }
                Ok(())
            }
            Body::Remote => Ok(()),
            Body::Error(error) => {
                self.queue_event(match error {
                    BusError::BusOff => PortEvent::BusOff,
                    BusError::ErrorPassive => PortEvent::ErrorPassive,
                    BusError::Overrun => PortEvent::Overrun,
                    BusError::Other => PortEvent::ErrorFrame,
                });
                Ok(())
            }
        }
    }

    // Waits up to `timeout` for one datagram and takes it in. False if none came.
    fn pump(&mut self, timeout: Duration) -> Result<bool, Error> {
        match self.dev.recv(timeout) {
            Ok(Some(packet)) => {
                self.ingest(&packet)?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(self.fail(e.to_string())),
        }
    }

    // --- Sending ---

    fn counter(&mut self) -> Result<u64, Error> {
        match self.dev.tx_packets() {
            Ok(count) => Ok(count),
            Err(e) => Err(self.fail(format!("can't read the interface's transmit counter: {e}"))),
        }
    }

    // Lets the kernel pass this frame's ID to the socket, so its echo can be seen.
    fn expect_echo_of(&mut self, id: u32, extended: bool) -> Result<(), Error> {
        let wanted = wire::exact_filter(id, extended);
        if self.echo_filter != Some(wanted) {
            self.echo_filter = Some(wanted);
            if let Err(e) = self.apply_filters() {
                return Err(self.fail(format!("setting the socket's filters failed: {e}")));
            }
        }
        Ok(())
    }
}

impl<D: Device> CanPort for SocketCanPort<D> {
    fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error> {
        self.check()?;
        self.filters = filters.to_vec();
        self.echo_filter = None;
        if let Err(e) = self.apply_filters() {
            return Err(self.fail(format!("setting the socket's filters failed: {e}")));
        }
        Ok(())
    }

    fn write(&mut self, frame: &TxFrame) -> Result<(), Error> {
        self.check()?;
        if self.listen_only {
            return Err(Error::Adapter(
                "the session is listen-only: nothing is written to the bus".to_owned(),
            ));
        }
        let limit = if frame.extended { 0x1FFF_FFFF } else { 0x7FF };
        if frame.id > limit {
            return Err(Error::Adapter(format!(
                "CAN ID {:X} doesn't fit in {} bits",
                frame.id,
                if frame.extended { 29 } else { 11 }
            )));
        }
        let before = if self.echo {
            self.expect_echo_of(frame.id, frame.extended)?;
            0
        } else {
            self.counter()?
        };
        self.in_flight = Some(InFlight {
            id: frame.id,
            extended: frame.extended,
            data: frame.data,
        });
        let bytes = wire::encode_tx(frame.id, frame.extended, frame.data);
        if let Err(e) = self.dev.send(&bytes) {
            self.in_flight = None;
            return Err(self.fail(format!("writing a frame failed: {e}")));
        }
        let deadline = Instant::now() + TX_CONFIRM_TIMEOUT;
        loop {
            let confirmed = if self.echo {
                self.in_flight.is_none()
            } else {
                self.counter()? > before
            };
            if confirmed {
                self.in_flight = None;
                return Ok(());
            }
            if let Some(fault) = self.queued_fault() {
                self.in_flight = None;
                return Err(self.fail(format!(
                    "{fault} while a transmitted frame was unconfirmed{UNCONFIRMED_ADVICE}"
                )));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.in_flight = None;
                return Err(self.fail(format!(
                    "no confirmation that frame {:X} went out within {:?}: {}{UNCONFIRMED_ADVICE}",
                    frame.id,
                    TX_CONFIRM_TIMEOUT,
                    if self.echo {
                        "the driver never echoed it, so no node on the bus acknowledged it, or \
                         the interface can't send"
                    } else {
                        "the interface's transmit counter didn't move, so no node on the bus \
                         acknowledged it, or the interface can't send"
                    }
                )));
            }
            // Without an echo the counter is read again soon; the wait for a frame is the pause.
            self.pump(if self.echo {
                left
            } else {
                left.min(COUNTER_STEP)
            })?;
        }
    }

    fn read(&mut self, timeout: Duration) -> Result<PortEvent, Error> {
        self.check()?;
        let deadline = Instant::now() + timeout.min(LONGEST_WAIT);
        let mut polled_past = 0;
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Ok(event);
            }
            if self.lost {
                self.lost = false;
                return Ok(PortEvent::Overrun);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                polled_past += 1;
                if polled_past > MAX_POLLED_PAST_DEADLINE {
                    // A read that was never to wait is a drain: giving up before the socket ran
                    // dry must not read as an empty queue, or a stale reply behind the flood
                    // could answer the next request. Not a fault of the port: the next drain goes
                    // on from here.
                    return Err(if timeout.is_zero() {
                        Error::Adapter(format!(
                            "more than {MAX_POLLED_PAST_DEADLINE} frames from other IDs are queued \
                             on the CAN socket: it can't be drained"
                        ))
                    } else {
                        Error::Timeout
                    });
                }
            }
            if !self.pump(left)? {
                return Err(Error::Timeout);
            }
        }
    }
}

// What to tell the user when a frame may still be in the driver's hands: the port can't take it
// back, because nothing in this backend changes the interface.
const UNCONFIRMED_ADVICE: &str = ". Nothing more will be sent. The frame may still be on its way or retrying: take the interface \
     down yourself (`ip link set <interface> down`) if the bus is disturbed";
