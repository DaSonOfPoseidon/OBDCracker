//! The `gs_usb` controller as a [`CanPort`]: frames out and in over the bulk endpoints, with the
//! device's own echo confirming each frame sent.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use super::usb::Usb;
use super::wire::{self, Body, BusError};
use crate::raw::port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};
use crate::{Error, LinkEvent};

/// How long a frame may go unconfirmed before the controller is reset. A classic frame takes well
/// under a millisecond on the bus, so this covers the USB round trip with room to spare.
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
// Echo IDs cycle through the few the kernel driver uses; candleLight firmware indexes a small
// table with them.
const ECHO_IDS: u32 = 10;
const MAX_DRAINED: usize = 4096;

/// One `gs_usb` channel. See `docs/gsusb.md`.
#[derive(Debug)]
pub(super) struct GsUsbPort<U: Usb> {
    usb: U,
    // The session may never write. Fixed when the port is made.
    listen_only: bool,
    // The controller has been started and not yet reset.
    started: bool,
    // Why the port stopped for good. Nothing more is written or read after.
    broken: Option<String>,
    filters: Vec<Filter>,
    queue: VecDeque<PortEvent>,
    lost: bool,
    next_echo: u32,
    in_flight: Option<u32>,
    events: Vec<LinkEvent>,
    lost_events: usize,
}

impl<U: Usb> GsUsbPort<U> {
    pub(super) fn new(usb: U, listen_only: bool) -> Self {
        Self {
            usb,
            listen_only,
            started: false,
            broken: None,
            filters: Vec::new(),
            queue: VecDeque::new(),
            lost: false,
            next_echo: 0,
            in_flight: None,
            events: Vec::new(),
            lost_events: 0,
        }
    }

    /// Adds a status line to what the audit log gets.
    pub(super) fn status(&mut self, line: String) {
        if self.events.len() >= MAX_EVENTS {
            self.lost_events += 1;
        } else {
            self.events.push(LinkEvent::Status {
                at: SystemTime::now(),
                line,
            });
        }
    }

    fn note(&mut self, command: String, answer: String) {
        if self.events.len() >= MAX_EVENTS {
            self.lost_events += 1;
        } else {
            self.events.push(LinkEvent::Command {
                at: SystemTime::now(),
                command,
                answer: vec![answer],
            });
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

    // Stops the port for good and takes the controller off the bus: a controller that went on
    // retrying a frame, or that nobody is reading, is no use to the bus.
    pub(super) fn fail(&mut self, why: String) -> Error {
        let mut why = why;
        if self.broken.is_none() {
            if self.started
                && let Err(e) = self.reset_controller()
            {
                why = format!("{why}; resetting the controller failed too: {e}");
            }
            self.broken = Some(why.clone());
        }
        Error::Adapter(why)
    }

    // --- Control transfers, each one logged ---

    pub(super) fn control_out(
        &mut self,
        what: &str,
        request: u8,
        value: u16,
        data: &[u8],
    ) -> Result<(), Error> {
        let result = self.usb.control_out(request, value, data);
        self.note(
            format!("gs_usb {what}"),
            match &result {
                Ok(()) => "ok".to_owned(),
                Err(e) => e.to_string(),
            },
        );
        result
    }

    pub(super) fn control_in(
        &mut self,
        what: &str,
        request: u8,
        value: u16,
        length: u16,
    ) -> Result<Vec<u8>, Error> {
        let result = self.usb.control_in(request, value, length);
        self.note(
            format!("gs_usb {what}"),
            match &result {
                Ok(bytes) => format!("ok, {} bytes", bytes.len()),
                Err(e) => e.to_string(),
            },
        );
        result
    }

    /// Puts the controller in reset, which takes it off the bus.
    pub(super) fn reset_controller(&mut self) -> Result<(), Error> {
        self.control_out(
            "MODE RESET",
            wire::BREQ_MODE,
            wire::CHANNEL,
            &wire::mode_message(wire::MODE_RESET, 0),
        )?;
        self.started = false;
        Ok(())
    }

    /// Starts the controller: listening only, or (never in a listen-only session) active.
    /// `berr` asks it to report bus errors as error frames.
    pub(super) fn start(&mut self, active: bool, berr: bool) -> Result<(), Error> {
        if active && self.listen_only {
            return Err(Error::Adapter(
                "refusing to leave listen-only mode".to_owned(),
            ));
        }
        self.check()?;
        let mut flags = if active { 0 } else { wire::FLAG_LISTEN_ONLY };
        if berr {
            flags |= wire::FLAG_BERR_REPORTING;
        }
        // A start that fails may still have taken effect, so it counts as started.
        self.started = true;
        self.control_out(
            &format!(
                "MODE START {} flags={flags:#06x}",
                if active { "active" } else { "listen-only" }
            ),
            wire::BREQ_MODE,
            wire::CHANNEL,
            &wire::mode_message(wire::MODE_START, flags),
        )
    }

    /// Resets the controller, and reports it if that failed. A failed reset leaves the port
    /// armed, so dropping it tries again as a last resort.
    pub(super) fn close(&mut self) -> Result<(), Error> {
        if self.started {
            self.reset_controller()?;
        }
        Ok(())
    }

    /// Reads and throws away what the device has queued, so none of it is taken for something
    /// that happened after this. Fails if it never runs dry.
    pub(super) fn drain_usb(&mut self) -> Result<usize, Error> {
        let mut drained = 0;
        while self.usb.bulk_in(Duration::ZERO)?.is_some() {
            drained += 1;
            if drained > MAX_DRAINED {
                return Err(Error::Adapter(
                    "the device keeps sending frames while its controller is in reset".to_owned(),
                ));
            }
        }
        self.queue.clear();
        self.lost = false;
        Ok(drained)
    }

    // --- Receiving ---

    #[cfg(test)]
    pub(super) fn filters(&self) -> &[Filter] {
        &self.filters
    }

    fn accepts(&self, id: u32, extended: bool) -> bool {
        self.filters
            .iter()
            .any(|f| f.extended == extended && id & f.mask == f.id & f.mask)
    }

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

    fn ingest(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let parsed = match wire::parse_frame(bytes) {
            Ok(parsed) => parsed,
            Err(e) => return Err(self.fail(format!("the device sent {e}"))),
        };
        // Only channel 0 is started, so another channel's frames are not our bus's.
        if u16::from(parsed.channel) != wire::CHANNEL {
            return Ok(());
        }
        if parsed.overflow {
            self.queue_event(PortEvent::Overrun);
        }
        match parsed.body {
            Body::Confirmation => match self.in_flight {
                Some(id) if id == parsed.echo_id => {
                    self.in_flight = None;
                    Ok(())
                }
                Some(id) => Err(self.fail(format!(
                    "the device confirmed echo ID {}, but the frame in flight has ID {id}",
                    parsed.echo_id
                ))),
                None => Err(self.fail(format!(
                    "the device confirmed echo ID {}, but no frame is in flight",
                    parsed.echo_id
                ))),
            },
            Body::Data { id, extended, data } => {
                if self.accepts(id, extended) {
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

    // Waits up to `timeout` for one packet and takes it in. False if none came.
    fn pump(&mut self, timeout: Duration) -> Result<bool, Error> {
        match self.usb.bulk_in(timeout) {
            Ok(Some(packet)) => {
                self.ingest(&packet)?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(self.fail(e.to_string())),
        }
    }
}

impl<U: Usb> CanPort for GsUsbPort<U> {
    fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error> {
        self.check()?;
        self.filters = filters.to_vec();
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
        if !self.started {
            return Err(Error::Adapter(
                "the CAN controller isn't started".to_owned(),
            ));
        }
        let echo_id = self.next_echo;
        self.next_echo = (self.next_echo + 1) % ECHO_IDS;
        self.in_flight = Some(echo_id);
        let bytes = wire::encode_tx(echo_id, frame.id, frame.extended, frame.bytes());
        if let Err(e) = self.usb.bulk_out(&bytes) {
            self.in_flight = None;
            return Err(self.fail(format!("writing a frame failed: {e}")));
        }
        let deadline = Instant::now() + TX_CONFIRM_TIMEOUT;
        while self.in_flight.is_some() {
            if let Some(fault) = self.queued_fault() {
                self.in_flight = None;
                return Err(self.fail(format!(
                    "{fault} while a transmitted frame was unconfirmed; the controller was reset"
                )));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !self.pump(left)? {
                self.in_flight = None;
                return Err(self.fail(format!(
                    "no confirmation that frame {:X} went out within {:?}: no node on the bus \
                     acknowledged it. The controller was reset so it stops retrying",
                    frame.id, TX_CONFIRM_TIMEOUT
                )));
            }
        }
        Ok(())
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
                    // A read that was never to wait is a drain: giving up before the device
                    // ran dry must not read as an empty queue, or a stale reply behind the
                    // flood could answer the next request. Not a fault of the port: the next
                    // drain goes on from here.
                    return Err(if timeout.is_zero() {
                        Error::Adapter(format!(
                            "more than {MAX_POLLED_PAST_DEADLINE} frames from other IDs are queued \
                             on the CAN port: it can't be drained"
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

impl<U: Usb> Drop for GsUsbPort<U> {
    // The last resort when nobody called `close`: take the controller off the bus. It writes
    // nothing else, so unwinding can't send a frame.
    fn drop(&mut self) {
        if self.started {
            let _ = self.reset_controller();
        }
    }
}
