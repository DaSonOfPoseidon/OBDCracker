//! The ISO-TP transport shared by the raw-CAN backends (gs_usb, SocketCAN): framing, flow control
//! and bus-state handling over any [`CanPort`]. See
//! [`docs/raw-can.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/raw-can.md).

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use obdcracker_core::isotp::{self, Addressing, FlowStatus, Frame, Segmenter, Step};
use obdcracker_safety::{
    Approved, ApprovedFlowControl, FeedOutcome, Protocol, ReplyWindow, Target,
};

use crate::{Error, LinkEvent, Response, Transport, hex};
use port::{CanPort, Filter, PortEvent, RxFrame, TxFrame};

mod pace;
mod port;
#[cfg(test)]
mod tests;

// ISO 15765-4: an emissions ECU answers on 0x7E8..=0x7EF.
const OBD_REPLY_BASE: u32 = 0x7E8;
const OBD_REPLY_MASK: u32 = 0x7F8;
const MASK_11_BIT: u32 = 0x7FF;
const MASK_29_BIT: u32 = 0x1FFF_FFFF;
// Physical diagnostic request and reply IDs share 0x700..=0x7FF.
const DIAGNOSTIC_BASE: u32 = 0x700;
const DIAGNOSTIC_MASK: u32 = 0x700;

// The most notes kept between `take_events` calls, and stale frames read before a request.
const MAX_EVENTS: usize = 64;
const MAX_STALE_FRAMES: usize = 256;
const LONGEST_WAIT: Duration = Duration::from_secs(3600);

const TP20_REFUSAL: &str = "raw CAN doesn't speak VW TP2.0 yet (#259)";

/// Timing a transfer waits on that the standard leaves to the implementation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// How long to wait for the module's flow control (ISO 15765-2's `N_Bs`: 1 s). Each wait
    /// frame restarts it.
    pub(crate) flow_control: Duration,
    /// How many wait flow controls in a row to sit through before giving up on the module.
    pub(crate) max_waits: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            flow_control: Duration::from_secs(1),
            max_waits: 10,
        }
    }
}

#[derive(Debug)]
struct Open {
    window: ReplyWindow,
    is_29_bit: bool,
}

/// ISO-TP over one CAN port.
///
/// Sends an approved request as one frame or as a segmented transfer paced by the module's flow
/// control, and receives replies through a [`ReplyWindow`], sending the flow control it mints.
/// Once the port reports bus-off, error-passive or an error frame, nothing more is sent. See
/// `docs/raw-can.md`.
#[derive(Debug)]
pub(crate) struct RawCan<P> {
    port: P,
    limits: Limits,
    sleep: fn(Duration),
    fault: Option<String>,
    filters: Vec<Filter>,
    window: Option<Open>,
    ready: VecDeque<Response>,
    // Frames of replies not yet complete, for the log if they never are: (source, when, line).
    partial: Vec<(u32, SystemTime, String)>,
    events: Vec<LinkEvent>,
    lost: usize,
    // When the last frame was confirmed sent, or a flow control frame arrived: STmin counts from it.
    last_frame: Option<Instant>,
}

impl<P: CanPort> RawCan<P> {
    pub(crate) fn new(port: P) -> Self {
        Self {
            port,
            limits: Limits::default(),
            sleep: std::thread::sleep,
            fault: None,
            filters: Vec::new(),
            window: None,
            ready: VecDeque::new(),
            partial: Vec::new(),
            events: Vec::new(),
            lost: 0,
            last_frame: None,
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    #[cfg(test)]
    fn with_sleeper(mut self, sleep: fn(Duration)) -> Self {
        self.sleep = sleep;
        self
    }

    fn check(&self) -> Result<(), Error> {
        match &self.fault {
            Some(fault) => Err(Error::Adapter(fault.clone())),
            None => Ok(()),
        }
    }

    // Latches: nothing is sent on a bus the controller says is faulted.
    fn fail(&mut self, fault: &str) -> Error {
        self.abandon();
        self.fault = Some(fault.to_owned());
        Error::Adapter(fault.to_owned())
    }

    // Ends the transfer in progress. What it received but nobody took is reported as unread, as
    // the log would otherwise never show it.
    fn abandon(&mut self) {
        self.window = None;
        for reply in std::mem::take(&mut self.ready) {
            let line = format!("{:03X} {}", reply.source, hex(&reply.payload));
            self.push_event(LinkEvent::Unread {
                at: SystemTime::now(),
                line,
            });
        }
        for (_, at, line) in std::mem::take(&mut self.partial) {
            self.push_event(LinkEvent::Unread { at, line });
        }
    }

    fn report_partial(&mut self, source: u32) {
        let (abandoned, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.partial)
            .into_iter()
            .partition(|(from, ..)| *from == source);
        self.partial = kept;
        for (_, at, line) in abandoned {
            self.push_event(LinkEvent::Unread { at, line });
        }
    }

    fn push_event(&mut self, event: LinkEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.lost += 1;
        } else {
            self.events.push(event);
        }
    }

    fn note(&mut self, line: String) {
        self.push_event(LinkEvent::Status {
            at: SystemTime::now(),
            line,
        });
    }

    fn frame_of(&mut self, event: PortEvent) -> Result<RxFrame, Error> {
        match event {
            PortEvent::Frame(frame) => Ok(frame),
            PortEvent::BusOff => Err(self.fail("the CAN controller went bus-off")),
            PortEvent::ErrorPassive => Err(self.fail("the CAN controller went error-passive")),
            PortEvent::ErrorFrame => Err(self.fail("an error frame was seen on the CAN bus")),
            PortEvent::Overrun => {
                // What is half-received can't be trusted.
                self.abandon();
                Err(Error::Adapter(
                    "the CAN port dropped received frames (receive overrun)".to_owned(),
                ))
            }
        }
    }

    fn write(&mut self, id: u32, extended: bool, bytes: &[u8]) -> Result<(), Error> {
        self.check()?;
        self.port.write(&TxFrame::padded(id, extended, bytes))?;
        self.last_frame = Some(Instant::now());
        Ok(())
    }

    // Drops what the last request left, and listens only for this one's replies.
    fn begin(&mut self, request: &Approved) -> Result<(), Error> {
        self.abandon();
        self.last_frame = None;
        let mut stale = 0;
        loop {
            let event = match self.port.read(Duration::ZERO) {
                Ok(event) => event,
                Err(Error::Timeout) => break,
                Err(e) => return Err(e),
            };
            // Whatever is still queued past the limit could be a late reply, which would read as
            // this request's.
            stale += 1;
            // Every frame is recorded, the one past the limit too, and a bus fault past the limit
            // still latches: the event is handled before the limit.
            match self.frame_of(event) {
                Err(e) if self.fault.is_some() => return Err(e),
                Ok(frame) => self.push_event(LinkEvent::Unread {
                    at: SystemTime::now(),
                    line: frame_line(&frame),
                }),
                Err(e) => self.note(e.to_string()),
            }
            if stale > MAX_STALE_FRAMES {
                return Err(Error::Adapter(format!(
                    "more than {MAX_STALE_FRAMES} stale frames are queued on the CAN port"
                )));
            }
        }
        let filters = filters_for(request);
        if filters != self.filters {
            self.port.set_filters(&filters)?;
            self.filters = filters;
        }
        Ok(())
    }

    // Feeds a received frame to the window. Returns the flow control it asks for, if any.
    fn accept(&mut self, frame: &RxFrame) -> Option<ApprovedFlowControl> {
        let open = self.window.as_mut()?;
        // A 29-bit frame whose ID reads like an 11-bit one is another module's.
        if frame.extended != open.is_29_bit {
            return None;
        }
        let outcome = open.window.feed(frame.id, &frame.data);
        // Anything but a consecutive frame that fits ends the transfer the source had half-sent
        // (a single or first frame starts another, and a bad frame leaves the receiver idle).
        // That is reported now, or a reply that completes would take its evidence with it.
        if !matches!(outcome, Ok(FeedOutcome::Ignored))
            && !matches!(
                Frame::parse(&frame.data, Addressing::Normal),
                Ok(Frame::Consecutive { .. })
            )
        {
            self.report_partial(frame.id);
        }
        match outcome {
            Ok(FeedOutcome::Complete { source, payload }) => {
                // The response is logged when it is returned.
                self.partial.retain(|(from, ..)| *from != source);
                self.ready
                    .push_back(Response::new(source, payload).at_bus_time(frame.time));
                None
            }
            Ok(FeedOutcome::SendFlowControl(token)) => {
                self.keep(frame);
                Some(token)
            }
            Ok(FeedOutcome::Pending) => {
                self.keep(frame);
                None
            }
            Ok(FeedOutcome::NoFlowControl { source }) => {
                self.keep(frame);
                self.note(format!(
                    "no flow control for the multi-frame reply from {source:03X}: the request has no known reply ID"
                ));
                None
            }
            Ok(FeedOutcome::Ignored) => None,
            Err(e) => {
                self.keep(frame);
                self.note(format!("dropped a frame from {:03X}: {e}", frame.id));
                // The bad frame ends the source's transfer, so what it kept is reported now.
                self.report_partial(frame.id);
                None
            }
        }
    }

    fn keep(&mut self, frame: &RxFrame) {
        if self.partial.len() >= MAX_EVENTS {
            self.lost += 1;
        } else {
            self.partial
                .push((frame.id, SystemTime::now(), frame_line(frame)));
        }
    }

    fn transmit(&mut self, request: &Approved) -> Result<(), Error> {
        let target = request.target();
        let mut segmenter = Segmenter::new(request.payload(), Addressing::Normal)
            .map_err(|e| Error::Adapter(format!("can't frame the request: {e}")))?;
        loop {
            match segmenter.step() {
                Step::Send(data) => {
                    if let Some(at) = self.last_frame {
                        pace::wait_gap(at, segmenter.st_min(), self.sleep);
                    }
                    self.write(target.can_id(), target.is_29_bit(), data.as_bytes())?;
                }
                Step::WaitForFlowControl => {
                    self.await_flow_control(&mut segmenter, request, target.is_29_bit())?;
                }
                Step::Done => return Ok(()),
                Step::Aborted => {
                    return Err(Error::Adapter(
                        "the module refused the request: it is too long for its buffer".to_owned(),
                    ));
                }
            }
        }
    }

    fn await_flow_control(
        &mut self,
        segmenter: &mut Segmenter<'_>,
        request: &Approved,
        is_29_bit: bool,
    ) -> Result<(), Error> {
        let reply = request.reply_id().ok_or_else(|| {
            Error::Adapter("a multi-frame request needs a known reply ID".to_owned())
        })?;
        let mut waits = 0;
        let mut deadline = Instant::now() + self.limits.flow_control;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Adapter(format!(
                    "no flow control from {reply:03X} within {:?}",
                    self.limits.flow_control
                )));
            }
            let event = match self.port.read(left) {
                Ok(event) => event,
                Err(Error::Timeout) => {
                    return Err(Error::Adapter(format!(
                        "no flow control from {reply:03X} within {:?}",
                        self.limits.flow_control
                    )));
                }
                Err(e) => return Err(e),
            };
            let frame = self.frame_of(event)?;
            if frame.id == reply
                && frame.extended == is_29_bit
                && let Ok(Frame::FlowControl(fc)) = Frame::parse(&frame.data, Addressing::Normal)
            {
                if fc.status == FlowStatus::Wait {
                    waits += 1;
                    if waits > self.limits.max_waits {
                        return Err(Error::Adapter(format!(
                            "{reply:03X} kept asking to wait ({} times)",
                            self.limits.max_waits
                        )));
                    }
                    deadline = Instant::now() + self.limits.flow_control;
                    continue;
                }
                return match segmenter.flow_control(fc) {
                    Ok(()) => {
                        self.last_frame = Some(Instant::now());
                        Ok(())
                    }
                    Err(isotp::Error::Overflow) => Err(Error::Adapter(format!(
                        "{reply:03X} refused the request: it is too long for the module's buffer"
                    ))),
                    Err(e) => Err(Error::Adapter(format!(
                        "flow control from {reply:03X}: {e}"
                    ))),
                };
            }
            // The module is answering early. Keep what completes; a flow control for its reply
            // isn't ours to send mid-request.
            if self.accept(&frame).is_some() {
                self.note(format!(
                    "didn't send flow control to {reply:03X} mid-request"
                ));
            }
        }
    }
}

impl<P: CanPort> Transport for RawCan<P> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.check()?;
        let target = request.target();
        if request.protocol() == Protocol::Tp20Channel
            || matches!(target, Target::Tp20Setup(_) | Target::Tp20Channel(_))
        {
            return Err(Error::Adapter(TP20_REFUSAL.to_owned()));
        }
        if request.payload().len() > Addressing::Normal.max_single_frame()
            && request.reply_id().is_none()
        {
            return Err(Error::Adapter(
                "a multi-frame request needs a known reply ID".to_owned(),
            ));
        }
        let window = ReplyWindow::open(request)
            .map_err(|e| Error::Adapter(format!("can't open a reply window: {e}")))?;
        self.begin(request)?;
        self.window = Some(Open {
            window,
            is_29_bit: target.is_29_bit(),
        });
        let sent = self.transmit(request);
        if sent.is_err() {
            self.abandon();
        }
        sent
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.recv_logged(timeout, &mut |_| Ok(()))
    }

    // The window stays open after a reply: a broadcast has more ECUs to hear, and a module that
    // sent response-pending has more to say. The next request, or an error, ends it.
    fn recv_logged(
        &mut self,
        timeout: Duration,
        before_send: &mut dyn FnMut(&ApprovedFlowControl) -> Result<(), Error>,
    ) -> Result<Response, Error> {
        self.check()?;
        let deadline = Instant::now() + timeout.min(LONGEST_WAIT);
        let mut polled = false;
        loop {
            if let Some(reply) = self.ready.pop_front() {
                return Ok(reply);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if polled && left.is_zero() {
                return Err(Error::Timeout);
            }
            polled = true;
            let event = match self.port.read(left) {
                Ok(event) => event,
                Err(Error::Timeout) => return Err(Error::Timeout),
                Err(e) => {
                    // A failing port may have lost frames the transfer needs.
                    self.abandon();
                    return Err(e);
                }
            };
            let frame = self.frame_of(event)?;
            if let Some(token) = self.accept(&frame) {
                // Without its flow control the module won't send the rest, and if the frame did
                // go out, what follows isn't a transfer we can vouch for.
                let sent = before_send(&token).and_then(|()| {
                    self.write(token.destination_id(), token.is_29_bit(), token.data())
                });
                if let Err(e) = sent {
                    self.abandon();
                    return Err(e);
                }
            }
        }
    }

    fn settle(&mut self) -> Result<(), Error> {
        self.abandon();
        Ok(())
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        let mut events = std::mem::take(&mut self.events);
        if self.lost > 0 {
            events.push(LinkEvent::Lost(std::mem::take(&mut self.lost)));
        }
        events
    }
}

fn frame_line(frame: &RxFrame) -> String {
    format!("{:03X} {}", frame.id, hex(&frame.data))
}

// What a port should hand over for this request's replies. The window checks every frame again.
fn filters_for(request: &Approved) -> Vec<Filter> {
    let target = request.target();
    let filter = match (target, request.reply_id()) {
        (Target::ObdFunctional, _) => Filter {
            id: OBD_REPLY_BASE,
            mask: OBD_REPLY_MASK,
            extended: false,
        },
        (_, Some(reply)) => Filter {
            id: reply,
            mask: if target.is_29_bit() {
                MASK_29_BIT
            } else {
                MASK_11_BIT
            },
            extended: target.is_29_bit(),
        },
        (_, None) if target.is_29_bit() => Filter {
            id: 0,
            mask: 0,
            extended: true,
        },
        (_, None) => Filter {
            id: DIAGNOSTIC_BASE,
            mask: DIAGNOSTIC_MASK,
            extended: false,
        },
    };
    vec![filter]
}
