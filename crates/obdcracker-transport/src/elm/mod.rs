//! ELM327 and STN adapters (such as an `OBDLink EX`), over any [`Link`].
//!
//! The adapter takes text commands: `AT` commands configure it, and a line of hex digits is a
//! request it puts on the bus. [`Elm`] only ever writes a fixed set of `AT` commands and the
//! hex of [`Approved`] requests. Every `AT` command contains a letter that isn't a hex digit, so
//! no mangled command can turn into a bus frame, and it never writes a bare carriage return,
//! which repeats the adapter's last command. Behaviour is from the ELM327 datasheet (ELM327DS
//! v2.0); see `docs/elm327.md`.

pub mod codec;

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use obdcracker_core::isotp::{Addressing, MAX_SHORT_PAYLOAD, Progress, Reassembler};
use obdcracker_safety::Approved;

use crate::link::{Driver, Link, LinkKind};
use crate::{Error, Response, Timing, Transport, hex};
use codec::{Event, Line, LineSplitter, parse_line};

// Run after the reset, in order. Each must answer OK.
const SETUP: &[&str] = &[
    // Echo, linefeeds off; spaces and headers on, so every frame shows its CAN ID and PCI byte
    "ATE0", "ATL0", "ATS1", "ATH1",
    // ISO 15765-4 CAN, 11-bit IDs, 500 kbit/s. Never automatic search: it sends probe frames
    // that no policy approved and no audit log records.
    "ATSP6",
    // The adapter adds and strips PCI bytes when sending, and sends flow control frames
    "ATCAF1", "ATCFC1", // Wait for replies after every request
    "ATR1",
    // Show every 11-bit reply ID from 0x700 to 0x7FF; `exchange` picks the ones that count
    "ATCF700", "ATCM700",
    // Adaptive timing, capped at the longest timeout (0xFF x 4 ms)
    "ATAT1", "ATSTFF",
];

/// The longest the adapter waits for a reply, or for more replies after one: `AT ST FF`.
pub const ADAPTER_TIMEOUT: Duration = Duration::from_millis(0xFF * 4);

// How long to wait for the adapter to go quiet before the reset, and the most time to spend.
const QUIET: Duration = Duration::from_millis(100);
const DRAIN_LIMIT: Duration = Duration::from_secs(2);
// How long a reset may take, and how many to try: the first may only interrupt the adapter.
const RESET_WAIT: Duration = Duration::from_secs(3);
const RESET_TRIES: usize = 2;
// How long an AT command may take.
const COMMAND_WAIT: Duration = Duration::from_secs(2);
// How long the adapter may take to finish a request before the next one: its own timeout after
// the last reply, plus time for the link.
const BUSY_WAIT: Duration = Duration::from_secs(3);
// The most modules whose multi-frame replies are reassembled at once. Frames from more are
// dropped.
const MAX_SENDERS: usize = 16;
// The longest any single receive waits, so a huge timeout can't overflow the clock.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);

/// An ELM327-compatible adapter on CAN (ISO 15765-4, 11-bit IDs, 500 kbit/s).
///
/// Requests must fit one CAN frame: up to 7 bytes, which covers every read-only request.
/// Longer ones are refused before anything is written. Multi-frame replies are reassembled
/// here, per module, from the frames the adapter prints, for up to 16 modules per request;
/// frames from any more are dropped, so those modules' replies time out.
///
/// The adapter sends ISO-TP flow control frames itself, which no audit log records: for the
/// OBD-II IDs (0x7DF and 0x7E0..=0x7E7) its standard ones, and for any other module
/// `30 00 00` (continue, no block limit, no gap) to the module's request ID.
///
/// If the adapter doesn't finish a command or request in time, refuses a setting, prints
/// something unexpected or an overlong line, says it reset (`LV RESET`, `ERRxx`, `LP ALERT`,
/// a banner) or is searching for a protocol (`SEARCHING...`, `UNABLE TO CONNECT`), or the link
/// fails, its state is unknown, and every later call fails without writing anything: connect
/// again.
#[derive(Debug)]
pub struct Elm<L> {
    link: L,
    splitter: LineSplitter,
    events: VecDeque<Event>,
    header: Option<u32>,
    flow: Option<Flow>,
    // A request is out and the adapter hasn't printed its prompt yet.
    busy: bool,
    // Why the adapter can't be trusted any more.
    broken: Option<String>,
    senders: Vec<(u32, Reassembler<Vec<u8>>)>,
}

// Where the adapter sends ISO-TP flow control frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    // The adapter's own ISO 15765-4 handling, for the OBD-II IDs
    Standard,
    // `30 00 00` to this request ID
    To(u32),
}

/// What an adapter says about itself. Reading it puts nothing on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// The `ATI` answer, such as `ELM327 v1.4b`. Clones often claim a version they don't fully
    /// implement.
    pub id: String,
    /// The `STI` answer from an STN chip (`OBDLink` adapters), such as `STN1155 v5.6.19`, or
    /// `None` for a plain ELM327.
    pub stn: Option<String>,
    /// The voltage on the OBD port as the adapter prints it (`ATRV`), such as `12.6V`.
    pub voltage: Option<String>,
}

impl<L: Link> Elm<L> {
    /// Resets the adapter and sets it up for CAN. Nothing is put on the bus.
    ///
    /// Fails if no ELM327 answers, or if the adapter refuses any setup command (some clones
    /// don't implement everything they claim).
    pub fn connect(link: L) -> Result<Self, Error> {
        let mut elm = Self {
            link,
            splitter: LineSplitter::default(),
            events: VecDeque::new(),
            header: None,
            flow: None,
            busy: false,
            broken: None,
            senders: Vec::new(),
        };
        elm.drain_stale()?;
        elm.reset()?;
        for command in SETUP {
            elm.expect_ok(command)?;
        }
        Ok(elm)
    }

    /// Timing for [`crate::exchange`] through this adapter. The adapter decides when a request
    /// is over (it prints its prompt), so P2 only has to outlast [`ADAPTER_TIMEOUT`] plus the
    /// link's delay.
    #[must_use]
    pub fn timing() -> Timing {
        Timing {
            p2: ADAPTER_TIMEOUT + Duration::from_secs(1),
            ..Timing::default()
        }
    }

    /// Asks the adapter what it is and what voltage it sees.
    pub fn info(&mut self) -> Result<AdapterInfo, Error> {
        let id = self.command("ATI")?.join(" ");
        let stn = self.command("STI")?.join(" ");
        let voltage = self.command("ATRV")?.join(" ");
        Ok(AdapterInfo {
            id,
            stn: (stn != "?" && !stn.is_empty()).then_some(stn),
            voltage: (voltage != "?" && !voltage.is_empty()).then_some(voltage),
        })
    }

    /// How the adapter is connected.
    pub fn link_kind(&self) -> LinkKind {
        self.link.kind()
    }

    /// The link to the adapter.
    pub fn link(&self) -> &L {
        &self.link
    }

    /// The link to the adapter. A [`Link`] can't be written to outside this crate, so this
    /// can't be used to send anything.
    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    // Discards whatever the adapter printed before we connected, until it goes quiet.
    fn drain_stale(&mut self) -> Result<(), Error> {
        let give_up = Instant::now() + DRAIN_LIMIT;
        let mut buf = [0; 256];
        while Instant::now() < give_up {
            if self.read(&mut buf, QUIET)? == 0 {
                break;
            }
        }
        Ok(())
    }

    // ATZ, until the banner and then a prompt arrive.
    fn reset(&mut self) -> Result<(), Error> {
        for _ in 0..RESET_TRIES {
            self.splitter.clear();
            self.events.clear();
            self.write(b"ATZ\r")?;
            let deadline = Instant::now() + RESET_WAIT;
            let mut banner = false;
            while let Some(event) = self.next_event(deadline)? {
                match event {
                    Event::Line(line) if line.starts_with("ELM327") => banner = true,
                    Event::Prompt if banner => return Ok(()),
                    _ => {}
                }
            }
        }
        Err(Error::Adapter(
            "no ELM327 answered; check the port, the baud rate and that the adapter is powered"
                .into(),
        ))
    }

    // Sends an AT or ST command and returns its answer, without the echo.
    fn command(&mut self, command: &str) -> Result<Vec<String>, Error> {
        // An all-hex line is a bus request, which only `send` may write.
        if command.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Adapter(format!("{command} isn't a command")));
        }
        self.ready()?;
        self.write(format!("{command}\r").as_bytes())?;
        let deadline = Instant::now() + COMMAND_WAIT;
        let mut lines = Vec::new();
        loop {
            match self.next_event(deadline)? {
                None => {
                    return Err(self.break_down(format!("no answer to {command}")));
                }
                Some(Event::Prompt) => break,
                // The rest of the answer may still be coming, so the next command can't tell
                // where its own answer starts.
                Some(Event::Overlong) => {
                    return Err(self.break_down(format!("overlong answer to {command}")));
                }
                Some(Event::Line(line)) if line.eq_ignore_ascii_case(command) => {}
                Some(Event::Line(line)) => {
                    if let Line::Status(status) = parse_line(&line)
                        && status.loses_settings()
                    {
                        return Err(self.break_down(format!("the adapter said {status}")));
                    }
                    // Only ATI answers with the banner; anywhere else it means a reset.
                    if command != "ATI" && line.starts_with("ELM327") {
                        return Err(self.break_down(format!("the adapter reset: {line}")));
                    }
                    lines.push(line);
                }
            }
        }
        Ok(lines)
    }

    // Any answer but OK leaves the adapter's settings unknown: it may have reset, or kept the
    // old header.
    fn expect_ok(&mut self, command: &str) -> Result<(), Error> {
        let lines = self.command(command)?;
        if lines.iter().map(String::as_str).eq(["OK"]) {
            return Ok(());
        }
        Err(
            self.break_down(if lines.iter().map(String::as_str).eq(["?"]) {
                format!("the adapter doesn't support {command}")
            } else {
                format!("{command} failed: {}", lines.join(" / "))
            }),
        )
    }

    // Fails if the adapter can't be trusted; otherwise waits for any request still running.
    fn ready(&mut self) -> Result<(), Error> {
        if let Some(why) = &self.broken {
            return Err(Error::Adapter(format!(
                "the adapter is in an unknown state ({why}); connect again"
            )));
        }
        if !self.busy {
            return Ok(());
        }
        // The rest of the last request's replies are dropped, but a reset among them still
        // counts.
        let deadline = Instant::now() + BUSY_WAIT;
        loop {
            match self.next_event(deadline)? {
                None => {
                    return Err(self.break_down("the adapter didn't finish a request".into()));
                }
                Some(Event::Prompt) => break,
                Some(Event::Line(text)) => {
                    self.reply_line(&text)?;
                }
                // It can't be read, so it could hide a reset.
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
            }
        }
        self.busy = false;
        self.senders.clear();
        Ok(())
    }

    fn break_down(&mut self, why: String) -> Error {
        let error = Error::Adapter(why.clone());
        self.broken = Some(why);
        error
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let kind = self.link.kind().name();
        self.link
            .write_all(bytes, Driver::new())
            .map_err(|e| self.break_down(format!("{kind} link: {e}")))
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Error> {
        let kind = self.link.kind().name();
        self.link
            .read(buf, timeout)
            .map_err(|e| self.break_down(format!("{kind} link: {e}")))
    }

    // The next thing the adapter printed, or None once the deadline passes.
    fn next_event(&mut self, deadline: Instant) -> Result<Option<Event>, Error> {
        let mut buf = [0; 256];
        let mut events = Vec::new();
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Ok(None);
            };
            let n = self.read(&mut buf, left)?;
            self.splitter.push(&buf[..n], &mut events);
            self.events.extend(events.drain(..));
        }
    }

    // Feeds one frame to its module's reassembler and returns the reply it completes.
    fn feed(&mut self, source: u32, data: &[u8]) -> Option<Response> {
        let index = match self.senders.iter().position(|(id, _)| *id == source) {
            Some(index) => index,
            None if self.senders.len() < MAX_SENDERS => {
                let buf = vec![0; MAX_SHORT_PAYLOAD];
                self.senders
                    .push((source, Reassembler::new(buf, Addressing::Normal)));
                self.senders.len() - 1
            }
            None => return None,
        };
        // A frame that doesn't fit its module's transfer drops that transfer only; the
        // reassembler starts over at the module's next single or first frame.
        match self.senders[index].1.feed(data) {
            Ok(Progress::Complete(payload)) => Some(Response {
                source,
                payload: payload.to_vec(),
            }),
            _ => None,
        }
    }

    fn set_target(&mut self, id: u32) -> Result<(), Error> {
        if self.header != Some(id) {
            self.expect_ok(&format!("ATSH{id:03X}"))?;
            self.header = Some(id);
        }
        let flow = if id == 0x7DF || (0x7E0..=0x7E7).contains(&id) {
            Flow::Standard
        } else {
            Flow::To(id)
        };
        if self.flow != Some(flow) {
            match flow {
                Flow::Standard => self.expect_ok("ATFCSM0")?,
                Flow::To(id) => {
                    self.expect_ok(&format!("ATFCSH{id:03X}"))?;
                    self.expect_ok("ATFCSD300000")?;
                    self.expect_ok("ATFCSM1")?;
                }
            }
            self.flow = Some(flow);
        }
        Ok(())
    }
}

impl<L: Link> Transport for Elm<L> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let payload = request.payload();
        if payload.is_empty() || payload.len() > Addressing::Normal.max_single_frame() {
            return Err(Error::Adapter(format!(
                "a {}-byte request doesn't fit one CAN frame; this adapter driver only sends single frames",
                payload.len()
            )));
        }
        self.ready()?;
        self.set_target(request.target().can_id())?;
        // The adapter ignores spaces, but leaving them out keeps the line short.
        let mut line = hex(payload).replace(' ', "");
        line.push('\r');
        self.write(line.as_bytes())?;
        self.busy = true;
        self.senders.clear();
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.ready_to_receive()?;
        let deadline = Instant::now() + timeout.min(LONGEST_WAIT);
        loop {
            match self.next_event(deadline)? {
                None => return Err(Error::Timeout),
                Some(Event::Prompt) => {
                    self.busy = false;
                    return Err(Error::Timeout);
                }
                // It can't be read, so it could hide a reset.
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    Line::Frame(frame) => {
                        if let Some(reply) = self.feed(frame.id(), frame.data()) {
                            return Ok(reply);
                        }
                    }
                    Line::Status(status) if status.is_failure() => {
                        return Err(Error::Adapter(format!("the adapter said {status}")));
                    }
                    _ => {}
                },
            }
        }
    }
}

impl<L: Link> Elm<L> {
    // Classifies a line printed after a request. Anything that means the adapter lost its
    // settings, or that isn't a reply at all, leaves it in an unknown state.
    fn reply_line(&mut self, text: &str) -> Result<Line, Error> {
        match parse_line(text) {
            // Its settings are gone: it may even search for a protocol on the next request,
            // sending frames nobody approved.
            Line::Status(status) if status.loses_settings() => {
                Err(self.break_down(format!("the adapter said {status}")))
            }
            // Such as a banner after a reset, or echo turned back on.
            Line::Ok | Line::Text(_) => {
                Err(self.break_down(format!("unexpected output from the adapter: {text}")))
            }
            line => Ok(line),
        }
    }

    // Receiving needs a request in progress; after the prompt there's nothing more to come.
    fn ready_to_receive(&mut self) -> Result<(), Error> {
        if let Some(why) = &self.broken {
            return Err(Error::Adapter(format!(
                "the adapter is in an unknown state ({why}); connect again"
            )));
        }
        if self.busy {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }
}
