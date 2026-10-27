//! ELM327 and STN adapters (such as an `OBDLink EX`), over any [`Link`].
//!
//! A line of hex digits is a request the adapter puts on the bus, so [`Elm`] writes only a fixed
//! set of `AT` commands and the hex of [`Approved`] requests, checks every echo, and never
//! writes an empty line. See `docs/elm327.md` for the adapter's behaviour and why.

pub mod codec;

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use obdcracker_core::isotp::{Addressing, MAX_SHORT_PAYLOAD, Progress, Reassembler};
use obdcracker_safety::{Approved, Protocol, Target};

use crate::link::{Driver, Link, LinkKind};
use crate::{Error, LinkEvent, Response, Timing, Transport, hex};
use codec::{Event, Line, LineSplitter, Status, parse_line};

// Sent after the reset, each must answer OK (docs/elm327.md#setup). Never automatic protocol
// search (`ATSP6`): it sends probe frames that no policy approved and no audit log records.
#[rustfmt::skip]
const SETUP: &[&str] = &[
    "ATL0", "ATS1", "ATH1",
    "ATSP6",
    "ATR1",
    "ATCRA7XX",
    "ATAT1", "ATSTFF",
];

// Programmable parameters that would change a default the setup relies on (datasheet pp. 57-61):
// the number, its default value, and what it sets.
const KEPT_DEFAULTS: &[(u8, u8, &str)] = &[
    (0x09, 0x00, "echo"),
    (0x24, 0x00, "CAN auto formatting"),
    (0x25, 0x00, "CAN flow control"),
    (0x29, 0xFF, "CAN data length display"),
];

// Raw frames for VW TP2.0 and back; the order matters (docs/elm327.md#vw-tp20-channel-frames).
const RAW_ON: [&str; 3] = ["ATCFC0", "ATV1", "ATCAF0"];
const RAW_OFF: [&str; 3] = ["ATCAF1", "ATV0", "ATCFC1"];

// `AT CRA` patterns (docs/elm327.md#receive-filter): every diagnostic reply ID, and every
// OBD-II emissions ECU's; for 29-bit IDs, every ISO 15765-4 reply to the tester and every VAG one.
const WIDE_FILTER: &str = "7XX";
const OBD_FILTER: &str = "7EX";
const ISO_29_BIT_FILTER: &str = "18DAF1XX";
const VAG_29_BIT_FILTER: &str = "17FE00XX";

/// The most [`LinkEvent`]s an [`Elm`] keeps until they're taken
/// ([`Transport::take_events`]); it counts any more as lost.
pub const MAX_EVENTS: usize = 4096;

/// How long the adapter waits for a reply, or for more replies after one: `AT ST FF`, unless an STN
/// is made to wait longer ([`Transport::patient`]).
pub const ADAPTER_TIMEOUT: Duration = Duration::from_millis(0xFF * 4);

/// The longest an STN chip can be made to wait for a reply while [`Transport::patient`]:
/// `STPTO`'s largest value, 65535 ms (STN1100 FRPM). A plain ELM327 can't wait longer than
/// [`ADAPTER_TIMEOUT`].
pub const STN_LONGEST_TIMEOUT: Duration = Duration::from_millis(65_535);

// How long the adapter must stay quiet before the reset, and the most time to spend waiting.
const QUIET: Duration = Duration::from_millis(100);
const DRAIN_LIMIT: Duration = Duration::from_secs(2);
// The first reset may only interrupt the adapter, hence two tries.
const RESET_WAIT: Duration = Duration::from_secs(3);
const RESET_TRIES: usize = 2;
const IDLE_CHECK: Duration = Duration::from_millis(1);
// `AT PPS` prints 12 lines. A reset keeps this many for the report and counts the rest as lost.
const MAX_ANSWER_LINES: usize = 32;
const COMMAND_WAIT: Duration = Duration::from_secs(2);
// Time to print the longest reply (4095 bytes) at 9600 baud: about 23 s
// (docs/elm327.md#timing).
const LONGEST_PRINT: Duration =
    Duration::from_millis(586 * FRAME_LINE_29 as u64 * 10 * 1000 / 9600 + 1);
const MAX_SENDERS: usize = 16;
const LONGEST_PRINT_ALL: Duration = LONGEST_PRINT.saturating_mul(16);
const _: () = assert!(MAX_SENDERS == 16, "update LONGEST_PRINT_ALL");
const LONGEST_REQUEST: Duration = STN_LONGEST_TIMEOUT
    .saturating_add(LONGEST_PRINT_ALL)
    .saturating_add(Duration::from_secs(1));
// How much longer than its own timeout the adapter may stay quiet in a request before it counts
// as hung (ELM327DS v2.1, p. 90; docs/elm327.md#timing).
const SILENCE_MARGIN: Duration = Duration::from_secs(6);
// The longest any single receive waits, so a huge timeout can't overflow the clock.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);
// How long a request's digits may take to echo before its carriage return (#54).
const ECHO_WAIT: Duration = Duration::from_secs(1);
// Ends a misheard line so the adapter refuses it: no single flipped bit of this leaves a line of
// hex digits (docs/elm327.md#safety).
const KILL: &[u8] = b"XX\r";
// Stops an adapter listening after a request (ELM327DS p. 7), which discards it. No single
// flipped bit of it is a hex digit, and if the prompt came first, `KILL`'s `X\r` ends the line it
// starts so the adapter refuses it.
const INTERRUPT: &[u8] = b"X";
// Characters in a printed consecutive frame, `7E8 21 41 41 41 41 41 41 41 \r`, and with a 29-bit
// ID, `17 FE 00 76 21 41 41 41 41 41 41 41 \r`.
const FRAME_LINE: u32 = 29;
const FRAME_LINE_29: u32 = 37;
// 9600 baud, the slowest an ELM327 starts at, for a link whose rate can't be known.
const SLOWEST_RATE: u32 = 9600 / 10;
// From here an STN was seen to print a long reply with no `BUFFER FULL` (#49).
const STN_UNPACED_RATE: u32 = 115_200 / 10;

/// An ELM327-compatible adapter on CAN (ISO 15765-4, 11-bit IDs, 500 kbit/s; 29-bit IDs when a
/// request needs them).
///
/// The adapter must accept `AT CRA` with `X` digits: an ELM327 v2.0 or later, or an STN chip
/// (`OBDLink` adapters, which call themselves v1.4b). Older chips refuse it, and
/// [`Elm::connect`] fails.
///
/// Requests must fit one CAN frame (up to 7 bytes) and are refused otherwise, before anything is
/// written. Multi-frame replies are reassembled per module, for up to 16 modules per request.
/// Replies still arriving at the next request are dropped and reported as [`LinkEvent`]s,
/// along with every command sent ([`Transport::take_events`]).
///
/// The adapter sends ISO-TP flow control frames itself, which no audit log records. A physical
/// request's asks for a gap between frames from the link's rate ([`Link::byte_rate`], 9600 baud
/// when unknown).
///
/// If the adapter does anything unexpected (it misechoes, resets, goes quiet, refuses a setting
/// or the link fails), its state is unknown: every later call fails without writing anything,
/// and the caller must connect again.
///
/// See docs/elm327.md#failure-states, #flow-control-per-target and #receive-filter.
#[derive(Debug)]
pub struct Elm<L> {
    link: L,
    splitter: LineSplitter,
    // What the adapter printed, read but not used yet, with when it was read.
    events: VecDeque<(SystemTime, Event)>,
    // When the event last taken from `events` was read.
    event_at: SystemTime,
    header: Option<u32>,
    // Whether the adapter is on 29-bit CAN (`ATSP7`) rather than 11-bit (`ATSP6`, the setup's).
    bits29: bool,
    // Whether the adapter sends raw frames ([`RAW_ON`]), for VW TP2.0.
    raw: bool,
    flow: Option<Flow>,
    // The `AT CRA` pattern in effect.
    filter: String,
    // A request is out and the adapter hasn't printed its prompt yet.
    busy: bool,
    // The request line the adapter hasn't echoed yet.
    echo: Option<String>,
    // Whether the adapter echoes a request's characters before its carriage return, once the
    // first request has shown it.
    early_echo: Option<bool>,
    // How long the driver has waited since the adapter last printed anything. Time the caller
    // spends elsewhere doesn't count; waits across calls add up.
    quiet: Duration,
    // When the last byte arrived, if since the current wait began.
    last_byte: Option<Instant>,
    // Why the adapter can't be trusted any more.
    broken: Option<String>,
    // What it printed when it was reset, such as `ELM327 v1.4b`.
    banner: String,
    // Its `STI` answer, if it's an STN chip.
    stn: Option<String>,
    // The link's byte rate, if replies are paced to it.
    pace: Option<u32>,
    // How long the adapter waits for a reply: `ADAPTER_TIMEOUT`, or longer on a patient STN.
    timeout: Duration,
    // Each module answering the request in progress.
    senders: Vec<Sender>,
    // Lines of the request in progress that are in no reply yet, in the order they were read,
    // with when, and the number each was given; reported once the request is over, as unread
    // or, for a status line, as a status.
    heard: Vec<(u64, SystemTime, String)>,
    next_heard: u64,
    // How many lines of the request in progress didn't fit in `heard`: lost unless a reply
    // turns out to use them.
    overflowed: usize,
    // What it did besides requests and replies, until taken, and how many more were dropped.
    log: Vec<LinkEvent>,
    lost: usize,
}

// A module answering the request in progress.
#[derive(Debug)]
struct Sender {
    id: u32,
    reassembler: Reassembler<Vec<u8>>,
    // The numbers of the `heard` lines of its reply so far.
    lines: Vec<u64>,
}

// Where the adapter sends ISO-TP flow control frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    // To the ID ISO 15765-4 gives, for the OBD-II IDs, with no gap between frames
    Standard,
    // To this request ID, with this gap between frames (STmin, ms)
    To(u32, u8),
}

/// Why [`Elm::connect_reporting`] failed, and what the adapter was sent and answered first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectFailed {
    /// Why it failed.
    pub error: Error,
    /// The commands sent and the lines read, oldest first.
    pub events: Vec<LinkEvent>,
}

/// What an adapter says about itself. Reading it puts nothing on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// The banner the adapter printed when it was reset, the same as its `ATI` answer, such as
    /// `ELM327 v1.4b`. Clones often claim a version they don't fully implement.
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
    /// don't implement everything they claim). [`Elm::connect_reporting`] also returns the
    /// commands sent before the failure.
    pub fn connect(link: L) -> Result<Self, Error> {
        Self::connect_reporting(link).map_err(|failed| failed.error)
    }

    /// [`Elm::connect`], returning with a failure what the adapter was sent and answered up to
    /// it ([`LinkEvent`]s), as nothing else can take them: for the audit log
    /// ([`crate::log_failure`]).
    ///
    /// # Errors
    ///
    /// As [`Elm::connect`].
    pub fn connect_reporting(link: L) -> Result<Self, ConnectFailed> {
        let mut elm = Self {
            link,
            splitter: LineSplitter::default(),
            events: VecDeque::new(),
            event_at: SystemTime::UNIX_EPOCH,
            header: None,
            bits29: false,
            raw: false,
            flow: None,
            filter: WIDE_FILTER.to_owned(),
            busy: false,
            echo: None,
            early_echo: None,
            quiet: Duration::ZERO,
            last_byte: None,
            broken: None,
            banner: String::new(),
            stn: None,
            pace: None,
            timeout: ADAPTER_TIMEOUT,
            senders: Vec::new(),
            heard: Vec::new(),
            next_heard: 0,
            log: Vec::new(),
            lost: 0,
            overflowed: 0,
        };
        match elm.set_up() {
            Ok(()) => Ok(elm),
            Err(error) => Err(ConnectFailed {
                error,
                events: elm.take_events(),
            }),
        }
    }

    fn set_up(&mut self) -> Result<(), Error> {
        let elm = self;
        elm.drain_stale()?;
        elm.reset()?;
        elm.check_defaults()?;
        for command in SETUP {
            elm.expect_ok(command)?;
        }
        // Only an STN chip names itself so; a clone may answer anything.
        let stn = elm.command("STI")?.join(" ");
        elm.stn = stn.starts_with("STN").then_some(stn);
        elm.pace = pace(elm.stn.is_some(), elm.link.byte_rate());
        // A learned timeout could be shorter than a paced module's gap and end its reply early.
        if elm.pace.is_some() {
            elm.expect_ok("ATAT0")?;
        }
        Ok(())
    }

    /// Timing for [`crate::exchange`] through this adapter. The adapter's prompt ends a request,
    /// so P2 and P2* are only outer bounds, about 7 minutes; an adapter that goes quiet
    /// fails within seconds instead. See docs/elm327.md#timing.
    #[must_use]
    pub fn timing() -> Timing {
        let default = Timing::default();
        Timing {
            p2: LONGEST_REQUEST,
            p2_star: default.p2_star.saturating_add(LONGEST_PRINT_ALL),
            ..default
        }
    }

    /// Asks the adapter what voltage it sees, and says what it is.
    ///
    /// The ID and STN version come from [`Elm::connect`], not `ATI`, so a reset now can't pass for
    /// an answer.
    pub fn info(&mut self) -> Result<AdapterInfo, Error> {
        let voltage = self.command("ATRV")?.join(" ");
        Ok(AdapterInfo {
            id: self.banner.clone(),
            stn: self.stn.clone(),
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

    /// The link to the adapter. A [`Link`] can't be written to or read outside this crate, so this
    /// can't send anything or hide the adapter's output from the driver.
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
            let at = SystemTime::now();
            // Some of it may have reached the adapter even if the write failed.
            if let Err(e) = self.write(b"ATZ\r") {
                self.note(LinkEvent::Command {
                    at,
                    command: "ATZ".to_owned(),
                    answer: Vec::new(),
                });
                return Err(e);
            }
            let deadline = Instant::now() + RESET_WAIT;
            let mut banner = None;
            let mut answer = Vec::new();
            let mut skipped = 0;
            let reset = loop {
                let event = match self.next_event(deadline) {
                    Ok(Some(event)) => event,
                    Ok(None) => break Ok(false),
                    Err(e) => break Err(e),
                };
                if let Event::Line(line) = &event {
                    if answer.len() < MAX_ANSWER_LINES {
                        answer.push(line.clone());
                    } else {
                        skipped += 1;
                    }
                }
                match event {
                    Event::Line(line) if line.starts_with("ELM327") => banner = Some(line),
                    Event::Prompt => {
                        if let Some(banner) = banner.take() {
                            self.banner = banner;
                            break Ok(true);
                        }
                    }
                    _ => {}
                }
            };
            self.note(LinkEvent::Command {
                at,
                command: "ATZ".to_owned(),
                answer,
            });
            if skipped > 0 {
                self.note(LinkEvent::Lost(skipped));
            }
            if reset? {
                return Ok(());
            }
        }
        Err(Error::Adapter(
            "no ELM327 answered; check the port, the baud rate and that the adapter is powered"
                .into(),
        ))
    }

    // Fails if a programmable parameter changed a default the setup relies on. An adapter without
    // them (`?`) is at the factory defaults.
    fn check_defaults(&mut self) -> Result<(), Error> {
        let lines = self.command("ATPPS")?;
        if lines.iter().map(String::as_str).eq(["?"]) {
            return Ok(());
        }
        let mut seen = Vec::new();
        for line in &lines {
            let mut words = line.split_whitespace();
            while let Some(word) = words.next() {
                let entry = word.split_once(':').and_then(|(pp, value)| {
                    let on = match words.next()? {
                        "N" => true,
                        "F" => false,
                        _ => return None,
                    };
                    Some((hex_byte(pp)?, hex_byte(value)?, on))
                });
                let Some((pp, value, on)) = entry.filter(|(pp, ..)| !seen.contains(pp)) else {
                    return Err(self.break_down(format!("unexpected answer to ATPPS: {line}")));
                };
                seen.push(pp);
                if let Some((_, default, what)) = KEPT_DEFAULTS.iter().find(|(p, ..)| *p == pp)
                    && on
                    && value != *default
                {
                    return Err(self.break_down(format!(
                        "PP {pp:02X} changes the default {what}; turn it off with AT PP {pp:02X} OFF"
                    )));
                }
            }
        }
        // A summary without one was cut short (docs/elm327.md#safety).
        if let Some((pp, ..)) = KEPT_DEFAULTS.iter().find(|(pp, ..)| !seen.contains(pp)) {
            return Err(self.break_down(format!("ATPPS didn't list PP {pp:02X}")));
        }
        Ok(())
    }

    // Sends an AT or ST command and returns its answer, after checking the echo. The command
    // and as much of its answer as was read are reported (`LinkEvent::Command`).
    fn command(&mut self, command: &str) -> Result<Vec<String>, Error> {
        // An all-hex line is a bus request, which only `send` may write.
        if command.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Adapter(format!("{command} isn't a command")));
        }
        self.ready()?;
        let at = SystemTime::now();
        let mut lines = Vec::new();
        let answered = self.command_answer(command, &mut lines);
        self.note(LinkEvent::Command {
            at,
            command: command.to_owned(),
            answer: lines.clone(),
        });
        answered.map(|()| lines)
    }

    fn note(&mut self, event: LinkEvent) {
        if self.log.len() < MAX_EVENTS {
            self.log.push(event);
        } else if let LinkEvent::Lost(count) = event {
            // What it counted is lost too.
            self.lost += count;
        } else {
            self.lost += 1;
        }
    }

    // Writes `command` and reads its answer's lines into `lines`.
    fn command_answer(&mut self, command: &str, lines: &mut Vec<String>) -> Result<(), Error> {
        self.write(format!("{command}\r").as_bytes())?;
        self.read_answer(command, lines)
    }

    // For a command whose only non-hex letter is its `T` (`ATCAF0`): written like a request, so
    // a flipped bit is caught before the carriage return. Needs an adapter that has shown it
    // echoes characters as it reads them.
    fn guarded_command(&mut self, command: &str) -> Result<(), Error> {
        if self.early_echo != Some(true) {
            return Err(Error::Adapter(format!(
                "{command} needs an adapter that echoes each character as it reads it (such as \
                 an OBDLink), and this one hasn't shown it does; send an ISO-TP request first"
            )));
        }
        self.ready()?;
        self.check_idle()?;
        let at = SystemTime::now();
        let mut lines = Vec::new();
        // Noted however it ends: a misheard command may still have done something.
        let answered = self
            .write(command.as_bytes())
            .and_then(|()| self.check_early_echo(command))
            .and_then(|()| self.write(b"\r"))
            .and_then(|()| self.read_answer(command, &mut lines));
        self.note(LinkEvent::Command {
            at,
            command: command.to_owned(),
            answer: lines.clone(),
        });
        answered?;
        if lines.iter().map(String::as_str).eq(["OK"]) {
            Ok(())
        } else {
            Err(self.break_down(format!("{command} failed: {}", lines.join(" / "))))
        }
    }

    // Reads the answer to `command`, already written, into `lines`.
    fn read_answer(&mut self, command: &str, lines: &mut Vec<String>) -> Result<(), Error> {
        let deadline = Instant::now() + COMMAND_WAIT;
        let mut echoed = false;
        loop {
            match self.next_event(deadline)? {
                // Some clones leave the prompt off (python-OBD #160, #205).
                None if !lines.is_empty() || (echoed && self.splitter.partial().is_some()) => {
                    return Err(self.break_down(format!(
                        "the adapter answered {command} but never printed its prompt (>)"
                    )));
                }
                None if echoed => {
                    return Err(self.break_down(format!(
                        "the adapter echoed {command} but never answered it"
                    )));
                }
                None => {
                    return Err(self.break_down(format!("no answer to {command}")));
                }
                Some(Event::Prompt) if !echoed => {
                    return Err(self.break_down(format!("the adapter didn't echo {command}")));
                }
                Some(Event::Prompt) => break,
                Some(Event::Overlong) => {
                    return Err(self.break_down(format!("overlong answer to {command}")));
                }
                // The adapter heard something else, and may have acted on it.
                Some(Event::Line(line)) if !echoed => {
                    if !line.eq_ignore_ascii_case(command) {
                        return Err(self.break_down(format!(
                            "the adapter echoed {line} instead of {command}"
                        )));
                    }
                    echoed = true;
                }
                Some(Event::Line(line)) => {
                    if let Line::Status(status) = parse_line(&line)
                        && leaves_unknown_state(status)
                    {
                        return Err(self.break_down(format!("the adapter said {status}")));
                    }
                    if line.starts_with("ELM327") {
                        return Err(self.break_down(format!("the adapter reset: {line}")));
                    }
                    if lines.len() == MAX_ANSWER_LINES {
                        return Err(self.break_down(format!("the answer to {command} is too long")));
                    }
                    lines.push(line);
                }
            }
        }
        Ok(())
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
                format!(
                    "the adapter doesn't support {command}{}",
                    self.needs_hint(command)
                )
            } else {
                format!("{command} failed: {}", lines.join(" / "))
            }),
        )
    }

    // `X` digits in `AT CRA` arrived in ELM327 v2.0, and most clones claiming it refuse them.
    fn needs_hint(&self, command: &str) -> String {
        if command.starts_with("ATCRA") && command.contains('X') {
            format!(
                "; this driver needs an ELM327 v2.0 or later, or an STN chip (OBDLink). This one \
                 says it's {}, but many clones claim a version they don't implement",
                self.banner
            )
        } else {
            String::new()
        }
    }

    fn trusted(&self) -> Result<(), Error> {
        match &self.broken {
            Some(why) => Err(Error::Adapter(format!(
                "the adapter is in an unknown state ({why}); connect again"
            ))),
            None => Ok(()),
        }
    }

    // Fails if the adapter can't be trusted; otherwise waits for any request still running.
    fn ready(&mut self) -> Result<(), Error> {
        self.trusted()?;
        if !self.busy {
            return self.check_idle();
        }
        // Dropped, but a reset among them still counts.
        self.drop_senders();
        let deadline = Instant::now() + LONGEST_REQUEST;
        loop {
            match self.next_request_event(deadline)? {
                None => {
                    return Err(self.break_down("the adapter didn't finish a request".into()));
                }
                Some(Event::Prompt) => {
                    self.prompt_after_request()?;
                    break;
                }
                Some(Event::Line(text)) => {
                    if self.echo.is_none() {
                        self.note(left_over(self.event_at, text.clone()));
                    }
                    self.reply_line(&text)?;
                }
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
            }
        }
        self.busy = false;
        self.check_idle()
    }

    // The adapter prints nothing between its prompt and the next line it's sent, so anything
    // already read past the prompt, or waiting on the link, could be a reset.
    fn check_idle(&mut self) -> Result<(), Error> {
        // Reads until the deadline whatever arrives: a stray NUL makes no event but may precede
        // a reset (docs/elm327.md#safety).
        let deadline = Instant::now() + IDLE_CHECK;
        let mut buf = [0; 256];
        let mut events = Vec::new();
        while self.events.is_empty() && self.splitter.partial().is_none() {
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Ok(());
            };
            let n = self.read(&mut buf, left)?;
            self.splitter.push(&buf[..n], &mut events);
            let now = SystemTime::now();
            self.events
                .extend(events.drain(..).map(|event| (now, event)));
        }
        let what = match self.events.pop_front().map(|(_, event)| event) {
            Some(Event::Line(line)) => line,
            Some(Event::Prompt) => ">".into(),
            Some(Event::Overlong) => "an overlong line".into(),
            None => match self.splitter.partial() {
                Some(Some(line)) => line.to_owned(),
                _ => "an overlong line".into(),
            },
        };
        Err(self.break_down(format!("the adapter printed {what} while idle")))
    }

    // Stops the adapter listening for more of the last request's replies. Lines it printed
    // until then that nobody read are reported as unread.
    fn interrupt(&mut self) -> Result<(), Error> {
        // It may have finished already, its prompt read or waiting on the link: then there's
        // nothing to stop.
        let deadline = Instant::now() + IDLE_CHECK;
        while let Some(event) = self.next_event(deadline)? {
            match event {
                // `ready` finishes the request as usual.
                Event::Prompt => {
                    self.events.push_front((self.event_at, Event::Prompt));
                    return Ok(());
                }
                Event::Overlong => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Event::Line(text) => {
                    if self.reply_line(&text)?.is_some() {
                        self.note(left_over(self.event_at, text));
                    }
                }
            }
        }
        let at = SystemTime::now();
        let mut answer = Vec::new();
        let interrupted = self
            .write(INTERRUPT)
            .and_then(|()| self.read_interrupted(&mut answer));
        self.note(LinkEvent::Command {
            at,
            command: String::from_utf8_lossy(INTERRUPT).into_owned(),
            answer,
        });
        let stopped = interrupted?;
        if !stopped {
            // The prompt came first, so `X` began a line: end it so the adapter refuses it.
            let at = SystemTime::now();
            let mut lines = Vec::new();
            let refused = self
                .write(&KILL[1..])
                .and_then(|()| self.read_answer("XX", &mut lines));
            self.note(LinkEvent::Command {
                at,
                command: "XX".to_owned(),
                answer: lines.clone(),
            });
            refused?;
            if !lines.iter().map(String::as_str).eq(["?"]) {
                return Err(self.break_down(format!(
                    "the adapter didn't refuse XX after its prompt: {}",
                    lines.join(" / ")
                )));
            }
        }
        self.busy = false;
        self.drop_senders();
        Ok(())
    }

    // Reads up to the prompt after `INTERRUPT`, noting the lines read on the way; returns
    // whether the adapter said it stopped (`STOPPED`), or had already finished.
    fn read_interrupted(&mut self, answer: &mut Vec<String>) -> Result<bool, Error> {
        let deadline = Instant::now() + COMMAND_WAIT;
        let mut stopped = false;
        loop {
            match self.next_event(deadline)? {
                None => {
                    return Err(self.break_down("the adapter didn't stop listening".into()));
                }
                Some(Event::Prompt) => return Ok(stopped),
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Some(Event::Line(text)) if !stopped && text == "STOPPED" => {
                    stopped = true;
                    answer.push(text);
                }
                Some(Event::Line(text)) => {
                    // A reply the caller never read, checked as any other.
                    if self.reply_line(&text)?.is_some() {
                        self.note(left_over(self.event_at, text));
                    }
                }
            }
        }
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
            .read(buf, timeout, Driver::new())
            .map_err(|e| self.break_down(format!("{kind} link: {e}")))
    }

    // The next thing the adapter printed, or None once the deadline passes.
    fn next_event(&mut self, deadline: Instant) -> Result<Option<Event>, Error> {
        let mut buf = [0; 256];
        let mut events = Vec::new();
        loop {
            if let Some((at, event)) = self.events.pop_front() {
                self.event_at = at;
                return Ok(Some(event));
            }
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Ok(None);
            };
            let n = self.read(&mut buf, left)?;
            if n > 0 {
                self.last_byte = Some(Instant::now());
            }
            self.splitter.push(&buf[..n], &mut events);
            let now = SystemTime::now();
            self.events
                .extend(events.drain(..).map(|event| (now, event)));
        }
    }

    // The next thing the adapter printed during a request, or None once the deadline passes.
    // Fails once the adapter has been quiet for its timeout plus `SILENCE_MARGIN`.
    fn next_request_event(&mut self, deadline: Instant) -> Result<Option<Event>, Error> {
        loop {
            let Some(left) = self
                .timeout
                .saturating_add(SILENCE_MARGIN)
                .checked_sub(self.quiet)
                .filter(|left| !left.is_zero())
            else {
                return Err(
                    self.break_down("the adapter went quiet without finishing a request".into())
                );
            };
            let started = Instant::now();
            self.last_byte = None;
            let event = self.next_event(deadline.min(started + left))?;
            self.quiet = match self.last_byte {
                Some(at) => at.elapsed(),
                None => self.quiet.saturating_add(started.elapsed()),
            };
            if let Some(event) = event {
                return Ok(Some(event));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    // Feeds one frame, printed as `line`, to its module's reassembler and returns the reply it
    // completes. Lines that end up in no reply are reported as unread.
    fn feed(&mut self, source: u32, data: &[u8], line: &str) -> Option<Response> {
        let number = self.hear(line);
        let index = match self.senders.iter().position(|s| s.id == source) {
            Some(index) => index,
            None if self.senders.len() < MAX_SENDERS => {
                let buf = vec![0; MAX_SHORT_PAYLOAD];
                self.senders.push(Sender {
                    id: source,
                    reassembler: Reassembler::new(buf, Addressing::Normal),
                    lines: Vec::new(),
                });
                self.senders.len() - 1
            }
            None => return None,
        };
        let sender = &mut self.senders[index];
        // A single or first frame starts a new transfer, abandoning any unfinished one.
        if data.first().is_some_and(|pci| pci >> 4 <= 1) {
            sender.lines.clear();
        }
        sender.lines.push(number);
        // A bad frame drops only its module's transfer.
        match sender.reassembler.feed(data) {
            Ok(Progress::Complete(payload)) => {
                let reply = Response {
                    source,
                    payload: payload.to_vec(),
                };
                let used = std::mem::take(&mut sender.lines);
                let kept = self.heard.len();
                self.heard.retain(|(number, ..)| !used.contains(number));
                // Lines that didn't fit in `heard` but belong to this reply aren't lost.
                let found = kept - self.heard.len();
                self.overflowed = self.overflowed.saturating_sub(used.len() - found);
                Some(reply)
            }
            Ok(_) => None,
            Err(_) => {
                sender.lines.clear();
                None
            }
        }
    }

    // Keeps a line read at `event_at` until it's known whether it's part of a reply.
    fn hear(&mut self, line: &str) -> u64 {
        let number = self.next_heard;
        self.next_heard += 1;
        if self.heard.len() < MAX_EVENTS {
            self.heard.push((number, self.event_at, line.to_owned()));
        } else {
            self.overflowed += 1;
        }
        number
    }

    // Forgets every module's reply in progress, reporting the lines in no reply.
    fn drop_senders(&mut self) {
        self.senders.clear();
        for (_, at, line) in std::mem::take(&mut self.heard) {
            self.note(left_over(at, line));
        }
        // After the request's lines, in order.
        let overflowed = std::mem::take(&mut self.overflowed);
        if overflowed > 0 {
            self.note(LinkEvent::Lost(overflowed));
        }
    }

    fn set_target(&mut self, request: &Approved) -> Result<(), Error> {
        let target = request.target();
        let id = target.can_id();
        let bits29 = target.is_29_bit();
        if self.bits29 != bits29 {
            // Forgotten first: a command that fails may still have taken effect.
            self.header = None;
            self.flow = None;
            self.filter.clear();
            self.bits29 = bits29;
            // Never automatic search (see `SETUP`).
            self.expect_ok(if bits29 { "ATSP7" } else { "ATSP6" })?;
        }
        if self.header != Some(id) {
            if bits29 {
                // Each keeps two non-hex letters, so no flipped bit makes a bus request.
                self.expect_ok(&format!("ATCP{:02X}", id >> 24))?;
                self.expect_ok(&format!("ATSH{:06X}", id & 0x00FF_FFFF))?;
            } else {
                self.expect_ok(&format!("ATSH{id:03X}"))?;
            }
            self.header = Some(id);
        }
        // See docs/elm327.md#flow-control-per-target.
        let gap = st_min(self.pace, bits29);
        let flow = if self.raw {
            self.flow.unwrap_or(Flow::Standard)
        } else if !bits29 && (id == 0x7DF || (gap == 0 && (0x7E0..=0x7E7).contains(&id))) {
            Flow::Standard
        } else {
            Flow::To(id, gap)
        };
        if self.flow != Some(flow) {
            match flow {
                Flow::Standard => self.expect_ok("ATFCSM0")?,
                Flow::To(id, gap) => {
                    self.expect_ok(&can_id_command("ATFCSH", id))?;
                    self.expect_ok(&format!("ATFCSD3000{gap:02X}"))?;
                    self.expect_ok("ATFCSM1")?;
                }
            }
            self.flow = Some(flow);
        }
        let filter = match (request.reply_id(), target) {
            (Some(reply), _) => can_id_text(reply, bits29),
            (None, Target::ObdFunctional) => OBD_FILTER.to_owned(),
            // A TP2.0 frame always knows its reply ID.
            (None, Target::Physical(_) | Target::Tp20Setup(_) | Target::Tp20Channel(_)) => {
                WIDE_FILTER.to_owned()
            }
            (None, Target::Physical29(id)) if id >> 16 == 0x18DA => ISO_29_BIT_FILTER.to_owned(),
            (None, Target::Physical29(_)) => VAG_29_BIT_FILTER.to_owned(),
        };
        if self.filter != filter {
            self.expect_ok(&format!("ATCRA{filter}"))?;
            self.filter = filter;
        }
        Ok(())
    }
}

// The link's byte rate if replies are paced to it: always, except for an STN on a fast link
// (docs/elm327.md#timing).
fn pace(stn: bool, byte_rate: Option<u32>) -> Option<u32> {
    let rate = byte_rate.filter(|&rate| rate > 0).unwrap_or(SLOWEST_RATE);
    (!stn || rate < STN_UNPACED_RATE).then_some(rate)
}

// STmin in ms that keeps the adapter's 512-byte buffer from filling: the time to print one frame
// line at the link's rate, rounded up, at most 127.
fn st_min(pace: Option<u32>, bits29: bool) -> u8 {
    let Some(rate) = pace else {
        return 0;
    };
    let line = if bits29 { FRAME_LINE_29 } else { FRAME_LINE };
    let ms = (line * 1000).div_ceil(rate);
    u8::try_from(ms.min(0x7F)).unwrap_or(0x7F)
}

// A CAN ID as the adapter takes it: 3 hex digits, or 8 for a 29-bit one.
fn can_id_text(id: u32, bits29: bool) -> String {
    if bits29 {
        format!("{id:08X}")
    } else {
        format!("{id:03X}")
    }
}

// `command` followed by the request ID `id`, at the width its value says.
fn can_id_command(command: &str, id: u32) -> String {
    format!("{command}{}", can_id_text(id, id > 0x7FF))
}

// A 3-digit pattern shows only 11-bit frames, an 8-digit one only 29-bit frames.
fn filter_shows(pattern: &str, id: u32) -> bool {
    let id = can_id_text(id, pattern.len() == 8);
    id.len() == pattern.len()
        && pattern
            .bytes()
            .zip(id.bytes())
            .all(|(want, got)| want == b'X' || want == got)
}

// A status line such as `NO DATA` was the adapter's answer (#88); anything else is a reply line
// nobody read.
fn left_over(at: SystemTime, line: String) -> LinkEvent {
    if matches!(parse_line(&line), Line::Status(_)) {
        LinkEvent::Status { at, line }
    } else {
        LinkEvent::Unread { at, line }
    }
}

// The driver never interrupts the adapter, so `STOPPED` means something else wrote to it.
fn leaves_unknown_state(status: Status) -> bool {
    status.loses_settings() || status == Status::Stopped
}

// Exactly two hex digits. `from_str_radix` alone would also take `+1`.
fn hex_byte(text: &str) -> Option<u8> {
    if text.len() == 2 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        u8::from_str_radix(text, 16).ok()
    } else {
        None
    }
}

impl<L: Link> Transport for Elm<L> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let payload = request.payload();
        // A TP2.0 channel frame goes out as it is, with CAN auto formatting off.
        let raw = request.protocol() == Protocol::Tp20Channel;
        let longest = if raw {
            8
        } else {
            Addressing::Normal.max_single_frame()
        };
        if payload.is_empty() || payload.len() > longest {
            return Err(Error::Adapter(format!(
                "a {}-byte request doesn't fit one CAN frame; this adapter driver only sends single frames",
                payload.len()
            )));
        }
        // A module on a TP2.0 channel waits only its T1 (about 100 ms) for an ACK, and the
        // adapter listens for its whole timeout after a frame (docs/elm327.md#vw-tp20-channel-frames).
        if raw && self.raw && self.busy && matches!(request.target(), Target::Tp20Channel(_)) {
            self.trusted()?;
            self.interrupt()?;
        }
        self.ready()?;
        if self.raw != raw {
            for command in if raw { RAW_ON } else { RAW_OFF } {
                self.guarded_command(command)?;
            }
            self.raw = raw;
        }
        self.set_target(request)?;
        // A setting command's prompt may have been followed by a reset.
        self.check_idle()?;
        let line = hex(payload).replace(' ', "");
        if self.early_echo == Some(false) {
            self.write(format!("{line}\r").as_bytes())?;
        } else {
            self.write(line.as_bytes())?;
            self.check_early_echo(&line)?;
            self.write(b"\r")?;
        }
        self.quiet = Duration::ZERO;
        self.echo = Some(line);
        self.busy = true;
        self.drop_senders();
        Ok(())
    }

    // See docs/elm327.md#timing: an STN needs `STPTO`, a plain ELM327 can't wait longer.
    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        let Some(wait) = wait else {
            if self.timeout != ADAPTER_TIMEOUT {
                self.expect_ok("ATSTFF")?;
                self.timeout = ADAPTER_TIMEOUT;
            }
            if self.pace.is_none() {
                self.expect_ok("ATAT1")?;
            }
            return Ok(None);
        };
        if self.pace.is_none() {
            self.expect_ok("ATAT0")?;
        }
        if self.stn.is_none() {
            return Ok(Some(ADAPTER_TIMEOUT));
        }
        let ms = wait.min(STN_LONGEST_TIMEOUT).as_millis();
        let wait =
            Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)).max(ADAPTER_TIMEOUT);
        if wait != self.timeout {
            let command = if wait == ADAPTER_TIMEOUT {
                "ATSTFF".to_owned()
            } else {
                format!("STPTO{ms}")
            };
            // Recorded first: a command that fails may still have taken effect.
            self.timeout = wait;
            self.expect_ok(&command)?;
        }
        Ok(Some(self.timeout))
    }

    fn settle(&mut self) -> Result<(), Error> {
        if self.broken.is_some() {
            self.drop_senders();
        }
        if self.busy { self.ready() } else { Ok(()) }
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        let mut events = std::mem::take(&mut self.log);
        if self.lost > 0 {
            events.push(LinkEvent::Lost(std::mem::take(&mut self.lost)));
        }
        events
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        self.ready_to_receive()?;
        let deadline = Instant::now() + timeout.min(LONGEST_WAIT);
        loop {
            match self.next_request_event(deadline)? {
                None => return Err(Error::Timeout),
                Some(Event::Prompt) => {
                    self.prompt_after_request()?;
                    self.busy = false;
                    self.drop_senders();
                    return Err(Error::Timeout);
                }
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    Some(Line::Frame(frame)) if self.raw => {
                        return Ok(Response {
                            source: frame.id(),
                            payload: frame.data().to_vec(),
                        });
                    }
                    Some(Line::Frame(frame)) => {
                        if let Some(reply) = self.feed(frame.id(), frame.data(), &text) {
                            return Ok(reply);
                        }
                    }
                    Some(Line::Status(Status::BufferFull)) => {
                        return Err(Error::Adapter(
                            "the adapter said BUFFER FULL: its link is too slow for the replies, \
                             and some were lost; use a faster baud rate"
                                .into(),
                        ));
                    }
                    Some(Line::Status(status)) if status.is_failure() => {
                        return Err(Error::Adapter(format!("the adapter said {status}")));
                    }
                    Some(_) => {
                        self.hear(&text);
                    }
                    None => {}
                },
            }
        }
    }
}

impl<L: Link> Elm<L> {
    // Reads the echo of a request's digits, written without their carriage return, so a misheard
    // line is caught before it reaches the bus. An adapter that echoes nothing on the first
    // request is taken to echo whole lines only (docs/elm327.md#safety).
    fn check_early_echo(&mut self, line: &str) -> Result<(), Error> {
        let mut echoed = vec![0; line.len()];
        let mut got = 0;
        let deadline = Instant::now() + ECHO_WAIT;
        while got < echoed.len() {
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                break;
            };
            got += self.read(&mut echoed[got..], left)?;
        }
        echoed.truncate(got);
        if echoed.is_empty() && self.early_echo.is_none() {
            self.early_echo = Some(false);
            return Ok(());
        }
        if echoed.eq_ignore_ascii_case(line.as_bytes()) {
            self.early_echo = Some(true);
            // Its echo is checked again once the carriage return completes the line.
            let mut events = Vec::new();
            self.splitter.push(&echoed, &mut events);
            let now = SystemTime::now();
            self.events
                .extend(events.into_iter().map(|event| (now, event)));
            return Ok(());
        }
        let why = if echoed.is_empty() {
            format!("the adapter didn't echo {line}")
        } else {
            // Untrusted output that reaches a terminal: printable ASCII only.
            let shown: String = echoed
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() {
                        char::from(b)
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("the adapter echoed {shown} instead of {line}")
        };
        // Best effort: the driver stops either way, and reconnecting resets the adapter.
        let _ = self.write(KILL);
        Err(self.break_down(format!("{why}; the request wasn't sent")))
    }

    // Classifies a line printed after a request: `None` for its echo. Anything but a reply
    // leaves the adapter in an unknown state.
    fn reply_line(&mut self, text: &str) -> Result<Option<Line>, Error> {
        if let Some(request) = self.echo.take() {
            // The adapter has already acted on what it heard; all that's left is to stop.
            if !text.eq_ignore_ascii_case(&request) {
                return Err(
                    self.break_down(format!("the adapter echoed {text} instead of {request}"))
                );
            }
            return Ok(None);
        }
        match parse_line(text) {
            // It may search for a protocol next, sending frames nobody approved.
            Line::Status(status) if leaves_unknown_state(status) => {
                Err(self.break_down(format!("the adapter said {status}")))
            }
            // Such as a line printed with headers off after a reset, whose data reads as a
            // 29-bit ID.
            Line::Frame(frame) if frame.is_29_bit() != self.bits29 => {
                Err(self.break_down(format!(
                    "unexpected output from the adapter: {text} (not {} frame)",
                    if self.bits29 { "a 29-bit" } else { "an 11-bit" }
                )))
            }
            // The adapter lost the filter, and may be sending flow control for frames it
            // shouldn't see.
            Line::Frame(frame) if !filter_shows(&self.filter, frame.id()) => {
                Err(self.break_down(format!(
                    "a frame from {:03X} got past the receive filter: {text}",
                    frame.id()
                )))
            }
            // Such as a banner after a reset.
            Line::Ok | Line::Text(_) => {
                Err(self.break_down(format!("unexpected output from the adapter: {text}")))
            }
            line => Ok(Some(line)),
        }
    }

    fn prompt_after_request(&mut self) -> Result<(), Error> {
        match self.echo.take() {
            Some(request) => Err(self.break_down(format!("the adapter didn't echo {request}"))),
            None => Ok(()),
        }
    }

    fn ready_to_receive(&mut self) -> Result<(), Error> {
        self.trusted()?;
        if self.busy {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }
}
