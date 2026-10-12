//! ELM327 and STN adapters (such as an `OBDLink EX`), over any [`Link`].
//!
//! The adapter takes text commands: `AT` commands configure it, and a line of hex digits is a
//! request it puts on the bus. [`Elm`] only ever writes a fixed set of `AT` commands and the
//! hex of [`Approved`] requests. No single bit flipped on the way, which a serial line can do,
//! turns one of those commands into a line of hex digits, and the adapter's echo of every line
//! is checked against what was written: a request's before its carriage return, so a misheard
//! one never reaches the bus, when the adapter echoes characters as it reads them. It never ends
//! an empty line with a carriage return, which repeats the adapter's last command. Behaviour is
//! from the ELM327 datasheet (ELM327DS v2.0) and measurements on an STN; see `docs/elm327.md`.

pub mod codec;

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use obdcracker_core::isotp::{Addressing, MAX_SHORT_PAYLOAD, Progress, Reassembler};
use obdcracker_safety::{Approved, Target};

use crate::link::{Driver, Link, LinkKind};
use crate::{Error, LinkEvent, Response, Timing, Transport, hex};
use codec::{Event, Line, LineSplitter, Status, parse_line};

// Run after the reset, in order. Each must answer OK. One flipped bit must not turn any of them
// into a line of hex digits, so commands with a single non-hex letter (`ATE0`, `ATCAF1`,
// `ATCF700`) are out. Echo stays on, and CAN auto formatting and flow control stay at their
// defaults (on), which `check_defaults` makes sure no programmable parameter changed.
#[rustfmt::skip]
const SETUP: &[&str] = &[
    // Linefeeds off; spaces and headers on, so every frame shows its CAN ID and PCI byte
    "ATL0", "ATS1", "ATH1",
    // ISO 15765-4 CAN, 11-bit IDs, 500 kbit/s. Never automatic search: it sends probe frames
    // that no policy approved and no audit log records.
    "ATSP6",
    // Wait for replies after every request
    "ATR1",
    // Show every 11-bit reply ID from 0x700 to 0x7FF (`WIDE_FILTER`) until a request narrows it
    "ATCRA7XX",
    // Adaptive timing, capped at the longest timeout (0xFF x 4 ms)
    "ATAT1", "ATSTFF",
];

// Programmable parameters that would change a default the setup relies on (datasheet pp. 57-61):
// the number, its default value, and what it sets.
const KEPT_DEFAULTS: &[(u8, u8, &str)] = &[
    (0x09, 0x00, "echo"),
    (0x24, 0x00, "CAN auto formatting"),
    (0x25, 0x00, "CAN flow control"),
    // Off, or every frame line has its data length between the CAN ID and the data
    (0x29, 0xFF, "CAN data length display"),
];

// `AT CRA` patterns: three hex digits, each of which may be `X` (any). Every diagnostic reply ID,
// and every OBD-II emissions ECU's.
const WIDE_FILTER: &str = "7XX";
const OBD_FILTER: &str = "7EX";

/// The most [`LinkEvent`]s an [`Elm`] keeps until they're taken
/// ([`Transport::take_events`]); it counts any more as lost.
pub const MAX_EVENTS: usize = 4096;

/// The longest the adapter waits for a reply, or for more replies after one: `AT ST FF`.
pub const ADAPTER_TIMEOUT: Duration = Duration::from_millis(0xFF * 4);

// How long to wait for the adapter to go quiet before the reset, and the most time to spend.
const QUIET: Duration = Duration::from_millis(100);
const DRAIN_LIMIT: Duration = Duration::from_secs(2);
// How long a reset may take, and how many to try: the first may only interrupt the adapter.
const RESET_WAIT: Duration = Duration::from_secs(3);
const RESET_TRIES: usize = 2;
// How long to look for output the adapter shouldn't have printed before writing to it.
const IDLE_CHECK: Duration = Duration::from_millis(1);
// The most lines an answer to a command may have: `AT PPS` prints 12.
const MAX_ANSWER_LINES: usize = 32;
// How long an AT command may take.
const COMMAND_WAIT: Duration = Duration::from_secs(2);
// How long the adapter may take to print the longest reply, 4095 bytes (a first frame and 585
// consecutive frames, each a line of up to 29 characters), at 9600 baud, the slowest an ELM327
// starts at (datasheet p. 7), 10 bits a character: about 18 s.
const LONGEST_PRINT: Duration = Duration::from_millis(586 * 29 * 10 * 1000 / 9600 + 1);
// The most modules whose multi-frame replies are reassembled at once. Frames from more are
// dropped.
const MAX_SENDERS: usize = 16;
// The time to print the longest reply from every one of them.
const LONGEST_PRINT_ALL: Duration = LONGEST_PRINT.saturating_mul(16);
const _: () = assert!(MAX_SENDERS == 16, "update LONGEST_PRINT_ALL");
// The longest a request may run: the adapter's timeout for the first reply, the time to print
// the longest reply from every module (about 5 minutes at 9600 baud), and time for the link.
// Only an adapter that keeps printing gets near it: a working one ends each request with its
// prompt, and one that goes quiet is caught by `SILENCE_LIMIT`.
const LONGEST_REQUEST: Duration = ADAPTER_TIMEOUT
    .saturating_add(LONGEST_PRINT_ALL)
    .saturating_add(Duration::from_secs(1));
// The longest the adapter stays quiet during a request: its own timeout, plus the default P2*
// (5 s) that v2.1 and STN chips wait after a response-pending reply (ELM327DS v2.1, p. 90),
// plus time for the link. Any longer and it has hung.
const SILENCE_LIMIT: Duration = ADAPTER_TIMEOUT
    .saturating_add(Duration::from_secs(5))
    .saturating_add(Duration::from_secs(1));
// The longest any single receive waits, so a huge timeout can't overflow the clock.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);
// How long a request's digits may take to echo before its carriage return. The STN in an
// `OBDLink EX` echoes each character within about 15 ms (#54); this leaves room for a slow link.
const ECHO_WAIT: Duration = Duration::from_secs(1);
// Ends a line the adapter misheard so that it refuses it: two letters that aren't hex digits, so
// no single flipped bit of this leaves a line of hex digits, then the carriage return the adapter
// needs before it drops the line (an STN holds an unfinished line indefinitely, #54).
const KILL: &[u8] = b"XX\r";
// The characters a consecutive frame takes as the adapter prints it, with headers and spaces on
// and linefeeds off: `7E8 21 41 41 41 41 41 41 41 \r`.
const FRAME_LINE: u32 = 29;
// The link's byte rate when it can't be known: 9600 baud, the slowest an ELM327 starts at.
const SLOWEST_RATE: u32 = 9600 / 10;
// The byte rate at and above which an STN was seen to print a long reply with no gap between
// frames (#49: about 770 bytes at 115200 baud, no `BUFFER FULL`).
const STN_UNPACED_RATE: u32 = 115_200 / 10;

/// An ELM327-compatible adapter on CAN (ISO 15765-4, 11-bit IDs, 500 kbit/s).
///
/// The adapter must accept `AT CRA` with `X` digits: an ELM327 v2.0 or later, or an STN chip
/// (`OBDLink` adapters, which call themselves v1.4b). Older chips refuse it, and
/// [`Elm::connect`] fails.
///
/// Replies still arriving when the next request is sent are dropped: checked for signs of a
/// reset, but not returned, as that would let a late reply to a repeated request pass for a
/// fresh one. Their lines are reported as [`LinkEvent::Unread`] instead, which an
/// [`crate::Audited`] wrapper logs, along with every command sent to the adapter
/// ([`Transport::take_events`]); dropping the wrapper reads what's left of the last request
/// first ([`Transport::settle`]).
///
/// Requests must fit one CAN frame: up to 7 bytes. That covers the OBD-II reads and UDS 0x22
/// with up to 3 DIDs, but not every request the policy allows (0x22 with 4 DIDs is 9 bytes).
/// Longer ones are refused before anything is written. Multi-frame replies are reassembled
/// here, per module, from the frames the adapter prints, for up to 16 modules per request;
/// frames from any more are dropped, so those modules' replies time out.
///
/// The adapter shows only the frames its receive filter (`AT CRA`) passes, set per request: the
/// module's reply ID when the request knows it (an OBD-II ECU, or a module the policy was
/// narrowed to with a vehicle profile), 0x7E0..=0x7EF for a broadcast, and 0x700..=0x7FF
/// otherwise. Frames it doesn't show get no flow control, so another module's long reply on a
/// busy bus isn't acknowledged in the tester's name.
///
/// The adapter sends ISO-TP flow control frames itself, which no audit log records: for a
/// broadcast (0x7DF), its standard ones to each ECU, and for a physical request to the module's
/// request ID. Each says continue, with no block limit. A physical request's also asks for a gap
/// between frames (`STmin`) of the time the adapter takes to print one frame on the link
/// ([`Link::byte_rate`], or 9600 baud when unknown), up to 127 ms. A broadcast's can't: only
/// the adapter's standard flow control reaches each ECU's own request ID, and it asks for no
/// gap. OBD-II broadcast replies are short, but several ECUs sending multi-frame replies at
/// once on a slow link can still fill the buffer. Frames arrive faster than a
/// slow link carries them away as text, and a plain ELM327 holds only 512 bytes before it
/// prints `BUFFER FULL` and drops the rest. An STN chip on a link of 115200 baud or faster gets
/// no gap, which a real one handled (#49).
///
/// The adapter's state is unknown, and every later call fails without writing anything (connect
/// again), if:
/// - it doesn't finish a command in time, or stays quiet in a request for longer than its own
///   timeout plus a response-pending wait (about 7 s, counted while the driver waits);
/// - it refuses a setting;
/// - it echoes a line other than the one written (a serial error). A request's digits are
///   written first, and its carriage return only once they've echoed correctly; otherwise the
///   line is ended with `XX` so the adapter refuses it, and nothing reaches the bus. An adapter
///   that echoes nothing before the carriage return on the first request is taken to echo whole
///   lines only, and a request it misheard has gone on the bus by the time its echo shows it;
/// - it prints something unexpected: an overlong line, `STOPPED` (the driver never interrupts
///   it, so something else did), a frame from outside its receive filter, or anything at all
///   between its prompt and the next line it's sent;
/// - it says it reset (`LV RESET`, `ERRxx`, `LP ALERT`, a banner) or is searching for a
///   protocol (`SEARCHING...`, `UNABLE TO CONNECT`);
/// - or the link fails.
///
/// [`Elm::connect`] also refuses an adapter whose programmable parameters turn off echo, CAN auto
/// formatting or CAN flow control, or turn on the CAN data length display, by default.
#[derive(Debug)]
pub struct Elm<L> {
    link: L,
    splitter: LineSplitter,
    // What the adapter printed, read but not used yet, with when it was read.
    events: VecDeque<(SystemTime, Event)>,
    // When the event last taken from `events` was read.
    event_at: SystemTime,
    header: Option<u32>,
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
    senders: Vec<(u32, Reassembler<Vec<u8>>)>,
    // What it did besides requests and replies, until taken, and how many more were dropped.
    log: Vec<LinkEvent>,
    lost: usize,
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
            senders: Vec::new(),
            log: Vec::new(),
            lost: 0,
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
        // Adaptive timing learns the timeout from response times and may set it below the gap
        // a paced module leaves between frames, ending the reply early (ELM327DS p. 12; the
        // OBDLink FRPM says the same timer waits for each next frame). So it's off when pacing,
        // and the timeout is always `AT ST FF`: every request then waits about 1 s after its
        // last reply.
        if elm.pace.is_some() {
            elm.expect_ok("ATAT0")?;
        }
        Ok(())
    }

    /// Timing for [`crate::exchange`] through this adapter. The adapter decides when a request
    /// is over: it prints its prompt, which ends the exchange at once. So P2 is only an outer
    /// bound: [`ADAPTER_TIMEOUT`] plus the time to print the longest reply (4095 bytes) from
    /// each of up to 16 modules at 9600 baud, about 5 minutes. P2* gets the same print
    /// allowance on top of the default. An adapter that goes quiet in a request without
    /// finishing it fails within seconds instead (see [`Elm`]).
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
    /// The ID is the banner from the reset and the STN version is `STI`'s answer from
    /// [`Elm::connect`]: asking again with `ATI` would make a reset now look like an answer.
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

    /// The link to the adapter. A [`Link`] can't be written to or read from outside this crate,
    /// so this can't be used to send anything or to hide the adapter's output from the driver.
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
            self.write(b"ATZ\r")?;
            let deadline = Instant::now() + RESET_WAIT;
            let mut banner = None;
            // What it printed, for the report; a flood isn't kept.
            let mut answer = Vec::new();
            let reset = loop {
                let event = match self.next_event(deadline) {
                    Ok(Some(event)) => event,
                    Ok(None) => break Ok(false),
                    Err(e) => break Err(e),
                };
                if let Event::Line(line) = &event
                    && answer.len() < MAX_ANSWER_LINES
                {
                    answer.push(line.clone());
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
        // `PPS` and all of these arrived together in ELM327 v1.1 (ELM327DS v2.1, p. 90), and STN
        // chips list them too, so a summary without one was cut short.
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
        } else {
            self.lost += 1;
        }
    }

    // Writes `command` and reads its answer's lines into `lines`.
    fn command_answer(&mut self, command: &str, lines: &mut Vec<String>) -> Result<(), Error> {
        self.write(format!("{command}\r").as_bytes())?;
        let deadline = Instant::now() + COMMAND_WAIT;
        let mut echoed = false;
        loop {
            match self.next_event(deadline)? {
                // Without the prompt the answer may not be over, so the next command can't tell
                // where its own starts. Some clones leave it off (python-OBD #160, #205).
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
                // The rest of the answer may still be coming, so the next command can't tell
                // where its own answer starts.
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
                    // The banner means a reset; `info` never asks for it.
                    if line.starts_with("ELM327") {
                        return Err(self.break_down(format!("the adapter reset: {line}")));
                    }
                    // A working adapter's answers are a few lines; don't collect a flood.
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

    // What a refused command says about the adapter: `X` digits in `AT CRA` arrived in ELM327
    // v2.0, and most clones that claim it (or v1.5, which was never released) refuse them.
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

    // Fails if the adapter can't be trusted; otherwise waits for any request still running.
    fn ready(&mut self) -> Result<(), Error> {
        if let Some(why) = &self.broken {
            return Err(Error::Adapter(format!(
                "the adapter is in an unknown state ({why}); connect again"
            )));
        }
        if !self.busy {
            return self.check_idle();
        }
        // The rest of the last request's replies are dropped, but a reset among them still
        // counts.
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
                    // Not the request's echo, which `reply_line` checks.
                    if self.echo.is_none() {
                        self.note(LinkEvent::Unread {
                            at: self.event_at,
                            line: text.clone(),
                        });
                    }
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
        self.check_idle()
    }

    // The adapter prints nothing between its prompt and the next line it's sent, so anything
    // already read past the prompt, or waiting on the link, could be a reset.
    fn check_idle(&mut self) -> Result<(), Error> {
        // Read until the deadline whatever arrives: a stray NUL (datasheet p. 8) makes no event
        // but may come just ahead of a reset. A reset whose first byte is still on its way at
        // the deadline can't be seen before writing; the checks on the reply catch it then (a
        // reset adapter has headers off, and may say SEARCHING...).
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
    // An adapter quiet for longer than `SILENCE_LIMIT` in a request has hung. Silence is the
    // time the driver spent waiting, added up across calls, so neither a caller that reads late
    // nor one that polls with short timeouts skews it.
    fn next_request_event(&mut self, deadline: Instant) -> Result<Option<Event>, Error> {
        loop {
            let Some(left) = SILENCE_LIMIT
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
            // Only the silent tail counts once anything arrived.
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

    fn set_target(&mut self, request: &Approved) -> Result<(), Error> {
        let id = request.target().can_id();
        if self.header != Some(id) {
            self.expect_ok(&format!("ATSH{id:03X}"))?;
            self.header = Some(id);
        }
        // A broadcast's flow control must go to each answering ECU's own request ID, which only
        // the adapter's ISO 15765-4 handling does, with no gap. Mode 2 (driver's data, adapter's
        // header) can't: it sends to the First Frame's own ID (p. 48). So only a physical
        // request is paced: mode 1, to its request ID.
        let gap = st_min(self.pace);
        let flow = if id == 0x7DF || (gap == 0 && (0x7E0..=0x7E7).contains(&id)) {
            Flow::Standard
        } else {
            Flow::To(id, gap)
        };
        if self.flow != Some(flow) {
            match flow {
                Flow::Standard => self.expect_ok("ATFCSM0")?,
                Flow::To(id, gap) => {
                    // Continue to send, no block limit, and the gap. `AT FC SD` keeps two
                    // non-hex letters (T, S), so one flipped bit can't make it a bus request.
                    self.expect_ok(&format!("ATFCSH{id:03X}"))?;
                    self.expect_ok(&format!("ATFCSD3000{gap:02X}"))?;
                    self.expect_ok("ATFCSM1")?;
                }
            }
            self.flow = Some(flow);
        }
        // Each `ATCRA` line keeps two non-hex letters (T, R), so one flipped bit can't make it a
        // bus request.
        let filter = match (request.reply_id(), request.target()) {
            (Some(reply), _) => format!("{reply:03X}"),
            (None, Target::ObdFunctional) => OBD_FILTER.to_owned(),
            (None, Target::Physical(_)) => WIDE_FILTER.to_owned(),
        };
        if self.filter != filter {
            self.expect_ok(&format!("ATCRA{filter}"))?;
            self.filter = filter;
        }
        Ok(())
    }
}

// The link's byte rate if replies are paced to it: always, except for an STN on a fast link.
fn pace(stn: bool, byte_rate: Option<u32>) -> Option<u32> {
    let rate = byte_rate.filter(|&rate| rate > 0).unwrap_or(SLOWEST_RATE);
    (!stn || rate < STN_UNPACED_RATE).then_some(rate)
}

// The gap between a module's consecutive frames, in ms, that keeps the adapter's output buffer
// from filling: the time to print one frame line at the link's byte rate, rounded up, at most
// 127 ms (the most STmin allows).
fn st_min(pace: Option<u32>) -> u8 {
    let Some(rate) = pace else {
        return 0;
    };
    let ms = (FRAME_LINE * 1000).div_ceil(rate);
    u8::try_from(ms.min(0x7F)).unwrap_or(0x7F)
}

// Whether an `AT CRA` pattern shows frames from `id`.
fn filter_shows(pattern: &str, id: u32) -> bool {
    let id = format!("{id:03X}");
    id.len() == pattern.len()
        && pattern
            .bytes()
            .zip(id.bytes())
            .all(|(want, got)| want == b'X' || want == got)
}

// Whether a status means the adapter's settings, or what it reads next, can't be trusted: it
// lost its settings, or it was interrupted (`STOPPED`), which this driver never does, so
// something else wrote to it and the interrupting byte may start the next line it reads.
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
        if payload.is_empty() || payload.len() > Addressing::Normal.max_single_frame() {
            return Err(Error::Adapter(format!(
                "a {}-byte request doesn't fit one CAN frame; this adapter driver only sends single frames",
                payload.len()
            )));
        }
        self.ready()?;
        self.set_target(request)?;
        // A setting command's prompt may have been followed by a reset.
        self.check_idle()?;
        // The adapter ignores spaces, but leaving them out keeps the line short.
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
        self.senders.clear();
        Ok(())
    }

    // Adaptive timing off waits the whole `AT ST FF` (about 1 s) for each reply. When pacing,
    // it's always off (see `connect`).
    fn patient(&mut self, on: bool) -> Result<(), Error> {
        if self.pace.is_some() {
            return Ok(());
        }
        self.expect_ok(if on { "ATAT0" } else { "ATAT1" })
    }

    // The rest of the last request's output is read, and reported as unread.
    fn settle(&mut self) -> Result<(), Error> {
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
                    return Err(Error::Timeout);
                }
                // It can't be read, so it could hide a reset.
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                // `None` is the echo.
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    Some(Line::Frame(frame)) => {
                        if let Some(reply) = self.feed(frame.id(), frame.data()) {
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
                    _ => {}
                },
            }
        }
    }
}

impl<L: Link> Elm<L> {
    // Reads the echo of a request's digits, written without their carriage return, so a line the
    // adapter misheard is caught before it can go on the bus. The adapter holds the line until
    // the carriage return. An adapter that echoes nothing before it, on the first request, is
    // taken to echo only whole lines, and its echo is checked after the carriage return instead.
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
            // The line's carriage return completes it, and its echo is checked again then.
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
            // Untrusted output that reaches a terminal: only printable ASCII.
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

    // Classifies a line printed after a request: `None` for its echo. Anything that means the
    // adapter lost its settings or misheard the request, or that isn't a reply at all, leaves
    // it in an unknown state.
    fn reply_line(&mut self, text: &str) -> Result<Option<Line>, Error> {
        if let Some(request) = self.echo.take() {
            // By now the adapter has sent whatever it heard; all that's left is to stop.
            if !text.eq_ignore_ascii_case(&request) {
                return Err(
                    self.break_down(format!("the adapter echoed {text} instead of {request}"))
                );
            }
            return Ok(None);
        }
        match parse_line(text) {
            // Its settings are gone: it may even search for a protocol on the next request,
            // sending frames nobody approved.
            Line::Status(status) if leaves_unknown_state(status) => {
                Err(self.break_down(format!("the adapter said {status}")))
            }
            // A frame the receive filter hides: the adapter lost the filter, and may be sending
            // flow control for frames it shouldn't see.
            Line::Frame(frame) if !filter_shows(&self.filter, frame.id()) => {
                Err(self.break_down(format!(
                    "a frame from {:03X} got past the receive filter",
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

    // The adapter finished a request; it must have echoed it first.
    fn prompt_after_request(&mut self) -> Result<(), Error> {
        match self.echo.take() {
            Some(request) => Err(self.break_down(format!("the adapter didn't echo {request}"))),
            None => Ok(()),
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
