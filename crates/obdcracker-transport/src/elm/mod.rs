//! ELM327 and STN adapters (such as an `OBDLink EX`), over any [`Link`].
//!
//! A line of hex digits is a request the adapter puts on the bus, so [`Elm`] writes only a fixed
//! set of `AT` commands and the hex of [`Approved`] requests, checks every echo, and never
//! writes an empty line. See [`docs/elm327.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md) for the adapter's behaviour and why.

pub mod codec;

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use obdcracker_core::isotp::{
    self, Addressing, CAN_DLC, FlowControl, FlowStatus, MAX_SHORT_PAYLOAD, Progress, Reassembler,
    Segmenter, Step,
};
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
// Whether the monitor acknowledges the frames it hears, set after `RAW_ON` and put back to the
// silent default after `RAW_OFF`: `STCMM 1`/`0` on an STN (OBDLink FRPM, section 8.8), `AT CSM 0`/`1`
// on an ELM327 (silent monitoring off/on). Behind a gateway the adapter is the only other node on
// the diagnostic bus, and a module repeats a frame nobody acknowledges until the adapter reports
// `CAN ERROR` (docs/elm327.md#vw-tp20-channel-frames). Each has two or more non-hex letters.
const MONITOR_ACK_ELM: [&str; 2] = ["ATCSM0", "ATCSM1"];
const MONITOR_ACK_STN: [&str; 2] = ["STCMM1", "STCMM0"];

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
// The most bytes of a multi-frame request: its `STPX d:` line is echoed back as one line, which
// the line splitter caps at `MAX_LINE`. Far below the STN's own limit, 2 KB (docs/elm327.md).
const STPX_MAX: usize = (codec::MAX_LINE - "STPX d:".len()) / 2;
// How long a request's digits may take to echo before its carriage return (#54).
const ECHO_WAIT: Duration = Duration::from_secs(1);
// Ends a misheard line so the adapter refuses it: no single flipped bit of this leaves a line of
// hex digits (docs/elm327.md#safety).
const KILL: &[u8] = b"XX\r";
// Monitors the bus with the filters as set, printing every frame until stopped: `AT MA` on an
// ELM327 (ELM327DS p. 20), `STM` on an STN, where `AT MA` and `STMA` pass every ID whatever
// `AT CRA` says (OBDLink FRPM, section 7.3). Each has two or more non-hex letters, so no single
// flipped bit makes a bus request (docs/elm327.md#safety).
const MONITOR_ELM: &str = "ATMA";
const MONITOR_STN: &str = "STM";
// Stops an adapter listening after a request, or monitoring (ELM327DS pp. 7, 20; STN FRPM,
// section 8.9), which discards it. No single flipped bit of it is a hex digit, and if the prompt
// came first, `KILL`'s `X\r` ends the line it starts so the adapter refuses it.
const INTERRUPT: &[u8] = b"X";
// The programmable parameter that holds the byte the adapter pads a short CAN frame with
// (datasheet p. 68).
const FILLER_PP: u8 = 0x26;
/// The longest the driver lets pass between two frames of a request it sends in segments,
/// measured from the carriage return of the frame before (or from reading the flow control, for
/// the first consecutive frame): half of ISO 15765-2's `N_Cr`, 1 s. A frame that would go later is
/// killed instead ([`docs/design/elm-caf0-segmenting.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/design/elm-caf0-segmenting.md), section 6).
pub const SEGMENT_GAP: Duration = Duration::from_millis(500);
/// The longest a request sent in segments may take from its first frame to its last.
pub const SEGMENT_TRANSFER: Duration = Duration::from_secs(30);
/// How long the driver writes nothing after a transfer it stopped part-way: `N_Cr` plus 250 ms, so
/// the module has dropped the part it received (section 7).
pub const SEGMENT_HOLD: Duration = Duration::from_millis(1250);
/// The most wait flow controls in a row the driver takes before it gives up on a request it
/// sends in segments.
pub const SEGMENT_MAX_WAITS: u8 = 10;
// Characters in a printed consecutive frame, `7E8 21 41 41 41 41 41 41 41 \r`, and with a 29-bit
// ID, `17 FE 00 76 21 41 41 41 41 41 41 41 \r`.
const FRAME_LINE: u32 = 29;
const FRAME_LINE_29: u32 = 37;
// A reply's bus time assumes the adapter prints at half the link's byte rate, as it may leave gaps
// between bytes, and subtracts this on top for USB latency timers and scheduling
// (docs/elm327.md#when-a-reply-left-the-bus).
const PRINT_RATE_SHARE: u32 = 2;
const HOST_ALLOWANCE: Duration = Duration::from_millis(100);
// A read that waited this long returned when its bytes arrived; a quicker one may have found them
// waiting.
const WAITED: Duration = Duration::from_millis(1);
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
/// A request must fit one CAN frame (up to 7 bytes), or on an adapter that has shown it echoes each
/// character as it reads it, be up to 44 bytes: an STN chip (such as an `OBDLink`) sends it as an
/// `STPX` command, which segments it
/// ([`docs/elm327.md#multi-frame-requests`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#multi-frame-requests)),
/// and any other adapter has the driver write its ISO-TP frames itself with `AT CAF0`, for a
/// module whose reply ID is known
/// ([`docs/design/elm-caf0-segmenting.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/design/elm-caf0-segmenting.md)).
/// Anything else is refused before anything is written. Multi-frame replies are reassembled per
/// module, for up to 16 modules per request.
/// Replies still arriving at the next request are dropped and reported as [`LinkEvent`]s,
/// along with every command sent ([`Transport::take_events`]).
///
/// The adapter sends ISO-TP flow control frames itself, which no audit log records. A physical
/// request's asks for a gap between frames from the link's rate ([`Link::byte_rate`], 9600 baud
/// when unknown).
///
/// A reply's [`Response::bus_time`] is set where the link has a byte rate ([`Link::byte_rate`]), and
/// is never later than the reply left the bus
/// ([`docs/elm327.md#when-a-reply-left-the-bus`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#when-a-reply-left-the-bus)).
///
/// If the adapter does anything unexpected (it misechoes, resets, goes quiet, refuses a setting
/// or the link fails), its state is unknown: every later call fails without writing anything,
/// and the caller must connect again.
///
/// See [`docs/elm327.md#failure-states`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#failure-states), [`#flow-control-per-target`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#flow-control-per-target) and [`#receive-filter`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#receive-filter).
// Each flag is an independent piece of the adapter's state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct Elm<L> {
    link: L,
    splitter: LineSplitter,
    // What the adapter printed, read but not used yet, with when it was read.
    events: VecDeque<(Stamp, Event)>,
    // When the event last taken from `events` was read.
    event_at: Stamp,
    // How many bytes the link has handed over, ever.
    printed: u64,
    // The bytes of the latest read can't have reached the host before this (`WAITED`).
    arrived_after: Instant,
    // A time the link's buffer was last known to hold only bytes that arrived later: the end of the
    // latest read that got nothing or waited (`WAITED`), or when the request in progress was sent.
    drained: Instant,
    // When the request in progress was sent, and what `printed` was then.
    sent: Option<(Instant, u64)>,
    header: Option<u32>,
    // Whether the adapter is on 29-bit CAN (`ATSP7`) rather than 11-bit (`ATSP6`, the setup's).
    bits29: bool,
    // Whether the adapter sends raw frames ([`RAW_ON`]), for VW TP2.0.
    raw: bool,
    // Whether `AT CAF0` is on to send a request in segments, which `send` switches lazily
    // (docs/design/elm-caf0-segmenting.md, section 8).
    segmenting: bool,
    // Whether `AT R0` was written and no `OK` to `ATR1` has followed (section 7).
    responses_off: bool,
    // The byte the adapter pads with (PP 26), or `None` if `ATPPS` didn't list it.
    filler: Option<u8>,
    // After a transfer stopped part-way, nothing is written before this (section 7).
    hold_until: Option<Instant>,
    // The bounds on a transfer in segments; tests may only tighten them
    // ([`Elm::tighten_segment_bounds`]).
    segment_gap: Duration,
    segment_transfer: Duration,
    // Lines `interrupt` reads before the adapter's `STOPPED`, kept for a caller that fails the
    // request on them. They are reported as unread all the same.
    caught: Option<Vec<String>>,
    // Whether the adapter's adaptive timing (`AT AT1`) is on, as far as we know: `None` while a
    // command that may have changed it is unanswered, so the next `sync_adaptive` sends it again.
    adaptive: Option<bool>,
    // Whether a patient window is open ([`Transport::patient`]).
    patient: bool,
    flow: Option<Flow>,
    // The `AT CRA` pattern in effect.
    filter: String,
    // A request is out and the adapter hasn't printed its prompt yet.
    busy: bool,
    // The request in progress is a frame on an open TP2.0 channel, so when the adapter's listen
    // ends before the caller's wait does, `recv` monitors the channel instead of going quiet
    // (docs/elm327.md#vw-tp20-channel-frames).
    listen: bool,
    // The adapter is monitoring the bus (`MONITOR_ELM` or `MONITOR_STN`) and prints no prompt
    // until the driver stops it.
    monitoring: bool,
    // A monitor printed `BUFFER FULL` while the driver was stopping it: frames were lost.
    monitor_overflow: bool,
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
    // turns out to use them. Once one doesn't fit, no later line is kept (`hear`), so every
    // kept line was read before every lost one and `Lost` can follow them in order.
    overflowed: usize,
    // What it did besides requests and replies, until taken, and how many more were dropped.
    log: Vec<LinkEvent>,
    lost: usize,
}

// When a read from the link finished, and how many bytes the link had handed over by then.
#[derive(Debug, Clone, Copy)]
struct Stamp {
    time: SystemTime,
    // The bytes of the read can't have reached the host before this.
    arrived_after: Instant,
    printed: u64,
}

impl Default for Stamp {
    fn default() -> Self {
        Self {
            time: SystemTime::UNIX_EPOCH,
            arrived_after: Instant::now(),
            printed: 0,
        }
    }
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
            event_at: Stamp::default(),
            printed: 0,
            arrived_after: Instant::now(),
            drained: Instant::now(),
            sent: None,
            header: None,
            bits29: false,
            raw: false,
            segmenting: false,
            responses_off: false,
            filler: None,
            hold_until: None,
            segment_gap: SEGMENT_GAP,
            segment_transfer: SEGMENT_TRANSFER,
            caught: None,
            adaptive: None,
            patient: false,
            flow: None,
            filter: WIDE_FILTER.to_owned(),
            busy: false,
            listen: false,
            monitoring: false,
            monitor_overflow: false,
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
        // SETUP ends with `ATAT1`.
        elm.adaptive = Some(true);
        // Only an STN chip names itself so; a clone may answer anything.
        let stn = elm.command("STI")?.join(" ");
        elm.stn = stn.starts_with("STN").then_some(stn);
        elm.pace = pace(elm.stn.is_some(), elm.link.byte_rate());
        // A learned timeout could be shorter than a paced module's gap and end its reply early.
        elm.sync_adaptive()
    }

    // Whether the adapter should learn how long to wait (`AT AT1`). Not while pacing, in raw mode,
    // segmenting (a learned timeout could end the wait for a slow module's flow control, #218) or
    // in a patient window: each needs it to wait its whole timeout after a frame, and a
    // learned one from the fast setup replies ended the wait for a TP2.0 module's data after
    // its ACK (#218).
    fn adaptive_wanted(&self) -> bool {
        self.pace.is_none() && !self.raw && !self.segmenting && !self.patient
    }

    // Sends `AT AT0` or `AT AT1` if the adapter isn't in the state `adaptive_wanted` names. Every
    // change to `pace`, `raw`, `segmenting` or `patient` calls this after making it.
    fn sync_adaptive(&mut self) -> Result<(), Error> {
        let wanted = self.adaptive_wanted();
        if self.adaptive == Some(wanted) {
            return Ok(());
        }
        // Unknown until the adapter has answered: a command that fails may still have taken effect.
        self.adaptive = None;
        let command = if wanted { "ATAT1" } else { "ATAT0" };
        // Written like the other mode switch commands once the adapter has shown it echoes
        // characters as it reads them; before that (a patient window can open first) as any
        // setting. Either way the line holds a non-hex letter twice, so a single flipped bit
        // can't make it a bus request.
        if self.early_echo == Some(true) {
            self.guarded_command(command)?;
        } else {
            self.expect_ok(command)?;
        }
        self.adaptive = Some(wanted);
        Ok(())
    }

    /// Timing for [`crate::exchange`] through this adapter. The adapter's prompt ends a request,
    /// so P2 and P2* are only outer bounds, about 7 minutes; an adapter that goes quiet
    /// fails within seconds instead. See [`docs/elm327.md#timing`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/elm327.md#timing).
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
            // No parameters: the factory filler.
            self.filler = Some(0x00);
            return Ok(());
        }
        let mut seen = Vec::new();
        let mut filler = None;
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
                if pp == FILLER_PP {
                    filler = Some(if on { value } else { 0x00 });
                }
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
        // A summary without PP 26 only refuses sending in segments (`check_segmenting`).
        self.filler = filler;
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

    // The setting that makes the monitor acknowledge frames (`acknowledge`), or silent again.
    fn monitor_ack_command(&self, acknowledge: bool) -> &'static str {
        let commands = if self.stn.is_some() {
            MONITOR_ACK_STN
        } else {
            MONITOR_ACK_ELM
        };
        commands[usize::from(!acknowledge)]
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
            Err(self.break_down(self.refusal(command, &lines)))
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
        Err(self.break_down(self.refusal(command, &lines)))
    }

    // Why a setting command didn't answer `OK`.
    fn refusal(&self, command: &str, lines: &[String]) -> String {
        if lines.iter().map(String::as_str).eq(["?"]) {
            format!(
                "the adapter doesn't support {command}{}",
                self.needs_hint(command)
            )
        } else {
            format!("{command} failed: {}", lines.join(" / "))
        }
    }

    // `X` digits in `AT CRA` arrived in ELM327 v2.0, and most clones claiming it refuse them.
    fn needs_hint(&self, command: &str) -> String {
        if command.starts_with("ATCRA") && command.contains('X') {
            format!(
                "; this driver needs an ELM327 v2.0 or later, or an STN chip (OBDLink). This one \
                 says it's {}, but many clones claim a version they don't implement",
                self.banner
            )
        } else if MONITOR_ACK_ELM.contains(&command) || MONITOR_ACK_STN.contains(&command) {
            // Raw mode isn't entered: its monitor couldn't hear a module's answer.
            "; without it the adapter's monitor wouldn't acknowledge a module's frames, and the \
             module would repeat each one until the adapter said CAN ERROR"
                .to_owned()
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
        // A monitor prints no prompt, so nothing else can be written until it's stopped.
        if self.busy && self.monitoring {
            self.interrupt()?;
        }
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
                        self.unread(text.clone());
                    }
                    self.reply_line(&text)?;
                }
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
            }
        }
        self.busy = false;
        self.take_overflow()?;
        self.check_idle()
    }

    // Reports a line nobody read. A monitor's `BUFFER FULL` means frames were lost: the caller
    // is told once the monitor has stopped (`take_overflow`).
    fn unread(&mut self, text: String) {
        // The caller sees it too, but it is reported all the same: the audit log shows what was
        // heard (docs/pitfalls.md). An adapter that never stops printing mustn't fill memory.
        if let Some(caught) = &mut self.caught
            && caught.len() < MAX_ANSWER_LINES
        {
            caught.push(text.clone());
        }
        if self.monitoring && matches!(parse_line(&text), Line::Status(Status::BufferFull)) {
            self.monitor_overflow = true;
        }
        self.note(left_over(self.event_at.time, text));
    }

    fn take_overflow(&mut self) -> Result<(), Error> {
        if std::mem::take(&mut self.monitor_overflow) {
            return Err(Error::Adapter(
                "the adapter said BUFFER FULL while monitoring: its link is too slow for the \
                 frames, and some were lost; use a faster baud rate"
                    .into(),
            ));
        }
        Ok(())
    }

    // Starts monitoring the bus right after the prompt, with the receive filter set for the
    // channel, to hear the frames the module sends from now on. Written like the other mode
    // switches: its echo is checked before the carriage return. Prints no prompt until
    // `interrupt` stops it.
    fn start_monitor(&mut self) -> Result<(), Error> {
        let command = if self.stn.is_some() {
            MONITOR_STN
        } else {
            MONITOR_ELM
        };
        if self.early_echo != Some(true) {
            return Err(Error::Adapter(format!(
                "{command} needs an adapter that echoes each character as it reads it (such as \
                 an OBDLink), and this one hasn't shown it does; send an ISO-TP request first"
            )));
        }
        self.check_idle()?;
        let at = SystemTime::now();
        // Noted however it ends: a misheard command may still have done something.
        let written = self
            .write(command.as_bytes())
            .and_then(|()| self.check_early_echo(command))
            .and_then(|()| self.write(b"\r"));
        self.note(LinkEvent::Command {
            at,
            command: command.to_owned(),
            answer: Vec::new(),
        });
        written?;
        self.quiet = Duration::ZERO;
        self.echo = Some(command.to_owned());
        self.monitoring = true;
        Ok(())
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
            let now = self.stamp();
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

    // Stops the adapter listening for more of the last request's replies, or monitoring. Lines it
    // printed until then that nobody read are reported as unread.
    fn interrupt(&mut self) -> Result<(), Error> {
        // It may have finished already, its prompt read or waiting on the link: then there's
        // nothing to stop.
        let deadline = Instant::now() + IDLE_CHECK;
        while let Some(event) = self.next_event(deadline)? {
            match event {
                // `ready` finishes the request as usual.
                Event::Prompt if !self.monitoring => {
                    self.events.push_front((self.event_at, Event::Prompt));
                    return Ok(());
                }
                // Nothing was written to stop it.
                Event::Prompt => {
                    return Err(self.break_down("the adapter stopped monitoring on its own".into()));
                }
                Event::Overlong => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Event::Line(text) => {
                    if self.reply_line(&text)?.is_some() {
                        self.unread(text);
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
        // A monitor's command has been echoed by now, whether or not anyone read it.
        if std::mem::take(&mut self.monitoring)
            && let Some(request) = self.echo.take()
        {
            return Err(self.break_down(format!("the adapter didn't echo {request}")));
        }
        self.listen = false;
        self.busy = false;
        self.drop_senders();
        self.take_overflow()
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
                        self.unread(text);
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
        let started = Instant::now();
        let n = self
            .link
            .read(buf, timeout, Driver::new())
            .map_err(|e| self.break_down(format!("{kind} link: {e}")))?;
        let ended = Instant::now();
        self.printed = self.printed.saturating_add(n as u64);
        // Bytes found waiting could have come at any time since the link was last drained, and if
        // that was long before this read began, the caller was away.
        let waited = ended.saturating_duration_since(started) >= WAITED
            && started.saturating_duration_since(self.drained) <= HOST_ALLOWANCE;
        self.arrived_after = if waited { ended } else { self.drained };
        // A short read that got bytes doesn't show that none are left: `Link::read` may return
        // part of what has arrived.
        if n == 0 || waited {
            self.drained = ended;
        }
        Ok(n)
    }

    fn stamp(&self) -> Stamp {
        Stamp {
            time: SystemTime::now(),
            arrived_after: self.arrived_after,
            printed: self.printed,
        }
    }

    // A time no later than when the reply just taken from `events` left the bus
    // (docs/elm327.md#when-a-reply-left-the-bus): the earliest its bytes can have reached the host,
    // less the time to print every byte the request has brought at a share of the link's rate and
    // less `HOST_ALLOWANCE`, but not before the request was sent. None where the link has no known
    // byte rate.
    fn bus_time(&self) -> Option<Instant> {
        let rate = self.link.byte_rate().filter(|&rate| rate > 0)?;
        let (sent, printed_then) = self.sent?;
        let printed = self.event_at.printed.saturating_sub(printed_then);
        let assumed = u128::from((rate / PRINT_RATE_SHARE).max(1));
        let nanos = u128::from(printed) * 1_000_000_000 / assumed;
        let behind = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
            .saturating_add(HOST_ALLOWANCE);
        Some(
            self.event_at
                .arrived_after
                .checked_sub(behind)
                .map_or(sent, |at| at.max(sent)),
        )
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
            let now = self.stamp();
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
        let bus_time = self.bus_time();
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
                let reply = Response::new(source, payload.to_vec()).at_bus_time(bus_time);
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
        if self.overflowed == 0 && self.heard.len() < MAX_EVENTS {
            self.heard
                .push((number, self.event_at.time, line.to_owned()));
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

// The driver interrupts the adapter only to stop a listen or a monitor, and reads that
// `STOPPED` itself (`interrupt`, `read_interrupted`). Anywhere else it means something else wrote.
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
        let single = Addressing::Normal.max_single_frame();
        let long = !raw && payload.len() > single;
        // Longer requests go out as `STPX` on an STN (docs/elm327.md#multi-frame-requests), and
        // on any other adapter as raw frames written with `AT CAF0`
        // (docs/design/elm-caf0-segmenting.md).
        let stpx = long && self.stn.is_some();
        if payload.is_empty() || (raw && payload.len() > 8) || (!raw && payload.len() > STPX_MAX) {
            return Err(Error::Adapter(format!(
                "a {}-byte request doesn't fit this driver's limit ({STPX_MAX} bytes where it \
                 sends in segments, {single} on other adapters)",
                payload.len(),
            )));
        }
        let segments = if long && !stpx {
            Some(self.check_segmenting(request)?)
        } else {
            None
        };
        if stpx && self.early_echo != Some(true) {
            return Err(Error::Adapter(format!(
                "a {}-byte request needs an adapter that echoes each character as it reads it \
                 (such as an OBDLink), and this one hasn't shown it does; send a single-frame \
                 request first",
                payload.len()
            )));
        }
        // A transfer that stopped part-way: the module drops what it got before anything else is
        // written (docs/design/elm-caf0-segmenting.md, section 7).
        if let Some(until) = self.hold_until.take()
            && let Some(wait) = until.checked_duration_since(Instant::now())
        {
            std::thread::sleep(wait);
        }
        // A module on a TP2.0 channel waits only its T1 (about 100 ms) for an ACK, and the
        // adapter listens for its whole timeout after a frame (docs/elm327.md#vw-tp20-channel-frames).
        if raw && self.raw && self.busy && matches!(request.target(), Target::Tp20Channel(_)) {
            self.trusted()?;
            self.interrupt()?;
        }
        self.ready()?;
        // A transfer that couldn't put `AT R1` back must not leave the adapter deaf to this
        // request's answer.
        if self.responses_off {
            self.restore_responses()?;
        }
        // A single frame written in `CAF0` would go out raw, with no PCI byte, so every request
        // that isn't sent in segments finds `AT CAF0` off (section 8).
        if self.segmenting && segments.is_none() {
            self.guarded_command("ATCAF1")?;
            self.segmenting = false;
            self.sync_adaptive()?;
        }
        if self.raw != raw {
            for command in if raw { RAW_ON } else { RAW_OFF } {
                self.guarded_command(command)?;
            }
            self.guarded_command(self.monitor_ack_command(raw))?;
            self.raw = raw;
            self.sync_adaptive()?;
        }
        if segments.is_some() && !self.segmenting {
            self.guarded_command("ATCAF0")?;
            self.segmenting = true;
            self.sync_adaptive()?;
        }
        self.set_target(request)?;
        // A setting command's prompt may have been followed by a reset.
        self.check_idle()?;
        if let Some(segments) = segments {
            return self.send_in_segments(request, segments);
        }
        let digits = hex(payload).replace(' ', "");
        let line = if stpx {
            format!("STPX d:{digits}")
        } else {
            digits
        };
        let sent_at;
        if self.early_echo == Some(false) {
            sent_at = Instant::now();
            self.write(format!("{line}\r").as_bytes())?;
        } else {
            self.write(line.as_bytes())?;
            self.check_early_echo(&line)?;
            sent_at = Instant::now();
            self.write(b"\r")?;
        }
        self.sent = Some((sent_at, self.printed));
        self.drained = sent_at;
        self.quiet = Duration::ZERO;
        self.echo = Some(line);
        self.busy = true;
        self.listen = raw && matches!(request.target(), Target::Tp20Channel(_));
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
            self.patient = false;
            self.sync_adaptive()?;
            return Ok(None);
        };
        self.patient = true;
        self.sync_adaptive()?;
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

    fn broadcasts_can_overflow(&self) -> bool {
        // The driver paces replies to a link it judges too slow to take them unpaced. A broadcast
        // can't be paced, since the adapter's own flow control is the only one that reaches each
        // ECU (docs/elm327.md#flow-control-per-target).
        self.pace.is_some()
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
            // A monitor can stay quiet for as long as the caller waits, so only the caller's
            // deadline bounds it; stopping it is bounded by `COMMAND_WAIT`.
            let event = if self.monitoring {
                self.next_event(deadline)?
            } else {
                self.next_request_event(deadline)?
            };
            match event {
                None => return Err(Error::Timeout),
                Some(Event::Prompt) => {
                    let listen = self.listen;
                    self.prompt_after_request()?;
                    self.drop_senders();
                    // The adapter stopped listening before the caller's wait ran out. Whatever
                    // the module sends from now on is lost unless the adapter listens again, and
                    // sending anything to make it would be a frame on the channel (an `A3` the
                    // module may answer by dropping it, #227): monitor instead, which sends no
                    // frame, only the CAN ACK bits `monitor_ack_command` turns on (#301).
                    if listen && Instant::now() < deadline {
                        self.start_monitor()?;
                        continue;
                    }
                    self.busy = false;
                    return Err(Error::Timeout);
                }
                Some(Event::Overlong) => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    Some(Line::Frame(frame)) if self.raw => {
                        return Ok(Response::new(frame.id(), frame.data().to_vec())
                            .at_bus_time(self.bus_time()));
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

// What `check_segmenting` found out about a request that can go in segments.
#[derive(Debug, Clone, Copy)]
struct Segments {
    // The module's reply ID, which recognises its flow control.
    reply: u32,
    // The byte that pads a short frame to 8 bytes (PP 26).
    filler: u8,
}

// Why a transfer in segments stopped.
enum Stop {
    // The adapter's state is unknown: the driver stops everything.
    Broken(Error),
    // The request failed with the adapter back at its prompt, and the driver goes on once the
    // module has dropped what it received (docs/design/elm-caf0-segmenting.md, section 7).
    Failed(String),
}

impl From<Error> for Stop {
    fn from(error: Error) -> Self {
        Self::Broken(error)
    }
}

// What a frame read while waiting for flow control means.
enum Next {
    // Continue to send: the transfer goes on.
    Accepted(FlowControl),
    // A wait: keep listening.
    Wait,
    // The request fails.
    Problem(String),
}

// How far a transfer in segments has got.
struct Transfer {
    // The request's length, and how many frames it takes.
    len: usize,
    frames: usize,
    request_id: u32,
    reply: u32,
    filler: u8,
    // Frames whose carriage return has been written.
    written: usize,
    // When the first frame's carriage return was written.
    started: Option<Instant>,
    // The last carriage return written or flow control read: what the module's N_Cr counts from.
    last_event: Instant,
    // The last consecutive frame's carriage return: what STmin counts from.
    last_consecutive: Option<Instant>,
}

// The gap a flow control's STmin asks for, which the driver can only keep to the millisecond:
// 100 to 900 µs (`0xF1..=0xF9`) rounds up.
fn pause(st_min: Duration) -> Duration {
    if st_min.is_zero() {
        st_min
    } else {
        st_min.max(Duration::from_millis(1))
    }
}

fn describe(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{} s", duration.as_secs())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

// Sending a request of 8 to 44 bytes as raw frames written with `AT CAF0`, the way
// docs/design/elm-caf0-segmenting.md sections 1 to 8 say.
impl<L: Link> Elm<L> {
    /// Shortens the bounds on sending a request in segments, for tests of the driver: the longest
    /// gap between two frames ([`SEGMENT_GAP`]) and the longest transfer ([`SEGMENT_TRANSFER`]).
    /// A longer bound is ignored, so no caller can loosen what keeps a module's half-received
    /// request from being acted on.
    #[doc(hidden)]
    pub fn tighten_segment_bounds(&mut self, gap: Duration, transfer: Duration) {
        self.segment_gap = self.segment_gap.min(gap);
        self.segment_transfer = self.segment_transfer.min(transfer);
    }

    // Section 1: what must hold before anything is written for a request over 7 bytes on an
    // adapter that isn't an STN.
    fn check_segmenting(&self, request: &Approved) -> Result<Segments, Error> {
        let len = request.payload().len();
        if self.early_echo != Some(true) {
            return Err(Error::Adapter(format!(
                "a {len}-byte request needs an adapter that echoes each character as it reads it \
                 (such as an OBDLink), and this one hasn't shown it does; send a single-frame \
                 request first"
            )));
        }
        let Some(reply) = request.reply_id() else {
            return Err(Error::Adapter(format!(
                "a {len}-byte request to {:03X} can't be sent in segments: there is no one \
                 module's flow control to wait for",
                request.target().can_id()
            )));
        };
        let Some(filler) = self.filler else {
            return Err(Error::Adapter(
                "ATPPS didn't list PP 26, the filler byte, so the padding of a request sent in \
                 segments is unknown"
                    .into(),
            ));
        };
        Ok(Segments { reply, filler })
    }

    fn send_in_segments(&mut self, request: &Approved, segments: Segments) -> Result<(), Error> {
        let payload = request.payload();
        let mut segmenter = Segmenter::new(payload, Addressing::Normal).map_err(|e| {
            Error::Adapter(format!(
                "a {}-byte request can't be sent in segments: {e}",
                payload.len()
            ))
        })?;
        let mut transfer = Transfer {
            len: payload.len(),
            frames: 1 + payload
                .len()
                .saturating_sub(CAN_DLC - 2)
                .div_ceil(CAN_DLC - 1),
            request_id: request.target().can_id(),
            reply: segments.reply,
            filler: segments.filler,
            written: 0,
            started: None,
            last_event: Instant::now(),
            last_consecutive: None,
        };
        match self.transfer(&mut segmenter, &mut transfer) {
            Ok(()) => {
                self.drop_senders();
                Ok(())
            }
            Err(Stop::Broken(error)) => Err(error),
            Err(Stop::Failed(why)) => Err(self.stop_transfer(&transfer, why)),
        }
    }

    // Writes the frames `segmenter` gives, reading the module's flow control where it asks for
    // it. Returns once the last frame is written, which the adapter answers as it does any request.
    fn transfer(&mut self, segmenter: &mut Segmenter<'_>, t: &mut Transfer) -> Result<(), Stop> {
        loop {
            match segmenter.step() {
                Step::Send(frame) => {
                    // A frame that isn't the last of its block asks the module for no reply, so
                    // the adapter needn't wait for one (section 3).
                    let inside = matches!(segmenter.clone().step(), Step::Send(_));
                    self.write_segment(segmenter, t, frame.as_bytes(), inside)?;
                    if inside {
                        self.finish_unanswered_frame(t)?;
                    }
                }
                Step::WaitForFlowControl => self.await_flow_control(segmenter, t)?,
                Step::Done => return Ok(()),
                Step::Aborted => {
                    return Err(Stop::Failed(format!(
                        "{:03X} can't take a {}-byte request (flow control said overflow); \
                         nothing more was sent",
                        t.reply, t.len
                    )));
                }
            }
        }
    }

    // Section 4: one frame, its digits echoed before its carriage return. `inside` says the
    // adapter shouldn't wait for a reply to it (`AT R0`).
    fn write_segment(
        &mut self,
        segmenter: &Segmenter<'_>,
        t: &mut Transfer,
        frame: &[u8],
        inside: bool,
    ) -> Result<(), Stop> {
        let number = t.written + 1;
        self.set_responses(!inside)?;
        // STmin is counted from the previous consecutive frame, across any flow control wait.
        if let Some(last) = t.last_consecutive
            && let Some(wait) =
                (last + pause(segmenter.st_min())).checked_duration_since(Instant::now())
        {
            std::thread::sleep(wait);
        }
        if let Some(started) = t.started
            && started.elapsed() > self.segment_transfer
        {
            return Err(Stop::Failed(self.transfer_limit(t)));
        }
        let mut data = frame.to_vec();
        data.resize(CAN_DLC, t.filler);
        let line = hex(&data).replace(' ', "");
        let at = SystemTime::now();
        let echoed = self
            .write(line.as_bytes())
            .and_then(|()| self.check_early_echo(&line));
        if let Err(error) = echoed {
            // The adapter may have heard something else, so the line is reported as it was written.
            self.note(LinkEvent::Command {
                at,
                command: line,
                answer: Vec::new(),
            });
            return Err(Stop::Broken(error));
        }
        if number > 1 {
            let waited = t.last_event.elapsed();
            if waited >= self.segment_gap {
                self.kill_line(&line)?;
                return Err(Stop::Failed(format!(
                    "{} ms passed before frame {number} of {} could be sent, and a module drops a \
                     transfer after 1000 ms between frames; nothing more was sent",
                    waited.as_millis(),
                    t.frames
                )));
            }
        }
        let wrote = self.write(b"\r");
        let sent_at = Instant::now();
        // Noted however the write ended: the frame may be on the bus.
        self.note(LinkEvent::Frame {
            at: SystemTime::now(),
            sent: true,
            id: t.request_id,
            data,
        });
        wrote?;
        t.written = number;
        t.started.get_or_insert(sent_at);
        t.last_event = sent_at;
        if number > 1 {
            t.last_consecutive = Some(sent_at);
        }
        self.sent = Some((sent_at, self.printed));
        self.drained = sent_at;
        self.quiet = Duration::ZERO;
        self.echo = Some(line);
        self.busy = true;
        self.listen = false;
        Ok(())
    }

    // Ends a line whose digits were echoed but that took too long to send, so the adapter
    // refuses it whole.
    fn kill_line(&mut self, line: &str) -> Result<(), Stop> {
        let command = format!("{line}XX");
        let at = SystemTime::now();
        let mut answer = Vec::new();
        let killed = self
            .write(KILL)
            .and_then(|()| self.read_answer(&command, &mut answer));
        self.note(LinkEvent::Command {
            at,
            command,
            answer: answer.clone(),
        });
        killed?;
        if answer.iter().map(String::as_str).eq(["?"]) {
            Ok(())
        } else {
            Err(Stop::Broken(self.break_down(format!(
                "the adapter didn't refuse {line}XX: {}",
                answer.join(" / ")
            ))))
        }
    }

    // Reads what a frame sent with `AT R0` prints, which is its echo and the prompt (section 3).
    fn finish_unanswered_frame(&mut self, t: &Transfer) -> Result<(), Stop> {
        let deadline = Instant::now() + COMMAND_WAIT;
        let mut problem = None;
        loop {
            match self.next_request_event(deadline)? {
                None => {
                    return Err(Stop::Broken(self.break_down(format!(
                        "the adapter never printed its prompt after frame {} of {}",
                        t.written, t.frames
                    ))));
                }
                Some(Event::Prompt) => {
                    self.prompt_after_request()?;
                    self.busy = false;
                    break;
                }
                Some(Event::Overlong) => {
                    return Err(Stop::Broken(
                        self.break_down("the adapter printed an overlong line".into()),
                    ));
                }
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    None => {}
                    Some(Line::Frame(_)) => {
                        self.note(left_over(self.event_at.time, text.clone()));
                        problem.get_or_insert(format!(
                            "{:03X} sent {text} after its flow control, before the rest of the \
                             request; nothing more was sent",
                            t.reply
                        ));
                    }
                    Some(Line::Status(status)) => {
                        self.note(left_over(self.event_at.time, text));
                        if let Some(why) = self.status_while_sending(status, t)? {
                            problem.get_or_insert(why);
                        }
                    }
                    Some(Line::Ok | Line::Text(_)) => {
                        return Err(Stop::Broken(
                            self.break_down(format!("unexpected output from the adapter: {text}")),
                        ));
                    }
                },
            }
        }
        problem.map_or(Ok(()), |why| Err(Stop::Failed(why)))
    }

    // A status line while frames go out: a failure of this request only, or one that leaves the
    // adapter in an unknown state. `None` for a line that means nothing here.
    fn status_while_sending(
        &mut self,
        status: Status,
        t: &Transfer,
    ) -> Result<Option<String>, Error> {
        match status {
            Status::BusBusy | Status::BufferFull | Status::DataError => Ok(Some(format!(
                "the adapter said {status} while sending frame {} of {}; nothing more was sent",
                t.written, t.frames
            ))),
            Status::ActAlert => Ok(None),
            other => Err(self.break_down(format!("the adapter said {other}"))),
        }
    }

    // Section 5: reads what the adapter prints after a frame until it has the module's flow
    // control, then stops its listen. Exactly one `ContinueToSend`, after at most
    // `SEGMENT_MAX_WAITS` waits, and nothing else passes.
    fn await_flow_control(
        &mut self,
        segmenter: &mut Segmenter<'_>,
        t: &mut Transfer,
    ) -> Result<(), Stop> {
        let deadline = t.started.unwrap_or_else(Instant::now) + self.segment_transfer;
        let ordinal = if t.written == 1 {
            "the first frame".to_owned()
        } else {
            format!("frame {}", t.written)
        };
        let mut waits = 0;
        let mut accepted = None;
        let mut problem = None;
        let mut no_data = false;
        let mut listening = true;
        // A status such as `BUS BUSY` comes with the adapter's prompt: read on to it. Anything
        // else that fails the request leaves the adapter listening, and it's stopped below.
        let mut read_on = false;
        while listening && accepted.is_none() && (problem.is_none() || read_on) {
            match self.next_request_event(deadline)? {
                // The limit ends the wait, prompt or not: the listen is stopped below, which
                // reads the prompt with a wait of its own.
                None => {
                    problem.get_or_insert(self.transfer_limit(t));
                    read_on = false;
                }
                Some(Event::Overlong) => {
                    return Err(Stop::Broken(
                        self.break_down("the adapter printed an overlong line".into()),
                    ));
                }
                Some(Event::Prompt) => {
                    self.prompt_after_request()?;
                    self.busy = false;
                    listening = false;
                }
                Some(Event::Line(text)) => match self.reply_line(&text)? {
                    None => {}
                    Some(Line::Frame(frame)) => {
                        // What the module's N_Cr counts from, however the request ends.
                        t.last_event = Instant::now();
                        self.note(LinkEvent::Frame {
                            at: self.event_at.time,
                            sent: false,
                            id: frame.id(),
                            data: frame.data().to_vec(),
                        });
                        let next =
                            Self::flow_control_in(frame.data(), &text, &ordinal, t, &mut waits);
                        match next {
                            Next::Accepted(fc) => {
                                self.accept(segmenter, fc)?;
                                accepted = Some(Instant::now());
                            }
                            Next::Wait => {}
                            Next::Problem(why) => {
                                problem.get_or_insert(why);
                            }
                        }
                    }
                    Some(Line::Status(status)) => {
                        self.note(left_over(self.event_at.time, text));
                        if status == Status::NoData {
                            no_data = true;
                        } else if let Some(why) = self.status_while_sending(status, t)? {
                            problem.get_or_insert(why);
                            read_on = true;
                        }
                    }
                    Some(Line::Ok | Line::Text(_)) => {
                        return Err(Stop::Broken(
                            self.break_down(format!("unexpected output from the adapter: {text}")),
                        ));
                    }
                },
            }
        }
        let caught = if listening {
            self.stop_listening()?
        } else {
            Vec::new()
        };
        if let Some(why) = problem {
            return Err(Stop::Failed(why));
        }
        self.check_caught(&caught, t)?;
        let Some(at) = accepted else {
            let said = if no_data {
                " (the adapter said NO DATA)"
            } else {
                ""
            };
            return Err(Stop::Failed(format!(
                "{:03X} sent no flow control for {ordinal} of a {}-byte request{said}; nothing \
                 more was sent",
                t.reply, t.len
            )));
        };
        t.last_event = at;
        Ok(())
    }

    // Stops the adapter's listen (section 3) and returns what it printed before it heard the stop.
    fn stop_listening(&mut self) -> Result<Vec<String>, Error> {
        self.caught = Some(Vec::new());
        let stopped = self.interrupt();
        let caught = self.caught.take().unwrap_or_default();
        stopped?;
        // Its prompt may have come first, still to be read.
        if self.busy {
            self.ready()?;
        }
        Ok(caught)
    }

    // A frame the module sent after the flow control it was waited for, or a status, fails the
    // request.
    fn check_caught(&mut self, caught: &[String], t: &Transfer) -> Result<(), Stop> {
        for text in caught {
            match parse_line(text) {
                Line::Frame(_) => {
                    return Err(Stop::Failed(format!(
                        "{:03X} sent {text} after its flow control, before the rest of the \
                         request; nothing more was sent",
                        t.reply
                    )));
                }
                // The adapter's listen ended as it was stopped.
                Line::Status(Status::NoData) => {}
                Line::Status(status) => {
                    if let Some(why) = self.status_while_sending(status, t)? {
                        return Err(Stop::Failed(why));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // What a frame printed while the driver waits for flow control means.
    fn flow_control_in(
        data: &[u8],
        text: &str,
        ordinal: &str,
        t: &Transfer,
        waits: &mut u8,
    ) -> Next {
        let reply = t.reply;
        match isotp::Frame::parse(data, Addressing::Normal) {
            Ok(isotp::Frame::FlowControl(fc)) => match fc.status {
                FlowStatus::ContinueToSend => Next::Accepted(fc),
                FlowStatus::Wait => {
                    *waits = waits.saturating_add(1);
                    if *waits > SEGMENT_MAX_WAITS {
                        Next::Problem(format!(
                            "{reply:03X} kept a {}-byte request waiting: more than \
                             {SEGMENT_MAX_WAITS} wait flow controls in a row; nothing more was \
                             sent",
                            t.len
                        ))
                    } else {
                        Next::Wait
                    }
                }
                FlowStatus::Overflow => Next::Problem(format!(
                    "{reply:03X} can't take a {}-byte request (flow control said overflow); \
                     nothing more was sent",
                    t.len
                )),
            },
            Err(_) if data.first().is_some_and(|pci| pci >> 4 == 3) => Next::Problem(format!(
                "{reply:03X} sent a flow control frame this driver can't use: {text}; nothing \
                 more was sent"
            )),
            _ => Next::Problem(format!(
                "{reply:03X} answered {ordinal} of a {}-byte request with {text} instead of \
                 flow control; nothing more was sent",
                t.len
            )),
        }
    }

    // Hands the flow control that lets the transfer go on to the segmenter.
    fn accept(&mut self, segmenter: &mut Segmenter<'_>, fc: FlowControl) -> Result<(), Stop> {
        segmenter.flow_control(fc).map_err(|e| {
            Stop::Broken(self.break_down(format!("the flow control doesn't fit the transfer: {e}")))
        })
    }

    fn transfer_limit(&self, t: &Transfer) -> String {
        format!(
            "a {}-byte request took more than {} to send; nothing more was sent",
            t.len,
            describe(self.segment_transfer)
        )
    }

    // `AT R0` for a frame the module doesn't answer, `AT R1` for one it does. `responses_off` is
    // set before `ATR0` is written, since a command that fails may still have taken effect.
    fn set_responses(&mut self, on: bool) -> Result<(), Error> {
        if self.responses_off != on {
            return Ok(());
        }
        if on {
            return self.restore_responses();
        }
        self.responses_off = true;
        self.expect_ok("ATR0")
    }

    fn restore_responses(&mut self) -> Result<(), Error> {
        let lines = self.command("ATR1")?;
        if lines.iter().map(String::as_str).eq(["OK"]) {
            self.responses_off = false;
            return Ok(());
        }
        Err(self.break_down(format!(
            "the adapter wouldn't go back to waiting for replies: {}",
            lines.join(" / ")
        )))
    }

    // Section 7: a transfer that stopped part-way sends nothing more, puts the adapter back to
    // waiting for replies, and holds the next request until the module has dropped what it got.
    fn stop_transfer(&mut self, t: &Transfer, why: String) -> Error {
        if self.responses_off
            && let Err(error) = self.restore_responses()
        {
            return error;
        }
        if t.started.is_some() {
            self.hold_until = Some(t.last_event + SEGMENT_HOLD);
        }
        Error::Adapter(why)
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
            let now = self.stamp();
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
        // A monitor prints no prompt until the driver stops it (`interrupt` reads that one
        // itself), so this one means the adapter's state isn't what the driver cached.
        if self.monitoring {
            return Err(self.break_down("the adapter stopped monitoring on its own".into()));
        }
        self.listen = false;
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
