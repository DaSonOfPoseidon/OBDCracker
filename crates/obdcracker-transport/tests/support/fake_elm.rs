//! A fake ELM327, written from its datasheet (ELM327DS v2.0), for testing the driver without an
//! adapter. It takes the bytes the host writes and produces what the adapter would print.
//! Shared by other crates' tests through `#[path]`, so it only uses public APIs.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use obdcracker_core::isotp::{Addressing, FlowControl, FlowStatus, Segmenter, Step};
use obdcracker_transport::hex;
use obdcracker_transport::link::{Driver, Link, LinkKind};

/// Answers a request sent to `header`: each reply's source CAN ID and payload.
pub type Responder = Box<dyn FnMut(u32, &[u8]) -> Vec<(u32, Vec<u8>)> + Send>;

/// Frames a module puts on the bus some time after a request: how long after, the source CAN ID
/// and the frame's data. They reach the host only if the adapter is listening or monitoring when
/// they arrive; otherwise they're lost, as on a real adapter.
pub type Delayed = Box<dyn FnMut(u32, &[u8]) -> Vec<(Duration, u32, Vec<u8>)> + Send>;

pub const BANNER: &str = "ELM327 v2.0";

#[allow(clippy::struct_excessive_bools)]
pub struct FakeElm {
    responder: Responder,
    input: Vec<u8>,
    // The line as received, for the echo.
    raw: Vec<u8>,
    output: VecDeque<u8>,
    // Whether the output holds a command's answer, which any byte written interrupts; the echo
    // of characters as they're typed doesn't.
    printing: bool,
    last: Option<String>,
    pub settings: Settings,
    /// Every line the host sent, after removing spaces, in order.
    pub commands: Vec<String>,
    pub sent: Vec<(u32, Vec<u8>)>,
    /// The module each flow control frame the adapter sent was for: every sender of a
    /// multi-frame reply that passed the receive filter.
    pub flow_control_for: Vec<u32>,
    pub flow_control_ids: Vec<u32>,
    /// Commands this adapter doesn't support (it answers `?`), as a clone might.
    pub unsupported: Vec<String>,
    pub sti: Option<String>,
    /// Times the host wrote while the adapter was still printing, which interrupts it.
    pub interrupted: usize,
    pub repeats: usize,
    /// Leave the prompt off after a bus request, as an adapter that hangs would.
    pub hang_after_request: bool,
    /// With CAN auto formatting off, keep listening after a bus request's frames until the
    /// host writes, as a real adapter does until its timeout runs out. The byte that stops it
    /// is discarded, and it prints `STOPPED` and its prompt after the frames it printed.
    pub listen_raw: bool,
    /// With `listen_raw`, the timeout runs out just as the host writes: the prompt comes
    /// first, and the byte is the first of the next line.
    pub listen_ends_on_write: bool,
    // Listening after a raw bus request (`listen_raw`).
    listening: bool,
    /// With `listen_raw`, as an STN that ends a raw listen after one frame: it prints the first
    /// frame the receive filter shows and then its prompt, and any frame after that is lost until
    /// the host starts listening again. With none shown it listens until the host writes.
    pub listen_one_frame: bool,
    /// Frames a module sends after a request (see [`Delayed`]).
    pub delayed: Option<Delayed>,
    /// Count each [`Delayed`] frame's time from when the adapter next starts monitoring (`STM`
    /// or `ATMA`), not from the request: the module answers a set time after the host started
    /// listening, whatever the test thread does before it. A request sent first drops frames
    /// still held, and with no monitor the frames never arrive.
    pub delay_from_monitor: bool,
    /// How long after its command line `STM` or `ATMA` takes to start printing. Frames that
    /// reach the adapter in between are lost, as on the real one, where the echo round trip alone
    /// is about 15 ms (session 11, #333). Nothing, the default, starts it at once.
    pub monitor_startup: Duration,
    // When the monitor started by the last `STM` or `ATMA` prints from.
    monitor_from: Instant,
    /// An STN without batched commands (firmware older than FRPM rev. F): `STBC` answers `?`.
    pub stbc_unsupported: bool,
    /// What `STBC` prints instead of `OK` or `?`, as an adapter that says something else would.
    pub stbc_says: Option<String>,
    /// A batch whose last element is `STM` loses it: the STN prints its prompt when the first
    /// element's listen ends and never monitors, as if the batch had been aborted.
    pub batch_drops_monitor: bool,
    /// Print the `|` that precedes the second element's output in a batch (STN FRPM, sections
    /// 8.15 and 16.2.2). Off, the STN prints none.
    pub batch_pipe: bool,
    // The line being run is a batch whose last element, `STM`, starts when the first element's
    // listen ends.
    batch_pending: bool,
    // ...but what follows the request isn't `STM`: it fails, as a command the adapter doesn't
    // know does, once the request is done.
    batch_bad_tail: bool,
    // The next line printed starts with the pipe that follows the first element's output.
    pipe_next: bool,
    // Frames waiting for the adapter to start monitoring (`delay_from_monitor`).
    held: Vec<(Duration, u32, Vec<u8>)>,
    // Frames on the bus that haven't reached the adapter yet.
    bus: Vec<(Instant, u32, Vec<u8>)>,
    /// Frames the receive filter would have shown that arrived while the adapter was neither
    /// listening nor monitoring, or after its listen ended: the module sent them, nobody heard.
    pub lost_frames: Vec<(u32, Vec<u8>)>,
    // Monitoring after `ATMA` or `STM`: every frame is printed until the host writes a byte.
    monitoring: bool,
    // `ATMA` on an STN passes every ID whatever `ATCRA` says (STN FRPM, section 7.3); `STM` uses
    // the filters as set.
    monitor_all: bool,
    /// The adapter is one of two nodes on the bus, as behind a gateway: a module's frame that
    /// nobody acknowledges is sent again and again, until the adapter prints `CAN ERROR`. Only a
    /// monitor that is silent on the bus (`monitor_ack` off) leaves a frame unacknowledged; a
    /// listen after a request always acknowledges (session 9, #301).
    pub two_node_bus: bool,
    /// The adapter takes the monitor ACK setting and says `OK`, but its monitor stays silent.
    pub monitor_ignores_ack: bool,
    /// Programmable parameters turned on, and their values (datasheet pp. 57-61). The rest are
    /// off, at their factory values.
    pub pp: Vec<(u8, u8)>,
    /// What `AT PPS` prints instead of the parameter summary.
    pub pps: Option<Vec<String>>,
    /// Bytes printed right after the next line's echo, before its answer.
    pub after_echo: Vec<u8>,
    /// Bytes printed right after the next prompt, as an adapter that resets while idle would.
    pub after_prompt: Vec<u8>,
    /// Echo a line only once its carriage return arrives, as some clones may
    /// (docs/elm327.md#safety).
    pub echo_at_line_end: bool,
    /// How many bytes a second the link to the host drains from the adapter's 512-byte output
    /// buffer (ELM327DS v2.0, p. 80), or `None` to print without a limit. Frames that arrive
    /// faster than the buffer drains overflow it, and the adapter prints `BUFFER FULL`.
    pub drain_rate: Option<u32>,
    /// What the adapter calls itself after a reset and to `ATI`. Clones often claim a version
    /// they don't implement, such as `ELM327 v1.5` or `ELM327 v2.1` (python-OBD #188, #205).
    pub banner: String,
    /// Bytes printed before the banner on a reset, as clones do (`\xfc\r\r`, python-OBD #205).
    pub reset_noise: Vec<u8>,
    /// Commands whose answer ends without its carriage return and prompt (`ATE0\rOK` and then
    /// nothing, python-OBD #160, #205).
    pub unfinished: Vec<String>,
    /// Commands that are echoed and then never answered at all.
    pub mute: Vec<String>,
    /// Answer every bus request with an empty line, as clones do when nothing answers
    /// (`0100` → `\r\r>`, python-OBD #205).
    pub empty_answers: bool,
    /// The module never answers the first frame of a multi-frame `STPX` request with flow control,
    /// so the STN prints `FC RX TIMEOUT` and its prompt, as the engine ECU of the A7 did (#215,
    /// #306).
    pub no_flow_control: bool,
    /// A module that takes a request written as raw frames with `AT CAF0` and answers it
    /// ([`Module`]).
    pub module: Option<Module>,
    /// A clone that answers `OK` to `AT CAF0` and stays in `AT CAF1`.
    pub ignores_caf0: bool,
    /// With `ignores_caf0`, a clone that takes a line of 8 bytes in `AT CAF1` instead of
    /// refusing it, and sends it as the data of one frame.
    pub takes_eight_bytes_in_caf1: bool,
    /// The lines `AT RV` prints: the voltage, `12.6V` unless a test sets another.
    pub voltage: Vec<String>,
}

// The adapter's output buffer, in bytes (ELM327DS v2.0, p. 80).
pub const OUTPUT_BUFFER: usize = 512;
// How many times a module sent a frame nobody acknowledged before the adapter gave up (car
// session 9: `300 10 00 03 7F 1A 11`, 31 times).
pub const UNACKED_REPEATS: usize = 31;
// How long a CAN frame takes on the bus at 500 kbit/s, about 130 bits with stuffing, in µs.
const FRAME_TIME_US: u64 = 260;

// What `AT PPS` prints for a v2.0 ELM327 with every parameter off (datasheet p. 57).
const PP_FACTORY: [u8; 0x30] = [
    0xFF, 0xFF, 0xFF, 0x32, 0x01, 0xFF, 0xF1, 0x09, 0xFF, 0x00, 0x0A, 0xFF, 0x68, 0x0D, 0x9A, 0xD5,
    0x0D, 0x00, 0xFF, 0x32, 0x50, 0x0A, 0xFF, 0x6D, 0x00, 0x62, 0xFF, 0xFF, 0x03, 0x0F, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x38, 0x02, 0xE0, 0x04, 0x80, 0x0A,
];

/// The adapter settings an `ATZ` restores to their defaults.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub echo: bool,
    pub headers: bool,
    pub spaces: bool,
    pub linefeeds: bool,
    pub protocol: Option<String>,
    pub header: u32,
    pub priority: u8,
    pub header29: u32,
    pub fc_header: Option<u32>,
    pub fc_data: Option<String>,
    pub fc_mode: u8,
    /// The `AT CRA` receive filter: three hex digits (eight for 29-bit IDs), each of which may
    /// be `X` (any). `None` shows every ID.
    pub cra: Option<String>,
    /// CAN auto formatting (`AT CAF1`, the default): ISO-TP framing of requests and replies.
    pub caf: bool,
    /// Automatic flow control (`AT CFC1`, the default): a flow control frame for every First
    /// Frame the receive filter shows, whatever `CAF` is (datasheet p. 14).
    pub cfc: bool,
    /// Variable DLC (`AT V1`); off, the default, every request is padded to 8 bytes, even with
    /// `CAF0` (datasheet pp. 27, 46).
    pub variable_dlc: bool,
    /// Whether a monitor acknowledges the frames it hears (`STCMM 1`, or `AT CSM 0` on an
    /// ELM327); off, the default, it is silent on the bus (STN FRPM, section 8.8).
    pub monitor_ack: bool,
    /// Whether the adapter waits for a reply after sending a request (`AT R1`, the default).
    /// With `AT R0` it returns to its prompt at once, and a frame the module sends then is lost
    /// (datasheet p. 23).
    pub responses: bool,
    /// Whether the STN parses batched commands (`STBC 1`, STN FRPM, sections 8.15 and 16.0): a
    /// line of elements separated by `|` runs from left to right, under one prompt.
    pub batching: bool,
}

impl Settings {
    pub fn bits29(&self) -> bool {
        self.protocol.as_deref() == Some("7")
    }

    pub fn request_id(&self) -> u32 {
        if self.bits29() {
            u32::from(self.priority) << 24 | self.header29
        } else {
            self.header
        }
    }

    fn shows(&self, id: u32) -> bool {
        self.cra.as_ref().is_none_or(|pattern| {
            let id = if pattern.len() == 8 {
                format!("{id:08X}")
            } else {
                format!("{id:03X}")
            };
            pattern.len() == id.len()
                && pattern
                    .chars()
                    .zip(id.chars())
                    .all(|(want, got)| want == 'X' || want == got)
        })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            echo: true,
            headers: false,
            spaces: true,
            linefeeds: false,
            protocol: None,
            header: 0x7DF,
            // The datasheet's defaults: the 29-bit OBD-II broadcast, 0x18DB33F1.
            priority: 0x18,
            header29: 0xDB_33F1,
            fc_header: None,
            fc_data: None,
            fc_mode: 0,
            cra: None,
            caf: true,
            cfc: true,
            variable_dlc: false,
            monitor_ack: false,
            responses: true,
            batching: false,
        }
    }
}

impl FakeElm {
    pub fn new(responder: Responder) -> Self {
        Self {
            responder,
            input: Vec::new(),
            raw: Vec::new(),
            output: VecDeque::new(),
            printing: false,
            last: None,
            settings: Settings::default(),
            commands: Vec::new(),
            sent: Vec::new(),
            flow_control_for: Vec::new(),
            flow_control_ids: Vec::new(),
            unsupported: Vec::new(),
            sti: None,
            interrupted: 0,
            repeats: 0,
            hang_after_request: false,
            listen_raw: false,
            listen_ends_on_write: false,
            listening: false,
            listen_one_frame: false,
            delayed: None,
            delay_from_monitor: false,
            monitor_startup: Duration::ZERO,
            monitor_from: Instant::now(),
            stbc_unsupported: false,
            stbc_says: None,
            batch_drops_monitor: false,
            batch_pipe: true,
            batch_pending: false,
            batch_bad_tail: false,
            pipe_next: false,
            held: Vec::new(),
            bus: Vec::new(),
            lost_frames: Vec::new(),
            monitoring: false,
            monitor_all: false,
            two_node_bus: true,
            monitor_ignores_ack: false,
            pp: Vec::new(),
            pps: None,
            after_echo: Vec::new(),
            after_prompt: Vec::new(),
            echo_at_line_end: false,
            drain_rate: None,
            banner: BANNER.to_owned(),
            reset_noise: Vec::new(),
            unfinished: Vec::new(),
            mute: Vec::new(),
            empty_answers: false,
            no_flow_control: false,
            module: None,
            ignores_caf0: false,
            takes_eight_bytes_in_caf1: false,
            voltage: vec!["12.6V".to_owned()],
        }
    }

    pub fn silent() -> Self {
        Self::new(Box::new(|_, _| Vec::new()))
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.poll();
        for &byte in bytes {
            if self.monitoring {
                // Any byte stops a monitor; it's discarded, and `STOPPED` and the prompt follow
                // what was printed (ELM327DS p. 20, STN FRPM section 8.9).
                self.monitoring = false;
                if self.listen_ends_on_write {
                    self.prompt();
                    self.printing = false;
                } else {
                    self.interrupted += 1;
                    self.print("STOPPED");
                    self.prompt();
                    continue;
                }
            }
            if self.listening {
                self.listening = false;
                if self.listen_ends_on_write {
                    self.prompt();
                    self.printing = false;
                } else {
                    self.interrupted += 1;
                    self.print("STOPPED");
                    self.prompt();
                    continue;
                }
            }
            if self.printing && !self.output.is_empty() {
                // Any byte interrupts the adapter while it's busy (datasheet p. 7).
                self.interrupted += 1;
                self.output.clear();
                self.print("STOPPED");
                self.prompt();
                continue;
            }
            match byte {
                b'\r' => {
                    let line: String = std::mem::take(&mut self.input)
                        .into_iter()
                        .map(char::from)
                        .collect();
                    let raw = std::mem::take(&mut self.raw);
                    self.printing = true;
                    self.run(&line, &raw);
                }
                // Spaces and control characters are ignored (datasheet p. 8), but echoed.
                b' ' | 0..=0x1F => self.receive(byte, false),
                _ => self.receive(byte, true),
            }
        }
    }

    // A character of the line being typed, echoed at once unless the echo waits for the line.
    fn receive(&mut self, byte: u8, input: bool) {
        self.raw.push(byte);
        if input {
            self.input.push(byte);
        }
        if self.settings.echo && !self.echo_at_line_end {
            self.output.push_back(byte);
        }
    }

    pub fn read(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.output.len());
        let bytes = self.output.drain(..n).collect();
        if self.output.is_empty() {
            self.printing = false;
        }
        bytes
    }

    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    fn print(&mut self, line: &str) {
        if std::mem::take(&mut self.pipe_next) && line != "STOPPED" {
            self.output.push_back(b'|');
        }
        self.output.extend(line.bytes());
        self.output.push_back(b'\r');
        if self.settings.linefeeds {
            self.output.push_back(b'\n');
        }
    }

    // The adapter is done with what it was running, a batch included: nothing of one goes on.
    fn prompt(&mut self) {
        self.batch_pending = false;
        self.pipe_next = false;
        self.output.push_back(b'\r');
        self.output.push_back(b'>');
        self.output.extend(std::mem::take(&mut self.after_prompt));
    }

    // The adapter has echoed each character as it arrived (or, with `echo_at_line_end`, echoes
    // the line now), and echoes the carriage return.
    fn run(&mut self, line: &str, raw: &[u8]) {
        let line = if line.is_empty() {
            // A bare carriage return repeats the last command (datasheet p. 8).
            self.repeats += 1;
            let Some(last) = self.last.clone() else {
                self.prompt();
                return;
            };
            last
        } else {
            line.to_ascii_uppercase()
        };
        self.commands.push(line.clone());
        self.last = Some(line.clone());
        if self.settings.echo {
            if raw.is_empty() {
                self.print(&line);
            } else {
                if self.echo_at_line_end {
                    self.output.extend(raw);
                }
                self.output.push_back(b'\r');
            }
        }
        self.output.extend(std::mem::take(&mut self.after_echo));
        if self.unsupported.contains(&line) {
            self.print("?");
            self.prompt();
            return;
        }
        if self.mute.contains(&line) {
            return;
        }
        if self.unfinished.contains(&line) {
            self.output.extend(b"OK");
            return;
        }
        if let Some(at) = line.strip_prefix("AT") {
            self.at(at);
        } else if line.contains('|') {
            self.batch(&line);
        } else if let Some(mode) = line
            .strip_prefix("STBC")
            .filter(|mode| !mode.starts_with("OF"))
        {
            // An STN's batched commands switch (STN FRPM, section 8.15): `OK` for 0 and 1, and `?`
            // from an adapter without them, such as a plain ELM327.
            let ok = self.sti.is_some() && !self.stbc_unsupported && matches!(mode, "0" | "1");
            if let Some(says) = self.stbc_says.clone() {
                self.print(&says);
            } else {
                if ok {
                    self.settings.batching = mode == "1";
                }
                self.print(if ok { "OK" } else { "?" });
            }
            self.prompt();
        } else if line == "STM" {
            // Monitor with the filters as set; an STN's command (STN FRPM, section 8.9), unknown
            // to a plain ELM327.
            if self.sti.is_some() {
                self.start_monitoring();
                self.monitor_all = false;
            } else {
                self.print("?");
                self.prompt();
            }
        } else if let Some(mode) = line.strip_prefix("STCMM") {
            // An STN's CAN monitoring mode: 0 silent, 1 a normal node that acknowledges, 2 silent
            // and receiving frames with errors (STN FRPM, section 8.8).
            let ok = self.sti.is_some() && matches!(mode, "0" | "1" | "2");
            if ok {
                self.settings.monitor_ack = mode == "1";
            }
            self.print(if ok { "OK" } else { "?" });
            self.prompt();
        } else if line == "STI" {
            let reply = self.sti.clone().unwrap_or_else(|| "?".into());
            self.print(&reply);
            self.prompt();
        } else if let Some(ms) = line.strip_prefix("STPTO") {
            // An STN's request timeout in decimal ms, 1 to 65535 (STN1100 FRPM); a plain ELM327
            // doesn't know the command.
            let valid =
                ms.bytes().all(|b| b.is_ascii_digit()) && ms.parse::<u16>().is_ok_and(|ms| ms > 0);
            self.print(if self.sti.is_some() && valid {
                "OK"
            } else {
                "?"
            });
            self.prompt();
        } else if let Some(params) = line.strip_prefix("STPX") {
            self.stpx(params);
        } else {
            self.request(&line);
        }
    }

    fn at(&mut self, cmd: &str) {
        let ok = match cmd {
            "Z" => {
                self.settings = Settings::default();
                // PP 09 sets the default echo (datasheet p. 59).
                if let Some(&(_, value)) = self.pp.iter().find(|(pp, _)| *pp == 0x09) {
                    self.settings.echo = value == 0x00;
                }
                self.last = None;
                self.output.extend(self.reset_noise.clone());
                self.print("");
                let banner = self.banner.clone();
                self.print(&banner);
                self.prompt();
                return;
            }
            "I" => {
                let banner = self.banner.clone();
                self.print(&banner);
                self.prompt();
                return;
            }
            "PPS" => {
                self.print_pps();
                return;
            }
            "MA" => {
                // No prompt until the host stops it.
                self.start_monitoring();
                self.monitor_all = self.sti.is_some();
                return;
            }
            "RV" => {
                for line in self.voltage.clone() {
                    self.print(&line);
                }
                self.prompt();
                return;
            }
            "E0" | "E1" => {
                self.settings.echo = cmd == "E1";
                true
            }
            "CAF0" | "CAF1" => {
                self.settings.caf = cmd == "CAF1" || self.ignores_caf0;
                true
            }
            "CFC0" | "CFC1" => {
                self.settings.cfc = cmd == "CFC1";
                true
            }
            "CSM0" | "CSM1" => {
                // Silent monitoring off (the monitor acknowledges) or on, the default.
                self.settings.monitor_ack = cmd == "CSM0";
                true
            }
            "V0" | "V1" => {
                self.settings.variable_dlc = cmd == "V1";
                true
            }
            "L0" | "L1" => {
                self.settings.linefeeds = cmd == "L1";
                true
            }
            "S0" | "S1" => {
                self.settings.spaces = cmd == "S1";
                true
            }
            "H0" | "H1" => {
                self.settings.headers = cmd == "H1";
                true
            }
            "R0" | "R1" => {
                self.settings.responses = cmd == "R1";
                true
            }
            "AT0" | "AT1" | "STFF" => true,
            "FCSM0" => {
                self.settings.fc_mode = 0;
                true
            }
            "FCSM2" => {
                // Mode 2 needs the data first; the adapter sets the header (datasheet p. 48).
                if self.settings.fc_data.is_some() {
                    self.settings.fc_mode = 2;
                    true
                } else {
                    false
                }
            }
            "FCSM1" => {
                // Mode 1 needs the header and data first (datasheet p. 48).
                if self.settings.fc_header.is_some() && self.settings.fc_data.is_some() {
                    self.settings.fc_mode = 1;
                    true
                } else {
                    false
                }
            }
            _ => self.set(cmd),
        };
        self.print(if ok { "OK" } else { "?" });
        self.prompt();
    }

    // `AT PPS`: four parameters a line, as `nn:vv N` (on) or `nn:vv F` (off).
    // A setting with a value: whether the adapter took it.
    fn set(&mut self, cmd: &str) -> bool {
        if let Some(protocol) = cmd.strip_prefix("SP") {
            self.settings.protocol = Some(protocol.to_owned());
            true
        } else if let Some(id) = cmd.strip_prefix("FCSH") {
            self.settings.fc_header = parse_id(id);
            self.settings.fc_header.is_some()
        } else if let Some(priority) = cmd.strip_prefix("CP") {
            // Two hex digits, at most 1F: the top 5 bits of a 29-bit ID.
            match parse_hex(priority).as_deref() {
                Some(&[priority]) if priority <= 0x1F => {
                    self.settings.priority = priority;
                    true
                }
                _ => false,
            }
        } else if let Some(pattern) = cmd.strip_prefix("CRA") {
            // Three hex digits or X, or eight for 29-bit IDs (datasheet p. 15); a bare
            // `AT CRA` shows every ID.
            let valid = matches!(pattern.len(), 3 | 8)
                && pattern.bytes().all(|b| b.is_ascii_hexdigit() || b == b'X');
            if valid {
                self.settings.cra = Some(pattern.to_owned());
            } else if pattern.is_empty() {
                self.settings.cra = None;
            }
            valid || pattern.is_empty()
        } else if let Some(data) = cmd.strip_prefix("FCSD") {
            self.settings.fc_data = Some(data.to_owned());
            true
        } else if let Some(id) = cmd.strip_prefix("SH") {
            // Three hex digits, or six for the low 24 bits of a 29-bit header.
            match (id.len(), parse_id(id)) {
                (3, Some(id)) => {
                    self.settings.header = id;
                    true
                }
                (6, Some(id)) => {
                    self.settings.header29 = id;
                    true
                }
                _ => false,
            }
        } else {
            false
        }
    }

    fn print_pps(&mut self) {
        let lines = self.pps.clone().unwrap_or_else(|| {
            PP_FACTORY
                .chunks(4)
                .enumerate()
                .map(|(row, values)| {
                    let line: Vec<String> = values
                        .iter()
                        .enumerate()
                        .map(|(i, &factory)| {
                            let pp = u8::try_from(row * 4 + i).unwrap();
                            match self.pp.iter().find(|(on, _)| *on == pp) {
                                Some(&(_, value)) => format!("{pp:02X}:{value:02X} N"),
                                None => format!("{pp:02X}:{factory:02X} F"),
                            }
                        })
                        .collect();
                    line.join("     ")
                })
                .collect()
        });
        for line in lines {
            self.print(&line);
        }
        self.prompt();
    }

    fn request(&mut self, hex_text: &str) {
        let mut bytes = match parse_hex(hex_text) {
            // With CAN auto formatting on, a request is one single frame: 1 to 7 bytes. Off, it's
            // the frame's data as it is: 1 to 8.
            Some(bytes) if (1..=7).contains(&bytes.len()) => bytes,
            Some(bytes) if !self.settings.caf && bytes.len() == 8 => bytes,
            Some(bytes) if self.takes_eight_bytes_in_caf1 && bytes.len() == 8 => bytes,
            _ => {
                self.print("?");
                self.prompt();
                return;
            }
        };
        if !self.settings.caf && !self.settings.variable_dlc {
            bytes.resize(8, self.filler());
        }
        let header = self.settings.request_id();
        if !self.settings.caf && self.module.as_ref().is_some_and(|m| m.request_id == header) {
            self.module_frame(header, &bytes);
        } else {
            self.transmit(bytes);
        }
    }

    // The byte the adapter pads a short frame with: PP 26, 0x00 unless it's turned on.
    fn filler(&self) -> u8 {
        self.pp
            .iter()
            .find(|(pp, _)| *pp == 0x26)
            .map_or(0x00, |&(_, value)| value)
    }

    // `STPX d:<hex>`, the only form the driver writes (STN FRPM, section 8.6): an STN sends up
    // to 2 KB, segmenting it itself. Anything else, or a plain ELM327, answers `?`.
    fn stpx(&mut self, params: &str) {
        // Spaces never reach `input`, so the line is `STPXD:<hex>`.
        let data = params
            .strip_prefix("D:")
            .and_then(parse_hex)
            .filter(|bytes| (1..=2048).contains(&bytes.len()));
        match data {
            Some(bytes) if self.sti.is_some() && self.no_flow_control && bytes.len() > 7 => {
                // The first frame went out; nothing more does.
                self.sent.push((self.settings.request_id(), bytes));
                self.print("FC RX TIMEOUT");
                self.prompt();
            }
            Some(bytes) if self.sti.is_some() => self.transmit(bytes),
            _ => {
                self.print("?");
                self.prompt();
            }
        }
    }

    // Puts a request on the bus and prints its answer.
    fn transmit(&mut self, mut bytes: Vec<u8>) {
        if !self.settings.caf && !self.settings.variable_dlc {
            bytes.resize(8, self.filler());
        }
        // Recorded even without a protocol: a real adapter would then search for one, sending
        // probe frames.
        let header = self.settings.request_id();
        self.sent.push((header, bytes.clone()));
        if !self.has_protocol() {
            return;
        }
        if !self.settings.responses {
            self.end_listen(Instant::now());
            return;
        }
        self.answer(header, &bytes, false);
    }

    // Whether a protocol is set; if not, prints what the adapter does instead of sending.
    fn has_protocol(&mut self) -> bool {
        let set = matches!(self.settings.protocol.as_deref(), Some("6" | "7"));
        if !set {
            self.print("CAN ERROR");
            self.prompt();
        }
        set
    }

    // Prints what the modules answer to a request on the bus. `logical` says each reply is a
    // whole payload for the fake to put in frames (a module's answer to a request it received
    // in segments), not one frame's data as it is.
    fn answer(&mut self, header: u32, bytes: &[u8], logical: bool) {
        let bytes = bytes.to_vec();
        let extra = if logical {
            self.module
                .as_ref()
                .map(|m| m.after_answer.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // The receive filter hides frames from other IDs, and the adapter sends no flow control
        // for what it doesn't show.
        let replies: Vec<_> = (self.responder)(header, &bytes)
            .into_iter()
            .filter(|(source, _)| self.settings.shows(*source))
            .collect();
        if self.empty_answers {
            self.print("");
            self.prompt();
            return;
        }
        // A listen that hears nothing ends with `NO DATA` at its timeout, which this fake never
        // reaches while listening.
        let one_frame = !logical && self.listen_raw && self.listen_one_frame && !self.settings.caf;
        if replies.is_empty() && !one_frame && extra.is_empty() {
            self.print("NO DATA");
        }
        let gap_us = self.st_min_us().max(FRAME_TIME_US);
        // Each frame line and when it arrives, in µs. Modules answer at once, so with the buffer
        // modelled their frames interleave, each module's spaced by the gap its flow control
        // asked for; otherwise each reply is printed whole, in turn.
        let mut lines = Vec::new();
        for (index, (source, payload)) in replies.into_iter().enumerate() {
            // Off, each reply is one frame's data as it is.
            let mut frames = if self.settings.caf || logical {
                frames(&payload)
            } else {
                vec![payload.iter().copied().take(8).collect()]
            };
            if !logical
                && !self.settings.caf
                && self.settings.cfc
                && payload.first().is_some_and(|b| b >> 4 == 1)
            {
                self.flow_control_for.push(source);
                let to = self.flow_control_to(source);
                self.flow_control_ids.push(to);
            }
            if frames.len() > 1 {
                self.flow_control_for.push(source);
                let to = self.flow_control_to(source);
                self.flow_control_ids.push(to);
                // The module goes on only if the flow control came to its own request ID: the
                // header, or for a broadcast the OBD-II one (ISO 15765-4: reply ID - 8).
                let request_id = if header == 0x7DF && !self.settings.bits29() {
                    source - 8
                } else {
                    header
                };
                if to != request_id {
                    frames.truncate(1);
                }
            }
            for (k, frame) in frames.into_iter().enumerate() {
                let line = self.frame_line(source, &frame);
                let (index, k) = (index as u64, k as u64);
                let at = if self.drain_rate.is_some() {
                    k * gap_us + index
                } else {
                    index << 32 | k
                };
                lines.push((at, source, frame, line));
            }
        }
        lines.sort_by_key(|(at, ..)| *at);
        // Bytes still in the buffer, in millionths of a byte, as the frames arrive.
        let mut queued: u64 = 0;
        let mut last = 0;
        let mut printed = 0;
        for (at, source, frame, line) in lines {
            if one_frame && printed > 0 {
                self.lost_frames.push((source, frame));
                continue;
            }
            if let Some(rate) = self.drain_rate {
                queued = queued.saturating_sub(u64::from(rate) * (at - last));
                last = at;
                queued += (line.len() as u64 + 1) * 1_000_000;
                if queued > OUTPUT_BUFFER as u64 * 1_000_000 {
                    self.print("BUFFER FULL");
                    break;
                }
            }
            self.print(&line);
            printed += 1;
        }
        for line in extra {
            self.print(&line);
        }
        self.schedule_late_frames(header, &bytes);
        if one_frame && printed > 0 {
            // The listen ended with its first frame.
            self.end_listen(Instant::now());
        } else if !logical && self.listen_raw && !self.settings.caf {
            self.listening = true;
        } else if !self.hang_after_request {
            self.end_listen(Instant::now());
        }
    }

    // Puts the frames a module sends after this request on the bus, or holds them for the
    // monitor (`delay_from_monitor`).
    fn schedule_late_frames(&mut self, header: u32, request: &[u8]) {
        let Some(delayed) = self.delayed.as_mut() else {
            return;
        };
        let late = delayed(header, request);
        if self.delay_from_monitor {
            self.held = late;
        } else {
            let now = Instant::now();
            self.bus.extend(
                late.into_iter()
                    .map(|(after, id, data)| (now + after, id, data)),
            );
        }
    }

    // A batch of a request and `STM` (STN FRPM, section 16): the request runs as it would alone,
    // and `STM` starts when its listen ends, with no host in between (`end_listen`).
    fn batch(&mut self, line: &str) {
        let mut elements = line.split('|');
        let request = elements.next().unwrap_or_default();
        if !self.settings.batching || self.sti.is_none() || parse_hex(request).is_none() {
            self.print("?");
            self.prompt();
            return;
        }
        // Left to right: the request goes out even if what follows it is refused.
        self.batch_bad_tail = !(elements.next() == Some("STM") && elements.next().is_none());
        self.batch_pending = true;
        self.request(request);
    }

    // The end of a request's listen: its prompt, or in a batch the next element, `STM`, which
    // starts at once whatever `monitor_startup` is: the STN's own switch, not the host's. `at` is
    // when the listen ended: for a frame that ended it, the frame's own time on the bus, not the
    // clock when the fake got round to it, so the test thread being descheduled loses no frame.
    fn end_listen(&mut self, at: Instant) {
        if !std::mem::take(&mut self.batch_pending) {
            self.prompt();
            return;
        }
        if std::mem::take(&mut self.batch_bad_tail) {
            self.print("?");
            self.prompt();
            return;
        }
        if self.batch_drops_monitor {
            self.prompt();
            return;
        }
        self.pipe_next = self.batch_pipe;
        self.monitor_all = false;
        self.start_monitoring_after(at, Duration::ZERO);
    }

    // Starts monitoring, which puts the frames held for it on the bus.
    fn start_monitoring(&mut self) {
        self.start_monitoring_after(Instant::now(), self.monitor_startup);
    }

    fn start_monitoring_after(&mut self, from: Instant, startup: Duration) {
        self.monitoring = true;
        let now = from + startup;
        self.monitor_from = now;
        let held = std::mem::take(&mut self.held);
        self.bus.extend(
            held.into_iter()
                .map(|(after, id, data)| (now + after, id, data)),
        );
    }

    // How a frame is printed after a request or while monitoring.
    fn frame_line(&self, source: u32, frame: &[u8]) -> String {
        if self.settings.headers && self.settings.bits29() {
            format!("{} {}", hex(&source.to_be_bytes()), hex(frame))
        } else if self.settings.headers {
            format!("{source:03X} {}", hex(frame))
        } else {
            hex(frame)
        }
    }

    /// When the next frame still on the bus reaches the adapter.
    pub fn next_frame_at(&self) -> Option<Instant> {
        self.bus.iter().map(|(at, ..)| *at).min()
    }

    /// Lets the frames that have reached the adapter by now in: printed if it's listening or
    /// monitoring and the receive filter shows them, else lost.
    pub fn poll(&mut self) {
        let now = Instant::now();
        let mut due: Vec<_> = self
            .bus
            .iter()
            .filter(|(at, ..)| *at <= now)
            .cloned()
            .collect();
        self.bus.retain(|(at, ..)| *at > now);
        due.sort_by_key(|(at, ..)| *at);
        for (at, id, data) in due {
            let monitoring = self.monitoring && at >= self.monitor_from;
            let monitored = monitoring && self.monitor_all;
            if !monitored && !self.settings.shows(id) {
                continue;
            }
            if self.listening || monitoring {
                let line = self.frame_line(id, &data);
                let acked = self.listening
                    || (self.settings.monitor_ack && !self.monitor_ignores_ack)
                    || !self.two_node_bus;
                if acked {
                    self.print(&line);
                } else {
                    // The module sends the frame again each time nobody acknowledges it. The
                    // adapter reports the error first, then prints what it heard (session 9).
                    self.print("CAN ERROR");
                    for _ in 0..UNACKED_REPEATS {
                        self.print(&line);
                    }
                }
                if self.listening && self.listen_one_frame {
                    self.listening = false;
                    self.end_listen(at);
                }
            } else {
                self.lost_frames.push((id, data));
            }
        }
    }
}

impl FakeElm {
    // Where the adapter sends flow control for a First Frame from `source` (datasheet p. 48):
    // mode 0 to the OBD-II request ID for an OBD-II reply ID, mode 1 to `AT FC SH`, and mode 2
    // to the First Frame's own ID, unchanged.
    fn flow_control_to(&self, source: u32) -> u32 {
        match self.settings.fc_mode {
            0 if (0x7E8..=0x7EF).contains(&source) => source - 8,
            // The datasheet doesn't say; nothing a module would expect.
            0 => 0,
            1 => self.settings.fc_header.unwrap_or(0),
            _ => source,
        }
    }

    // The gap between consecutive frames that the adapter's flow control asks for: none with its
    // own ISO 15765-4 handling (mode 0), else the STmin in `AT FC SD` (ISO 15765-2).
    fn st_min_us(&self) -> u64 {
        if self.settings.fc_mode == 0 {
            return 0;
        }
        let st_min = self
            .settings
            .fc_data
            .as_deref()
            .and_then(parse_hex)
            .and_then(|data| data.get(2).copied())
            .unwrap_or(0);
        match st_min {
            0..=0x7F => u64::from(st_min) * 1000,
            0xF1..=0xF9 => u64::from(st_min - 0xF0) * 100,
            _ => 127_000,
        }
    }
}

/// A flow control frame's data, padded to 8 bytes: `status` 0 is continue to send, 1 wait, 2
/// overflow.
pub fn flow_control_frame(status: u8, block_size: u8, st_min: u8) -> Vec<u8> {
    vec![0x30 | status, block_size, st_min, 0, 0, 0, 0, 0]
}

// A transfer in progress in a [`Module`].
struct Partial {
    data: Vec<u8>,
    len: usize,
    next_seq: u8,
    in_block: usize,
    last: Instant,
}

/// A module that takes a request written as raw frames with `AT CAF0`, as an ECU takes one in
/// ISO-TP frames, and answers it with whatever the fake's responder gives for the whole request.
/// It asks for the rest of a request with `flow_control` after the first frame and after every
/// block, drops a transfer that waits longer than `n_cr` for its next frame, and records what
/// reached it. What it prints reaches the host only while the adapter listens (`AT R1`) and the
/// receive filter shows it.
#[allow(clippy::struct_excessive_bools)]
pub struct Module {
    /// The ID it listens on, which the adapter's header must be.
    pub request_id: u32,
    /// The ID its flow control and answer come from.
    pub reply_id: u32,
    /// The frames it prints after a first frame and after each block's last frame: the ID
    /// each comes from and its data. The block size is that of the last continue-to-send.
    pub flow_control: Vec<(u32, Vec<u8>)>,
    /// How long it waits for a consecutive frame before it drops the transfer (ISO 15765-2's
    /// `N_Cr`, 1 s).
    pub n_cr: Duration,
    /// It takes a first frame while a transfer is in progress for a consecutive frame's
    /// mistake and ignores it, as a receiver that isn't told to start over does.
    pub ignores_first_frame_while_receiving: bool,
    /// Frames of another module on the bus, printed with each flow control: the receive filter
    /// should hide them.
    pub other_nodes: Vec<(u32, Vec<u8>)>,
    /// Print its frames whatever the receive filter says, as an adapter that lost its filter does.
    pub unfiltered: bool,
    /// The adapter prints this for the nth frame line it is given (counting from 1) instead of
    /// sending it, as `BUS BUSY` would.
    pub status_on_frame: Option<(usize, String)>,
    /// Lines the adapter prints after the answer to the last frame, before its prompt.
    pub after_answer: Vec<String>,
    /// The requests it has received whole.
    pub received: Vec<Vec<u8>>,
    /// Every frame that reached it, and when.
    pub frames: Vec<(Instant, Vec<u8>)>,
    /// Transfers it dropped: its timer ran out, or a consecutive frame was out of order.
    pub dropped: usize,
    attempts: usize,
    partial: Option<Partial>,
}

impl Module {
    /// A module that answers every first frame with continue-to-send, block size 0 and `STmin` 0.
    pub fn new(request_id: u32, reply_id: u32) -> Self {
        Self {
            request_id,
            reply_id,
            flow_control: vec![(reply_id, flow_control_frame(0, 0, 0))],
            n_cr: Duration::from_secs(1),
            ignores_first_frame_while_receiving: false,
            other_nodes: Vec::new(),
            unfiltered: false,
            status_on_frame: None,
            after_answer: Vec::new(),
            received: Vec::new(),
            frames: Vec::new(),
            dropped: 0,
            attempts: 0,
            partial: None,
        }
    }

    /// Asks for `block_size` frames at a time, `st_min` apart.
    pub fn with_flow(mut self, block_size: u8, st_min: u8) -> Self {
        self.flow_control = vec![(self.reply_id, flow_control_frame(0, block_size, st_min))];
        self
    }

    /// Prints these frames, from `reply_id`, as its flow control.
    pub fn with_flow_frames(mut self, frames: Vec<Vec<u8>>) -> Self {
        self.flow_control = frames.into_iter().map(|f| (self.reply_id, f)).collect();
        self
    }

    // What a frame that reaches the module does: whether it asks for flow control, and the request
    // it completes.
    fn receive(&mut self, bytes: &[u8], now: Instant) -> (bool, Option<Vec<u8>>) {
        self.frames.push((now, bytes.to_vec()));
        if self
            .partial
            .as_ref()
            .is_some_and(|p| now.duration_since(p.last) > self.n_cr)
        {
            self.partial = None;
            self.dropped += 1;
        }
        let block_size = self.block_size();
        let mut flow_due = false;
        let mut message = None;
        match bytes[0] >> 4 {
            0 => {
                let len = usize::from(bytes[0] & 0x0F);
                if (1..=7).contains(&len) {
                    message = Some(bytes[1..=len].to_vec());
                    self.partial = None;
                }
            }
            1 => {
                if self.partial.is_none() || !self.ignores_first_frame_while_receiving {
                    self.partial = Some(Partial {
                        data: bytes[2..].to_vec(),
                        len: usize::from(bytes[0] & 0x0F) << 8 | usize::from(bytes[1]),
                        next_seq: 1,
                        in_block: 0,
                        last: now,
                    });
                    flow_due = true;
                }
            }
            2 => {
                if let Some(partial) = self.partial.as_mut() {
                    if bytes[0] & 0x0F == partial.next_seq {
                        partial.data.extend_from_slice(&bytes[1..]);
                        partial.next_seq = (partial.next_seq + 1) & 0x0F;
                        partial.in_block += 1;
                        partial.last = now;
                        if partial.data.len() >= partial.len {
                            partial.data.truncate(partial.len);
                            message = self.partial.take().map(|p| p.data);
                        } else if block_size != 0 && partial.in_block == block_size {
                            partial.in_block = 0;
                            flow_due = true;
                        }
                    } else {
                        self.partial = None;
                        self.dropped += 1;
                    }
                }
            }
            _ => {}
        }
        if let Some(message) = &message {
            self.received.push(message.clone());
        }
        (flow_due, message)
    }

    // The frames it prints when it asks for flow control, with the other nodes' that go with them.
    fn printed_flow(&self) -> Vec<(u32, Vec<u8>)> {
        self.flow_control
            .iter()
            .chain(&self.other_nodes)
            .cloned()
            .collect()
    }

    fn block_size(&self) -> usize {
        self.flow_control
            .iter()
            .rev()
            .find(|(_, data)| data.first() == Some(&0x30))
            .and_then(|(_, data)| data.get(1))
            .map_or(0, |&bs| usize::from(bs))
    }
}

impl FakeElm {
    /// Takes `module`'s request as frames: see [`Module`].
    pub fn with_module(mut self, module: Module) -> Self {
        self.module = Some(module);
        self
    }

    // One frame line written with `AT CAF0` to the module's request ID.
    fn module_frame(&mut self, header: u32, bytes: &[u8]) {
        if let Some(module) = self.module.as_mut() {
            module.attempts += 1;
            let shown = module
                .status_on_frame
                .clone()
                .filter(|(nth, _)| *nth == module.attempts);
            if let Some((_, text)) = shown {
                self.print(&text);
                self.prompt();
                return;
            }
        }
        self.sent.push((header, bytes.to_vec()));
        if !self.has_protocol() {
            return;
        }
        let Some(module) = self.module.as_mut() else {
            return;
        };
        let (flow_due, message) = module.receive(bytes, Instant::now());
        let unfiltered = module.unfiltered;
        let flow = if flow_due {
            module.printed_flow()
        } else {
            Vec::new()
        };
        let responses = self.settings.responses;
        let mut printed = 0;
        for (id, data) in flow {
            let shown = unfiltered || self.settings.shows(id);
            if !responses {
                // The adapter isn't listening: the module sent it for nobody.
                if shown {
                    self.lost_frames.push((id, data));
                }
            } else if shown {
                let line = self.frame_line(id, &data);
                self.print(&line);
                printed += 1;
            }
        }
        if let Some(message) = message {
            if responses {
                self.answer(header, &message, true);
            } else {
                self.prompt();
            }
        } else if !responses {
            self.prompt();
        } else if printed == 0 {
            // Nothing came before the adapter's timeout.
            self.print("NO DATA");
            self.prompt();
        } else if self.listen_one_frame {
            self.prompt();
        } else {
            // It listens on until its timeout, which the host cuts short with a byte.
            self.listening = true;
        }
    }
}

// Three hex digits, or six or eight (a 29-bit header's low 24 bits, or a whole 29-bit ID).
fn parse_id(text: &str) -> Option<u32> {
    (matches!(text.len(), 3 | 6 | 8) && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(text, 16).ok())
        .flatten()
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

// The CAN frames a module sends for one reply, as the adapter shows them with headers on: each
// padded to 8 bytes with 0x00, as many modules do.
pub fn frames(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut segmenter = Segmenter::new(payload, Addressing::Normal).unwrap();
    let mut frames = Vec::new();
    loop {
        match segmenter.step() {
            Step::Send(frame) => {
                let mut bytes = frame.as_bytes().to_vec();
                bytes.resize(8, 0x00);
                frames.push(bytes);
            }
            Step::WaitForFlowControl => segmenter
                .flow_control(FlowControl {
                    status: FlowStatus::ContinueToSend,
                    block_size: 0,
                    st_min: Duration::ZERO,
                })
                .unwrap(),
            Step::Done => return frames,
            Step::Aborted => unreachable!(),
        }
    }
}

/// A [`Link`] to a [`FakeElm`] that hands out at most `chunk` bytes per read.
pub struct FakeLink {
    pub elm: FakeElm,
    pub chunk: usize,
    pub written: Vec<u8>,
    pub writes: Vec<Vec<u8>>,
    /// When set, every read returns these bytes instead of the adapter's output, forever, once
    /// `inject` is used up.
    pub flood: Option<Vec<u8>>,
    pub flooded: usize,
    /// When set, the link is gone: every write and read fails.
    pub closed: bool,
    /// Bytes the next read returns before the adapter's own output.
    pub inject: Vec<u8>,
    /// Flips these bits of this byte of the next write, as a noisy serial line would.
    pub corrupt_next_write: Option<(usize, u8)>,
    /// Flips these bits of this byte of the next write of exactly these bytes.
    pub corrupt_write_of: Option<(Vec<u8>, usize, u8)>,
    /// Flips these bits of this byte of the write with this index in `writes`, counting from
    /// the first write on the link.
    pub corrupt_write_at: Option<(usize, usize, u8)>,
    /// Bytes that arrive at these times, whatever the adapter prints. A read waits for the next
    /// one, up to its timeout.
    pub scheduled: VecDeque<(std::time::Instant, Vec<u8>)>,
    /// What the link says its byte rate is.
    pub byte_rate: Option<u32>,
    /// When set, every write fails, though reads still work.
    pub fail_writes: bool,
    /// The link goes down after this many more writes: the next one and every read fail.
    pub kill_after_writes: Option<usize>,
    /// The link goes down just after the next write of exactly these bytes went through: every
    /// later read and write fails.
    pub close_after_write_of: Option<Vec<u8>>,
    /// Waits this long before delivering the next write of exactly these bytes, as a slow link
    /// would.
    pub slow_write_of: Option<(Vec<u8>, Duration)>,
    /// After the write with this index in `writes`, the next reads each wait this long first,
    /// in order: a link or adapter slow to answer.
    pub slow_reads_after: Option<(usize, VecDeque<Duration>)>,
    slow_reads: VecDeque<Duration>,
}

impl FakeLink {
    pub fn new(elm: FakeElm) -> Self {
        Self {
            elm,
            chunk: 64,
            written: Vec::new(),
            writes: Vec::new(),
            flood: None,
            flooded: 0,
            closed: false,
            inject: Vec::new(),
            corrupt_next_write: None,
            corrupt_write_of: None,
            corrupt_write_at: None,
            scheduled: VecDeque::new(),
            byte_rate: Some(115_200 / 10),
            fail_writes: false,
            kill_after_writes: None,
            close_after_write_of: None,
            slow_write_of: None,
            slow_reads_after: None,
            slow_reads: VecDeque::new(),
        }
    }

    /// A link at `baud` bits a second, which drains the adapter's output buffer at that rate.
    pub fn at_baud(mut elm: FakeElm, baud: u32) -> Self {
        elm.drain_rate = Some(baud / 10);
        let mut link = Self::new(elm);
        link.byte_rate = Some(baud / 10);
        link
    }
}

impl Link for FakeLink {
    fn write_all(&mut self, bytes: &[u8], _driver: Driver) -> io::Result<()> {
        if self.closed || self.fail_writes {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if let Some(left) = &mut self.kill_after_writes {
            if *left == 0 {
                self.closed = true;
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            *left -= 1;
        }
        if self
            .slow_write_of
            .as_ref()
            .is_some_and(|(of, _)| of == bytes)
            && let Some((_, wait)) = self.slow_write_of.take()
        {
            std::thread::sleep(wait);
        }
        let sent = bytes;
        self.written.extend_from_slice(bytes);
        let number = self.writes.len();
        self.writes.push(bytes.to_vec());
        if self
            .slow_reads_after
            .as_ref()
            .is_some_and(|(at, _)| *at == number)
            && let Some((_, delays)) = self.slow_reads_after.take()
        {
            self.slow_reads = delays;
        }
        let mut bytes = bytes.to_vec();
        if self.corrupt_write_at.is_some_and(|(at, _, _)| at == number)
            && let Some((_, index, bits)) = self.corrupt_write_at.take()
        {
            bytes[index] ^= bits;
        }
        if let Some((index, bits)) = self.corrupt_next_write.take() {
            bytes[index] ^= bits;
        }
        if self
            .corrupt_write_of
            .as_ref()
            .is_some_and(|(of, _, _)| *of == bytes)
            && let Some((_, index, bits)) = self.corrupt_write_of.take()
        {
            bytes[index] ^= bits;
        }
        self.elm.write(&bytes);
        if self.close_after_write_of.as_deref() == Some(sent) {
            self.close_after_write_of = None;
            self.closed = true;
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration, _driver: Driver) -> io::Result<usize> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if let Some(delay) = self.slow_reads.pop_front() {
            std::thread::sleep(delay);
        }
        if !self.inject.is_empty() {
            let n = buf.len().min(self.inject.len());
            buf[..n].copy_from_slice(&self.inject[..n]);
            self.inject.drain(..n);
            return Ok(n);
        }
        if let Some(flood) = &self.flood {
            self.flooded += 1;
            let n = buf.len().min(flood.len());
            buf[..n].copy_from_slice(&flood[..n]);
            return Ok(n);
        }
        if let Some((at, _)) = self.scheduled.front() {
            let now = std::time::Instant::now();
            if *at <= now {
                let (_, bytes) = self.scheduled.pop_front().unwrap();
                buf[..bytes.len()].copy_from_slice(&bytes);
                return Ok(bytes.len());
            }
            if !self.elm.has_output() {
                std::thread::sleep((*at - now).min(timeout));
                return Ok(0);
            }
        }
        self.elm.poll();
        if !self.elm.has_output()
            && let Some(at) = self.elm.next_frame_at()
        {
            // A module's frame is still on its way: wait for it, up to the read's timeout.
            std::thread::sleep(
                at.saturating_duration_since(std::time::Instant::now())
                    .min(timeout),
            );
            self.elm.poll();
        }
        let bytes = self.elm.read(self.chunk.min(buf.len()));
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn kind(&self) -> LinkKind {
        LinkKind::UsbSerial
    }

    fn byte_rate(&self) -> Option<u32> {
        self.byte_rate
    }
}

impl std::fmt::Debug for FakeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeLink").finish_non_exhaustive()
    }
}
