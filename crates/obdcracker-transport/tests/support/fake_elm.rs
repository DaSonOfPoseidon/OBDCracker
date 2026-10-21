//! A fake ELM327, written from its datasheet (ELM327DS v2.0), for testing the driver without an
//! adapter. It takes the bytes the host writes and produces what the adapter would print.
//! Shared by other crates' tests through `#[path]`, so it only uses public APIs.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use obdcracker_core::isotp::{Addressing, FlowControl, FlowStatus, Segmenter, Step};
use obdcracker_transport::hex;
use obdcracker_transport::link::{Driver, Link, LinkKind};

/// Answers a request sent to `header`: each reply's source CAN ID and payload.
pub type Responder = Box<dyn FnMut(u32, &[u8]) -> Vec<(u32, Vec<u8>)> + Send>;

pub const BANNER: &str = "ELM327 v2.0";

/// The fake adapter's state, as the datasheet describes it after a reset.
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
    /// The settings an `ATZ` resets.
    pub settings: Settings,
    /// Every line the host sent, after removing spaces, in order.
    pub commands: Vec<String>,
    /// Every request put on the bus: the header and payload.
    pub sent: Vec<(u32, Vec<u8>)>,
    /// The module each flow control frame the adapter sent was for: every sender of a
    /// multi-frame reply that passed the receive filter.
    pub flow_control_for: Vec<u32>,
    /// The CAN ID each of those flow control frames went to.
    pub flow_control_ids: Vec<u32>,
    /// Commands this adapter doesn't support (it answers `?`), as a clone might.
    pub unsupported: Vec<String>,
    /// What `STI` answers; `None` for a plain ELM327.
    pub sti: Option<String>,
    /// Times the host wrote while the adapter was still printing, which interrupts it.
    pub interrupted: usize,
    /// Times the host sent a bare carriage return, which repeats the last command.
    pub repeats: usize,
    /// Leave the prompt off after a bus request, as an adapter that hangs would.
    pub hang_after_request: bool,
    /// Programmable parameters turned on, and their values (datasheet pp. 57-61). The rest are
    /// off, at their factory values.
    pub pp: Vec<(u8, u8)>,
    /// What `AT PPS` prints instead of the parameter summary.
    pub pps: Option<Vec<String>>,
    /// Bytes printed right after the next line's echo, before its answer.
    pub after_echo: Vec<u8>,
    /// Bytes printed right after the next prompt, as an adapter that resets while idle would.
    pub after_prompt: Vec<u8>,
    /// Echo a line only once its carriage return arrives, as some clones may. The STN in an
    /// `OBDLink EX` (and the ELM327) echoes each character as it arrives, and holds the line
    /// until the carriage return, however long that takes (#54).
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
}

// The adapter's output buffer, in bytes (ELM327DS v2.0, p. 80).
pub const OUTPUT_BUFFER: usize = 512;
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
    /// The 11-bit header (`AT SH` with 3 digits).
    pub header: u32,
    /// The 29-bit header's priority bits (`AT CP`) and the rest (`AT SH` with 6 digits).
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
}

impl Settings {
    // Whether the adapter is on 29-bit CAN (protocol 7).
    pub fn bits29(&self) -> bool {
        self.protocol.as_deref() == Some("7")
    }

    // The CAN ID requests go to.
    pub fn request_id(&self) -> u32 {
        if self.bits29() {
            u32::from(self.priority) << 24 | self.header29
        } else {
            self.header
        }
    }

    // Whether the receive filter shows frames from `id`.
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
        }
    }

    /// An adapter on a bus where nothing answers.
    pub fn silent() -> Self {
        Self::new(Box::new(|_, _| Vec::new()))
    }

    /// Takes bytes from the host.
    pub fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
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

    /// Takes up to `max` bytes the adapter has printed.
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
        self.output.extend(line.bytes());
        self.output.push_back(b'\r');
        if self.settings.linefeeds {
            self.output.push_back(b'\n');
        }
    }

    fn prompt(&mut self) {
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
            "RV" => {
                self.print("12.6V");
                self.prompt();
                return;
            }
            "E0" | "E1" => {
                self.settings.echo = cmd == "E1";
                true
            }
            "CAF0" | "CAF1" => {
                self.settings.caf = cmd == "CAF1";
                true
            }
            "CFC0" | "CFC1" => {
                self.settings.cfc = cmd == "CFC1";
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
            "R1" | "AT0" | "AT1" | "STFF" => true,
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
            _ => {
                self.print("?");
                self.prompt();
                return;
            }
        };
        if !self.settings.caf && !self.settings.variable_dlc {
            bytes.resize(8, 0x00);
        }
        // Recorded even without a protocol: a real adapter would then search for one, sending
        // probe frames.
        let header = self.settings.request_id();
        self.sent.push((header, bytes.clone()));
        if !matches!(self.settings.protocol.as_deref(), Some("6" | "7")) {
            self.print("CAN ERROR");
            self.prompt();
            return;
        }
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
        if replies.is_empty() {
            self.print("NO DATA");
        }
        let gap_us = self.st_min_us().max(FRAME_TIME_US);
        // Each frame line and when it arrives, in µs. Modules answer at once, so with the buffer
        // modelled their frames interleave, each module's spaced by the gap its flow control
        // asked for; otherwise each reply is printed whole, in turn.
        let mut lines = Vec::new();
        for (index, (source, payload)) in replies.into_iter().enumerate() {
            // Off, each reply is one frame's data as it is.
            let mut frames = if self.settings.caf {
                frames(&payload)
            } else {
                vec![payload.iter().copied().take(8).collect()]
            };
            if !self.settings.caf
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
                let line = if self.settings.headers && self.settings.bits29() {
                    format!("{} {}", hex(&source.to_be_bytes()), hex(&frame))
                } else if self.settings.headers {
                    format!("{source:03X} {}", hex(&frame))
                } else {
                    hex(&frame)
                };
                let (index, k) = (index as u64, k as u64);
                let at = if self.drain_rate.is_some() {
                    k * gap_us + index
                } else {
                    index << 32 | k
                };
                lines.push((at, line));
            }
        }
        lines.sort_by_key(|(at, _)| *at);
        // Bytes still in the buffer, in millionths of a byte, as the frames arrive.
        let mut queued: u64 = 0;
        let mut last = 0;
        for (at, line) in lines {
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
        }
        if !self.hang_after_request {
            self.prompt();
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
    /// Every byte the host wrote.
    pub written: Vec<u8>,
    /// Each write the host made, in order.
    pub writes: Vec<Vec<u8>>,
    /// When set, every read returns these bytes instead of the adapter's output, forever, once
    /// `inject` is used up.
    pub flood: Option<Vec<u8>>,
    /// How many reads the flood answered.
    pub flooded: usize,
    /// When set, the link is gone: every write and read fails.
    pub closed: bool,
    /// Bytes the next read returns before the adapter's own output.
    pub inject: Vec<u8>,
    /// Flips these bits of this byte of the next write, as a noisy serial line would.
    pub corrupt_next_write: Option<(usize, u8)>,
    /// Flips these bits of this byte of the next write of exactly these bytes.
    pub corrupt_write_of: Option<(Vec<u8>, usize, u8)>,
    /// Bytes that arrive at these times, whatever the adapter prints. A read waits for the next
    /// one, up to its timeout.
    pub scheduled: VecDeque<(std::time::Instant, Vec<u8>)>,
    /// What the link says its byte rate is.
    pub byte_rate: Option<u32>,
    /// When set, every write fails, though reads still work.
    pub fail_writes: bool,
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
            scheduled: VecDeque::new(),
            byte_rate: Some(115_200 / 10),
            fail_writes: false,
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
        self.written.extend_from_slice(bytes);
        self.writes.push(bytes.to_vec());
        let mut bytes = bytes.to_vec();
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
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration, _driver: Driver) -> io::Result<usize> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
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
