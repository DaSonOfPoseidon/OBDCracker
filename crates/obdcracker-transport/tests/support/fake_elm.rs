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
pub struct FakeElm {
    responder: Responder,
    input: Vec<u8>,
    // The line as received, for the echo.
    raw: Vec<u8>,
    output: VecDeque<u8>,
    last: Option<String>,
    /// The settings an `ATZ` resets.
    pub settings: Settings,
    /// Every line the host sent, after removing spaces, in order.
    pub commands: Vec<String>,
    /// Every request put on the bus: the header and payload.
    pub sent: Vec<(u32, Vec<u8>)>,
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
}

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
    pub fc_header: Option<u32>,
    pub fc_data: Option<String>,
    pub fc_mode: u8,
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
            fc_header: None,
            fc_data: None,
            fc_mode: 0,
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
            last: None,
            settings: Settings::default(),
            commands: Vec::new(),
            sent: Vec::new(),
            unsupported: Vec::new(),
            sti: None,
            interrupted: 0,
            repeats: 0,
            hang_after_request: false,
            pp: Vec::new(),
            pps: None,
            after_echo: Vec::new(),
        }
    }

    /// An adapter on a bus where nothing answers.
    pub fn silent() -> Self {
        Self::new(Box::new(|_, _| Vec::new()))
    }

    /// Takes bytes from the host.
    pub fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if !self.output.is_empty() {
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
                    self.run(&line, &raw);
                }
                // Spaces and control characters are ignored (datasheet p. 8), but echoed.
                b' ' | 0..=0x1F => self.raw.push(byte),
                _ => {
                    self.raw.push(byte);
                    self.input.push(byte);
                }
            }
        }
    }

    /// Takes up to `max` bytes the adapter has printed.
    pub fn read(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.output.len());
        self.output.drain(..n).collect()
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
    }

    // The adapter echoes what it received, as it received it, once the line ends.
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
                self.output.extend(raw);
                self.output.push_back(b'\r');
            }
        }
        self.output.extend(std::mem::take(&mut self.after_echo));
        if self.unsupported.contains(&line) {
            self.print("?");
            self.prompt();
            return;
        }
        if let Some(at) = line.strip_prefix("AT") {
            self.at(at);
        } else if line == "STI" {
            let reply = self.sti.clone().unwrap_or_else(|| "?".into());
            self.print(&reply);
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
                self.print("");
                self.print(BANNER);
                self.prompt();
                return;
            }
            "I" => {
                self.print(BANNER);
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
            "R1" | "AT1" | "STFF" | "CRA7XX" => true,
            "FCSM0" => {
                self.settings.fc_mode = 0;
                true
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
            _ => {
                if let Some(protocol) = cmd.strip_prefix("SP") {
                    self.settings.protocol = Some(protocol.to_owned());
                    true
                } else if let Some(id) = cmd.strip_prefix("FCSH") {
                    self.settings.fc_header = parse_id(id);
                    self.settings.fc_header.is_some()
                } else if let Some(data) = cmd.strip_prefix("FCSD") {
                    self.settings.fc_data = Some(data.to_owned());
                    true
                } else if let Some(id) = cmd.strip_prefix("SH") {
                    match parse_id(id) {
                        Some(id) => {
                            self.settings.header = id;
                            true
                        }
                        None => false,
                    }
                } else {
                    false
                }
            }
        };
        self.print(if ok { "OK" } else { "?" });
        self.prompt();
    }

    // `AT PPS`: four parameters a line, as `nn:vv N` (on) or `nn:vv F` (off).
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
        let bytes = match parse_hex(hex_text) {
            // With CAN auto formatting on, a request is one single frame: 1 to 7 bytes.
            Some(bytes) if (1..=7).contains(&bytes.len()) => bytes,
            _ => {
                self.print("?");
                self.prompt();
                return;
            }
        };
        // Recorded even without a protocol: a real adapter would then search for one, sending
        // probe frames.
        self.sent.push((self.settings.header, bytes.clone()));
        if self.settings.protocol.as_deref() != Some("6") {
            self.print("CAN ERROR");
            self.prompt();
            return;
        }
        let replies = (self.responder)(self.settings.header, &bytes);
        if replies.is_empty() {
            self.print("NO DATA");
        }
        for (source, payload) in replies {
            for frame in frames(&payload) {
                let line = if self.settings.headers {
                    format!("{source:03X} {}", hex(&frame))
                } else {
                    hex(&frame)
                };
                self.print(&line);
            }
        }
        if !self.hang_after_request {
            self.prompt();
        }
    }
}

fn parse_id(text: &str) -> Option<u32> {
    (text.len() == 3 && text.bytes().all(|b| b.is_ascii_hexdigit()))
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
}

impl FakeLink {
    pub fn new(elm: FakeElm) -> Self {
        Self {
            elm,
            chunk: 64,
            written: Vec::new(),
            flood: None,
            flooded: 0,
            closed: false,
            inject: Vec::new(),
            corrupt_next_write: None,
        }
    }
}

impl Link for FakeLink {
    fn write_all(&mut self, bytes: &[u8], _driver: Driver) -> io::Result<()> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.written.extend_from_slice(bytes);
        let mut bytes = bytes.to_vec();
        if let Some((index, bits)) = self.corrupt_next_write.take() {
            bytes[index] ^= bits;
        }
        self.elm.write(&bytes);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], _timeout: Duration) -> io::Result<usize> {
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
        let bytes = self.elm.read(self.chunk.min(buf.len()));
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn kind(&self) -> LinkKind {
        LinkKind::UsbSerial
    }
}

impl std::fmt::Debug for FakeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeLink").finish_non_exhaustive()
    }
}
