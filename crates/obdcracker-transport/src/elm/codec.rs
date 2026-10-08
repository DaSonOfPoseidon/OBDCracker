//! What an ELM327 prints, split into lines and classified. Pure and IO-free: everything here
//! treats the adapter's output as untrusted input.
//!
//! The formats follow the ELM327 datasheet (ELM327DS v2.0), with echo off, headers on and
//! spaces on (`ATE0`, `ATH1`, `ATS1`), which is how [`super::Elm`] sets the adapter up.

/// The longest line kept, in bytes. A frame line with headers and spaces on is 27 characters,
/// and one marked `<DATA ERROR` is under 40; anything longer isn't from a working adapter.
pub const MAX_LINE: usize = 96;

/// Something the adapter printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// One non-empty line, without its line ending: printable ASCII and U+FFFD only.
    Line(String),
    /// The `>` prompt: the adapter has finished and waits for the next command.
    Prompt,
    /// A line longer than [`MAX_LINE`]. Its bytes were dropped.
    Overlong,
}

/// Splits the adapter's output into [`Event`]s. Lines end at a carriage return or a line feed,
/// empty lines are skipped, NUL bytes are dropped (the datasheet warns the ELM327 may insert
/// them), and `>` is the prompt. Memory use is bounded by [`MAX_LINE`].
///
/// Every byte that isn't printable ASCII becomes U+FFFD, so a line is always safe to print:
/// an adapter (or anyone who can reach a Wi-Fi one) can't send terminal escape sequences.
#[derive(Debug, Default)]
pub struct LineSplitter {
    line: String,
    // Bytes in `line`; a replacement character takes three in the string.
    len: usize,
    overlong: bool,
}

impl LineSplitter {
    /// Takes the next bytes read from the adapter and appends what they complete to `events`.
    pub fn push(&mut self, bytes: &[u8], events: &mut Vec<Event>) {
        for &byte in bytes {
            match byte {
                0 => {}
                b'\r' | b'\n' => self.end_line(events),
                b'>' => {
                    self.end_line(events);
                    events.push(Event::Prompt);
                }
                _ if self.overlong => {}
                _ if self.len == MAX_LINE => {
                    self.line.clear();
                    self.len = 0;
                    self.overlong = true;
                    events.push(Event::Overlong);
                }
                _ => {
                    self.line.push(if byte == b' ' || byte.is_ascii_graphic() {
                        char::from(byte)
                    } else {
                        char::REPLACEMENT_CHARACTER
                    });
                    self.len += 1;
                }
            }
        }
    }

    /// Drops a partial line, such as after the adapter was interrupted.
    pub fn clear(&mut self) {
        self.line.clear();
        self.len = 0;
        self.overlong = false;
    }

    fn end_line(&mut self, events: &mut Vec<Event>) {
        if !self.line.is_empty() {
            events.push(Event::Line(std::mem::take(&mut self.line)));
        }
        self.len = 0;
        self.overlong = false;
    }
}

/// One CAN frame as the adapter printed it: an 11-bit ID and 1 to 8 data bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanFrame {
    id: u16,
    data: [u8; 8],
    len: usize,
}

impl CanFrame {
    /// The 11-bit CAN ID the frame came from.
    #[must_use]
    pub fn id(&self) -> u32 {
        u32::from(self.id)
    }

    /// The frame's data bytes, PCI byte first.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// A message the adapter prints instead of data (datasheet, "Error Messages and Alerts").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `?`: the adapter didn't understand the command, and didn't act on it.
    Unknown,
    /// `NO DATA`: nothing answered before the adapter's timeout.
    NoData,
    /// `SEARCHING...`: the adapter is looking for the protocol.
    Searching,
    /// `STOPPED`: the adapter was interrupted by a byte from the host.
    Stopped,
    /// `BUFFER FULL`: the adapter's output buffer overflowed, so data was lost.
    BufferFull,
    /// `BUS BUSY`: too much bus activity to send.
    BusBusy,
    /// `BUS ERROR`: an invalid signal on the bus, usually wiring.
    BusError,
    /// `CAN ERROR`: the CAN controller couldn't start, send or receive.
    CanError,
    /// `DATA ERROR`, or a frame marked `<DATA ERROR`: a reply that couldn't be recovered.
    DataError,
    /// A frame marked `<RX ERROR`: an error in the received CAN data.
    RxError,
    /// `FB ERROR`: an output's feedback check failed, usually wiring.
    FbError,
    /// `LV RESET`: the adapter reset after its supply dropped, losing its settings.
    LvReset,
    /// `UNABLE TO CONNECT`: no protocol found.
    UnableToConnect,
    /// `ACT ALERT`: no activity for a while; the adapter may go to sleep soon.
    ActAlert,
    /// `LP ALERT`: the adapter goes to low power in two seconds.
    LpAlert,
    /// `ERRxx`: an internal error, such as `ERR94` (a fatal CAN error).
    Internal(u8),
}

impl Status {
    /// Whether the adapter has lost the settings a driver gave it: it has reset or is about to
    /// (`LV RESET`, `LP ALERT`, any `ERRxx`; `ERR94` needs a full reset, which restores the
    /// defaults, datasheet p. 79), or it is searching for a protocol (`SEARCHING...`, and
    /// `UNABLE TO CONNECT` after a search failed), which a driver that sets one never asks for.
    #[must_use]
    pub fn loses_settings(self) -> bool {
        matches!(
            self,
            Self::LvReset
                | Self::LpAlert
                | Self::Internal(_)
                | Self::Searching
                | Self::UnableToConnect
        )
    }

    /// Whether this means the command failed or the adapter is in trouble. `NO DATA`,
    /// `STOPPED` and `ACT ALERT` aren't failures.
    #[must_use]
    pub fn is_failure(self) -> bool {
        !matches!(self, Self::NoData | Self::Stopped | Self::ActAlert)
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Unknown => "?",
            Self::NoData => "NO DATA",
            Self::Searching => "SEARCHING...",
            Self::Stopped => "STOPPED",
            Self::BufferFull => "BUFFER FULL",
            Self::BusBusy => "BUS BUSY",
            Self::BusError => "BUS ERROR",
            Self::CanError => "CAN ERROR",
            Self::DataError => "DATA ERROR",
            Self::RxError => "RX ERROR",
            Self::FbError => "FB ERROR",
            Self::LvReset => "LV RESET",
            Self::UnableToConnect => "UNABLE TO CONNECT",
            Self::ActAlert => "ACT ALERT",
            Self::LpAlert => "LP ALERT",
            Self::Internal(code) => return write!(f, "ERR{code:02X}"),
        };
        f.write_str(text)
    }
}

/// What one line means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A CAN frame.
    Frame(CanFrame),
    /// `OK`: an AT command succeeded.
    Ok,
    /// A status or error message.
    Status(Status),
    /// Anything else, such as the `ATI` banner or an `ATRV` voltage.
    Text(String),
}

/// Classifies one line from [`LineSplitter`].
#[must_use]
pub fn parse_line(line: &str) -> Line {
    if line.ends_with(" <DATA ERROR") {
        return Line::Status(Status::DataError);
    }
    if line.ends_with(" <RX ERROR") {
        return Line::Status(Status::RxError);
    }
    if line == "OK" {
        return Line::Ok;
    }
    if let Some(status) = parse_status(line) {
        return Line::Status(status);
    }
    match parse_frame(line) {
        Some(frame) => Line::Frame(frame),
        None => Line::Text(line.to_owned()),
    }
}

fn parse_status(line: &str) -> Option<Status> {
    let status = match line {
        "?" => Status::Unknown,
        "NO DATA" => Status::NoData,
        "SEARCHING..." => Status::Searching,
        "STOPPED" => Status::Stopped,
        "BUFFER FULL" => Status::BufferFull,
        "BUS BUSY" => Status::BusBusy,
        "BUS ERROR" => Status::BusError,
        "CAN ERROR" => Status::CanError,
        "DATA ERROR" => Status::DataError,
        "FB ERROR" => Status::FbError,
        "LV RESET" => Status::LvReset,
        "UNABLE TO CONNECT" => Status::UnableToConnect,
        "ACT ALERT" | "!ACT ALERT" => Status::ActAlert,
        "LP ALERT" | "!LP ALERT" => Status::LpAlert,
        _ => return Some(Status::Internal(hex_byte(line.strip_prefix("ERR")?)?)),
    };
    Some(status)
}

// "7E8 06 41 00 BE 3F A8 13": a 3-digit ID and 1 to 8 bytes, each separated by one space.
// ELM327s print a space after the last byte too, so one trailing space is allowed.
fn parse_frame(line: &str) -> Option<CanFrame> {
    let line = line.strip_suffix(' ').unwrap_or(line);
    let mut tokens = line.split(' ');
    let id = tokens.next()?;
    if id.len() != 3 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let id = u16::from_str_radix(id, 16).ok().filter(|&id| id <= 0x7FF)?;
    let mut data = [0; 8];
    let mut len = 0;
    for token in tokens {
        *data.get_mut(len)? = hex_byte(token)?;
        len += 1;
    }
    (len > 0).then_some(CanFrame { id, data, len })
}

// Exactly two hex digits. `from_str_radix` alone would also take "+F".
fn hex_byte(text: &str) -> Option<u8> {
    if text.len() != 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(text, 16).ok()
}
