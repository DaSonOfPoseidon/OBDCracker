//! What an ELM327 prints, split into lines and classified. Pure and IO-free: everything here
//! treats the adapter's output as untrusted input.
//!
//! The formats follow the ELM327 datasheet (ELM327DS v2.0) with headers and spaces on, as
//! [`super::Elm`] sets them. See docs/elm327.md#output-format.

/// The longest line kept, in bytes. A frame line with headers and spaces on is 27 characters
/// (35 with a 29-bit ID), and one marked `<DATA ERROR` is under 50; anything longer isn't from
/// a working adapter.
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

    /// The line received so far, if a line has started: the text, or `None` for an overlong one.
    #[must_use]
    pub fn partial(&self) -> Option<Option<&str>> {
        if self.overlong {
            Some(None)
        } else {
            (!self.line.is_empty()).then_some(Some(self.line.as_str()))
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
    id: u32,
    data: [u8; 8],
    len: usize,
}

impl CanFrame {
    /// The CAN ID the frame came from: 11-bit, or 29-bit if [`CanFrame::is_29_bit`].
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Whether the adapter printed a 29-bit header (four bytes) for the frame.
    #[must_use]
    pub fn is_29_bit(&self) -> bool {
        self.id > 0x7FF
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
    /// (`LV RESET`, `LP ALERT`, any `ERRxx`) or is searching for a protocol (`SEARCHING...`,
    /// `UNABLE TO CONNECT`). See docs/elm327.md#failure-states.
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

// "7E8 06 41 00 BE 3F A8 13": a 3-digit ID and 1 to 8 bytes, each separated by one space. A
// 29-bit ID is printed as four bytes instead, "18 DA F1 10 03 62 F1 87", its first at most 0x1F.
// ELM327s print a space after the last byte too, so one trailing space is allowed.
fn parse_frame(line: &str) -> Option<CanFrame> {
    let line = line.strip_suffix(' ').unwrap_or(line);
    let mut tokens = line.split(' ').peekable();
    let first = *tokens.peek()?;
    let id = if first.len() == 3 && first.bytes().all(|b| b.is_ascii_hexdigit()) {
        tokens.next();
        u32::from_str_radix(first, 16)
            .ok()
            .filter(|&id| id <= 0x7FF)?
    } else {
        let mut header = [0; 4];
        for byte in &mut header {
            *byte = hex_byte(tokens.next()?)?;
        }
        let id = u32::from_be_bytes(header);
        // A 29-bit ID with an 11-bit value would read as an 11-bit frame's.
        (0x800..=0x1FFF_FFFF).contains(&id).then_some(id)?
    };
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
