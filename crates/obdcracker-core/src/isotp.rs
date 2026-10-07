//! ISO 15765-2 (ISO-TP) framing of diagnostic payloads onto 8-byte classic CAN frames.

use core::fmt;
use core::time::Duration;

/// The most bytes a classic CAN frame carries.
pub const CAN_DLC: usize = 8;

/// The longest payload a classic-CAN ISO-TP transfer can carry (a 12-bit first-frame length).
pub const MAX_PAYLOAD: usize = 4095;

/// How a module is addressed inside the CAN frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// The CAN ID alone selects the module. Used by OBD-II and most UDS modules.
    Normal,
    /// The first data byte is the module's sub-address, as on Toyota body modules behind 0x750.
    /// It leaves one byte less for the payload in every frame.
    Extended(u8),
}

impl Addressing {
    fn header_len(self) -> usize {
        match self {
            Self::Normal => 0,
            Self::Extended(_) => 1,
        }
    }

    /// The largest payload that fits a single frame: 7 bytes, or 6 with extended addressing.
    #[must_use]
    pub fn max_single_frame(self) -> usize {
        CAN_DLC - 1 - self.header_len()
    }
}

/// The data bytes of one CAN frame, unpadded; the adapter pads to 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanData {
    data: [u8; CAN_DLC],
    len: usize,
}

impl CanData {
    fn new(addressing: Addressing) -> Self {
        let mut frame = Self {
            data: [0; CAN_DLC],
            len: 0,
        };
        if let Addressing::Extended(addr) = addressing {
            frame.push(&[addr]);
        }
        frame
    }

    // Callers never push past 8 bytes: every frame type's layout is sized to fit.
    fn push(&mut self, bytes: &[u8]) {
        self.data[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// The frame's data bytes: address byte (if extended), PCI, then payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Whether the receiver of a multi-frame transfer is ready for more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStatus {
    /// Send the next block of consecutive frames.
    ContinueToSend,
    /// Wait for another flow control frame before sending more.
    Wait,
    /// The transfer is too long for the receiver's buffer; abort it.
    Overflow,
}

/// A flow control frame: how the receiver wants consecutive frames paced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowControl {
    /// Whether to send, wait or abort.
    pub status: FlowStatus,
    /// How many consecutive frames to send before waiting for the next flow control frame.
    /// 0 means send them all.
    pub block_size: u8,
    /// The minimum gap between consecutive frames.
    pub st_min: Duration,
}

impl FlowControl {
    /// The flow control frame's data bytes.
    #[must_use]
    pub fn encode(&self, addressing: Addressing) -> CanData {
        let status = match self.status {
            FlowStatus::ContinueToSend => 0,
            FlowStatus::Wait => 1,
            FlowStatus::Overflow => 2,
        };
        let mut frame = CanData::new(addressing);
        frame.push(&[0x30 | status, self.block_size, encode_st_min(self.st_min)]);
        frame
    }
}

/// One ISO-TP frame, with the payload bytes borrowed from the CAN data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A whole payload that fits in one frame.
    Single(&'a [u8]),
    /// The start of a multi-frame payload.
    First {
        /// The length of the whole payload.
        len: u16,
        /// The first bytes of the payload.
        data: &'a [u8],
    },
    /// The next part of a multi-frame payload. The last one may carry padding past the
    /// payload's end, which the reassembler drops.
    Consecutive {
        /// The sequence number, 0 to 15, wrapping.
        seq: u8,
        /// The payload bytes, plus any padding.
        data: &'a [u8],
    },
    /// The receiver's pacing for a multi-frame transfer.
    FlowControl(FlowControl),
}

/// Why CAN data isn't a valid ISO-TP frame or transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The frame has no data, or more than 8 bytes.
    BadFrameSize,
    /// The extended address byte is for another module.
    WrongAddress(u8),
    /// A length field is zero, out of range, or longer than the data.
    BadLength,
    /// The frame type or flow status is reserved, or needs CAN FD.
    Unsupported,
    /// The receiver refused the transfer because it's too long for its buffer.
    Overflow,
    /// A frame arrived that doesn't fit the transfer's current state.
    UnexpectedFrame,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFrameSize => f.write_str("ISO-TP frame is empty or longer than 8 bytes"),
            Self::WrongAddress(addr) => write!(f, "ISO-TP frame is for address {addr:02X}"),
            Self::BadLength => f.write_str("ISO-TP length field doesn't match the data"),
            Self::Unsupported => f.write_str("ISO-TP frame type is reserved or needs CAN FD"),
            Self::Overflow => f.write_str("ISO-TP receiver's buffer is too small for the transfer"),
            Self::UnexpectedFrame => f.write_str("ISO-TP frame doesn't fit the transfer"),
        }
    }
}

impl<'a> Frame<'a> {
    /// Parses the data bytes of one CAN frame. Padding after a single frame's payload is ignored.
    pub fn parse(bytes: &'a [u8], addressing: Addressing) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > CAN_DLC {
            return Err(Error::BadFrameSize);
        }
        let bytes = match addressing {
            Addressing::Normal => bytes,
            Addressing::Extended(addr) => {
                let (&first, rest) = bytes.split_first().ok_or(Error::BadFrameSize)?;
                if first != addr {
                    return Err(Error::WrongAddress(first));
                }
                rest
            }
        };
        let (&pci, rest) = bytes.split_first().ok_or(Error::BadFrameSize)?;
        let low = pci & 0x0F;
        match pci >> 4 {
            0x0 => {
                let len = usize::from(low);
                if len == 0 || len > addressing.max_single_frame() || len > rest.len() {
                    return Err(Error::BadLength);
                }
                Ok(Self::Single(&rest[..len]))
            }
            0x1 => {
                let (&len_low, data) = rest.split_first().ok_or(Error::BadLength)?;
                let len = u16::from(low) << 8 | u16::from(len_low);
                if len == 0 {
                    // The escape for lengths over 4095, which classic CAN can't carry
                    return Err(Error::Unsupported);
                }
                if usize::from(len) <= addressing.max_single_frame()
                    || data.len() != CAN_DLC - 2 - addressing.header_len()
                {
                    return Err(Error::BadLength);
                }
                Ok(Self::First { len, data })
            }
            0x2 if !rest.is_empty() => Ok(Self::Consecutive {
                seq: low,
                data: rest,
            }),
            0x2 => Err(Error::BadLength),
            0x3 => {
                let status = match low {
                    0 => FlowStatus::ContinueToSend,
                    1 => FlowStatus::Wait,
                    2 => FlowStatus::Overflow,
                    _ => return Err(Error::Unsupported),
                };
                let [block_size, st_min, ..] = *rest else {
                    return Err(Error::BadLength);
                };
                Ok(Self::FlowControl(FlowControl {
                    status,
                    block_size,
                    st_min: decode_st_min(st_min),
                }))
            }
            _ => Err(Error::Unsupported),
        }
    }
}

// STmin: 0x00-0x7F milliseconds, 0xF1-0xF9 hundreds of microseconds. Reserved values are read as
// the longest gap, 127 ms, as ISO 15765-2 requires.
fn decode_st_min(byte: u8) -> Duration {
    match byte {
        0x00..=0x7F => Duration::from_millis(u64::from(byte)),
        0xF1..=0xF9 => Duration::from_micros(u64::from(byte - 0xF0) * 100),
        _ => Duration::from_millis(127),
    }
}

// Rounds up to the next value STmin can express, so the gap is never shorter than asked.
fn encode_st_min(st_min: Duration) -> u8 {
    let micros = st_min.as_micros();
    match micros {
        0 => 0,
        1..=900 => 0xF0 + u8::try_from(micros.div_ceil(100)).unwrap_or(9),
        _ => u8::try_from(micros.div_ceil(1000)).map_or(0x7F, |ms| ms.min(0x7F)),
    }
}

/// What the sender should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Put this frame on the bus. Keep [`Segmenter::st_min`] between consecutive frames.
    Send(CanData),
    /// Wait for the receiver's flow control frame and pass it to [`Segmenter::flow_control`].
    WaitForFlowControl,
    /// The whole payload has been sent.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendState {
    Start,
    Waiting,
    // How many consecutive frames are left in this block; None means no limit.
    Sending(Option<u8>),
    Done,
}

/// Splits one payload into ISO-TP frames, following the receiver's flow control. IO-free: the
/// caller sends each frame and feeds back the flow control frames it receives.
#[derive(Debug, Clone)]
pub struct Segmenter<'a> {
    payload: &'a [u8],
    addressing: Addressing,
    offset: usize,
    seq: u8,
    st_min: Duration,
    state: SendState,
}

impl<'a> Segmenter<'a> {
    /// Starts a transfer of 1 to 4095 bytes.
    pub fn new(payload: &'a [u8], addressing: Addressing) -> Result<Self, Error> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::BadLength);
        }
        Ok(Self {
            payload,
            addressing,
            offset: 0,
            seq: 0,
            st_min: Duration::ZERO,
            state: SendState::Start,
        })
    }

    /// The next thing to do: send a frame, wait for flow control, or stop.
    pub fn step(&mut self) -> Step {
        match self.state {
            SendState::Start => Step::Send(self.first()),
            SendState::Waiting => Step::WaitForFlowControl,
            SendState::Sending(left) => Step::Send(self.consecutive(left)),
            SendState::Done => Step::Done,
        }
    }

    /// Applies a flow control frame received while waiting for one.
    pub fn flow_control(&mut self, fc: FlowControl) -> Result<(), Error> {
        if self.state != SendState::Waiting {
            return Err(Error::UnexpectedFrame);
        }
        match fc.status {
            FlowStatus::ContinueToSend => {
                self.st_min = fc.st_min;
                self.state = SendState::Sending((fc.block_size != 0).then_some(fc.block_size));
                Ok(())
            }
            FlowStatus::Wait => Ok(()),
            FlowStatus::Overflow => {
                self.state = SendState::Done;
                Err(Error::Overflow)
            }
        }
    }

    /// The minimum gap the receiver asked for between consecutive frames.
    #[must_use]
    pub fn st_min(&self) -> Duration {
        self.st_min
    }

    fn first(&mut self) -> CanData {
        let mut frame = CanData::new(self.addressing);
        let len = self.payload.len();
        if len <= self.addressing.max_single_frame() {
            // len <= 7, so it fits the PCI nibble
            frame.push(&[len.to_le_bytes()[0]]);
            frame.push(self.payload);
            self.state = SendState::Done;
        } else {
            let [low, high, ..] = len.to_le_bytes();
            let chunk = CAN_DLC - 2 - self.addressing.header_len();
            frame.push(&[0x10 | high, low]);
            frame.push(&self.payload[..chunk]);
            self.offset = chunk;
            self.state = SendState::Waiting;
        }
        frame
    }

    fn consecutive(&mut self, left: Option<u8>) -> CanData {
        self.seq = (self.seq + 1) & 0x0F;
        let chunk =
            (CAN_DLC - 1 - self.addressing.header_len()).min(self.payload.len() - self.offset);
        let mut frame = CanData::new(self.addressing);
        frame.push(&[0x20 | self.seq]);
        frame.push(&self.payload[self.offset..self.offset + chunk]);
        self.offset += chunk;
        self.state = if self.offset == self.payload.len() {
            SendState::Done
        } else {
            match left {
                Some(1) => SendState::Waiting,
                Some(n) => SendState::Sending(Some(n - 1)),
                None => SendState::Sending(None),
            }
        };
        frame
    }
}

/// Wraps a payload of 1 to 7 bytes in a single frame. Longer payloads need [`Segmenter`].
#[must_use]
pub fn single_frame(payload: &[u8]) -> Option<CanData> {
    let mut seg = Segmenter::new(payload, Addressing::Normal).ok()?;
    match seg.step() {
        Step::Send(frame) if seg.step() == Step::Done => Some(frame),
        _ => None,
    }
}
