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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFrameSize => f.write_str("ISO-TP frame is empty or longer than 8 bytes"),
            Self::WrongAddress(addr) => write!(f, "ISO-TP frame is for address {addr:02X}"),
            Self::BadLength => f.write_str("ISO-TP length field doesn't match the data"),
            Self::Unsupported => f.write_str("ISO-TP frame type is reserved or needs CAN FD"),
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

/// The data of one single frame: the PCI byte (0x0 nibble, then the length) followed by up to 7
/// payload bytes. Unpadded; the adapter pads to 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleFrame {
    data: [u8; 8],
    len: usize,
}

impl SingleFrame {
    /// The frame's data bytes, PCI byte first.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Wraps a payload of 1 to 7 bytes in a single frame. Longer payloads need multi-frame transfer.
#[must_use]
pub fn single_frame(payload: &[u8]) -> Option<SingleFrame> {
    let len = u8::try_from(payload.len())
        .ok()
        .filter(|len| (1..=7).contains(len))?;
    let mut data = [0; 8];
    data[0] = len;
    data[1..=payload.len()].copy_from_slice(payload);
    Some(SingleFrame {
        data,
        len: payload.len() + 1,
    })
}
