//! VW TP2.0, the transport VAG's older modules use for KWP2000 on CAN: channel setup, data
//! frames with ACKs, keep-alive and disconnect. See docs/tp20.md#frames.
//!
//! There is no public standard and no layout is confirmed on the A7 yet (#124), so every reply
//! is checked exactly.

use core::fmt;
use core::time::Duration;

/// The CAN ID a channel setup is sent on. A module answers on this plus its address.
pub const SETUP_ID: u32 = 0x200;

/// Asks the module to answer a test of the channel with its parameters, keeping it open.
pub const KEEP_ALIVE: [u8; 1] = [0xA3];

/// Closes the channel. The module answers with the same.
pub const DISCONNECT: [u8; 1] = [0xA8];

/// The longest payload [`data_frame`] fits in one frame, after its opcode and 2-byte length.
pub const MAX_SINGLE_FRAME: usize = 5;

const SETUP_REQUEST: u8 = 0xC0;
const SETUP_POSITIVE: u8 = 0xD0;
const SETUP_REFUSALS: [u8; 3] = [0xD6, 0xD7, 0xD8];
const TESTER_ADDRESS: u8 = 0x00;
const KWP2000_APPLICATION: u8 = 0x01;
const ID_INVALID: u8 = 0x10;
const PARAMETERS_REQUEST: u8 = 0xA0;
const PARAMETERS_REPLY: u8 = 0xA1;
const TEST: u8 = 0xA3;
const DISCONNECT_BYTE: u8 = 0xA8;
const ACK_READY: u8 = 0xB;
const ACK_NOT_READY: u8 = 0x9;
const NOT_GIVEN: u8 = 0xFF;
const CAN_DLC: usize = 8;

/// Why a TP2.0 frame couldn't be built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The frame is shorter than its layout.
    TooShort,
    /// A payload doesn't fit one data frame ([`MAX_SINGLE_FRAME`]).
    TooLong,
    /// The frame doesn't match its layout: an unknown opcode, a field out of range, a sequence
    /// number out of order, or a length the data doesn't keep.
    Malformed,
    /// The module refused the channel setup, with this opcode.
    Refused(u8),
    /// A reply is longer than the buffer it's reassembled into.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("TP2.0 frame is too short"),
            Self::TooLong => f.write_str("payload doesn't fit one TP2.0 frame"),
            Self::Malformed => f.write_str("TP2.0 frame is malformed"),
            Self::Refused(op) => write!(f, "the module refused the TP2.0 channel (0x{op:02X})"),
            Self::Overflow => f.write_str("TP2.0 reply is longer than its buffer"),
        }
    }
}

impl core::error::Error for Error {}

/// A channel setup request for the module at `address`, sent on [`SETUP_ID`], for KWP2000.
#[must_use]
pub fn channel_setup(address: u8) -> [u8; 7] {
    [
        address,
        SETUP_REQUEST,
        0x00,
        ID_INVALID,
        0x00,
        0x03,
        KWP2000_APPLICATION,
    ]
}

/// The CAN ID the module at `address` answers a channel setup on.
#[must_use]
pub fn setup_reply_id(address: u8) -> u32 {
    SETUP_ID + u32::from(address)
}

/// The CAN IDs of an open channel, as the module gave them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// The ID the tester sends on, which the module listens on.
    pub send_id: u32,
    /// The ID the module answers on.
    pub receive_id: u32,
}

/// Decodes a module's answer to [`channel_setup`]. Only a positive KWP2000 answer to the tester
/// with two different, valid 11-bit IDs outside the setup range is accepted.
///
/// # Errors
///
/// [`Error::Refused`] for a refusal, else [`Error::TooShort`] or [`Error::Malformed`].
pub fn decode_channel_setup(reply: &[u8]) -> Result<Channel, Error> {
    let &[tester, op, rx_low, rx_high, tx_low, tx_high, application] = reply else {
        return Err(if reply.len() < 7 {
            Error::TooShort
        } else {
            Error::Malformed
        });
    };
    if tester != TESTER_ADDRESS {
        return Err(Error::Malformed);
    }
    if SETUP_REFUSALS.contains(&op) {
        return Err(Error::Refused(op));
    }
    if op != SETUP_POSITIVE || application != KWP2000_APPLICATION {
        return Err(Error::Malformed);
    }
    let receive_id = setup_id(rx_low, rx_high)?;
    let send_id = setup_id(tx_low, tx_high)?;
    if send_id == receive_id {
        return Err(Error::Malformed);
    }
    Ok(Channel {
        send_id,
        receive_id,
    })
}

// Any high-byte bit past the low 3 (the invalid flag included), or an ID in the setup range, is
// malformed. See docs/tp20.md#frames.
fn setup_id(low: u8, high: u8) -> Result<u32, Error> {
    if high & !0x07 != 0 {
        return Err(Error::Malformed);
    }
    let id = u32::from(high) << 8 | u32::from(low);
    if (SETUP_ID..SETUP_ID + 0x100).contains(&id) {
        return Err(Error::Malformed);
    }
    Ok(id)
}

/// The tester's channel parameters: block size 15, T1 100 ms, T3 5 ms.
#[must_use]
pub fn channel_parameters() -> [u8; 6] {
    [PARAMETERS_REQUEST, 0x0F, 0x8A, NOT_GIVEN, 0x32, NOT_GIVEN]
}

/// A module's channel parameters, from its answer to [`channel_parameters`] or [`KEEP_ALIVE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// How many frames it takes before it asks for an ACK.
    pub block_size: u8,
    /// How long it waits for an ACK.
    pub t1: Duration,
    /// The gap it wants between frames sent to it.
    pub t3: Duration,
}

/// Decodes a parameters reply (`A1`). T1 and T3 must be given.
///
/// # Errors
///
/// [`Error::TooShort`] or [`Error::Malformed`], a block size of 0 included.
pub fn decode_channel_parameters(reply: &[u8]) -> Result<Parameters, Error> {
    let &[op, block_size, t1, _t2, t3, _t4] = reply else {
        return Err(if reply.len() < 6 {
            Error::TooShort
        } else {
            Error::Malformed
        });
    };
    if op != PARAMETERS_REPLY || block_size == 0 {
        return Err(Error::Malformed);
    }
    Ok(Parameters {
        block_size,
        t1: time(t1).ok_or(Error::Malformed)?,
        t3: time(t3).ok_or(Error::Malformed)?,
    })
}

fn time(byte: u8) -> Option<Duration> {
    if byte == NOT_GIVEN {
        return None;
    }
    let unit_us = match byte >> 6 {
        0 => 100,
        1 => 1_000,
        2 => 10_000,
        _ => 100_000,
    };
    Some(Duration::from_micros(unit_us * u64::from(byte & 0x3F)))
}

/// Whether `reply` answers the channel setup or disconnect `request`. A refusal answers a setup.
#[must_use]
pub fn answers(request: &[u8], reply: &[u8]) -> bool {
    match request {
        [_, SETUP_REQUEST, ..] => matches!(
            reply,
            [TESTER_ADDRESS, op, ..] if *op == SETUP_POSITIVE || SETUP_REFUSALS.contains(op)
        ),
        [DISCONNECT_BYTE] => reply == DISCONNECT,
        _ => false,
    }
}

/// One frame's data bytes, unpadded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outgoing {
    data: [u8; CAN_DLC],
    len: usize,
}

impl Outgoing {
    /// The frame's bytes, opcode first.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// `payload` as one data frame with sequence number `sequence`: the last of its message, asking
/// for an ACK.
///
/// # Errors
///
/// [`Error::TooLong`] for a payload over [`MAX_SINGLE_FRAME`] bytes, [`Error::Malformed`] for
/// an empty one or a sequence number over 0x0F.
pub fn data_frame(sequence: u8, payload: &[u8]) -> Result<Outgoing, Error> {
    if sequence > 0x0F || payload.is_empty() {
        return Err(Error::Malformed);
    }
    if payload.len() > MAX_SINGLE_FRAME {
        return Err(Error::TooLong);
    }
    let len = u8::try_from(payload.len()).map_err(|_| Error::TooLong)?;
    let mut data = [0; CAN_DLC];
    data[0] = 0x10 | sequence;
    data[2] = len;
    data[3..3 + payload.len()].copy_from_slice(payload);
    Ok(Outgoing {
        data,
        len: 3 + payload.len(),
    })
}

/// The ACK of a module's frames, ready for the frame with sequence number `next` (mod 16).
#[must_use]
pub fn ack(next: u8) -> [u8; 1] {
    [ACK_READY << 4 | (next & 0x0F)]
}

/// One frame on an open channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Part of a message.
    Data {
        /// The frame's sequence number, 0 to 15.
        sequence: u8,
        /// Whether it's the message's last frame.
        last: bool,
        /// Whether the sender waits for an ACK after it.
        wants_ack: bool,
        /// The bytes after the opcode: a message's first frame starts with its 2-byte length.
        bytes: &'a [u8],
    },
    /// An ACK, saying which sequence number comes next.
    Ack {
        /// The sequence number the sender of the ACK expects next.
        next: u8,
        /// Whether it's ready for it; if not, the frames wait.
        ready: bool,
    },
    /// Channel parameters (`A1`).
    Parameters(Parameters),
    /// A channel test (`A3`).
    Test,
    /// A disconnect (`A8`).
    Disconnect,
}

impl<'a> Frame<'a> {
    /// Reads one frame's data bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an empty or overlong frame, a reserved opcode, or a frame of the
    /// wrong length for its opcode; as [`decode_channel_parameters`] for `A1`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let (&first, rest) = bytes.split_first().ok_or(Error::Malformed)?;
        if bytes.len() > CAN_DLC {
            return Err(Error::Malformed);
        }
        let (op, low) = (first >> 4, first & 0x0F);
        match (op, first, rest) {
            (0x0..=0x3, _, [_, ..]) => Ok(Self::Data {
                sequence: low,
                last: op & 0x1 != 0,
                wants_ack: op & 0x2 == 0,
                bytes: rest,
            }),
            (ACK_READY | ACK_NOT_READY, _, []) => Ok(Self::Ack {
                next: low,
                ready: op == ACK_READY,
            }),
            (_, PARAMETERS_REPLY, _) => decode_channel_parameters(bytes).map(Self::Parameters),
            (_, TEST, []) => Ok(Self::Test),
            (_, DISCONNECT_BYTE, []) => Ok(Self::Disconnect),
            _ => Err(Error::Malformed),
        }
    }
}

/// What feeding a data frame to a [`Reassembler`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress<'b> {
    /// Keep feeding frames.
    Pending,
    /// Send [`ack`] of this sequence number, then keep feeding frames.
    Ack(u8),
    /// The whole message has arrived.
    Complete {
        /// The message.
        payload: &'b [u8],
        /// The ACK to send for it, if its last frame asked for one.
        ack: Option<u8>,
    },
}

/// Puts a module's messages back together from its data frames, checking each sequence number
/// and length exactly. A frame that breaks the framing drops the message it was part of, through
/// that message's last frame, and the next message is taken from whatever sequence number it
/// starts at.
#[derive(Debug)]
pub struct Reassembler<B> {
    buf: B,
    // The sequence number the module's next frame must have; None until one is known.
    expected: Option<u8>,
    // The message being received: its length, and how many of its bytes have arrived.
    message: Option<(usize, usize)>,
    // Whether the frames until the next last one belong to a dropped message.
    dropping: bool,
}

impl<B: AsMut<[u8]>> Reassembler<B> {
    /// Reassembles messages of up to `buf`'s length.
    pub fn new(buf: B) -> Self {
        Self {
            buf,
            expected: None,
            message: None,
            dropping: false,
        }
    }

    /// Feeds one data frame's bytes (opcode first).
    ///
    /// # Errors
    ///
    /// The frame isn't a well-formed data frame, its sequence number is out of order, its length
    /// field is 0 or doesn't fit the buffer ([`Error::Overflow`]), or the data goes past the
    /// length or a last frame ends before it. The data frames of a dropped message that follow are
    /// [`Progress::Pending`] or [`Progress::Ack`] whatever their sequence numbers and contents;
    /// any other frame is still an error, as from [`Frame::parse`] ([`Error::Malformed`] if it
    /// parses as something else).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Progress<'_>, Error> {
        if self.dropping {
            return self.drop_frame(bytes);
        }
        match self.take(bytes) {
            Ok(Some((len, ack))) => Ok(Progress::Complete {
                payload: &self.buf.as_mut()[..len],
                ack,
            }),
            Ok(None) => Ok(match Frame::parse(bytes) {
                Ok(Frame::Data {
                    wants_ack: true,
                    sequence,
                    ..
                }) => Progress::Ack((sequence + 1) & 0x0F),
                _ => Progress::Pending,
            }),
            Err(e) => {
                // Only a message's last frame is marked, so its later frames would otherwise
                // read as the start of the next one.
                self.dropping = match Frame::parse(bytes) {
                    Ok(Frame::Data { last, .. }) => !last,
                    _ => self.message.is_some(),
                };
                self.expected = None;
                self.message = None;
                Err(e)
            }
        }
    }

    // Takes one frame of a dropped message.
    fn drop_frame(&mut self, bytes: &[u8]) -> Result<Progress<'_>, Error> {
        let Frame::Data {
            sequence,
            last,
            wants_ack,
            ..
        } = Frame::parse(bytes)?
        else {
            return Err(Error::Malformed);
        };
        self.dropping = !last;
        Ok(if wants_ack {
            Progress::Ack((sequence + 1) & 0x0F)
        } else {
            Progress::Pending
        })
    }

    // Takes one frame; returns the message's length and its ACK once it's complete.
    fn take(&mut self, bytes: &[u8]) -> Result<Option<(usize, Option<u8>)>, Error> {
        let Frame::Data {
            sequence,
            last,
            wants_ack,
            bytes: data,
        } = Frame::parse(bytes)?
        else {
            return Err(Error::Malformed);
        };
        if self.expected.is_some_and(|expected| expected != sequence) {
            return Err(Error::Malformed);
        }
        let next = (sequence + 1) & 0x0F;
        self.expected = Some(next);
        let buf = self.buf.as_mut();
        let (len, got, data) = if let Some((len, got)) = self.message {
            (len, got, data)
        } else {
            let [high, low, data @ ..] = data else {
                return Err(Error::TooShort);
            };
            let len = usize::from(u16::from_be_bytes([*high, *low]));
            if len == 0 {
                return Err(Error::Malformed);
            }
            if len > buf.len() {
                return Err(Error::Overflow);
            }
            (len, 0, data)
        };
        let end = got + data.len();
        if end > len || (end == len) != last {
            return Err(Error::Malformed);
        }
        buf[got..end].copy_from_slice(data);
        if last {
            self.message = None;
            return Ok(Some((len, wants_ack.then_some(next))));
        }
        self.message = Some((len, end));
        Ok(None)
    }
}
