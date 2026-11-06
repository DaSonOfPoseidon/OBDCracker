//! SocketCAN's `struct can_frame` and error frames, byte for byte. The kernel is untrusted like any
//! other source: every length, flag and ID is checked. See
//! [`docs/socketcan.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/socketcan.md).

use super::device::KernelFilter;
use crate::raw::port::Filter;

/// A classic CAN frame as the kernel hands it over: `can_id` (4, host byte order), `len` (1), three
/// bytes of padding and flags, 8 data bytes. Nothing is negotiated that makes it longer (no CAN
/// FD), so any other length is refused.
pub(super) const FRAME_LEN: usize = 16;

pub(super) const EFF_FLAG: u32 = 0x8000_0000;
pub(super) const RTR_FLAG: u32 = 0x4000_0000;
const ERR_FLAG: u32 = 0x2000_0000;
pub(super) const EFF_MASK: u32 = 0x1FFF_FFFF;
pub(super) const SFF_MASK: u32 = 0x7FF;

// The error classes of an error frame's `can_id`, and the controller detail in data byte 1.
const ERR_TX_TIMEOUT: u32 = 0x001;
const ERR_CRTL: u32 = 0x004;
const ERR_PROT: u32 = 0x008;
const ERR_TRX: u32 = 0x010;
const ERR_ACK: u32 = 0x020;
const ERR_BUSOFF: u32 = 0x040;
const ERR_BUSERROR: u32 = 0x080;
const ERR_RESTARTED: u32 = 0x100;
const ERR_CNT: u32 = 0x200;
const CRTL_RX_OVERFLOW: u8 = 0x01;
const CRTL_PASSIVE: u8 = 0x10 | 0x20;
const ERR_DLC: u8 = 8;

/// The error classes to ask the kernel for: every one but a lost arbitration, which the controller
/// retries by itself and which a busy bus has all the time.
pub(super) const ERROR_MASK: u32 = ERR_TX_TIMEOUT
    | ERR_CRTL
    | ERR_PROT
    | ERR_TRX
    | ERR_ACK
    | ERR_BUSOFF
    | ERR_BUSERROR
    | ERR_RESTARTED
    | ERR_CNT;

/// A classic data frame to send, as the kernel takes it: DLC `data.len()` (1 to 8, never padded
/// here), with zeros after the data.
pub(super) fn encode_tx(id: u32, extended: bool, data: &[u8]) -> [u8; FRAME_LEN] {
    debug_assert!((1..=8).contains(&data.len()));
    let can_id = if extended {
        (id & EFF_MASK) | EFF_FLAG
    } else {
        id & SFF_MASK
    };
    let mut bytes = [0; FRAME_LEN];
    bytes[0..4].copy_from_slice(&can_id.to_ne_bytes());
    bytes[4] = u8::try_from(data.len()).expect("a classic frame has at most 8 bytes");
    bytes[8..8 + data.len()].copy_from_slice(data);
    bytes
}

/// What a controller reports about the bus besides frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BusError {
    BusOff,
    ErrorPassive,
    /// The controller's receive queue overflowed.
    Overrun,
    /// Any other error frame: a warning, a bus error, a restart, no acknowledgement.
    Other,
}

/// What a frame from the kernel is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Body {
    Data {
        id: u32,
        extended: bool,
        data: Vec<u8>,
    },
    /// A remote frame, which carries no data.
    Remote,
    Error(BusError),
}

/// Reads one frame. The length, DLC and ID must be what a classic CAN frame allows, or the frame
/// is refused.
pub(super) fn parse_frame(bytes: &[u8]) -> Result<Body, String> {
    if bytes.len() != FRAME_LEN {
        return Err(format!("a frame of {} bytes, not {FRAME_LEN}", bytes.len()));
    }
    let can_id = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let dlc = bytes[4];
    if dlc > 8 {
        return Err(format!("a frame with DLC {dlc}, above 8"));
    }
    let mut data = [0; 8];
    data.copy_from_slice(&bytes[8..]);
    if can_id & ERR_FLAG != 0 {
        return Ok(Body::Error(classify_error(can_id, dlc, data)));
    }
    if can_id & RTR_FLAG != 0 {
        return Ok(Body::Remote);
    }
    let extended = can_id & EFF_FLAG != 0;
    if !extended && can_id & EFF_MASK & !SFF_MASK != 0 {
        return Err(format!(
            "an 11-bit frame with ID bits above 11: {can_id:#010x}"
        ));
    }
    Ok(Body::Data {
        id: can_id & if extended { EFF_MASK } else { SFF_MASK },
        extended,
        data: data[..usize::from(dlc)].to_vec(),
    })
}

// A receive overflow on its own is the only error that doesn't latch. Anything not understood
// counts as an error on the bus.
fn classify_error(can_id: u32, dlc: u8, data: [u8; 8]) -> BusError {
    let class = can_id & EFF_MASK;
    let detail = if dlc == ERR_DLC { data[1] } else { 0 };
    if class & ERR_BUSOFF != 0 {
        BusError::BusOff
    } else if class & ERR_CRTL != 0 && detail & CRTL_PASSIVE != 0 {
        BusError::ErrorPassive
    } else if class == ERR_CRTL && detail == CRTL_RX_OVERFLOW {
        BusError::Overrun
    } else {
        BusError::Other
    }
}

/// The kernel filter that passes the frames `filter` describes, and only data frames of its ID
/// width: the flag bits are part of the mask, so an 11-bit filter never passes a 29-bit frame
/// with the same low bits, and a remote frame never passes.
pub(super) fn kernel_filter(filter: &Filter) -> KernelFilter {
    let width = if filter.extended { EFF_MASK } else { SFF_MASK };
    KernelFilter {
        id: (filter.id & width) | if filter.extended { EFF_FLAG } else { 0 },
        mask: (filter.mask & width) | EFF_FLAG | RTR_FLAG,
    }
}

/// The kernel filter that passes exactly the frames with this ID and width.
pub(super) fn exact_filter(id: u32, extended: bool) -> KernelFilter {
    kernel_filter(&Filter {
        id,
        mask: if extended { EFF_MASK } else { SFF_MASK },
        extended,
    })
}
