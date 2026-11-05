//! `gs_usb`'s control messages and host frames, byte for byte. Every number is little-endian,
//! which is what the host format message (`0x0000BEEF`) asks the device for. See
//! [`docs/gsusb.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/gsusb.md).

// Vendor requests on the interface.
pub(super) const BREQ_HOST_FORMAT: u8 = 0;
pub(super) const BREQ_BITTIMING: u8 = 1;
pub(super) const BREQ_MODE: u8 = 2;
pub(super) const BREQ_BT_CONST: u8 = 4;
pub(super) const BREQ_DEVICE_CONFIG: u8 = 5;

// The host format and device config messages use wValue 1; the others name the channel (0: the
// device's first CAN controller).
pub(super) const VALUE_HOST_FORMAT: u16 = 1;
pub(super) const CHANNEL: u16 = 0;

pub(super) const MODE_RESET: u32 = 0;
pub(super) const MODE_START: u32 = 1;

// Mode flags, and the features that say which a device has: the same bit numbers.
pub(super) const FLAG_LISTEN_ONLY: u32 = 1 << 0;
pub(super) const FLAG_BERR_REPORTING: u32 = 1 << 12;
pub(super) const FEATURE_LISTEN_ONLY: u32 = 1 << 0;
pub(super) const FEATURE_USB_QUIRK_LPC546XX: u32 = 1 << 9;
pub(super) const FEATURE_BERR_REPORTING: u32 = 1 << 12;

pub(super) const DEVICE_CONFIG_LEN: usize = 12;
pub(super) const BT_CONST_LEN: usize = 40;
/// A classic CAN frame on the bulk endpoints: a 12-byte header and 8 data bytes. Nothing is
/// negotiated that makes it longer (no timestamp, no CAN FD, no padding quirk).
pub(super) const FRAME_LEN: usize = 20;
/// The echo ID of a frame received from the bus. Any other value confirms a frame we sent.
pub(super) const ECHO_ID_RX: u32 = 0xFFFF_FFFF;

const EFF_FLAG: u32 = 0x8000_0000;
const RTR_FLAG: u32 = 0x4000_0000;
const ERR_FLAG: u32 = 0x2000_0000;
const EFF_MASK: u32 = 0x1FFF_FFFF;
const SFF_MASK: u32 = 0x7FF;

const FRAME_OVERFLOW: u8 = 1 << 0;

// The error class bits and controller detail of an error frame (SocketCAN's numbering, which the
// device passes through).
const ERR_CRTL: u32 = 0x04;
const ERR_BUSOFF: u32 = 0x40;
const CRTL_RX_OVERFLOW: u8 = 0x01;
const CRTL_PASSIVE: u8 = 0x10 | 0x20;
const ERR_DLC: u8 = 8;

/// The host format message: the host is little-endian.
pub(super) fn host_format() -> [u8; 4] {
    0x0000_BEEF_u32.to_le_bytes()
}

/// A mode message: [`MODE_RESET`] or [`MODE_START`] with flags.
pub(super) fn mode_message(mode: u32, flags: u32) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&mode.to_le_bytes());
    bytes[4..].copy_from_slice(&flags.to_le_bytes());
    bytes
}

fn word(bytes: &[u8], index: usize) -> u32 {
    let at = index * 4;
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// What the device says about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeviceConfig {
    /// How many CAN controllers the device has.
    pub(super) channels: u16,
    pub(super) sw_version: u32,
    pub(super) hw_version: u32,
}

impl DeviceConfig {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != DEVICE_CONFIG_LEN {
            return Err(format!(
                "the device config is {} bytes, not {DEVICE_CONFIG_LEN}",
                bytes.len()
            ));
        }
        Ok(Self {
            // The device sends the number of channels less one.
            channels: u16::from(bytes[3]) + 1,
            sw_version: word(&bytes[4..], 0),
            hw_version: word(&bytes[4..], 1),
        })
    }
}

/// The controller's clock and the limits of its bit timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BtConst {
    pub(super) feature: u32,
    pub(super) fclk_can: u32,
    pub(super) tseg1_min: u32,
    pub(super) tseg1_max: u32,
    pub(super) tseg2_min: u32,
    pub(super) tseg2_max: u32,
    pub(super) sjw_max: u32,
    pub(super) brp_min: u32,
    pub(super) brp_max: u32,
    pub(super) brp_inc: u32,
}

impl BtConst {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != BT_CONST_LEN {
            return Err(format!(
                "the bit timing constants are {} bytes, not {BT_CONST_LEN}",
                bytes.len()
            ));
        }
        Ok(Self {
            feature: word(bytes, 0),
            fclk_can: word(bytes, 1),
            tseg1_min: word(bytes, 2),
            tseg1_max: word(bytes, 3),
            tseg2_min: word(bytes, 4),
            tseg2_max: word(bytes, 5),
            sjw_max: word(bytes, 6),
            brp_min: word(bytes, 7),
            brp_max: word(bytes, 8),
            brp_inc: word(bytes, 9),
        })
    }
}

/// A bit timing in the device's terms. The device adds `prop_seg` and `phase_seg1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BitTiming {
    pub(super) prop_seg: u32,
    pub(super) phase_seg1: u32,
    pub(super) phase_seg2: u32,
    pub(super) sjw: u32,
    pub(super) brp: u32,
}

impl BitTiming {
    pub(super) fn to_bytes(self) -> [u8; 20] {
        let words = [
            self.prop_seg,
            self.phase_seg1,
            self.phase_seg2,
            self.sjw,
            self.brp,
        ];
        let mut bytes = [0; 20];
        for (at, word) in words.iter().enumerate() {
            bytes[at * 4..at * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

/// A classic data frame to send, as the bulk OUT endpoint takes it: `echo_id` is handed back when
/// the controller has put the frame on the bus.
pub(super) fn encode_tx(echo_id: u32, id: u32, extended: bool, data: [u8; 8]) -> [u8; FRAME_LEN] {
    debug_assert_ne!(echo_id, ECHO_ID_RX);
    let can_id = if extended {
        (id & EFF_MASK) | EFF_FLAG
    } else {
        id & SFF_MASK
    };
    let mut bytes = [0; FRAME_LEN];
    bytes[0..4].copy_from_slice(&echo_id.to_le_bytes());
    bytes[4..8].copy_from_slice(&can_id.to_le_bytes());
    bytes[8] = 8;
    // Channel 0, flags 0 and the reserved byte stay zero.
    bytes[12..].copy_from_slice(&data);
    bytes
}

/// What a controller reports about the bus besides frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BusError {
    BusOff,
    ErrorPassive,
    /// The controller's receive queue overflowed.
    Overrun,
    /// Any other error frame: a warning, a bus error, a restart.
    Other,
}

/// What a frame from the device is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Body {
    /// The controller has put the frame with this echo ID on the bus.
    Confirmation,
    Data {
        id: u32,
        extended: bool,
        data: Vec<u8>,
    },
    /// A remote frame, which carries no data.
    Remote,
    Error(BusError),
}

/// A parsed frame from the bulk IN endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Parsed {
    pub(super) echo_id: u32,
    pub(super) channel: u8,
    /// The device dropped frames before this one.
    pub(super) overflow: bool,
    pub(super) body: Body,
}

/// Reads one frame. The device is untrusted: the length, flags, DLC and ID must all be what a
/// classic CAN frame allows, or the frame is refused.
pub(super) fn parse_frame(bytes: &[u8]) -> Result<Parsed, String> {
    if bytes.len() != FRAME_LEN {
        return Err(format!("a frame of {} bytes, not {FRAME_LEN}", bytes.len()));
    }
    let echo_id = word(bytes, 0);
    let can_id = word(bytes, 1);
    let (dlc, channel, flags) = (bytes[8], bytes[9], bytes[10]);
    if flags & !FRAME_OVERFLOW != 0 {
        return Err(format!("a frame with unsupported flags {flags:#04x}"));
    }
    if dlc > 8 {
        return Err(format!("a frame with DLC {dlc}, above 8"));
    }
    let mut data = [0; 8];
    data.copy_from_slice(&bytes[12..]);
    let body = if echo_id != ECHO_ID_RX {
        Body::Confirmation
    } else if can_id & ERR_FLAG != 0 {
        Body::Error(classify_error(can_id, dlc, data))
    } else if can_id & RTR_FLAG != 0 {
        Body::Remote
    } else {
        let extended = can_id & EFF_FLAG != 0;
        if !extended && can_id & EFF_MASK & !SFF_MASK != 0 {
            return Err(format!(
                "an 11-bit frame with ID bits above 11: {can_id:#010x}"
            ));
        }
        Body::Data {
            id: can_id & if extended { EFF_MASK } else { SFF_MASK },
            extended,
            data: data[..usize::from(dlc)].to_vec(),
        }
    };
    Ok(Parsed {
        echo_id,
        channel,
        overflow: flags & FRAME_OVERFLOW != 0,
        body,
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
