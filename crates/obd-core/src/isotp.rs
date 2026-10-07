//! ISO 15765-2 (ISO-TP) framing of diagnostic payloads onto 8-byte classic CAN frames.

/// The data of one single frame: the PCI byte (0x0 nibble, then the length) followed by up to 7
/// payload bytes. Unpadded; the adapter pads to 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleFrame {
    data: [u8; 8],
    len: usize,
}

impl SingleFrame {
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
