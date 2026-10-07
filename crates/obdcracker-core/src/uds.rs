//! UDS (ISO 14229-1) requests and reply decoding.
//!
//! The request builders return payload bytes, which still have to pass the safety policy
//! before they can be sent. Each decoder takes one module's reassembled reply.

use crate::response::{Error, positive, printable};

/// The `ReadDataByIdentifier` service.
pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;

/// Standard identification data identifiers (ISO 14229-1 annex C). Manufacturer DIDs come from
/// vehicle profiles.
pub mod did {
    /// The manufacturer's spare part number.
    pub const SPARE_PART_NUMBER: u16 = 0xF187;
    /// The manufacturer's ECU software number.
    pub const SOFTWARE_NUMBER: u16 = 0xF188;
    /// The manufacturer's ECU software version.
    pub const SOFTWARE_VERSION: u16 = 0xF189;
    /// The vehicle identification number.
    pub const VIN: u16 = 0xF190;
    /// The manufacturer's ECU hardware number.
    pub const HARDWARE_NUMBER: u16 = 0xF191;
    /// The ODX file that describes the module's diagnostics.
    pub const ODX_FILE: u16 = 0xF19E;
}

/// A `ReadDataByIdentifier` request for one DID.
#[must_use]
pub fn read_did(did: u16) -> [u8; 3] {
    let [high, low] = did.to_be_bytes();
    [READ_DATA_BY_IDENTIFIER, high, low]
}

// The DID echoed at the start of `data`, and the bytes after it.
fn split_did(data: &[u8]) -> Result<(u16, &[u8]), Error> {
    let [high, low, rest @ ..] = data else {
        return Err(Error::TooShort);
    };
    Ok((u16::from_be_bytes([*high, *low]), rest))
}

/// Decodes the reply to a single-DID read: checks the echoed DID and returns its data.
pub fn decode_did(reply: &[u8], did: u16) -> Result<&[u8], Error> {
    let (got, data) = split_did(positive(READ_DATA_BY_IDENTIFIER, reply)?)?;
    if got != did {
        return Err(Error::Malformed);
    }
    if data.is_empty() {
        return Err(Error::TooShort);
    }
    Ok(data)
}

/// Decodes the reply to a multi-DID read. The reply doesn't say where each DID's data ends, so
/// `layout` gives each DID and its data length, in request order (from the vehicle profile).
pub fn decode_dids<'a, 'l>(
    reply: &'a [u8],
    layout: &'l [(u16, usize)],
) -> Result<DidValues<'a, 'l>, Error> {
    Ok(DidValues {
        rest: positive(READ_DATA_BY_IDENTIFIER, reply)?,
        layout: layout.iter(),
        failed: false,
    })
}

/// Each DID and its data from a multi-DID reply. A mismatch with the layout, or bytes left
/// over at the end, yields an error and ends it.
#[derive(Debug, Clone)]
pub struct DidValues<'a, 'l> {
    rest: &'a [u8],
    layout: core::slice::Iter<'l, (u16, usize)>,
    failed: bool,
}

impl<'a> DidValues<'a, '_> {
    fn fail(&mut self, error: Error) -> Result<(u16, &'a [u8]), Error> {
        self.failed = true;
        Err(error)
    }
}

impl<'a> Iterator for DidValues<'a, '_> {
    type Item = Result<(u16, &'a [u8]), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let Some(&(did, len)) = self.layout.next() else {
            return if self.rest.is_empty() {
                None
            } else {
                Some(self.fail(Error::Malformed))
            };
        };
        let (got, rest) = match split_did(self.rest) {
            Ok(split) => split,
            Err(e) => return Some(self.fail(e)),
        };
        if got != did {
            return Some(self.fail(Error::Malformed));
        }
        let Some((data, rest)) = rest.split_at_checked(len) else {
            return Some(self.fail(Error::TooShort));
        };
        self.rest = rest;
        Some(Ok((did, data)))
    }
}

/// Identification data as text, without the trailing spaces or 0x00 bytes modules pad it with.
pub fn decode_text(data: &[u8]) -> Result<&str, Error> {
    let end = data
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    printable(&data[..end])
}
