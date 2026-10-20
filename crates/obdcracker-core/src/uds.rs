//! UDS (ISO 14229-1) requests and reply decoding.
//!
//! The request builders return payload bytes, which still have to pass the safety policy
//! before they can be sent. Each decoder takes one module's reassembled reply.

use core::fmt;
use core::slice;
use core::time::Duration;

use crate::obd::Dtc;
use crate::response::{Error, positive, printable};

/// The `ReadDataByIdentifier` service.
pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;

/// The `ReadDTCInformation` service.
pub const READ_DTC_INFORMATION: u8 = 0x19;

const REPORT_NUMBER_BY_STATUS_MASK: u8 = 0x01;
const REPORT_DTC_BY_STATUS_MASK: u8 = 0x02;
const REPORT_SUPPORTED_DTC: u8 = 0x0A;
const REPORT_DTC_SNAPSHOT_BY_DTC: u8 = 0x04;
const REPORT_DTC_EXTENDED_DATA_BY_DTC: u8 = 0x06;
// The record number that asks for every record.
const ALL_RECORDS: u8 = 0xFF;
// The extended data record number that asks for every OBD record (ISO 14229-1).
const ALL_OBD_RECORDS: u8 = 0xFE;

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
    /// The system name or engine type.
    pub const SYSTEM_NAME: u16 = 0xF197;
    /// The ODX file that describes the module's diagnostics.
    pub const ODX_FILE: u16 = 0xF19E;

    /// Whether ISO 14229-1 makes `did` text: the VIN and the part, software, hardware, system
    /// and ODX names. Other DIDs, standard ones such as the manufacture date (F18B) included,
    /// can hold any bytes.
    #[must_use]
    pub fn is_text(did: u16) -> bool {
        matches!(
            did,
            SPARE_PART_NUMBER
                | SOFTWARE_NUMBER
                | SOFTWARE_VERSION
                | VIN
                | HARDWARE_NUMBER
                | SYSTEM_NAME
                | ODX_FILE
        )
    }
}

/// A `ReadDataByIdentifier` request for one DID.
#[must_use]
pub fn read_did(did: u16) -> [u8; 3] {
    let [high, low] = did.to_be_bytes();
    [READ_DATA_BY_IDENTIFIER, high, low]
}

/// The `DiagnosticSessionControl` service.
pub const DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;

/// The `TesterPresent` service.
pub const TESTER_PRESENT: u8 = 0x3E;

/// A diagnostic session a tester may switch a module to. The programming session isn't one:
/// the policy bans it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticSession {
    /// The session a module starts in and returns to (0x01).
    Default,
    /// The extended diagnostic session (0x03), which unlocks more reads.
    Extended,
}

/// A `DiagnosticSessionControl` request, with the positive reply asked for.
#[must_use]
pub fn session_control(session: DiagnosticSession) -> [u8; 2] {
    let sub = match session {
        DiagnosticSession::Default => 0x01,
        DiagnosticSession::Extended => 0x03,
    };
    [DIAGNOSTIC_SESSION_CONTROL, sub]
}

/// The reply timing a module gives in its positive answer to `DiagnosticSessionControl`, for the
/// session it entered (ISO 14229-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTiming {
    /// `P2server_max`: how long the module may take to answer, or send response-pending.
    pub p2: Duration,
    /// `P2*server_max`: how long the module may take to answer after response-pending.
    pub p2_star: Duration,
}

/// Decodes the timing in a positive answer to [`session_control`] for `session`:
/// `50 <session> <P2 in ms, 2 bytes> <P2* in 10 ms units, 2 bytes>`.
///
/// # Errors
///
/// A refusal, a reply for another service or session, or a reply that isn't exactly that long.
pub fn decode_session_timing(
    reply: &[u8],
    session: DiagnosticSession,
) -> Result<SessionTiming, Error> {
    let data = positive(DIAGNOSTIC_SESSION_CONTROL, reply)?;
    let [echo, p2_high, p2_low, star_high, star_low] = *data else {
        return Err(if data.len() < 5 {
            Error::TooShort
        } else {
            Error::Malformed
        });
    };
    if echo != session_control(session)[1] {
        return Err(Error::Malformed);
    }
    Ok(SessionTiming {
        p2: Duration::from_millis(u64::from(u16::from_be_bytes([p2_high, p2_low]))),
        p2_star: Duration::from_millis(u64::from(u16::from_be_bytes([star_high, star_low])) * 10),
    })
}

/// A `TesterPresent` request, `3E 00`, which keeps a non-default session open. The positive
/// reply isn't suppressed (`3E 80`): an ELM adapter waits out its whole timeout for a reply that
/// never comes.
#[must_use]
pub fn tester_present() -> [u8; 2] {
    [TESTER_PRESENT, 0x00]
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
/// An empty layout, or a length of 0, is [`Error::Malformed`].
pub fn decode_dids<'a, 'l>(
    reply: &'a [u8],
    layout: &'l [(u16, usize)],
) -> Result<DidValues<'a, 'l>, Error> {
    let rest = positive(READ_DATA_BY_IDENTIFIER, reply)?;
    // A positive reply carries at least one DID, and each DID at least one data byte.
    if layout.is_empty() || layout.iter().any(|&(_, len)| len == 0) {
        return Err(Error::Malformed);
    }
    Ok(DidValues {
        rest,
        layout: layout.iter(),
        failed: false,
    })
}

/// Each DID and its data from a multi-DID reply. A mismatch with the layout, or bytes left
/// over at the end, yields an error and ends it.
#[derive(Debug, Clone)]
pub struct DidValues<'a, 'l> {
    rest: &'a [u8],
    layout: slice::Iter<'l, (u16, usize)>,
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
///
/// Data that's nothing but padding gives an empty string: the module has no value set for that
/// identifier (an unprogrammed serial number, say), which is a valid state, not a bad reply.
pub fn decode_text(data: &[u8]) -> Result<&str, Error> {
    let end = data
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    printable(&data[..end])
}

/// A request for how many DTCs match a status mask (`ReadDTCInformation` 0x01).
#[must_use]
pub fn dtc_count_by_status_mask(mask: u8) -> [u8; 3] {
    [READ_DTC_INFORMATION, REPORT_NUMBER_BY_STATUS_MASK, mask]
}

/// A request for every DTC matching a status mask (`ReadDTCInformation` 0x02).
#[must_use]
pub fn dtcs_by_status_mask(mask: u8) -> [u8; 3] {
    [READ_DTC_INFORMATION, REPORT_DTC_BY_STATUS_MASK, mask]
}

/// A request for every DTC the module can store, whatever its status (`ReadDTCInformation` 0x0A).
#[must_use]
pub fn supported_dtcs() -> [u8; 2] {
    [READ_DTC_INFORMATION, REPORT_SUPPORTED_DTC]
}

/// A request for one DTC's snapshot records (`ReadDTCInformation` 0x04): what the module stored
/// when the fault happened. Record 0xFF asks for every record.
#[must_use]
pub fn dtc_snapshots(dtc: UdsDtc, record: u8) -> [u8; 6] {
    dtc_detail_request(REPORT_DTC_SNAPSHOT_BY_DTC, dtc, record)
}

/// A request for one DTC's extended data records (`ReadDTCInformation` 0x06), such as its
/// occurrence counter. Record 0xFF asks for every record, 0xFE for every OBD record.
#[must_use]
pub fn dtc_extended_data(dtc: UdsDtc, record: u8) -> [u8; 6] {
    dtc_detail_request(REPORT_DTC_EXTENDED_DATA_BY_DTC, dtc, record)
}

fn dtc_detail_request(sub: u8, dtc: UdsDtc, record: u8) -> [u8; 6] {
    let [_, high, mid, low] = dtc.code().to_be_bytes();
    [READ_DTC_INFORMATION, sub, high, mid, low, record]
}

/// A DTC's status byte (ISO 14229-1 D.2), one flag per bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DtcStatus(pub u8);

impl DtcStatus {
    fn bit(self, n: u8) -> bool {
        self.0 & (1 << n) != 0
    }

    /// Bit 0: the most recent test failed.
    #[must_use]
    pub fn test_failed(self) -> bool {
        self.bit(0)
    }

    /// Bit 1: a test failed during the current operation cycle.
    #[must_use]
    pub fn test_failed_this_operation_cycle(self) -> bool {
        self.bit(1)
    }

    /// Bit 2: pending, failed in the current or last operation cycle.
    #[must_use]
    pub fn pending(self) -> bool {
        self.bit(2)
    }

    /// Bit 3: confirmed, failed often enough to be stored.
    #[must_use]
    pub fn confirmed(self) -> bool {
        self.bit(3)
    }

    /// Bit 4: the test hasn't completed since DTCs were last cleared.
    #[must_use]
    pub fn test_not_completed_since_last_clear(self) -> bool {
        self.bit(4)
    }

    /// Bit 5: the test has failed at least once since DTCs were last cleared.
    #[must_use]
    pub fn test_failed_since_last_clear(self) -> bool {
        self.bit(5)
    }

    /// Bit 6: the test hasn't completed during the current operation cycle.
    #[must_use]
    pub fn test_not_completed_this_operation_cycle(self) -> bool {
        self.bit(6)
    }

    /// Bit 7: the module asks for a warning lamp (such as the MIL).
    #[must_use]
    pub fn warning_indicator_requested(self) -> bool {
        self.bit(7)
    }
}

/// Each set flag, in bit order, such as `failed, confirmed`; `no flags` if none is set.
impl fmt::Display for DtcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 8] = [
            "failed",
            "failed this cycle",
            "pending",
            "confirmed",
            "not tested since clear",
            "failed since clear",
            "not tested this cycle",
            "lamp",
        ];
        let mut set = (0..8u8)
            .filter(|&n| self.bit(n))
            .map(|n| NAMES[usize::from(n)]);
        match set.next() {
            None => f.write_str("no flags"),
            Some(first) => {
                f.write_str(first)?;
                set.try_for_each(|name| write!(f, ", {name}"))
            }
        }
    }
}

/// How a module encodes its DTCs, from the reply to [`dtc_count_by_status_mask`]
/// (ISO 14229-1 D.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtcFormat {
    /// 0x00: SAE J2012-DA format 00 (ISO 15031-6), the same codes OBD-II reports.
    SaeJ2012Da00,
    /// 0x01: ISO 14229-1's own format, whose meaning the manufacturer defines.
    Iso14229,
    /// 0x02: SAE J1939-73, used by heavy vehicles.
    SaeJ1939,
    /// 0x03: ISO 11992-4, used by trailers.
    Iso11992,
    /// 0x04: SAE J2012-DA format 04.
    SaeJ2012Da04,
    /// A format without a name here, kept as received.
    Other(u8),
}

impl From<u8> for DtcFormat {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Self::SaeJ2012Da00,
            0x01 => Self::Iso14229,
            0x02 => Self::SaeJ1939,
            0x03 => Self::Iso11992,
            0x04 => Self::SaeJ2012Da04,
            other => Self::Other(other),
        }
    }
}

impl DtcFormat {
    /// The format's byte value.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::SaeJ2012Da00 => 0x00,
            Self::Iso14229 => 0x01,
            Self::SaeJ1939 => 0x02,
            Self::Iso11992 => 0x03,
            Self::SaeJ2012Da04 => 0x04,
            Self::Other(code) => code,
        }
    }
}

/// A three-byte UDS DTC. What the bytes mean depends on the module's [`DtcFormat`], so it's
/// shown as 6 hex digits; use [`UdsDtc::j2012`] for the `P0401` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdsDtc(u32);

impl UdsDtc {
    /// Wraps the DTC's three bytes, held in the low 24 bits.
    #[must_use]
    pub fn new(code: u32) -> Self {
        Self(code & 0x00FF_FFFF)
    }

    /// The DTC's three bytes, in the low 24 bits.
    #[must_use]
    pub fn code(self) -> u32 {
        self.0
    }

    /// The DTC as an SAE J2012 code and failure type, if the module's format is J2012
    /// (0x00 or 0x04). `None` for other formats, whose bytes mean something else.
    #[must_use]
    pub fn j2012(self, format: DtcFormat) -> Option<J2012Dtc> {
        if !matches!(format, DtcFormat::SaeJ2012Da00 | DtcFormat::SaeJ2012Da04) {
            return None;
        }
        let [_, high, low, failure_type] = self.0.to_be_bytes();
        Some(J2012Dtc {
            dtc: Dtc::new(u16::from_be_bytes([high, low])),
            failure_type,
        })
    }
}

impl fmt::Display for UdsDtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06X}", self.0)
    }
}

/// A UDS DTC in SAE J2012 form: the two-byte code OBD-II also reports, and a failure type
/// byte (what kind of fault, such as a short to ground). Shown as `P0401-00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct J2012Dtc {
    /// The two-byte code.
    pub dtc: Dtc,
    /// The failure type byte.
    pub failure_type: u8,
}

impl fmt::Display for J2012Dtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{:02X}", self.dtc, self.failure_type)
    }
}

/// The reply to a DTC count request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtcCount {
    /// Which status bits the module supports.
    pub availability: DtcStatus,
    /// How the module encodes its DTCs.
    pub format: DtcFormat,
    /// How many DTCs match the mask.
    pub count: u16,
}

// The data after a ReadDTCInformation reply's echoed subfunction, which must be `sub`.
fn dtc_reply(reply: &[u8], sub: u8) -> Result<&[u8], Error> {
    let [echoed, rest @ ..] = positive(READ_DTC_INFORMATION, reply)? else {
        return Err(Error::TooShort);
    };
    if *echoed != sub {
        return Err(Error::Malformed);
    }
    Ok(rest)
}

/// Decodes the reply to [`dtc_count_by_status_mask`].
pub fn decode_dtc_count(reply: &[u8]) -> Result<DtcCount, Error> {
    let rest = dtc_reply(reply, REPORT_NUMBER_BY_STATUS_MASK)?;
    let [availability, format, high, low] = *rest else {
        return Err(Error::Malformed);
    };
    Ok(DtcCount {
        availability: DtcStatus(availability),
        format: DtcFormat::from(format),
        count: u16::from_be_bytes([high, low]),
    })
}

/// One DTC and its status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtcRecord {
    /// The DTC.
    pub dtc: UdsDtc,
    /// Its status flags.
    pub status: DtcStatus,
}

/// Decodes the reply to [`dtcs_by_status_mask`]: the status bits the module supports, and each
/// DTC matching the mask with its status.
pub fn decode_dtcs_by_status_mask(reply: &[u8]) -> Result<(DtcStatus, DtcRecords<'_>), Error> {
    dtc_records(reply, REPORT_DTC_BY_STATUS_MASK)
}

/// Decodes the reply to [`supported_dtcs`]: the status bits the module supports, and every DTC
/// it can store with its status.
pub fn decode_supported_dtcs(reply: &[u8]) -> Result<(DtcStatus, DtcRecords<'_>), Error> {
    dtc_records(reply, REPORT_SUPPORTED_DTC)
}

/// One DTC's snapshot or extended data, from the reply to [`dtc_snapshots`] or
/// [`dtc_extended_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtcData<'a> {
    /// The DTC's status.
    pub status: DtcStatus,
    /// The records, each a record number and its data, as the module sent them. A record's
    /// length depends on the module's data identifiers, so they aren't split. Empty if the
    /// module stored none.
    pub records: &'a [u8],
}

/// Decodes the reply to [`dtc_snapshots`] for `dtc` and `record`.
///
/// # Errors
///
/// A refusal, a reply for another subfunction or DTC, one cut short before the status, or one
/// whose first record isn't the one asked for (unless every record was).
pub fn decode_dtc_snapshots(reply: &[u8], dtc: UdsDtc, record: u8) -> Result<DtcData<'_>, Error> {
    dtc_data(reply, REPORT_DTC_SNAPSHOT_BY_DTC, dtc, record)
}

/// Decodes the reply to [`dtc_extended_data`] for `dtc` and `record`.
///
/// # Errors
///
/// As [`decode_dtc_snapshots`]; 0xFE, every OBD record, also takes any first record.
pub fn decode_dtc_extended_data(
    reply: &[u8],
    dtc: UdsDtc,
    record: u8,
) -> Result<DtcData<'_>, Error> {
    dtc_data(reply, REPORT_DTC_EXTENDED_DATA_BY_DTC, dtc, record)
}

// The status and records after the echoed subfunction `sub` and `dtc`.
fn dtc_data(reply: &[u8], sub: u8, dtc: UdsDtc, record: u8) -> Result<DtcData<'_>, Error> {
    let rest = dtc_reply(reply, sub)?;
    let [high, mid, low, status, records @ ..] = rest else {
        return Err(Error::TooShort);
    };
    if UdsDtc::new(u32::from_be_bytes([0, *high, *mid, *low])) != dtc {
        return Err(Error::Malformed);
    }
    let any = record == ALL_RECORDS
        || (sub == REPORT_DTC_EXTENDED_DATA_BY_DTC && record == ALL_OBD_RECORDS);
    if !any && records.first().is_some_and(|&first| first != record) {
        return Err(Error::Malformed);
    }
    Ok(DtcData {
        status: DtcStatus(*status),
        records,
    })
}

// The availability mask and 4-byte DTC records after the echoed subfunction `sub`.
fn dtc_records(reply: &[u8], sub: u8) -> Result<(DtcStatus, DtcRecords<'_>), Error> {
    let rest = dtc_reply(reply, sub)?;
    let (&availability, records) = rest.split_first().ok_or(Error::TooShort)?;
    let (records, partial) = records.as_chunks::<4>();
    if !partial.is_empty() {
        return Err(Error::Malformed);
    }
    Ok((DtcStatus(availability), DtcRecords(records.iter())))
}

/// The DTC records in a `ReadDTCInformation` reply.
#[derive(Debug, Clone)]
pub struct DtcRecords<'a>(slice::Iter<'a, [u8; 4]>);

impl Iterator for DtcRecords<'_> {
    type Item = DtcRecord;

    fn next(&mut self) -> Option<DtcRecord> {
        self.0.next().map(|&[a, b, c, status]| DtcRecord {
            dtc: UdsDtc(u32::from_be_bytes([0, a, b, c])),
            status: DtcStatus(status),
        })
    }
}
