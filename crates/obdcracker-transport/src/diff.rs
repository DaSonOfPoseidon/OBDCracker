//! What changed between two reads of the same car: a [`Fingerprint`], a [`Scan`], a [`Sweep`], a
//! multi-DID read or the VINs, each as a list of [`Change`]s. Nothing is sent: both sides are values
//! already read (or a document written by `--json`, read back with the `serde` feature).
//! See [`docs/usage.md#diff`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/usage.md#diff).
//!
//! - ECUs are matched by their reply CAN ID, and modules by name and reply CAN ID together: a module
//!   under another response ID is one removed and one added, not changed.
//! - The changes come in a fixed order whatever order the lists were in: ECUs by CAN ID (each
//!   ECU's own changes together), then modules by name and CAN ID, DIDs and DTCs by their number.
//! - An ECU or module on one side only is a single change; what it holds isn't listed.
//! - A list that couldn't be read on one side ([`Change::Unreadable`]) is one change: comparing it
//!   with a list that was read would report every entry as added or removed.
//! - A list that repeats an ECU, module, DID, DTC or PID (a hand-edited document) can't be compared:
//!   which entry counts isn't known, so the `diff_*` functions return a [`DuplicateError`].
//! - Live values (a scan's mode 01 PID readings) and the run's own state (a sweep's stop, a DTC
//!   count) aren't compared: they differ on every run.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::RangeInclusive;

use obdcracker_core::obd::{Cvn, Dtc, MonitorKind, MonitorStatus};
use obdcracker_core::uds::{DtcStatus, UdsDtc};

use crate::fingerprint::{
    Calibration, DidValue, Fingerprint, Identification, ReadError, UdsModule,
};
use crate::hex;
use crate::read_dids::DidsData;
use crate::scan::{ModuleScan, ObdEcu, PidReading, Scan};
use crate::sweep::Sweep;

type DidRead = Result<DidValue, ReadError>;
type Did = (u16, DidRead);

/// Which of the two results compared a [`DuplicateError`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The first result (`old`).
    Old,
    /// The second result (`new`).
    New,
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Old => "old",
            Self::New => "new",
        })
    }
}

/// A result lists the same ECU, module, DID or DTC twice, so it doesn't say which entry is the car's.
/// Reads made by this crate never do this; a hand-edited document can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateError {
    /// Which result repeats it.
    pub input: Input,
    /// What is repeated, such as `ECU 7E8` or `DID F189 of engine (0x7E8)`.
    pub entry: String,
}

impl fmt::Display for DuplicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} result lists {} twice", self.input, self.entry)
    }
}

impl std::error::Error for DuplicateError {}

/// A module, as results identify it: its name and the CAN ID it answers on.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId {
    /// The module's name, such as `engine`.
    pub name: String,
    /// The CAN ID it answers on.
    #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
    pub response_id: u32,
}

impl From<&UdsModule> for ModuleId {
    fn from(module: &UdsModule) -> Self {
        Self {
            name: module.name.clone(),
            response_id: module.response_id,
        }
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{})", Plain(&self.name), CanId(self.response_id))
    }
}

/// Whose list a [`Change::Unreadable`] is about.
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "kind"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// An emissions ECU.
    Ecu {
        /// The CAN ID it answers on.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
    },
    /// A module read over UDS.
    Module(ModuleId),
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecu { source } => CanId(*source).fmt(f),
            Self::Module(module) => Plain(&module.name).fmt(f),
        }
    }
}

/// A list that was read on at least one side, for [`Change::Unreadable`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum List {
    /// An ECU's calibration IDs (mode 09 PID 04).
    Calids,
    /// An ECU's calibration verification numbers (mode 09 PID 06).
    Cvns,
    /// The mode 01 PIDs an ECU supports.
    ObdPids,
    /// The mode 09 PIDs an ECU supports.
    ObdInfo,
    /// An ECU's stored emissions DTCs (mode 03).
    ObdDtcs,
    /// An ECU's pending emissions DTCs (mode 07).
    ObdPendingDtcs,
    /// An ECU's permanent emissions DTCs (mode 0A).
    ObdPermanentDtcs,
    /// An ECU's MIL and readiness monitors (mode 01 PID 01).
    MonitorStatus,
    /// A module's DTCs (UDS `19 02`).
    UdsDtcs,
    /// The DIDs of a multi-DID read.
    Dids,
}

impl fmt::Display for List {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Calids => "CALIDs",
            Self::Cvns => "CVNs",
            Self::ObdPids => "mode 01 PIDs",
            Self::ObdInfo => "mode 09 PIDs",
            Self::ObdDtcs | Self::UdsDtcs => "DTCs",
            Self::ObdPendingDtcs => "pending DTCs",
            Self::ObdPermanentDtcs => "permanent DTCs",
            Self::MonitorStatus => "readiness",
            Self::Dids => "DIDs",
        })
    }
}

/// One difference between two reads of a car, from the first (`old`) to the second (`new`).
///
/// With the `serde` feature it serializes as an object whose `change` is the variant's name, and
/// whose other fields are written as in `docs/json.md`: CAN IDs, DIDs, PIDs and bytes as hex, a
/// read that can fail as `{"value": ...}` or `{"error": ...}`, and a side with no value as `null`.
/// Slots (`slot`) count from 1.
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "change"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// An emissions ECU answered only the second time.
    EcuAdded {
        /// The CAN ID it answers on.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
    },
    /// An emissions ECU answered only the first time.
    EcuRemoved {
        /// The CAN ID it answered on.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
    },
    /// A calibration ID differs. `None` is an empty slot (only 0x00 padding).
    CalidChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The calibration's place in the ECU's list, from 1.
        slot: usize,
        /// The calibration ID in the first read.
        old: Option<String>,
        /// The calibration ID in the second.
        new: Option<String>,
    },
    /// The second read lists a calibration ID the first didn't have a slot for.
    CalidAdded {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The calibration's place in the ECU's list, from 1.
        slot: usize,
        /// The calibration ID; `None` is an empty slot.
        calid: Option<String>,
    },
    /// The first read listed a calibration ID the second doesn't have a slot for.
    CalidRemoved {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The calibration's place in the ECU's list, from 1.
        slot: usize,
        /// The calibration ID; `None` is an empty slot.
        calid: Option<String>,
    },
    /// A calibration verification number differs: the calibration was changed (a tune).
    CvnChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The CVN's place in the ECU's list, from 1.
        slot: usize,
        /// The CVN in the first read.
        old: Cvn,
        /// The CVN in the second.
        new: Cvn,
    },
    /// The second read lists a CVN the first didn't have a slot for.
    CvnAdded {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The CVN's place in the ECU's list, from 1.
        slot: usize,
        /// The CVN.
        cvn: Cvn,
    },
    /// The first read listed a CVN the second doesn't have a slot for.
    CvnRemoved {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The CVN's place in the ECU's list, from 1.
        slot: usize,
        /// The CVN.
        cvn: Cvn,
    },
    /// The ECU supports a mode 01 PID it didn't.
    ObdPidAdded {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The PID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::byte"))]
        pid: u8,
    },
    /// The ECU no longer supports a mode 01 PID.
    ObdPidRemoved {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The PID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::byte"))]
        pid: u8,
    },
    /// Where the ECU's PID list was cut short ([`crate::scan::ObdEcu::pids_cut_short`]) differs.
    /// The PIDs past the cut show as added or removed too.
    PidsCutShortChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The bitmap PID the list was cut at in the first read, `None` if it wasn't.
        #[cfg_attr(feature = "serde", serde(serialize_with = "wire::option_byte"))]
        old: Option<u8>,
        /// The bitmap PID the list was cut at in the second, `None` if it wasn't.
        #[cfg_attr(feature = "serde", serde(serialize_with = "wire::option_byte"))]
        new: Option<u8>,
    },
    /// The ECU supports a mode 09 PID it didn't.
    ObdInfoAdded {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The PID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::byte"))]
        pid: u8,
    },
    /// The ECU no longer supports a mode 09 PID.
    ObdInfoRemoved {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The PID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::byte"))]
        pid: u8,
    },
    /// The ECU's name (mode 09 PID 0A) differs, or was read in only one of the two.
    EcuNameChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The name in the first read.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::json::outcome::serialize")
        )]
        old: Result<String, ReadError>,
        /// The name in the second.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::json::outcome::serialize")
        )]
        new: Result<String, ReadError>,
    },
    /// An emissions DTC is stored that wasn't.
    ObdDtcNew {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// An emissions DTC that was stored no longer is.
    ObdDtcCleared {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// A pending emissions DTC (mode 07) is there that wasn't.
    ObdPendingDtcNew {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// A pending emissions DTC that was there no longer is.
    ObdPendingDtcCleared {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// A permanent emissions DTC (mode 0A) is there that wasn't.
    ObdPermanentDtcNew {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// A permanent emissions DTC that was there no longer is.
    ObdPermanentDtcCleared {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The DTC.
        dtc: Dtc,
    },
    /// The malfunction indicator lamp is on where it was off, or off where it was on.
    MilChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// Whether it was on in the first read.
        old: bool,
        /// Whether it was on in the second.
        new: bool,
    },
    /// A readiness monitor that both reads say the ECU supports went from incomplete to complete,
    /// or back.
    MonitorChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The monitor, as [`MonitorKind::name`] writes it.
        #[cfg_attr(feature = "serde", serde(serialize_with = "wire::monitor"))]
        monitor: MonitorKind,
        /// Whether it was complete in the first read.
        old: bool,
        /// Whether it was complete in the second.
        new: bool,
    },
    /// A module was read only the second time.
    ModuleAdded {
        /// The module.
        module: ModuleId,
    },
    /// A module was read only the first time.
    ModuleRemoved {
        /// The module.
        module: ModuleId,
    },
    /// Whether the module answered anything at all ([`crate::scan::ModuleScan::answered`]) differs.
    AnsweredChanged {
        /// The module.
        module: ModuleId,
        /// Whether it answered in the first read.
        old: bool,
        /// Whether it answered in the second.
        new: bool,
    },
    /// A DID's value differs. `None` is a DID the read doesn't have at all; an error is a
    /// refusal or a missing answer.
    DidChanged {
        /// The module.
        module: ModuleId,
        /// The DID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::did"))]
        did: u16,
        /// The value or error in the first read.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::json::option_outcome::serialize")
        )]
        old: Option<DidRead>,
        /// The value or error in the second.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::json::option_outcome::serialize")
        )]
        new: Option<DidRead>,
    },
    /// A multi-DID read's bytes that couldn't be split into DIDs ([`DidsData::unsplit`]) differ.
    UnsplitChanged {
        /// The module.
        module: ModuleId,
        /// The bytes in the first read.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::bytes"))]
        old: Vec<u8>,
        /// The bytes in the second.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::bytes"))]
        new: Vec<u8>,
    },
    /// A module reports a DTC it didn't.
    UdsDtcNew {
        /// The module.
        module: ModuleId,
        /// The DTC.
        dtc: UdsDtc,
        /// Its status.
        status: DtcStatus,
    },
    /// A module no longer reports a DTC.
    UdsDtcCleared {
        /// The module.
        module: ModuleId,
        /// The DTC.
        dtc: UdsDtc,
        /// Its status in the first read.
        status: DtcStatus,
    },
    /// A DTC's status differs.
    UdsDtcStatusChanged {
        /// The module.
        module: ModuleId,
        /// The DTC.
        dtc: UdsDtc,
        /// Its status in the first read.
        old: DtcStatus,
        /// Its status in the second.
        new: DtcStatus,
    },
    /// An ECU's VIN differs.
    VinChanged {
        /// The ECU's CAN ID.
        #[cfg_attr(feature = "serde", serde(with = "crate::json::can_id"))]
        source: u32,
        /// The VIN in the first read.
        old: String,
        /// The VIN in the second.
        new: String,
    },
    /// A list wasn't read the same way on both sides: it failed in one or both and the errors
    /// differ, so there is nothing to compare entry by entry.
    Unreadable {
        /// Whose list it is.
        scope: Scope,
        /// Which list.
        list: List,
        /// Why it failed in the first read, `None` if it was read.
        old: Option<ReadError>,
        /// Why it failed in the second, `None` if it was read.
        new: Option<ReadError>,
    },
}

#[cfg(feature = "serde")]
mod wire {
    use obdcracker_core::obd::MonitorKind;
    use serde::Serializer;

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `serialize_with` passes a reference"
    )]
    pub(super) fn monitor<S: Serializer>(
        kind: &MonitorKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(kind.name())
    }

    #[expect(
        clippy::ref_option,
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `serialize_with` passes a reference"
    )]
    pub(super) fn option_byte<S: Serializer>(
        byte: &Option<u8>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match byte {
            Some(byte) => serializer.collect_str(&format_args!("{byte:02X}")),
            None => serializer.serialize_none(),
        }
    }
}

// A CAN ID as the results print it: 3 hex digits, or 8 for a 29-bit one.
struct CanId(u32);

impl fmt::Display for CanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 <= 0x7FF {
            write!(f, "{:03X}", self.0)
        } else {
            write!(f, "{:08X}", self.0)
        }
    }
}

// Text from a document, which anyone could have edited, on its way to a terminal: only printable
// ASCII goes through, the rest as `\u{..}`, so it can't carry an escape sequence.
struct Plain<'a>(&'a str);

impl fmt::Display for Plain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        escaped(f, self.0, false)
    }
}

// `Plain` between double quotes, with the quotes in it escaped: a value that is text, which no
// marker such as `(absent)` or `[01]` can be mistaken for.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        escaped(f, self.0, true)?;
        f.write_str("\"")
    }
}

fn escaped(f: &mut fmt::Formatter<'_>, text: &str, quotes: bool) -> fmt::Result {
    text.chars().try_for_each(|c| {
        if c == '\\' || (quotes && c == '"') {
            write!(f, "\\{c}")
        } else if (' '..='~').contains(&c) {
            fmt::Write::write_char(f, c)
        } else {
            write!(f, "{}", c.escape_unicode())
        }
    })
}

// A DID's value or error as one word or group, so "no value" and "no such DID" read differently.
// Text is quoted, bytes bracketed and the rest parenthesized: none can pass for another.
struct Shown<'a>(&'a Option<DidRead>);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("(absent)"),
            Some(Ok(DidValue::Text(text))) => Quoted(text).fmt(f),
            Some(Ok(bytes @ DidValue::Bytes(_))) => write!(f, "[{bytes}]"),
            Some(Ok(DidValue::NotSet)) => f.write_str("(not set)"),
            Some(Err(e)) => write!(f, "({e})"),
        }
    }
}

struct Calid<'a>(&'a Option<String>);

impl fmt::Display for Calid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(calid) => Quoted(calid).fmt(f),
            None => f.write_str("(empty)"),
        }
    }
}

struct Name<'a>(&'a Result<String, ReadError>);

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(name) => Quoted(name).fmt(f),
            Err(e) => write!(f, "({e})"),
        }
    }
}

struct Cut(Option<u8>);

impl fmt::Display for Cut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(pid) => write!(f, "cut short at {pid:02X}"),
            None => f.write_str("complete"),
        }
    }
}

struct Reason<'a>(&'a Option<ReadError>);

impl fmt::Display for Reason<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(e) => e.fmt(f),
            None => f.write_str("read"),
        }
    }
}

fn answered(answered: bool) -> &'static str {
    if answered {
        "answered"
    } else {
        "didn't answer"
    }
}

// A line about the ECU on `source`.
fn ecu(f: &mut fmt::Formatter<'_>, source: u32, what: fmt::Arguments<'_>) -> fmt::Result {
    write!(f, "{} {what}", CanId(source))
}

// A line about a module, by name.
fn module(f: &mut fmt::Formatter<'_>, module: &ModuleId, what: fmt::Arguments<'_>) -> fmt::Result {
    write!(f, "{} {what}", Plain(&module.name))
}

/// One line per change, such as `7E8 CALID 1: "4G0907589F" → "4G0907589G"` or
/// `transmission F189 "0005" → "0006"`. A DID's, CALID's or ECU name's text is in double quotes
/// (with `\"` and `\\` for those characters), so it can't be mistaken for bytes (`[01]`) or a
/// marker (`(absent)`, `(not set)`, `(empty)`, or why a read failed). Text that came from a document
/// is shown as printable ASCII, with anything else as `\u{..}`.
impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcuAdded { .. }
            | Self::EcuRemoved { .. }
            | Self::CalidChanged { .. }
            | Self::CalidAdded { .. }
            | Self::CalidRemoved { .. }
            | Self::CvnChanged { .. }
            | Self::CvnAdded { .. }
            | Self::CvnRemoved { .. }
            | Self::ObdPidAdded { .. }
            | Self::ObdPidRemoved { .. }
            | Self::PidsCutShortChanged { .. }
            | Self::ObdInfoAdded { .. }
            | Self::ObdInfoRemoved { .. }
            | Self::EcuNameChanged { .. }
            | Self::ObdDtcNew { .. }
            | Self::ObdDtcCleared { .. }
            | Self::VinChanged { .. } => fmt_ecu_change(self, f),
            Self::ObdPendingDtcNew { .. }
            | Self::ObdPendingDtcCleared { .. }
            | Self::ObdPermanentDtcNew { .. }
            | Self::ObdPermanentDtcCleared { .. }
            | Self::MilChanged { .. }
            | Self::MonitorChanged { .. } => fmt_readiness_change(self, f),
            Self::ModuleAdded { .. }
            | Self::ModuleRemoved { .. }
            | Self::AnsweredChanged { .. }
            | Self::DidChanged { .. }
            | Self::UnsplitChanged { .. }
            | Self::UdsDtcNew { .. }
            | Self::UdsDtcCleared { .. }
            | Self::UdsDtcStatusChanged { .. }
            | Self::Unreadable { .. } => fmt_module_change(self, f),
        }
    }
}

// The changes about an emissions ECU, which `fmt` sends here.
fn fmt_ecu_change(change: &Change, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match change {
        Change::EcuAdded { source } => ecu(f, *source, format_args!("ECU added")),
        Change::EcuRemoved { source } => ecu(f, *source, format_args!("ECU removed")),
        Change::CalidChanged {
            source,
            slot,
            old,
            new,
        } => {
            let (old, new) = (Calid(old), Calid(new));
            ecu(f, *source, format_args!("CALID {slot}: {old} → {new}"))
        }
        Change::CalidAdded {
            source,
            slot,
            calid,
        } => ecu(
            f,
            *source,
            format_args!("CALID {slot} added: {}", Calid(calid)),
        ),
        Change::CalidRemoved {
            source,
            slot,
            calid,
        } => ecu(
            f,
            *source,
            format_args!("CALID {slot} removed: {}", Calid(calid)),
        ),
        Change::CvnChanged {
            source,
            slot,
            old,
            new,
        } => ecu(f, *source, format_args!("CVN {slot}: {old} → {new}")),
        Change::CvnAdded { source, slot, cvn } => {
            ecu(f, *source, format_args!("CVN {slot} added: {cvn}"))
        }
        Change::CvnRemoved { source, slot, cvn } => {
            ecu(f, *source, format_args!("CVN {slot} removed: {cvn}"))
        }
        Change::ObdPidAdded { source, pid } => {
            ecu(f, *source, format_args!("mode 01 PID {pid:02X} added"))
        }
        Change::ObdPidRemoved { source, pid } => {
            ecu(f, *source, format_args!("mode 01 PID {pid:02X} removed"))
        }
        Change::PidsCutShortChanged { source, old, new } => {
            let (old, new) = (Cut(*old), Cut(*new));
            ecu(f, *source, format_args!("PID list {new} (was {old})"))
        }
        Change::ObdInfoAdded { source, pid } => {
            ecu(f, *source, format_args!("mode 09 PID {pid:02X} added"))
        }
        Change::ObdInfoRemoved { source, pid } => {
            ecu(f, *source, format_args!("mode 09 PID {pid:02X} removed"))
        }
        Change::EcuNameChanged { source, old, new } => {
            let (old, new) = (Name(old), Name(new));
            ecu(f, *source, format_args!("name: {old} → {new}"))
        }
        Change::ObdDtcNew { source, dtc } => ecu(f, *source, format_args!("DTC new: {dtc}")),
        Change::ObdDtcCleared { source, dtc } => {
            ecu(f, *source, format_args!("DTC cleared: {dtc}"))
        }
        Change::VinChanged { source, old, new } => {
            let (old, new) = (Plain(old), Plain(new));
            ecu(f, *source, format_args!("VIN {old} → {new}"))
        }
        other => unreachable!("{other:?} isn't about an ECU: `fmt` sends it to the module lines"),
    }
}

// The pending and permanent DTC changes, the MIL and the readiness monitors, which `fmt` sends here.
fn fmt_readiness_change(change: &Change, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match change {
        Change::ObdPendingDtcNew { source, dtc } => {
            ecu(f, *source, format_args!("pending DTC new: {dtc}"))
        }
        Change::ObdPendingDtcCleared { source, dtc } => {
            ecu(f, *source, format_args!("pending DTC cleared: {dtc}"))
        }
        Change::ObdPermanentDtcNew { source, dtc } => {
            ecu(f, *source, format_args!("permanent DTC new: {dtc}"))
        }
        Change::ObdPermanentDtcCleared { source, dtc } => {
            ecu(f, *source, format_args!("permanent DTC cleared: {dtc}"))
        }
        Change::MilChanged { source, old, new } => {
            let on = |on: &bool| if *on { "on" } else { "off" };
            ecu(f, *source, format_args!("MIL: {} → {}", on(old), on(new)))
        }
        Change::MonitorChanged {
            source,
            monitor,
            old,
            new,
        } => {
            let state = |complete: &bool| if *complete { "complete" } else { "incomplete" };
            ecu(
                f,
                *source,
                format_args!(
                    "monitor {}: {} → {}",
                    monitor.name().replace('_', " "),
                    state(old),
                    state(new)
                ),
            )
        }
        other => unreachable!("{other:?} isn't a readiness change: `fmt` sends it elsewhere"),
    }
}

// The changes about a module, and the lists that couldn't be compared, which `fmt` sends here.
fn fmt_module_change(change: &Change, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match change {
        Change::ModuleAdded { module } => write!(f, "module added: {module}"),
        Change::ModuleRemoved { module } => write!(f, "module removed: {module}"),
        Change::AnsweredChanged {
            module: id,
            old,
            new,
        } => {
            let (old, new) = (answered(*old), answered(*new));
            module(f, id, format_args!("{old} → {new}"))
        }
        Change::DidChanged {
            module: id,
            did,
            old,
            new,
        } => {
            let (old, new) = (Shown(old), Shown(new));
            module(f, id, format_args!("{did:04X} {old} → {new}"))
        }
        Change::UnsplitChanged {
            module: id,
            old,
            new,
        } => {
            let (old, new) = (hex(old), hex(new));
            module(f, id, format_args!("unsplit data [{old}] → [{new}]"))
        }
        Change::UdsDtcNew {
            module: id,
            dtc,
            status,
        } => module(f, id, format_args!("DTC new: {dtc} ({status})")),
        Change::UdsDtcCleared {
            module: id,
            dtc,
            status,
        } => module(f, id, format_args!("DTC cleared: {dtc} ({status})")),
        Change::UdsDtcStatusChanged {
            module: id,
            dtc,
            old,
            new,
        } => module(f, id, format_args!("DTC {dtc} status: {old} → {new}")),
        Change::Unreadable {
            scope,
            list,
            old,
            new,
        } => {
            let (old, new) = (Reason(old), Reason(new));
            write!(f, "{scope} {list} can't be compared: old {old}, new {new}")
        }
        other => unreachable!("{other:?} is about an ECU: `fmt` sends it to the ECU lines"),
    }
}

// One entry's place in the two lists being compared.
enum Side<'a, T> {
    Old(&'a T),
    New(&'a T),
    Both(&'a T, &'a T),
}

// The entries of both lists by `key`, in key order. The lists have no repeated key (`unique`
// checked): of a repeated one only the last entry would count.
fn sides<'a, K: Ord, T>(
    old: &'a [T],
    new: &'a [T],
    key: impl Fn(&T) -> K,
) -> Vec<(K, Side<'a, T>)> {
    let index = |items: &'a [T]| {
        let mut map = BTreeMap::new();
        for item in items {
            map.insert(key(item), item);
        }
        map
    };
    let (old, mut new) = (index(old), index(new));
    let mut found = Vec::with_capacity(old.len().max(new.len()));
    for (key, old) in old {
        found.push(match new.remove(&key) {
            Some(new) => (key, Side::Both(old, new)),
            None => (key, Side::Old(old)),
        });
    }
    found.extend(new.into_iter().map(|(key, new)| (key, Side::New(new))));
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

// Fails with a description of the first entry of `items` whose key an earlier one has.
fn unique<K: Ord, T>(
    items: &[T],
    key: impl Fn(&T) -> K,
    describe: impl Fn(&K) -> String,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for item in items {
        let key = key(item);
        if seen.contains(&key) {
            return Err(describe(&key));
        }
        seen.insert(key);
    }
    Ok(())
}

fn unique_dids(dids: &[Did], whose: &ModuleId) -> Result<(), String> {
    unique(
        dids,
        |(did, _)| *did,
        |did| format!("DID {did:04X} of {whose}"),
    )
}

fn unique_ecus<T>(items: &[T], source: fn(&T) -> u32) -> Result<(), String> {
    unique(items, source, |source| format!("ECU {}", CanId(*source)))
}

fn unique_modules<T>(items: &[T], id: fn(&T) -> ModuleId) -> Result<(), String> {
    unique(items, id, |id| format!("module {id}"))
}

// `check` on the old result, then on the new one.
fn both_unique<T: ?Sized>(
    old: &T,
    new: &T,
    check: impl Fn(&T) -> Result<(), String>,
) -> Result<(), DuplicateError> {
    for (input, side) in [(Input::Old, old), (Input::New, new)] {
        check(side).map_err(|entry| DuplicateError { input, entry })?;
    }
    Ok(())
}

// What was added (`true`) or removed (`false`) from one set to the other, in key order.
fn membership<K: Ord + Clone>(old: &BTreeSet<K>, new: &BTreeSet<K>) -> Vec<(K, bool)> {
    old.symmetric_difference(new)
        .map(|key| (key.clone(), new.contains(key)))
        .collect()
}

// Compares two lists that were each read or failed: both read, `both` compares them; both failed
// the same way is no change; anything else is the one change that the lists can't be compared.
fn lists<T>(
    out: &mut Vec<Change>,
    scope: &Scope,
    list: List,
    old: &Result<T, ReadError>,
    new: &Result<T, ReadError>,
    both: impl FnOnce(&mut Vec<Change>, &T, &T),
) {
    match (old, new) {
        (Ok(old), Ok(new)) => both(out, old, new),
        (Err(old), Err(new)) if old == new => {}
        _ => out.push(Change::Unreadable {
            scope: scope.clone(),
            list,
            old: old.as_ref().err().cloned(),
            new: new.as_ref().err().cloned(),
        }),
    }
}

// An ECU on one side only is one change; one on both is compared by `both`.
fn ecus<T>(
    out: &mut Vec<Change>,
    old: &[T],
    new: &[T],
    source: fn(&T) -> u32,
    mut both: impl FnMut(&mut Vec<Change>, u32, &T, &T),
) {
    for (source, side) in sides(old, new, source) {
        match side {
            Side::Old(_) => out.push(Change::EcuRemoved { source }),
            Side::New(_) => out.push(Change::EcuAdded { source }),
            Side::Both(old, new) => both(out, source, old, new),
        }
    }
}

// A module on one side only is one change; one on both is compared by `both`.
fn modules<T>(
    out: &mut Vec<Change>,
    old: &[T],
    new: &[T],
    id: fn(&T) -> ModuleId,
    mut both: impl FnMut(&mut Vec<Change>, &ModuleId, &T, &T),
) {
    for (module, side) in sides(old, new, id) {
        match side {
            Side::Old(_) => out.push(Change::ModuleRemoved { module }),
            Side::New(_) => out.push(Change::ModuleAdded { module }),
            Side::Both(old, new) => both(out, &module, old, new),
        }
    }
}

fn dids(out: &mut Vec<Change>, module: &ModuleId, old: &[Did], new: &[Did]) {
    for (did, side) in sides(old, new, |(did, _)| *did) {
        let (old, new) = match side {
            Side::Old(old) => (Some(&old.1), None),
            Side::New(new) => (None, Some(&new.1)),
            Side::Both(old, new) => (Some(&old.1), Some(&new.1)),
        };
        if old != new {
            out.push(Change::DidChanged {
                module: module.clone(),
                did,
                old: old.cloned(),
                new: new.cloned(),
            });
        }
    }
}

fn identification(
    out: &mut Vec<Change>,
    module: &ModuleId,
    old: &Identification,
    new: &Identification,
) {
    dids(out, module, &old.dids, &new.dids);
}

fn calibration(out: &mut Vec<Change>, source: u32, old: &Calibration, new: &Calibration) {
    let scope = Scope::Ecu { source };
    lists(
        out,
        &scope,
        List::Calids,
        &old.calids,
        &new.calids,
        |out, old, new| {
            for slot in 0..old.len().max(new.len()) {
                let number = slot + 1;
                match (old.get(slot), new.get(slot)) {
                    (Some(old), Some(new)) if old != new => out.push(Change::CalidChanged {
                        source,
                        slot: number,
                        old: old.clone(),
                        new: new.clone(),
                    }),
                    (Some(calid), None) => out.push(Change::CalidRemoved {
                        source,
                        slot: number,
                        calid: calid.clone(),
                    }),
                    (None, Some(calid)) => out.push(Change::CalidAdded {
                        source,
                        slot: number,
                        calid: calid.clone(),
                    }),
                    _ => {}
                }
            }
        },
    );
    lists(
        out,
        &scope,
        List::Cvns,
        &old.cvns,
        &new.cvns,
        |out, old, new| {
            for slot in 0..old.len().max(new.len()) {
                let number = slot + 1;
                match (old.get(slot), new.get(slot)) {
                    (Some(&old), Some(&new)) if old != new => out.push(Change::CvnChanged {
                        source,
                        slot: number,
                        old,
                        new,
                    }),
                    (Some(&cvn), None) => out.push(Change::CvnRemoved {
                        source,
                        slot: number,
                        cvn,
                    }),
                    (None, Some(&cvn)) => out.push(Change::CvnAdded {
                        source,
                        slot: number,
                        cvn,
                    }),
                    _ => {}
                }
            }
        },
    );
}

fn module_id(name: &str, response_id: u32) -> ModuleId {
    ModuleId {
        name: name.to_owned(),
        response_id,
    }
}

fn fingerprint_unique(fingerprint: &Fingerprint) -> Result<(), String> {
    unique_ecus(&fingerprint.ecus, |ecu| ecu.source)?;
    let id = |module: &Identification| module_id(&module.name, module.response_id);
    unique_modules(&fingerprint.modules, id)?;
    fingerprint
        .modules
        .iter()
        .try_for_each(|module| unique_dids(&module.dids, &id(module)))
}

/// What changed between two fingerprints: each ECU's calibration IDs and CVNs (a tune changes
/// the CVNs), and each module's identification DIDs.
///
/// # Errors
///
/// A [`DuplicateError`] if either lists an ECU, module or DID twice.
pub fn diff_fingerprint(
    old: &Fingerprint,
    new: &Fingerprint,
) -> Result<Vec<Change>, DuplicateError> {
    both_unique(old, new, fingerprint_unique)?;
    let mut out = Vec::new();
    ecus(
        &mut out,
        &old.ecus,
        &new.ecus,
        |ecu| ecu.source,
        calibration,
    );
    modules(
        &mut out,
        &old.modules,
        &new.modules,
        |module| module_id(&module.name, module.response_id),
        identification,
    );
    Ok(out)
}

fn pids(readings: &[PidReading]) -> BTreeSet<u8> {
    readings.iter().map(|(pid, _)| *pid).collect()
}

fn obd_ecu(out: &mut Vec<Change>, source: u32, old: &ObdEcu, new: &ObdEcu) {
    let scope = Scope::Ecu { source };
    lists(
        out,
        &scope,
        List::ObdPids,
        &old.pids,
        &new.pids,
        |out, old, new| {
            for (pid, added) in membership(&pids(old), &pids(new)) {
                out.push(if added {
                    Change::ObdPidAdded { source, pid }
                } else {
                    Change::ObdPidRemoved { source, pid }
                });
            }
        },
    );
    let cut = |ecu: &ObdEcu| ecu.pids_cut_short.as_ref().map(|(pid, _)| *pid);
    if cut(old) != cut(new) {
        out.push(Change::PidsCutShortChanged {
            source,
            old: cut(old),
            new: cut(new),
        });
    }
    lists(
        out,
        &scope,
        List::ObdInfo,
        &old.supported_info,
        &new.supported_info,
        |out, old, new| {
            let set = |pids: &[u8]| pids.iter().copied().collect::<BTreeSet<_>>();
            for (pid, added) in membership(&set(old), &set(new)) {
                out.push(if added {
                    Change::ObdInfoAdded { source, pid }
                } else {
                    Change::ObdInfoRemoved { source, pid }
                });
            }
        },
    );
    if old.ecu_name != new.ecu_name {
        out.push(Change::EcuNameChanged {
            source,
            old: old.ecu_name.clone(),
            new: new.ecu_name.clone(),
        });
    }
    lists(
        out,
        &scope,
        List::ObdDtcs,
        &old.stored_dtcs,
        &new.stored_dtcs,
        |out, old, new| {
            let set = |dtcs: &[Dtc]| dtcs.iter().copied().collect::<BTreeSet<_>>();
            for (dtc, new) in membership(&set(old), &set(new)) {
                out.push(if new {
                    Change::ObdDtcNew { source, dtc }
                } else {
                    Change::ObdDtcCleared { source, dtc }
                });
            }
        },
    );
    readiness(out, source, old, new);
}

// What changed in an ECU's pending and permanent DTCs, MIL and readiness monitors.
fn readiness(out: &mut Vec<Change>, source: u32, old: &ObdEcu, new: &ObdEcu) {
    let scope = Scope::Ecu { source };
    dtc_lists(
        out,
        &scope,
        List::ObdPendingDtcs,
        (&old.pending_dtcs, &new.pending_dtcs),
        |dtc, added| {
            if added {
                Change::ObdPendingDtcNew { source, dtc }
            } else {
                Change::ObdPendingDtcCleared { source, dtc }
            }
        },
    );
    dtc_lists(
        out,
        &scope,
        List::ObdPermanentDtcs,
        (&old.permanent_dtcs, &new.permanent_dtcs),
        |dtc, added| {
            if added {
                Change::ObdPermanentDtcNew { source, dtc }
            } else {
                Change::ObdPermanentDtcCleared { source, dtc }
            }
        },
    );
    // A read one side never made (a document from before it) has nothing to compare.
    if let (Some(old), Some(new)) = (&old.monitor_status, &new.monitor_status) {
        lists(
            out,
            &scope,
            List::MonitorStatus,
            old,
            new,
            |out, old, new| monitor_status(out, source, old, new),
        );
    }
}

type DtcRead = Option<Result<Vec<Dtc>, ReadError>>;

// Pending or permanent DTCs, new or cleared. `change` builds each from the DTC and whether it was
// added. A list one side never read (a document from before it) isn't compared.
fn dtc_lists(
    out: &mut Vec<Change>,
    scope: &Scope,
    list: List,
    (old, new): (&DtcRead, &DtcRead),
    change: impl Fn(Dtc, bool) -> Change,
) {
    let (Some(old), Some(new)) = (old, new) else {
        return;
    };
    lists(out, scope, list, old, new, |out, old, new| {
        let set = |dtcs: &[Dtc]| dtcs.iter().copied().collect::<BTreeSet<_>>();
        for (dtc, added) in membership(&set(old), &set(new)) {
            out.push(change(dtc, added));
        }
    });
}

// The MIL, then each monitor both statuses have and support, in the order `monitors()` gives.
fn monitor_status(out: &mut Vec<Change>, source: u32, old: &MonitorStatus, new: &MonitorStatus) {
    if old.mil_on != new.mil_on {
        out.push(Change::MilChanged {
            source,
            old: old.mil_on,
            new: new.mil_on,
        });
    }
    for (monitor, old) in old.monitors() {
        let Some(new) = new.monitor(monitor) else {
            continue;
        };
        if old.supported && new.supported && old.complete != new.complete {
            out.push(Change::MonitorChanged {
                source,
                monitor,
                old: old.complete,
                new: new.complete,
            });
        }
    }
}

fn module_scan(out: &mut Vec<Change>, module: &ModuleId, old: &ModuleScan, new: &ModuleScan) {
    if old.answered != new.answered {
        out.push(Change::AnsweredChanged {
            module: module.clone(),
            old: old.answered,
            new: new.answered,
        });
    }
    dids(out, module, &old.dids, &new.dids);
    lists(
        out,
        &Scope::Module(module.clone()),
        List::UdsDtcs,
        &old.dtcs,
        &new.dtcs,
        |out, old, new| {
            for (dtc, side) in sides(old, new, |record| record.dtc) {
                let module = module.clone();
                match side {
                    Side::Old(old) => out.push(Change::UdsDtcCleared {
                        module,
                        dtc,
                        status: old.status,
                    }),
                    Side::New(new) => out.push(Change::UdsDtcNew {
                        module,
                        dtc,
                        status: new.status,
                    }),
                    Side::Both(old, new) if old.status != new.status => {
                        out.push(Change::UdsDtcStatusChanged {
                            module,
                            dtc,
                            old: old.status,
                            new: new.status,
                        });
                    }
                    Side::Both(..) => {}
                }
            }
        },
    );
}

// Each of an ECU's lists keyed by PID or DTC, whether or not the other document has it.
fn obd_ecu_unique(ecu: &ObdEcu) -> Result<(), String> {
    let whose = CanId(ecu.source);
    if let Ok(readings) = &ecu.pids {
        unique(
            readings,
            |(pid, _)| *pid,
            |pid| format!("PID {pid:02X} of ECU {whose}"),
        )?;
    }
    if let Ok(pids) = &ecu.supported_info {
        unique(
            pids,
            |pid| *pid,
            |pid| format!("mode 09 PID {pid:02X} of ECU {whose}"),
        )?;
    }
    let dtcs = [
        ("stored", Some(&ecu.stored_dtcs)),
        ("pending", ecu.pending_dtcs.as_ref()),
        ("permanent", ecu.permanent_dtcs.as_ref()),
    ];
    for (kind, read) in dtcs {
        if let Some(Ok(dtcs)) = read {
            unique(
                dtcs,
                |dtc| *dtc,
                |dtc| format!("{kind} DTC {dtc} of ECU {whose}"),
            )?;
        }
    }
    Ok(())
}

fn scan_unique(scan: &Scan) -> Result<(), String> {
    unique_ecus(&scan.ecus, |ecu| ecu.source)?;
    scan.ecus.iter().try_for_each(obd_ecu_unique)?;
    let id = |module: &ModuleScan| module_id(&module.name, module.response_id);
    unique_modules(&scan.modules, id)?;
    scan.modules.iter().try_for_each(|module| {
        unique_dids(&module.dids, &id(module))?;
        match &module.dtcs {
            Ok(dtcs) => unique(
                dtcs,
                |record| record.dtc,
                |dtc| format!("DTC {dtc} of {}", id(module)),
            ),
            Err(_) => Ok(()),
        }
    })
}

/// What changed between two scans: each ECU's supported PIDs (not their values, which change on
/// every run), mode 09 PIDs, name, stored, pending and permanent DTCs, MIL and readiness monitors,
/// and each module's DIDs and DTCs. A read that one scan never made (a document from before the
/// read existed) isn't compared. The freeze frame and the mode 06 monitor IDs aren't compared
/// either: they change between runs.
///
/// # Errors
///
/// A [`DuplicateError`] if either lists an ECU, module, DID or module DTC twice, or an ECU's PID, mode 09 PID
/// or stored, pending or permanent DTC.
pub fn diff_scan(old: &Scan, new: &Scan) -> Result<Vec<Change>, DuplicateError> {
    both_unique(old, new, scan_unique)?;
    let mut out = Vec::new();
    ecus(&mut out, &old.ecus, &new.ecus, |ecu| ecu.source, obd_ecu);
    modules(
        &mut out,
        &old.modules,
        &new.modules,
        |module| module_id(&module.name, module.response_id),
        module_scan,
    );
    Ok(out)
}

fn sweep_dids(sweep: &Sweep, range: &RangeInclusive<u16>) -> Vec<Did> {
    sweep
        .found
        .iter()
        .filter(|(did, _)| range.contains(did))
        .map(|(did, read)| (*did, read.clone().map(DidValue::Bytes)))
        .collect()
}

/// What changed between two sweeps of `module`, comparing only the DIDs in `range`: the range both
/// sweeps read all of (a sweep that stopped early didn't read what is past its stop). A DID found in
/// only one of them is reported, so this is not for sweeps of different ranges.
///
/// # Errors
///
/// A [`DuplicateError`] if either lists a DID in `range` twice.
pub fn diff_sweep(
    module: &UdsModule,
    old: &Sweep,
    new: &Sweep,
    range: RangeInclusive<u16>,
) -> Result<Vec<Change>, DuplicateError> {
    let id = ModuleId::from(module);
    let (old, new) = (sweep_dids(old, &range), sweep_dids(new, &range));
    both_unique(&old, &new, |dids| unique_dids(dids, &id))?;
    let mut out = Vec::new();
    dids(&mut out, &id, &old, &new);
    Ok(out)
}

fn split_dids(data: &DidsData) -> Vec<Did> {
    data.split
        .iter()
        .map(|(did, bytes)| (*did, Ok(DidValue::Bytes(bytes.clone()))))
        .collect()
}

/// What changed between two multi-DID reads ([`crate::read_dids::read_dids`]) of `module`: each
/// split DID's bytes, and the bytes that couldn't be split. Both should have asked for the same DIDs.
///
/// # Errors
///
/// A [`DuplicateError`] if either lists a DID twice.
pub fn diff_dids_data(
    module: &UdsModule,
    old: &Result<DidsData, ReadError>,
    new: &Result<DidsData, ReadError>,
) -> Result<Vec<Change>, DuplicateError> {
    let id = ModuleId::from(module);
    both_unique(old, new, |read| match read {
        Ok(data) => unique_dids(&split_dids(data), &id),
        Err(_) => Ok(()),
    })?;
    let mut out = Vec::new();
    lists(
        &mut out,
        &Scope::Module(id.clone()),
        List::Dids,
        old,
        new,
        |out, old, new| {
            dids(out, &id, &split_dids(old), &split_dids(new));
            if old.unsplit != new.unsplit {
                out.push(Change::UnsplitChanged {
                    module: id.clone(),
                    old: old.unsplit.clone(),
                    new: new.unsplit.clone(),
                });
            }
        },
    );
    Ok(out)
}

/// What changed between two lists of VINs by the CAN ID of the ECU that gave each (`vin`'s
/// result): an ECU that appeared or disappeared, and a VIN that differs. A VIN that didn't change
/// isn't in the result, and an ECU that appeared or disappeared doesn't show its VIN.
///
/// # Errors
///
/// A [`DuplicateError`] if either lists an ECU twice.
pub fn diff_vins(
    old: &[(u32, String)],
    new: &[(u32, String)],
) -> Result<Vec<Change>, DuplicateError> {
    both_unique(old, new, |vins| unique_ecus(vins, |(source, _)| *source))?;
    let mut out = Vec::new();
    for (source, side) in sides(old, new, |(source, _)| *source) {
        match side {
            Side::Old(_) => out.push(Change::EcuRemoved { source }),
            Side::New(_) => out.push(Change::EcuAdded { source }),
            Side::Both(old, new) if old.1 != new.1 => out.push(Change::VinChanged {
                source,
                old: old.1.clone(),
                new: new.1.clone(),
            }),
            Side::Both(..) => {}
        }
    }
    Ok(out)
}
