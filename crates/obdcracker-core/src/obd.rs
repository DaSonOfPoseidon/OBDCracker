//! OBD-II (SAE J1979) requests and reply decoding, in the CAN format of ISO 15765-4.
//!
//! The request builders return payload bytes, which still have to pass the safety policy
//! before they can be sent. Each decoder takes one module's reassembled reply.

use core::fmt;
use core::slice;

use crate::response::{Error, positive, printable};

/// Mode 01: current powertrain data.
pub const CURRENT_DATA: u8 = 0x01;

/// Mode 02: freeze frame data.
pub const FREEZE_FRAME: u8 = 0x02;

/// Mode 06: on-board monitor test results.
pub const MONITOR_RESULTS: u8 = 0x06;

/// Mode 03: stored (confirmed) emissions DTCs.
pub const STORED_DTCS: u8 = 0x03;

/// Mode 07: pending DTCs, found during the current or last driving cycle.
pub const PENDING_DTCS: u8 = 0x07;

/// Mode 0A: permanent DTCs, which only the car's own monitors can clear.
pub const PERMANENT_DTCS: u8 = 0x0A;

/// Mode 09: vehicle information.
pub const VEHICLE_INFO: u8 = 0x09;

/// A mode 01 request for one PID.
#[must_use]
pub fn current_data(pid: u8) -> [u8; 2] {
    [CURRENT_DATA, pid]
}

/// The unit a decoded value is in.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Percent, 0 to 100.
    Percent,
    /// Degrees Celsius.
    Celsius,
    /// Revolutions per minute.
    Rpm,
    /// Kilometres per hour.
    KilometresPerHour,
    /// Volts.
    Volts,
    /// Grams per second (air flow).
    GramsPerSecond,
    /// Seconds.
    Seconds,
    /// Kilometres.
    Kilometres,
    /// A count with no unit, such as warm-ups since the codes were cleared.
    Count,
    /// Kilopascals, absolute.
    Kilopascals,
    /// Degrees of crankshaft rotation, relative to top dead centre.
    Degrees,
    /// Litres per hour.
    LitresPerHour,
    /// Newton metres.
    NewtonMetres,
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Percent => "%",
            Self::Celsius => "°C",
            Self::Rpm => "rpm",
            Self::KilometresPerHour => "km/h",
            Self::Volts => "V",
            Self::GramsPerSecond => "g/s",
            Self::Seconds => "s",
            Self::Kilometres => "km",
            Self::Count => "",
            Self::Kilopascals => "kPa",
            Self::Degrees => "°",
            Self::LitresPerHour => "L/h",
            Self::NewtonMetres => "Nm",
        })
    }
}

/// Which of the 32 PIDs after a bitmap PID (0x00, 0x20, 0x40, …) a module supports. The last
/// bit says whether the next bitmap PID is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportedPids {
    base: u8,
    bits: u32,
}

impl SupportedPids {
    /// Builds a bitmap from the bitmap PID it answers and its four data bytes.
    #[must_use]
    pub fn new(base: u8, data: [u8; 4]) -> Self {
        Self {
            base,
            bits: u32::from_be_bytes(data),
        }
    }

    /// Whether `pid` is in this bitmap's range and marked supported.
    #[must_use]
    pub fn contains(&self, pid: u8) -> bool {
        match pid.checked_sub(self.base) {
            Some(offset @ 1..=32) => self.bits & (1 << (32 - u32::from(offset))) != 0,
            _ => false,
        }
    }

    /// The supported PIDs, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (1..=32u8)
            .filter_map(|offset| self.base.checked_add(offset))
            .filter(|&pid| self.contains(pid))
    }
}

/// A decoded PID value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    /// A physical quantity.
    Quantity {
        /// The value, scaled per SAE J1979.
        value: f32,
        /// Its unit.
        unit: Unit,
    },
    /// A supported-PID bitmap (PIDs 0x00, 0x20, 0x40, …).
    Supported(SupportedPids),
    /// A PID this crate doesn't decode yet, with every byte left in the reply. Its length isn't
    /// known, so if the request asked for several PIDs, these bytes also hold the later ones.
    Raw(&'a [u8]),
}

/// One PID and its value from a reply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading<'a> {
    /// The PID.
    pub pid: u8,
    /// Its decoded value.
    pub value: Value<'a>,
}

// The PIDs with a known data length and formula, per SAE J1979.
fn decode_pid(pid: u8, data: &[u8]) -> Option<(usize, Value<'static>)> {
    let byte = |i: usize| data.get(i).copied().map(f32::from);
    let word = || Some(byte(0)? * 256.0 + byte(1)?);
    let quantity = |value, unit| Value::Quantity { value, unit };
    let decoded = match pid {
        0x00 | 0x20 | 0x40 | 0x60 | 0x80 | 0xA0 | 0xC0 | 0xE0 => {
            let bytes = data.get(..4)?.try_into().ok()?;
            (4, Value::Supported(SupportedPids::new(pid, bytes)))
        }
        0x04 | 0x11 | 0x45 | 0x49 | 0x4A | 0x4C => {
            (1, quantity(byte(0)? * 100.0 / 255.0, Unit::Percent))
        }
        0x05 | 0x0F | 0x46 | 0x5C => (1, quantity(byte(0)? - 40.0, Unit::Celsius)),
        0x0C => (2, quantity(word()? / 4.0, Unit::Rpm)),
        0x0D => (1, quantity(byte(0)?, Unit::KilometresPerHour)),
        0x10 => (2, quantity(word()? / 100.0, Unit::GramsPerSecond)),
        0x1F => (2, quantity(word()?, Unit::Seconds)),
        0x21 | 0x31 => (2, quantity(word()?, Unit::Kilometres)),
        0x30 => (1, quantity(byte(0)?, Unit::Count)),
        0x33 => (1, quantity(byte(0)?, Unit::Kilopascals)),
        0x3C | 0x3E => (2, quantity(word()? / 10.0 - 40.0, Unit::Celsius)),
        0x42 => (2, quantity(word()? / 1000.0, Unit::Volts)),
        0x5D => (2, quantity(word()? / 128.0 - 210.0, Unit::Degrees)),
        0x5E => (2, quantity(word()? / 20.0, Unit::LitresPerHour)),
        0x61 | 0x62 => (1, quantity(byte(0)? - 125.0, Unit::Percent)),
        0x63 => (2, quantity(word()?, Unit::NewtonMetres)),
        _ => return None,
    };
    Some(decoded)
}

fn is_known(pid: u8) -> bool {
    decode_pid(pid, &[0; 4]).is_some()
}

/// Decodes a mode 01 reply into its readings, one per PID.
///
/// A PID this crate doesn't know comes back as [`Value::Raw`] holding the rest of the reply,
/// since its length is unknown, and ends the readings.
pub fn decode_current_data(reply: &[u8]) -> Result<Readings<'_>, Error> {
    let rest = positive(CURRENT_DATA, reply)?;
    if rest.is_empty() {
        return Err(Error::TooShort);
    }
    Ok(Readings { rest })
}

/// The readings in a mode 01 reply. A truncated reading yields [`Error::TooShort`] and ends it.
#[derive(Debug, Clone)]
pub struct Readings<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Readings<'a> {
    type Item = Result<Reading<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&pid, data) = self.rest.split_first()?;
        if !is_known(pid) {
            self.rest = &[];
            // Every PID has at least one data byte
            if data.is_empty() {
                return Some(Err(Error::TooShort));
            }
            return Some(Ok(Reading {
                pid,
                value: Value::Raw(data),
            }));
        }
        let Some((len, value)) = decode_pid(pid, data) else {
            self.rest = &[];
            return Some(Err(Error::TooShort));
        };
        self.rest = &data[len..];
        Some(Ok(Reading { pid, value }))
    }
}

/// A mode 06 request for one monitor ID.
#[must_use]
pub fn monitor_results(mid: u8) -> [u8; 2] {
    [MONITOR_RESULTS, mid]
}

/// Decodes a mode 06 reply to a request for the supported-monitor-ID bitmap `mid` (0x00, 0x20,
/// 0x40, …, 0xE0): `46 <mid>` and four bytes. Any other monitor ID is malformed here, because
/// the test records after it aren't decoded; see
/// [`docs/protocols.md#on-board-monitor-test-results-mode-06`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#on-board-monitor-test-results-mode-06).
pub fn decode_supported_monitor_ids(reply: &[u8], mid: u8) -> Result<SupportedPids, Error> {
    let [got, data @ ..] = positive(MONITOR_RESULTS, reply)? else {
        return Err(Error::TooShort);
    };
    if *got != mid || !mid.is_multiple_of(0x20) {
        return Err(Error::Malformed);
    }
    let bitmap = data.try_into().map_err(|_| Error::Malformed)?;
    Ok(SupportedPids::new(mid, bitmap))
}

/// A mode 02 request for one PID of one freeze frame (0 is the first).
#[must_use]
pub fn freeze_frame(pid: u8, frame: u8) -> [u8; 3] {
    [FREEZE_FRAME, pid, frame]
}

/// A value from a freeze frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FreezeFrameValue<'a> {
    /// PID 0x02: the code that stored the frame, or `None` for P0000, which says there is none.
    Cause(Option<Dtc>),
    /// Any other PID, decoded as in mode 01.
    Pid(Value<'a>),
}

/// Decodes a mode 02 reply to a request for `pid` in freeze frame `frame` (`42 <pid> <frame>`
/// and the value). The reply must echo both, and a PID with a known length must have exactly
/// that many bytes. One that isn't known comes back as [`Value::Raw`].
pub fn decode_freeze_frame(
    reply: &[u8],
    pid: u8,
    frame: u8,
) -> Result<FreezeFrameValue<'_>, Error> {
    let [got_pid, got_frame, data @ ..] = positive(FREEZE_FRAME, reply)? else {
        return Err(Error::TooShort);
    };
    if *got_pid != pid || *got_frame != frame {
        return Err(Error::Malformed);
    }
    if pid == CAUSE_PID {
        return match *data {
            [hi, lo] => Ok(FreezeFrameValue::Cause(
                Some(u16::from_be_bytes([hi, lo]))
                    .filter(|&code| code != 0)
                    .map(Dtc),
            )),
            [_] | [] => Err(Error::TooShort),
            _ => Err(Error::Malformed),
        };
    }
    if !is_known(pid) {
        return if data.is_empty() {
            Err(Error::TooShort)
        } else {
            Ok(FreezeFrameValue::Pid(Value::Raw(data)))
        };
    }
    match decode_pid(pid, data) {
        Some((len, value)) if len == data.len() => Ok(FreezeFrameValue::Pid(value)),
        Some(_) => Err(Error::Malformed),
        None => Err(Error::TooShort),
    }
}

const CAUSE_PID: u8 = 0x02;
const MONITOR_STATUS_PID: u8 = 0x01;

/// Whether the engine is spark or compression ignition, which decides what the last two bytes of
/// the monitor status mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnitionType {
    /// Petrol and other spark-ignition engines.
    Spark,
    /// Diesel and other compression-ignition engines.
    Compression,
}

/// An on-board diagnostic monitor of the emissions system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorKind {
    /// Misfire (both engine types).
    Misfire,
    /// Fuel system (both engine types).
    FuelSystem,
    /// Comprehensive components (both engine types).
    Components,
    /// Catalyst (spark).
    Catalyst,
    /// Heated catalyst (spark).
    HeatedCatalyst,
    /// Evaporative system (spark).
    EvaporativeSystem,
    /// Secondary air system (spark).
    SecondaryAir,
    /// A/C refrigerant (spark; reserved in newer editions of J1979).
    AcRefrigerant,
    /// Oxygen sensor (spark).
    OxygenSensor,
    /// Oxygen sensor heater (spark).
    OxygenSensorHeater,
    /// EGR and/or VVT system (both engine types).
    EgrVvt,
    /// Non-methane hydrocarbon catalyst (compression).
    NmhcCatalyst,
    /// `NOx` and/or SCR aftertreatment (compression).
    NoxScr,
    /// Boost pressure (compression).
    BoostPressure,
    /// Exhaust gas sensor (compression).
    ExhaustGasSensor,
    /// Particulate matter filter (compression).
    ParticulateFilter,
}

// The engine-specific monitors, by bit of bytes C and D. A bit with no entry is reserved.
const SPARK_MONITORS: [(u8, MonitorKind); 8] = [
    (0, MonitorKind::Catalyst),
    (1, MonitorKind::HeatedCatalyst),
    (2, MonitorKind::EvaporativeSystem),
    (3, MonitorKind::SecondaryAir),
    (4, MonitorKind::AcRefrigerant),
    (5, MonitorKind::OxygenSensor),
    (6, MonitorKind::OxygenSensorHeater),
    (7, MonitorKind::EgrVvt),
];
const COMPRESSION_MONITORS: [(u8, MonitorKind); 6] = [
    (0, MonitorKind::NmhcCatalyst),
    (1, MonitorKind::NoxScr),
    (3, MonitorKind::BoostPressure),
    (5, MonitorKind::ExhaustGasSensor),
    (6, MonitorKind::ParticulateFilter),
    (7, MonitorKind::EgrVvt),
];

/// One monitor's state. `complete` means something only when `supported` is set: a module may
/// send either value for a monitor it doesn't have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitor {
    /// Whether the car has this monitor.
    pub supported: bool,
    /// Whether it has finished since the codes were last cleared.
    pub complete: bool,
}

/// The MIL and readiness monitors from mode 01 PID 01.
///
/// See [`docs/protocols.md#monitor-status-mode-01-pid-01`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#monitor-status-mode-01-pid-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorStatus {
    /// Whether the malfunction indicator lamp is on.
    pub mil_on: bool,
    /// How many emissions DTCs are confirmed, 0 to 127.
    pub dtc_count: u8,
    /// Whether the engine is spark or compression ignition.
    pub ignition: IgnitionType,
    /// The misfire monitor.
    pub misfire: Monitor,
    /// The fuel system monitor.
    pub fuel_system: Monitor,
    /// The comprehensive component monitor.
    pub components: Monitor,
    engine_supported: u8,
    engine_incomplete: u8,
}

impl MonitorStatus {
    fn engine_monitor(&self, bit: u8) -> Monitor {
        Monitor {
            supported: self.engine_supported & (1 << bit) != 0,
            complete: self.engine_incomplete & (1 << bit) == 0,
        }
    }

    fn engine_table(&self) -> &'static [(u8, MonitorKind)] {
        match self.ignition {
            IgnitionType::Spark => &SPARK_MONITORS,
            IgnitionType::Compression => &COMPRESSION_MONITORS,
        }
    }

    /// The state of `kind`, or `None` if this engine type has no such monitor.
    #[must_use]
    pub fn monitor(&self, kind: MonitorKind) -> Option<Monitor> {
        match kind {
            MonitorKind::Misfire => Some(self.misfire),
            MonitorKind::FuelSystem => Some(self.fuel_system),
            MonitorKind::Components => Some(self.components),
            _ => self
                .engine_table()
                .iter()
                .find(|(_, k)| *k == kind)
                .map(|&(bit, _)| self.engine_monitor(bit)),
        }
    }

    /// Every monitor this engine type has, supported or not: the three common ones, then the
    /// engine-specific ones in bit order.
    pub fn monitors(&self) -> impl Iterator<Item = (MonitorKind, Monitor)> + '_ {
        [
            (MonitorKind::Misfire, self.misfire),
            (MonitorKind::FuelSystem, self.fuel_system),
            (MonitorKind::Components, self.components),
        ]
        .into_iter()
        .chain(
            self.engine_table()
                .iter()
                .map(|&(bit, kind)| (kind, self.engine_monitor(bit))),
        )
    }
}

/// Decodes a mode 01 reply for PID 01 alone (`41 01 A B C D`). The reply must be exactly that:
/// other PIDs, or more bytes, are malformed. [`decode_current_data`] leaves PID 01 as
/// [`Value::Raw`].
pub fn decode_monitor_status(reply: &[u8]) -> Result<MonitorStatus, Error> {
    let [pid, data @ ..] = positive(CURRENT_DATA, reply)? else {
        return Err(Error::TooShort);
    };
    let &[a, b, c, d] = data else {
        return Err(Error::Malformed);
    };
    if *pid != MONITOR_STATUS_PID {
        return Err(Error::Malformed);
    }
    let common = |supported_bit: u8| Monitor {
        supported: b & (1 << supported_bit) != 0,
        complete: b & (1 << (supported_bit + 4)) == 0,
    };
    Ok(MonitorStatus {
        mil_on: a & 0x80 != 0,
        dtc_count: a & 0x7F,
        ignition: if b & 0x08 == 0 {
            IgnitionType::Spark
        } else {
            IgnitionType::Compression
        },
        misfire: common(0),
        fuel_system: common(1),
        components: common(2),
        engine_supported: c,
        engine_incomplete: d,
    })
}

/// A mode 03 request for every stored emissions DTC.
#[must_use]
pub fn stored_dtcs() -> [u8; 1] {
    [STORED_DTCS]
}

/// A two-byte diagnostic trouble code, shown in the SAE J2012 form such as `P0401`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dtc(u16);

impl Dtc {
    /// Wraps the code's two bytes, as sent on the bus.
    #[must_use]
    pub fn new(code: u16) -> Self {
        Self(code)
    }

    /// The code's two bytes.
    #[must_use]
    pub fn code(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Dtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The top two bits pick the system: powertrain, chassis, body or network.
        let system = ['P', 'C', 'B', 'U'][usize::from(self.0 >> 14)];
        write!(f, "{system}{:04X}", self.0 & 0x3FFF)
    }
}

/// Decodes a mode 03 reply in the CAN format (ISO 15765-4): a count byte, then that many
/// two-byte codes. The count must match the bytes, and the codes skip P0000, the padding a module
/// fills unused slots with. Pre-CAN layouts aren't decoded; see [`docs/protocols.md#obd-ii-decoding`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#obd-ii-decoding).
pub fn decode_stored_dtcs(reply: &[u8]) -> Result<Dtcs<'_>, Error> {
    decode_dtc_list(STORED_DTCS, reply)
}

fn decode_dtc_list(request_sid: u8, reply: &[u8]) -> Result<Dtcs<'_>, Error> {
    let (&count, codes) = positive(request_sid, reply)?
        .split_first()
        .ok_or(Error::TooShort)?;
    if codes.len() != usize::from(count) * 2 {
        return Err(Error::Malformed);
    }
    Ok(Dtcs(codes.as_chunks::<2>().0.iter()))
}

/// The codes in a mode 03, 07 or 0A reply, without P0000 padding.
#[derive(Debug, Clone)]
pub struct Dtcs<'a>(slice::Iter<'a, [u8; 2]>);

impl Iterator for Dtcs<'_> {
    type Item = Dtc;

    fn next(&mut self) -> Option<Dtc> {
        self.0
            .by_ref()
            .map(|&pair| u16::from_be_bytes(pair))
            .find(|&code| code != 0)
            .map(Dtc)
    }
}

/// A mode 07 request for every pending emissions DTC.
#[must_use]
pub fn pending_dtcs() -> [u8; 1] {
    [PENDING_DTCS]
}

/// A mode 0A request for every permanent emissions DTC.
#[must_use]
pub fn permanent_dtcs() -> [u8; 1] {
    [PERMANENT_DTCS]
}

/// Decodes a mode 07 reply: the same layout and checks as [`decode_stored_dtcs`], under `0x47`.
pub fn decode_pending_dtcs(reply: &[u8]) -> Result<Dtcs<'_>, Error> {
    decode_dtc_list(PENDING_DTCS, reply)
}

/// Decodes a mode 0A reply: the same layout and checks as [`decode_stored_dtcs`], under `0x4A`.
pub fn decode_permanent_dtcs(reply: &[u8]) -> Result<Dtcs<'_>, Error> {
    decode_dtc_list(PERMANENT_DTCS, reply)
}

/// A mode 09 request for one PID.
#[must_use]
pub fn vehicle_info(pid: u8) -> [u8; 2] {
    [VEHICLE_INFO, pid]
}

const CALID_LEN: usize = 16;
const CVN_LEN: usize = 4;
const VIN_LEN: usize = 17;
const ECU_NAME_LEN: usize = 20;

fn info(reply: &[u8], pid: u8) -> Result<(usize, &[u8]), Error> {
    let rest = positive(VEHICLE_INFO, reply)?;
    let [got, count, data @ ..] = rest else {
        return Err(Error::TooShort);
    };
    if *got != pid {
        return Err(Error::Malformed);
    }
    Ok((usize::from(*count), data))
}

// Printable ASCII after trimming the trailing 0x00 padding. J1979 requires these fields, so
// one that's nothing but padding is malformed.
fn text(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::Malformed)?
        + 1;
    printable(&bytes[..end])
}

/// Decodes the mode 09 PID 00 reply: which vehicle information PIDs 01 to 20 are supported.
pub fn decode_supported_info(reply: &[u8]) -> Result<SupportedPids, Error> {
    let rest = positive(VEHICLE_INFO, reply)?;
    let [0x00, a, b, c, d] = *rest else {
        return Err(Error::Malformed);
    };
    Ok(SupportedPids::new(0x00, [a, b, c, d]))
}

// SAE J1979: digits and upper case letters except I, O and Q, which look like 1 and 0.
fn is_vin_char(b: u8) -> bool {
    (b.is_ascii_digit() || b.is_ascii_uppercase()) && !matches!(b, b'I' | b'O' | b'Q')
}

/// Decodes the mode 09 PID 02 reply: the 17-character VIN.
pub fn decode_vin(reply: &[u8]) -> Result<&str, Error> {
    let (count, data) = info(reply, 0x02)?;
    if count != 1 {
        return Err(Error::Malformed);
    }
    check_vin(data)
}

/// Checks that `data` is a VIN, from any source (mode 09 PID 02's data, UDS DID F190): exactly
/// 17 digits and upper case letters other than I, O and Q (SAE J1979), with no padding.
pub fn check_vin(data: &[u8]) -> Result<&str, Error> {
    if data.len() != VIN_LEN || !data.iter().all(|&b| is_vin_char(b)) {
        return Err(Error::Malformed);
    }
    text(data)
}

/// Whether `data` says no VIN is stored: 17 of one filler byte (`-`, space, 0x00 or 0xFF). Modules
/// that don't know the VIN send it in UDS DID F190; the 2014 A7's rear lid sends dashes.
#[must_use]
pub fn is_vin_placeholder(data: &[u8]) -> bool {
    data.len() == VIN_LEN
        && data
            .first()
            .is_some_and(|&fill| matches!(fill, b'-' | b' ' | 0x00 | 0xFF))
        && data.iter().all(|&b| b == data[0])
}

/// Decodes the mode 09 PID 04 reply: each calibration ID (the software calibration's name),
/// with its padding removed. A module may report several, and some of them may be empty slots.
pub fn decode_calids(reply: &[u8]) -> Result<Calids<'_>, Error> {
    let (count, data) = info(reply, 0x04)?;
    if count == 0 || data.len() != count * CALID_LEN {
        return Err(Error::Malformed);
    }
    Ok(Calids(data.as_chunks::<CALID_LEN>().0.iter()))
}

/// The calibration IDs in a mode 09 PID 04 reply. A slot of nothing but 0x00 padding is empty
/// (`None`): the 2014 A7's engine sends one, with CVN 00000000. One that isn't printable text
/// yields [`Error::Malformed`].
#[derive(Debug, Clone)]
pub struct Calids<'a>(slice::Iter<'a, [u8; CALID_LEN]>);

impl<'a> Iterator for Calids<'a> {
    type Item = Result<Option<&'a str>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|calid| {
            if calid.iter().all(|&b| b == 0) {
                Ok(None)
            } else {
                text(calid).map(Some)
            }
        })
    }
}

/// A calibration verification number: a checksum of the calibration in the module, shown as
/// 8 hex digits. A changed calibration (such as a tune) has a different CVN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cvn(pub [u8; CVN_LEN]);

impl fmt::Display for Cvn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02X}"))
    }
}

/// Decodes the mode 09 PID 06 reply: one CVN per calibration ID.
pub fn decode_cvns(reply: &[u8]) -> Result<Cvns<'_>, Error> {
    let (count, data) = info(reply, 0x06)?;
    if count == 0 || data.len() != count * CVN_LEN {
        return Err(Error::Malformed);
    }
    Ok(Cvns(data.as_chunks::<CVN_LEN>().0.iter()))
}

/// The CVNs in a mode 09 PID 06 reply.
#[derive(Debug, Clone)]
pub struct Cvns<'a>(slice::Iter<'a, [u8; CVN_LEN]>);

impl Iterator for Cvns<'_> {
    type Item = Cvn;

    fn next(&mut self) -> Option<Cvn> {
        self.0.next().map(|&cvn| Cvn(cvn))
    }
}

/// A module's name from mode 09 PID 0A, such as `ECM` / `EngineControl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcuName<'a> {
    /// The short name, up to 4 characters.
    pub acronym: &'a str,
    /// The full name, up to 15 characters.
    pub name: &'a str,
}

/// Decodes the mode 09 PID 0A reply: 4 bytes of acronym, `-`, then 15 bytes of name, each
/// without blanks and padded with 0x00.
pub fn decode_ecu_name(reply: &[u8]) -> Result<EcuName<'_>, Error> {
    let (count, data) = info(reply, 0x0A)?;
    if count != 1 || data.len() != ECU_NAME_LEN || data[4] != b'-' {
        return Err(Error::Malformed);
    }
    Ok(EcuName {
        acronym: name_text(&data[..4])?,
        name: name_text(&data[5..])?,
    })
}

// An ECU name field: required text with no blanks between words (SAE J1979-DA).
fn name_text(bytes: &[u8]) -> Result<&str, Error> {
    let name = text(bytes)?;
    if name.contains(' ') {
        return Err(Error::Malformed);
    }
    Ok(name)
}
