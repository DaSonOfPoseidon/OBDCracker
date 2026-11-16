//! Live data: mode 01 PIDs and profile DIDs read again and again, one timestamped [`Sample`] per
//! [`Poller::poll`]. See
//! [`docs/library.md#live-data`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/library.md#live-data).
//!
//! The poller never sleeps: the caller decides when to poll, and [`next_due`] says when the next
//! one is due so a slow poll doesn't leave a backlog.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant};

use obdcracker_core::obd::{self, MAX_PIDS_PER_REQUEST, Value};
use obdcracker_core::response::Error as ReplyError;
use obdcracker_core::uds;
use obdcracker_safety::{Approved, Policy, Protocol, Rejection, Target};

use crate::fingerprint::{
    FingerprintError, LongRead, ReadError, UdsModule, approve_ecu_list, ask, decoded, ecus_to_ask,
};
use crate::read_dids::{DidsData, ReadDidsError, check_dids, split};
use crate::scan::{PidReading, PidValue};
use crate::{Error, Timing, Transport};

/// The longest [`next_due`] waits after a poll started, so an interval can't overflow an
/// [`Instant`].
pub const LONGEST_INTERVAL: Duration = Duration::from_secs(3600);

/// A module and the DIDs to read from it on each poll, with one `22` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidPoll {
    /// The module the DIDs are read from.
    pub module: UdsModule,
    /// Each DID, with its data's length where the module always sends the same number of bytes
    /// (from the vehicle profile). A reply doesn't say where one DID's data ends, so a DID with no
    /// length is split off only if it is the last one asked for; the bytes from an earlier one on
    /// come back as [`DidsData::unsplit`] (see [`crate::read_dids::read_dids`], whose rules a poll
    /// follows). At most [`crate::read_dids::MAX_DIDS`], none twice.
    ///
    /// With 4 or more DIDs the request is over 7 bytes, which an [`crate::elm::Elm`] sends only
    /// once an earlier request has shown that the adapter echoes each character. A poller that
    /// also has PIDs sends those first; one with only DIDs must send something else first, or its
    /// first poll fails with [`PollError::Transport`] and nothing written.
    pub dids: Vec<(u16, Option<usize>)>,
}

/// Why a [`Poller`] couldn't be built or a poll failed. Nothing was sent for the errors
/// [`Poller::new`] gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollError {
    /// No PID and no DID to poll.
    NothingToPoll,
    /// A supported-PID bitmap (0x00, 0x20, ... 0xE0) isn't a value to poll.
    BitmapPid(u8),
    /// A PID is named twice, which would be read twice in a poll.
    DuplicatePid(u8),
    /// Two [`DidPoll`]s share a module name or request ID, which the sample couldn't tell apart.
    DuplicateModule(String),
    /// A module's DID list is empty, too long or names a DID twice
    /// ([`ReadDidsError::NoDids`], [`ReadDidsError::TooMany`] or [`ReadDidsError::Duplicate`]).
    BadDids {
        /// The module's name.
        module: String,
        /// What is wrong with its list.
        error: ReadDidsError,
    },
    /// The policy refused a request, so nothing reached the bus.
    Rejected(Rejection),
    /// The adapter failed. What it was sent is in the audit log, and the poll's values are lost.
    Transport(Error),
}

impl fmt::Display for PollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingToPoll => f.write_str("no PID or DID to poll"),
            Self::BitmapPid(pid) => write!(f, "PID {pid:02X} is a supported-PID bitmap"),
            Self::DuplicatePid(pid) => write!(f, "PID {pid:02X} is named twice"),
            Self::DuplicateModule(name) => write!(f, "module {name} is named twice"),
            Self::BadDids { module, error } => write!(f, "module {module}: {error}"),
            Self::Rejected(rejection) => write!(f, "safety policy {rejection}"),
            Self::Transport(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PollError {}

impl From<FingerprintError> for PollError {
    fn from(e: FingerprintError) -> Self {
        match e {
            FingerprintError::Rejected(rejection) => Self::Rejected(rejection),
            FingerprintError::Transport(e) => Self::Transport(e),
            // Only an extended session yields this, and a poll asks for none.
            e @ FingerprintError::Session(_) => Self::Transport(Error::Adapter(e.to_string())),
        }
    }
}

/// One poll's values.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// When the poll's first request was about to be sent.
    pub started: Instant,
    /// When its last reply was in (or its wait ran out).
    pub finished: Instant,
    /// Each emissions ECU that answered a mode 01 request, by reply CAN ID, with one reading per
    /// PID polled, in the order [`Poller::new`] was given them. A PID the ECU didn't answer is
    /// [`ReadError::NoReply`]. A reply that isn't exactly the PIDs asked for (an extra or
    /// repeated PID, a cut-off or surplus byte) is [`ReadError::Undecodable`] for every PID of
    /// that request, with the reply. Another ECU's values aren't affected.
    pub pids: BTreeMap<u32, Vec<PidReading>>,
    /// What each module answered, in the order the [`DidPoll`]s were given.
    pub dids: Vec<DidSample>,
    /// Whether a request of this poller got no reply, in this poll or an earlier one, or the
    /// adapter failed mid-poll. A reply that was only late may then arrive during a later poll
    /// that sends the same request, and be read as that poll's value: nothing in the reply tells
    /// them apart, so no value in this sample can be trusted to be fresh. It stays set, as
    /// [`crate::Left::out_of_step`] does: reconnect and build a new [`Poller`] to clear it. A
    /// request none of whose PIDs or DIDs the module supports is never answered, so polling only
    /// those keeps it set; a PID left out of a reply that answered the rest doesn't set it. An
    /// ECU that stays silent to a broadcast is seen only once it has answered that request (or
    /// `01 00`, where the adapter asks each ECU alone) before.
    pub out_of_step: bool,
}

/// One module's answer to a poll's `22` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidSample {
    /// The module.
    pub module: UdsModule,
    /// Its answer, or why it gave none.
    pub result: Result<DidsData, ReadError>,
}

/// Reads a fixed list of mode 01 PIDs and profile DIDs on each [`Poller::poll`].
///
/// PIDs this crate decodes ([`obd::is_known_pid`]) go up to six to a broadcast request (SAE
/// J1979), in the order given. Any other PID gets a request of its own, since its length isn't
/// known and it would swallow the PIDs after it. Where the transport can't take eight ECUs' long
/// replies at once ([`Transport::broadcasts_can_overflow`]), each ECU that answers `01 00` is
/// asked alone, in turn, as [`crate::fingerprint::fingerprint`] does for its long reads. That list
/// is taken on the first poll that finds an ECU (a poll asks again until one answers), so an ECU
/// that comes online after that is missed until a new `Poller`.
///
/// Every request is approved when the poller is built. A refusal is an error from
/// [`Poller::new`], and nothing is sent.
#[derive(Debug)]
pub struct Poller {
    pids: Vec<u8>,
    // Each request's PIDs, as indexes into `pids`: the known PIDs in groups of up to six, then
    // each unknown one alone.
    batches: Vec<Batch>,
    ecu_list: Approved,
    ecus: Vec<u32>,
    modules: Vec<DidRequest>,
    out_of_step: bool,
}

// Each emissions ECU's readings, by reply CAN ID.
type PidReadings = BTreeMap<u32, Vec<PidReading>>;

#[derive(Debug)]
struct Batch {
    indexes: Vec<usize>,
    pids: Vec<u8>,
    request: LongRead,
    // The reply IDs of the ECUs that have answered this request, in any poll.
    answered_before: BTreeSet<u32>,
}

#[derive(Debug)]
struct DidRequest {
    poll: DidPoll,
    ids: Vec<u16>,
    lengths: BTreeMap<u16, usize>,
    request: Approved,
}

impl Poller {
    /// A poller for `pids` and `dids`.
    ///
    /// # Errors
    ///
    /// [`PollError::NothingToPoll`], [`PollError::BitmapPid`], [`PollError::DuplicatePid`],
    /// [`PollError::DuplicateModule`], [`PollError::BadDids`] or, when the policy refuses a
    /// request, [`PollError::Rejected`].
    pub fn new(policy: &Policy, pids: &[u8], dids: Vec<DidPoll>) -> Result<Self, PollError> {
        if pids.is_empty() && dids.is_empty() {
            return Err(PollError::NothingToPoll);
        }
        for (index, &pid) in pids.iter().enumerate() {
            if pid.is_multiple_of(0x20) {
                return Err(PollError::BitmapPid(pid));
            }
            if pids[..index].contains(&pid) {
                return Err(PollError::DuplicatePid(pid));
            }
        }
        let mut modules: Vec<DidRequest> = Vec::with_capacity(dids.len());
        for poll in dids {
            let taken = |other: &DidRequest| {
                other.poll.module.name == poll.module.name
                    || other.poll.module.request_id == poll.module.request_id
            };
            if modules.iter().any(taken) {
                return Err(PollError::DuplicateModule(poll.module.name));
            }
            modules.push(DidRequest::approve(policy, poll)?);
        }
        let known = (0..pids.len()).filter(|&index| obd::is_known_pid(pids[index]));
        let known: Vec<usize> = known.collect();
        let unknown = (0..pids.len()).filter(|&index| !obd::is_known_pid(pids[index]));
        let groups = known
            .chunks(MAX_PIDS_PER_REQUEST)
            .map(<[usize]>::to_vec)
            .chain(unknown.map(|index| vec![index]));
        let mut batches = Vec::new();
        for indexes in groups {
            let group: Vec<u8> = indexes.iter().map(|&index| pids[index]).collect();
            let mut buf = [0; 7];
            let Some(payload) = obd::current_data_multi(&group, &mut buf) else {
                unreachable!("a group is 1 to {MAX_PIDS_PER_REQUEST} PIDs");
            };
            batches.push(Batch {
                indexes,
                pids: group,
                request: LongRead::approve(policy, payload)?,
                answered_before: BTreeSet::new(),
            });
        }
        Ok(Self {
            pids: pids.to_vec(),
            batches,
            ecu_list: approve_ecu_list(policy)?,
            ecus: Vec::new(),
            modules,
            out_of_step: false,
        })
    }

    /// Reads every PID and DID once.
    ///
    /// The PIDs are read first, then each module's DIDs. A request nobody answers is an empty or
    /// [`ReadError::NoReply`] entry in the [`Sample`], not an error: only an adapter failure is
    /// one, and it loses the whole poll. Either leaves the poller [`Sample::out_of_step`].
    ///
    /// # Errors
    ///
    /// [`PollError::Transport`] when the adapter fails.
    pub fn poll<T: Transport + ?Sized>(
        &mut self,
        transport: &mut T,
        timing: Timing,
    ) -> Result<Sample, PollError> {
        let started = Instant::now();
        let mut unanswered = false;
        let read = self.read_all(transport, timing, &mut unanswered);
        self.out_of_step |= unanswered || read.is_err();
        let (pids, dids) = read?;
        Ok(Sample {
            started,
            finished: Instant::now(),
            pids,
            dids,
            out_of_step: self.out_of_step,
        })
    }

    // The PIDs, then each module's DIDs. `unanswered` is set when a request got no reply.
    fn read_all<T: Transport + ?Sized>(
        &mut self,
        transport: &mut T,
        timing: Timing,
        unanswered: &mut bool,
    ) -> Result<(PidReadings, Vec<DidSample>), PollError> {
        let mut pids = BTreeMap::new();
        if !self.batches.is_empty() {
            if self.ecus.is_empty() {
                self.ecus = ecus_to_ask(transport, &self.ecu_list, timing)?;
            }
            pids = self.read_pids(transport, timing, unanswered)?;
        }
        let mut dids = Vec::with_capacity(self.modules.len());
        for module in &self.modules {
            let sample = module.read(transport, timing)?;
            *unanswered |= matches!(
                sample.result,
                Err(ReadError::NoReply | ReadError::StillPending)
            );
            dids.push(sample);
        }
        Ok((pids, dids))
    }

    // Each ECU's readings, one per PID polled, in order.
    fn read_pids<T: Transport + ?Sized>(
        &mut self,
        transport: &mut T,
        timing: Timing,
        unanswered: &mut bool,
    ) -> Result<BTreeMap<u32, Vec<PidReading>>, PollError> {
        let Self {
            pids,
            batches,
            ecus,
            ..
        } = self;
        let mut slots: BTreeMap<u32, Vec<Option<Result<PidValue, ReadError>>>> = BTreeMap::new();
        for batch in batches {
            let replies = batch.request.read(transport, ecus, timing)?;
            // An ECU answers a request once; a repeat isn't another answer.
            let mut answered = BTreeSet::new();
            for reply in replies.iter().filter(|r| answered.insert(r.source)) {
                let slot = slots
                    .entry(reply.source)
                    .or_insert_with(|| vec![None; pids.len()]);
                let values = decoded(&reply.payload, |payload| decode_batch(payload, &batch.pids));
                for (&index, &pid) in batch.indexes.iter().zip(&batch.pids) {
                    slot[index] = Some(match &values {
                        Ok(values) => values
                            .iter()
                            .find(|(got, _)| *got == pid)
                            .map_or(Err(ReadError::NoReply), |(_, value)| Ok(value.clone())),
                        Err(e) => Err(e.clone()),
                    });
                }
            }
            // Each ECU in the list, and each that answered this request before, owes an answer.
            // Broadcast to ECUs not known yet, nobody owes one but somebody should give one.
            *unanswered |= answered.is_empty()
                || ecus
                    .iter()
                    .chain(&batch.answered_before)
                    .any(|ecu| !answered.contains(ecu));
            batch.answered_before.extend(answered);
        }
        Ok(slots
            .into_iter()
            .map(|(source, slot)| {
                let readings = pids
                    .iter()
                    .zip(slot)
                    .map(|(&pid, reading)| (pid, reading.unwrap_or(Err(ReadError::NoReply))))
                    .collect();
                (source, readings)
            })
            .collect())
    }
}

impl DidRequest {
    fn approve(policy: &Policy, poll: DidPoll) -> Result<Self, PollError> {
        let ids: Vec<u16> = poll.dids.iter().map(|&(id, _)| id).collect();
        check_dids(&ids).map_err(|error| PollError::BadDids {
            module: poll.module.name.clone(),
            error,
        })?;
        let mut payload = vec![uds::READ_DATA_BY_IDENTIFIER];
        payload.extend(ids.iter().flat_map(|id| id.to_be_bytes()));
        let request = policy
            .approve(
                Protocol::Uds,
                Target::physical(poll.module.request_id),
                &payload,
            )
            .map_err(PollError::Rejected)?;
        let lengths = poll
            .dids
            .iter()
            .filter_map(|&(id, length)| Some((id, length?)))
            .collect();
        Ok(Self {
            poll,
            ids,
            lengths,
            request,
        })
    }

    fn read<T: Transport + ?Sized>(
        &self,
        transport: &mut T,
        timing: Timing,
    ) -> Result<DidSample, PollError> {
        let module = &self.poll.module;
        let result = ask(
            transport,
            &self.request,
            module.response_id,
            timing,
            |reply| split(reply, &self.ids, &|did| self.lengths.get(&did).copied()),
        )?;
        Ok(DidSample {
            module: module.clone(),
            result,
        })
    }
}

// One ECU's reply to a request for `requested`: exactly the PIDs it answered, each asked for and
// named once, and nothing else. An ECU leaves out the PIDs it doesn't support, so a requested PID
// may be missing. Any other reply, a cut-off one included, is no answer at all.
fn decode_batch(payload: &[u8], requested: &[u8]) -> Result<Vec<(u8, PidValue)>, ReplyError> {
    let mut values: Vec<(u8, PidValue)> = Vec::with_capacity(requested.len());
    for reading in obd::decode_current_data(payload)? {
        let reading = reading?;
        if !requested.contains(&reading.pid) || values.iter().any(|(pid, _)| *pid == reading.pid) {
            return Err(ReplyError::Malformed);
        }
        let value = match reading.value {
            Value::Quantity { value, unit } => PidValue::Quantity { value, unit },
            Value::Raw(data) => PidValue::Raw(data.to_vec()),
            Value::Supported(_) => return Err(ReplyError::Malformed),
        };
        values.push((reading.pid, value));
    }
    Ok(values)
}

/// When the next poll is due, given that the last one `started` and the time is `now`.
///
/// That is `interval` after `started`, or `now` if that has passed, so a poll that took longer
/// than the interval is followed by one at once, not by a run of them to catch up. `interval` is
/// capped at [`LONGEST_INTERVAL`] so the sum can't overflow, and an interval of zero is due `now`.
/// The caller sleeps until the result, and passes the new poll's start next time.
#[must_use]
pub fn next_due(started: Instant, interval: Duration, now: Instant) -> Instant {
    started
        .checked_add(interval.min(LONGEST_INTERVAL))
        .map_or(now, |due| due.max(now))
}
