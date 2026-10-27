//! One DTC's detail from one module: the snapshot records (UDS `19 04`), what the module stored
//! when the fault happened, and the extended data records (`19 06`), such as how often it
//! happened. Reads only.

use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::{self, DtcStatus, UdsDtc};
use obdcracker_safety::{Policy, Protocol, Target};

use crate::fingerprint::{FingerprintError, ReadError, UdsModule, ask};
use crate::{Timing, Transport};

/// A DTC's snapshot or extended data, as one module sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    /// The DTC's status.
    pub status: DtcStatus,
    /// The records, each a record number and its data, as the module sent them. Their lengths
    /// depend on the module's data identifiers, so they aren't split. Empty if it stored none.
    pub records: Vec<u8>,
}

impl DtcDetail {
    /// Whether the module answered either read, a refusal included.
    #[must_use]
    pub fn answered(&self) -> bool {
        let answered = |value: &Result<RecordData, ReadError>| {
            !matches!(value, Err(ReadError::NoReply | ReadError::StillPending))
        };
        answered(&self.snapshots) || self.extended_data.as_ref().is_some_and(answered)
    }
}

impl From<uds::DtcData<'_>> for RecordData {
    fn from(data: uds::DtcData<'_>) -> Self {
        Self {
            status: data.status,
            records: data.records.to_vec(),
        }
    }
}

/// What [`read_dtc_detail`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtcDetail {
    /// The snapshot records asked for (`19 04 <DTC> <record>`).
    pub snapshots: Result<RecordData, ReadError>,
    /// The extended data records asked for (`19 06 <DTC> <record>`). `None` if it wasn't asked:
    /// the snapshot read went unanswered (a refusal doesn't name its DTC, so that read's late
    /// refusal could have passed for this one's answer), or the module said it was busy (NRC
    /// 0x21), so it isn't sent another request.
    pub extended_data: Option<Result<RecordData, ReadError>>,
    /// A read went unanswered, so its reply may still arrive as the answer to the connection's
    /// next request.
    pub out_of_step: bool,
}

/// Reads `dtc`'s snapshot records, then its extended data records, from `module`: the record
/// numbered `record` of each, or every record for 0xFF (and every OBD extended data record for
/// 0xFE). A reply for another record doesn't answer the read: it may be a late answer to an
/// earlier request. Both requests are approved before anything is sent. The extended data isn't
/// asked after an unanswered or busy snapshot read ([`DtcDetail::extended_data`]).
///
/// # Errors
///
/// [`FingerprintError::Rejected`] if the policy refuses either request (nothing is sent), or
/// [`FingerprintError::Transport`] if the adapter fails.
pub fn read_dtc_detail<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    dtc: UdsDtc,
    record: u8,
    timing: Timing,
) -> Result<DtcDetail, FingerprintError> {
    let target = Target::physical(module.request_id);
    let approve = |payload: &[u8]| {
        policy
            .approve(Protocol::Uds, target, payload)
            .map_err(FingerprintError::Rejected)
    };
    let snapshot_request = approve(&uds::dtc_snapshots(dtc, record))?;
    let extended_request = approve(&uds::dtc_extended_data(dtc, record))?;
    let unanswered = |value: &Result<RecordData, ReadError>| {
        matches!(value, Err(ReadError::NoReply | ReadError::StillPending))
    };
    let snapshots = ask(
        transport,
        &snapshot_request,
        module.response_id,
        timing,
        |reply| uds::decode_dtc_snapshots(reply, dtc, record).map(RecordData::from),
    )?;
    if unanswered(&snapshots) {
        return Ok(DtcDetail {
            snapshots,
            extended_data: None,
            out_of_step: true,
        });
    }
    // "Busy, repeat request" isn't an answer: the module is still on the first read.
    if matches!(&snapshots, Err(ReadError::Reply(ReplyError::Negative(refusal)))
        if refusal.nrc == Nrc::BusyRepeatRequest)
    {
        return Ok(DtcDetail {
            snapshots,
            extended_data: None,
            out_of_step: false,
        });
    }
    let extended_data = ask(
        transport,
        &extended_request,
        module.response_id,
        timing,
        |reply| uds::decode_dtc_extended_data(reply, dtc, record).map(RecordData::from),
    )?;
    Ok(DtcDetail {
        snapshots,
        out_of_step: unanswered(&extended_data),
        extended_data: Some(extended_data),
    })
}
