//! The only place a request the car may receive can be created.
//!
//! Every transport's `send` takes an [`Approved`] request, and only [`Policy::approve`] can make one.
//! Approval checks the payload against a closed allowlist. Anything that isn't on it is rejected,
//! unknown services included.
//!
//! ```compile_fail
//! // Approved can't be built outside this crate, so nothing can skip the policy.
//! let forged = obdcracker_safety::Approved { target: obdcracker_safety::Target::Physical(0x7E0), payload: vec![0x34], tier: obdcracker_safety::Tier::Read };
//! ```

/// What a request could do to the car, from harmless to dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Reads that change nothing in the car.
    Read,
    /// Erases stored fault codes and their freeze frames.
    ClearDtc,
    /// Changes a module's coding or adaptation values (and the security access that unlocks them).
    Coding,
    /// Reprograms or resets a module. These requests are always banned.
    Flash,
}

/// Where a request goes on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The OBD-II broadcast address 0x7DF, which every emissions ECU answers.
    ObdFunctional,
    /// One module's 11-bit request ID.
    Physical(u32),
}

impl Target {
    /// The 11-bit CAN ID the request is sent to.
    #[must_use]
    pub fn can_id(self) -> u32 {
        match self {
            Self::ObdFunctional => OBD_FUNCTIONAL_ID,
            Self::Physical(id) => id,
        }
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The request is on the allowlist, but its tier isn't unlocked.
    Locked(Tier),
    /// The request could reprogram or reset a module. No setting allows it.
    Banned,
    /// Not on the allowlist, malformed, or empty.
    NotAllowed,
    /// UDS sent to the broadcast address, or a physical ID outside 0x700..=0x7FF.
    WrongTarget,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked(tier) => {
                let tier = match tier {
                    Tier::Read => "read",
                    Tier::ClearDtc => "clear-DTC",
                    Tier::Coding => "coding",
                    Tier::Flash => "flash",
                };
                write!(f, "refused: the {tier} tier is locked")
            }
            Self::Banned => f.write_str("refused: flash-tier requests are banned"),
            Self::NotAllowed => f.write_str("refused: not on the allowlist, or malformed"),
            Self::WrongTarget => f.write_str("refused: wrong target for this request"),
        }
    }
}

impl std::error::Error for Rejection {}

/// A request that passed the policy. Only this crate can create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    target: Target,
    payload: Vec<u8>,
    tier: Tier,
}

impl Approved {
    /// Where the request goes.
    #[must_use]
    pub fn target(&self) -> Target {
        self.target
    }

    /// The request bytes, service ID first, exactly as approved.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The tier the policy classified the request as.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
}

/// Decides which requests may be sent. Read-only is the only policy for now; unlocking a higher
/// tier will need a cargo feature, an explicit runtime unlock, and passing preconditions.
#[derive(Debug)]
pub struct Policy {
    unlocked: Tier,
}

impl Policy {
    /// A policy that allows only [`Tier::Read`] requests.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            unlocked: Tier::Read,
        }
    }

    /// Checks a request against the allowlist and returns it as [`Approved`] if it may be sent.
    ///
    /// Flash-tier requests are always [`Rejection::Banned`], whatever the policy unlocks.
    pub fn approve(&self, target: Target, payload: &[u8]) -> Result<Approved, Rejection> {
        let (tier, kind) = classify(payload).ok_or(Rejection::NotAllowed)?;
        if tier == Tier::Flash {
            return Err(Rejection::Banned);
        }
        if tier > self.unlocked {
            return Err(Rejection::Locked(tier));
        }
        check_target(target, kind)?;
        Ok(Approved {
            target,
            payload: payload.to_vec(),
            tier,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Obd,
    Uds,
}

const OBD_FUNCTIONAL_ID: u32 = 0x7DF;

fn check_target(target: Target, kind: Kind) -> Result<(), Rejection> {
    match (target, kind) {
        (Target::ObdFunctional, Kind::Obd) => Ok(()),
        (Target::Physical(id), _) if (0x700..=0x7FF).contains(&id) && id != OBD_FUNCTIONAL_ID => {
            Ok(())
        }
        _ => Err(Rejection::WrongTarget),
    }
}

// The allowlist. Returns None for anything not on it, including malformed lengths.
fn classify(payload: &[u8]) -> Option<(Tier, Kind)> {
    let (&sid, data) = payload.split_first()?;
    // UDS subfunctions use bit 7 to suppress the positive response; it doesn't change the meaning.
    let sub = data.first().map(|b| b & 0x7F);
    let class = match sid {
        // OBD-II mode 01 current data: one to six PIDs
        0x01 if (1..=6).contains(&data.len()) => (Tier::Read, Kind::Obd),
        // OBD-II mode 03 stored DTCs
        0x03 if data.is_empty() => (Tier::Read, Kind::Obd),
        // OBD-II mode 04 clear DTCs
        0x04 if data.is_empty() => (Tier::ClearDtc, Kind::Obd),
        // OBD-II mode 09 vehicle information: one PID
        0x09 if data.len() == 1 => (Tier::Read, Kind::Obd),
        // DiagnosticSessionControl: default and extended are reads; programming is flashing
        0x10 if data.len() == 1 => match sub? {
            0x01 | 0x03 => (Tier::Read, Kind::Uds),
            0x02 => (Tier::Flash, Kind::Uds),
            _ => return None,
        },
        // ClearDiagnosticInformation: a 3-byte DTC group
        0x14 if data.len() == 3 => (Tier::ClearDtc, Kind::Uds),
        // ReadDTCInformation: every subfunction is a read
        0x19 if !data.is_empty() => (Tier::Read, Kind::Uds),
        // ReadDataByIdentifier: one or more 2-byte DIDs
        0x22 if !data.is_empty() && data.len() % 2 == 0 => (Tier::Read, Kind::Uds),
        // SecurityAccess unlocks coding
        0x27 if !data.is_empty() => (Tier::Coding, Kind::Uds),
        // WriteDataByIdentifier: a DID and at least one byte
        0x2E if data.len() >= 3 => (Tier::Coding, Kind::Uds),
        // TesterPresent
        0x3E if data.len() == 1 && sub? == 0x00 => (Tier::Read, Kind::Uds),
        // ECUReset, RoutineControl, RequestDownload/Upload, TransferData, RequestTransferExit,
        // WriteMemoryByAddress: banned whatever their length
        0x11 | 0x31 | 0x34 | 0x35 | 0x36 | 0x37 | 0x3D => (Tier::Flash, Kind::Uds),
        _ => return None,
    };
    Some(class)
}

/// Whether `payload` could change a module's state if a module received it, whatever the
/// policy allows: everything the policy locks or bans, and services it doesn't allow that drive
/// or silence the car.
///
/// For links that can corrupt a request on its way to the bus, such as an ELM327's ASCII serial
/// line, which has no checksum: a driver refuses a request when any corruption it can't detect
/// would turn it into one of these.
///
/// Services whose parameter picks the action (reset, communication control, IO control, DTC
/// setting) count only with a parameter ISO 14229-1 defines or leaves to manufacturers; a
/// module refuses the reserved ones (NRC 0x12 or 0x31). Writes, clears and flashing count at any
/// length, in case a module doesn't check it, and so does every session but the default and
/// extended ones. OBD-II mode 08 (control of an on-board system) is left out on purpose: every
/// mode 09 request is one bit away from it, and the A7 is a diesel with no evaporative-system
/// test for it to start.
#[must_use]
pub fn could_change_state(payload: &[u8]) -> bool {
    let Some((&sid, data)) = payload.split_first() else {
        return false;
    };
    // The suppress-positive-response bit doesn't change what a subfunction does. 0x40..=0x7E are
    // the manufacturers' and system suppliers' own values.
    let sub = data.first().map(|b| b & 0x7F);
    match sid {
        // DiagnosticSessionControl: anything but the default and extended sessions, compared
        // unmasked, because KWP2000 has no suppress bit and `10 85` is its programming session
        0x10 => !matches!(data.first(), None | Some(0x01 | 0x03 | 0x81 | 0x83)),
        // ECUReset
        0x11 => matches!(sub, Some(0x01..=0x05 | 0x40..=0x7E)),
        // CommunicationControl
        0x28 => matches!(sub, Some(0x00..=0x05 | 0x40..=0x7E)),
        // ControlDTCSetting
        0x85 => matches!(sub, Some(0x01 | 0x02 | 0x40..=0x7E)),
        // IOControlByIdentifier: a 2-byte DID, then the control parameter
        0x2F => data.get(2).is_some_and(|&parameter| parameter <= 0x03),
        // Clearing, coding and flashing, whatever the length; then DynamicallyDefineDataIdentifier,
        // RequestFileTransfer, SecuredDataTransmission (which can carry any request),
        // ResponseOnEvent, LinkControl, and KWP2000's inputOutputControlByLocalIdentifier and
        // writeDataByLocalIdentifier
        0x04
        | 0x14
        | 0x27
        | 0x2E
        | 0x31
        | 0x34..=0x37
        | 0x3D
        | 0x2C
        | 0x38
        | 0x84
        | 0x86
        | 0x87
        | 0x30
        | 0x3B => true,
        _ => classify(payload).is_some_and(|(tier, _)| tier > Tier::Read),
    }
}
