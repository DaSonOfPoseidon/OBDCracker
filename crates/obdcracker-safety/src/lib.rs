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
    /// UDS sent to the broadcast address, a physical ID outside 0x700..=0x7FF, an ID that
    /// OBD-II ECUs answer on (0x7E8..=0x7EF), or, once the policy is narrowed to a car's modules
    /// ([`Policy::narrowed_to`]), any ID that isn't one of their request IDs.
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

/// A module's request and reply CAN IDs, as a vehicle profile gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleIds {
    /// The 11-bit CAN ID requests are sent to.
    pub request: u32,
    /// The 11-bit CAN ID the module answers on.
    pub reply: u32,
}

/// Why [`Policy::narrowed_to`] refused a list of modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowingError {
    /// A request ID the policy refuses anyway.
    Request(u32),
    /// A reply ID outside 0x700..=0x7FF, or the broadcast ID 0x7DF.
    Reply(u32),
    /// An ID that is one module's request ID and a module's reply ID.
    RequestIsReply(u32),
    /// A request ID with two different reply IDs.
    AmbiguousReply(u32),
}

impl std::fmt::Display for NarrowingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(id) => write!(f, "0x{id:03X} can't be a request ID"),
            Self::Reply(id) => write!(f, "0x{id:03X} can't be a reply ID"),
            Self::RequestIsReply(id) => {
                write!(f, "0x{id:03X} is both a request ID and a reply ID")
            }
            Self::AmbiguousReply(id) => {
                write!(f, "request ID 0x{id:03X} has two different reply IDs")
            }
        }
    }
}

impl std::error::Error for NarrowingError {}

/// A request that passed the policy. Only this crate can create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    target: Target,
    payload: Vec<u8>,
    tier: Tier,
    reply: Option<u32>,
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

    /// The CAN ID the one module addressed answers on, if it's known: 8 above an OBD-II ECU's
    /// request ID (ISO 15765-4), or the reply ID of a module the policy was narrowed to. `None`
    /// for a broadcast, or a physical ID with no known module.
    #[must_use]
    pub fn reply_id(&self) -> Option<u32> {
        self.reply
    }
}

/// Decides which requests may be sent. Read-only is the only policy for now; unlocking a higher
/// tier will need a cargo feature, an explicit runtime unlock, and passing preconditions.
#[derive(Debug)]
pub struct Policy {
    unlocked: Tier,
    // With a vehicle profile, the only modules physical requests may go to.
    modules: Option<Vec<ModuleIds>>,
}

impl Policy {
    /// A policy that allows only [`Tier::Read`] requests.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            unlocked: Tier::Read,
            modules: None,
        }
    }

    /// Narrows the policy to a car's modules, as its vehicle profile lists them: a physical
    /// request must then go to one of their request IDs, and never to any of their reply IDs.
    /// Everything the policy refused before, it still refuses; the broadcast is unaffected.
    ///
    /// Narrowing again narrows further: a request must then fit both lists.
    ///
    /// # Errors
    ///
    /// A request ID the policy refuses anyway, a reply ID outside 0x700..=0x7FF (or 0x7DF), an ID
    /// that is both a request ID and a reply ID, or a request ID with two reply IDs.
    pub fn narrowed_to(self, modules: &[ModuleIds]) -> Result<Self, NarrowingError> {
        for module in modules {
            if check_target(Target::Physical(module.request), Kind::Uds).is_err() {
                return Err(NarrowingError::Request(module.request));
            }
            if !(0x700..=0x7FF).contains(&module.reply) || module.reply == OBD_FUNCTIONAL_ID {
                return Err(NarrowingError::Reply(module.reply));
            }
            if modules.iter().any(|other| other.reply == module.request) {
                return Err(NarrowingError::RequestIsReply(module.request));
            }
            if modules
                .iter()
                .any(|other| other.request == module.request && other.reply != module.reply)
            {
                return Err(NarrowingError::AmbiguousReply(module.request));
            }
        }
        let modules = match self.modules {
            None => modules.to_vec(),
            Some(earlier) => modules
                .iter()
                .filter(|module| earlier.contains(module))
                .copied()
                .collect(),
        };
        Ok(Self {
            modules: Some(modules),
            ..self
        })
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
        let reply = match (target, &self.modules) {
            (Target::ObdFunctional, _) => None,
            (Target::Physical(id), Some(modules)) => Some(
                modules
                    .iter()
                    .find(|module| module.request == id)
                    .ok_or(Rejection::WrongTarget)?
                    .reply,
            ),
            (Target::Physical(id), None) => OBD_REQUEST_IDS.contains(&id).then(|| id + 8),
        };
        Ok(Approved {
            target,
            payload: payload.to_vec(),
            tier,
            reply,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Obd,
    Uds,
}

const OBD_FUNCTIONAL_ID: u32 = 0x7DF;
// ISO 15765-4: emissions ECUs answer on 0x7E8..=0x7EF (their request ID + 8).
const OBD_REQUEST_IDS: core::ops::RangeInclusive<u32> = 0x7E0..=0x7E7;
const OBD_RESPONSE_IDS: core::ops::RangeInclusive<u32> = 0x7E8..=0x7EF;

fn check_target(target: Target, kind: Kind) -> Result<(), Rejection> {
    match (target, kind) {
        (Target::ObdFunctional, Kind::Obd) => Ok(()),
        // Never a response ID: a request there looks like an ECU's reply to everyone listening.
        (Target::Physical(id), _)
            if (0x700..=0x7FF).contains(&id)
                && id != OBD_FUNCTIONAL_ID
                && !OBD_RESPONSE_IDS.contains(&id) =>
        {
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
