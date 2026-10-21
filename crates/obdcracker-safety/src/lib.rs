//! The only place a request the car may receive can be created.
//!
//! Every transport's `send` takes an [`Approved`] request, and only [`Policy::approve`] can make one.
//! Approval checks the payload against a closed allowlist, one per [`Protocol`]: anything not on it is
//! rejected, unknown services included. See `docs/safety.md` for the model and the addressing rules.
//!
//! ```compile_fail
//! // Approved can't be built outside this crate, so nothing can skip the policy.
//! let forged = obdcracker_safety::Approved { protocol: obdcracker_safety::Protocol::Uds, target: obdcracker_safety::Target::Physical(0x7E0), payload: vec![0x34], tier: obdcracker_safety::Tier::Read, reply: None };
//! ```
//!
//! ```compile_fail
//! // Nor can a TP2.0 channel, so a disconnect goes only on a channel a module opened.
//! let forged = obdcracker_safety::OpenTp20Channel { send_id: 0x000, receive_id: 0x300 };
//! ```

use obdcracker_core::tp20;

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

/// The diagnostic protocol a request is in, which says what its bytes mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDS (ISO 14229-1) and the OBD-II modes (SAE J1979) on ISO-TP. They share one set of service
    /// IDs: OBD-II modes are below 0x10, UDS services from 0x10 up.
    Uds,
    /// KWP2000 (ISO 14230-3). It has no suppress-positive-response bit, and its session and reset
    /// parameters mean other things than UDS's.
    Kwp2000,
    /// VW TP2.0 channel management: a channel setup or a disconnect. The policy builds these
    /// frames itself ([`Policy::approve_tp20_setup`], [`Policy::approve_tp20_disconnect`]), so
    /// [`Policy::approve`] refuses them.
    Tp20Channel,
}

/// Where a request goes on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The OBD-II broadcast address 0x7DF, which every emissions ECU answers.
    ObdFunctional,
    /// One module's 11-bit request ID.
    Physical(u32),
    /// One module's 29-bit request ID, in the ISO 15765-4 or VAG request range. See
    /// `docs/safety.md#addressing`.
    Physical29(u32),
    /// A VW TP2.0 channel setup for the module at this address, sent on 0x200.
    Tp20Setup(u8),
    /// An open VW TP2.0 channel: the 11-bit ID the module gave the tester to send on.
    Tp20Channel(u32),
}

impl Target {
    /// The physical target for `id`: 11-bit up to 0x7FF, 29-bit above. Every ID the policy
    /// allows at one width is outside the other's ranges, so a profile's IDs say their width.
    #[must_use]
    pub fn physical(id: u32) -> Self {
        if id <= MAX_11_BIT {
            Self::Physical(id)
        } else {
            Self::Physical29(id)
        }
    }

    /// The CAN ID the request is sent to.
    #[must_use]
    pub fn can_id(self) -> u32 {
        match self {
            Self::ObdFunctional => OBD_FUNCTIONAL_ID,
            Self::Tp20Setup(_) => tp20::SETUP_ID,
            Self::Physical(id) | Self::Physical29(id) | Self::Tp20Channel(id) => id,
        }
    }

    /// Whether the request goes out with a 29-bit CAN ID.
    #[must_use]
    pub fn is_29_bit(self) -> bool {
        matches!(self, Self::Physical29(_))
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
    /// The target isn't allowed for the request: see `docs/safety.md#addressing`. Once the policy is
    /// narrowed ([`Policy::narrowed_to`]), any ID that isn't a module's request ID is one too.
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

/// A module's request and reply CAN IDs, as a vehicle profile gives them: both 11-bit (up to
/// 0x7FF) or both 29-bit (above it, see [`Target::physical`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleIds {
    /// The CAN ID requests are sent to.
    pub request: u32,
    /// The CAN ID the module answers on.
    pub reply: u32,
}

/// Why [`Policy::narrowed_to`] refused a list of modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowingError {
    /// A request ID the policy refuses anyway.
    Request(u32),
    /// A reply ID that isn't a valid reply of the request ID's width (`docs/safety.md#addressing`).
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
    protocol: Protocol,
    target: Target,
    payload: Vec<u8>,
    tier: Tier,
    reply: Option<u32>,
}

/// A VW TP2.0 channel a module opened in answer to an approved setup ([`Policy::tp20_channel`]).
/// Only this crate can create one, so a disconnect goes only on a channel a module gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTp20Channel {
    send_id: u32,
    receive_id: u32,
}

impl OpenTp20Channel {
    /// The ID the tester sends on, which the module listens on.
    #[must_use]
    pub fn send_id(self) -> u32 {
        self.send_id
    }

    /// The ID the module answers on.
    #[must_use]
    pub fn receive_id(self) -> u32 {
        self.receive_id
    }
}

impl Approved {
    /// The protocol the request was approved as.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

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
    // With a vehicle profile, the only addresses a TP2.0 channel may be set up to.
    tp20: Option<Vec<u8>>,
}

impl Policy {
    /// A policy that allows only [`Tier::Read`] requests.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            unlocked: Tier::Read,
            modules: None,
            tp20: None,
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
    /// A request ID the policy refuses anyway, a reply ID it can't be ([`NarrowingError::Reply`]),
    /// an ID that is both a request ID and a reply ID, or a request ID with two reply IDs.
    pub fn narrowed_to(self, modules: &[ModuleIds]) -> Result<Self, NarrowingError> {
        for module in modules {
            let target = Target::physical(module.request);
            if check_target(target, Kind::Physical).is_err() {
                return Err(NarrowingError::Request(module.request));
            }
            let reply_ok = if target.is_29_bit() {
                is_29_bit_reply(module.reply)
            } else {
                (0x700..=MAX_11_BIT).contains(&module.reply) && module.reply != OBD_FUNCTIONAL_ID
            };
            if !reply_ok {
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

    /// Narrows the TP2.0 channel setups to these module addresses, as a vehicle profile lists
    /// them. Narrowing again narrows further; physical requests are unaffected.
    #[must_use]
    pub fn narrowed_to_tp20(self, addresses: &[u8]) -> Self {
        let tp20 = match self.tp20 {
            None => addresses.to_vec(),
            Some(earlier) => addresses
                .iter()
                .filter(|address| earlier.contains(address))
                .copied()
                .collect(),
        };
        Self {
            tp20: Some(tp20),
            ..self
        }
    }

    /// A VW TP2.0 channel setup for the module at `address`, sent on 0x200 and answered on
    /// 0x200 + `address`. It opens a channel and changes nothing.
    ///
    /// # Errors
    ///
    /// [`Rejection::WrongTarget`] for address 0 (the tester's), or one the policy was narrowed
    /// away from ([`Policy::narrowed_to_tp20`]).
    pub fn approve_tp20_setup(&self, address: u8) -> Result<Approved, Rejection> {
        if address == TP20_TESTER
            || self
                .tp20
                .as_ref()
                .is_some_and(|addresses| !addresses.contains(&address))
        {
            return Err(Rejection::WrongTarget);
        }
        Ok(Approved {
            protocol: Protocol::Tp20Channel,
            target: Target::Tp20Setup(address),
            payload: tp20::channel_setup(address).to_vec(),
            tier: Tier::Read,
            reply: Some(tp20::setup_reply_id(address)),
        })
    }

    /// The channel a module opened: `reply` is what came from `source` in answer to `setup`.
    ///
    /// # Errors
    ///
    /// [`Rejection::NotAllowed`] unless `setup` is a channel setup ([`Policy::approve_tp20_setup`])
    /// and `reply` a positive answer to it with two valid IDs ([`tp20::decode_channel_setup`]);
    /// [`Rejection::WrongTarget`] unless `source` is the ID that setup is answered on.
    pub fn tp20_channel(
        &self,
        setup: &Approved,
        source: u32,
        reply: &[u8],
    ) -> Result<OpenTp20Channel, Rejection> {
        if !matches!(setup.target, Target::Tp20Setup(_)) {
            return Err(Rejection::NotAllowed);
        }
        if setup.reply != Some(source) {
            return Err(Rejection::WrongTarget);
        }
        let channel = tp20::decode_channel_setup(reply).map_err(|_| Rejection::NotAllowed)?;
        Ok(OpenTp20Channel {
            send_id: channel.send_id,
            receive_id: channel.receive_id,
        })
    }

    /// A VW TP2.0 disconnect (`A8`) on a channel a module opened: sent on its send ID, answered
    /// on its receive ID. It closes the channel and changes nothing.
    ///
    /// # Errors
    ///
    /// [`Rejection::WrongTarget`] unless the channel's IDs are ones the policy lets `A8` go on
    /// (`docs/safety.md#addressing`).
    pub fn approve_tp20_disconnect(
        &self,
        channel: &OpenTp20Channel,
    ) -> Result<Approved, Rejection> {
        let OpenTp20Channel {
            send_id,
            receive_id,
        } = *channel;
        let module_id = self.modules.as_ref().is_some_and(|modules| {
            modules
                .iter()
                .any(|module| module.request == send_id || module.reply == send_id)
        });
        if receive_id != TP20_TESTER_RECEIVE_ID
            || !(TP20_TESTER_RECEIVE_ID..=MAX_11_BIT).contains(&send_id)
            || (OBD_FUNCTIONAL_ID..=*OBD_RESPONSE_IDS.end()).contains(&send_id)
            || module_id
        {
            return Err(Rejection::WrongTarget);
        }
        Ok(Approved {
            protocol: Protocol::Tp20Channel,
            target: Target::Tp20Channel(send_id),
            payload: tp20::DISCONNECT.to_vec(),
            tier: Tier::Read,
            reply: Some(receive_id),
        })
    }

    /// Checks a request in `protocol` against that protocol's allowlist and returns it as
    /// [`Approved`] if it may be sent.
    ///
    /// Flash-tier requests are always [`Rejection::Banned`], whatever the policy unlocks.
    pub fn approve(
        &self,
        protocol: Protocol,
        target: Target,
        payload: &[u8],
    ) -> Result<Approved, Rejection> {
        // Channel frames come only from the policy's own builders, and no service goes on them.
        if protocol == Protocol::Tp20Channel {
            return Err(Rejection::NotAllowed);
        }
        if matches!(target, Target::Tp20Setup(_) | Target::Tp20Channel(_)) {
            return Err(Rejection::WrongTarget);
        }
        let (tier, kind) = match protocol {
            Protocol::Uds => classify_uds(payload),
            Protocol::Kwp2000 => classify_kwp2000(payload).map(|tier| (tier, Kind::Physical)),
            Protocol::Tp20Channel => None,
        }
        .ok_or(Rejection::NotAllowed)?;
        if tier == Tier::Flash {
            return Err(Rejection::Banned);
        }
        if tier > self.unlocked {
            return Err(Rejection::Locked(tier));
        }
        check_target(target, kind)?;
        let reply = match (target, &self.modules) {
            (Target::ObdFunctional | Target::Tp20Setup(_) | Target::Tp20Channel(_), _) => None,
            (Target::Physical(id) | Target::Physical29(id), Some(modules)) => Some(
                modules
                    .iter()
                    .find(|module| module.request == id)
                    .ok_or(Rejection::WrongTarget)?
                    .reply,
            ),
            (Target::Physical(id), None) => OBD_REQUEST_IDS.contains(&id).then(|| id + 8),
            // VAG's reply IDs come from a profile.
            (Target::Physical29(id), None) => {
                is_iso_29_bit_request(id).then_some(ISO_29_BIT_REPLY | ((id >> 8) & 0xFF))
            }
        };
        Ok(Approved {
            protocol,
            target,
            payload: payload.to_vec(),
            tier,
            reply,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    // OBD-II: the broadcast or an emissions ECU.
    Obd,
    // UDS and KWP2000: one module, never the broadcast.
    Physical,
}

const OBD_FUNCTIONAL_ID: u32 = 0x7DF;
const MAX_11_BIT: u32 = 0x7FF;
// VW TP2.0: see docs/safety.md#addressing.
const TP20_TESTER: u8 = 0x00;
const TP20_TESTER_RECEIVE_ID: u32 = 0x300;
// 29-bit request and reply ranges: see docs/safety.md#addressing.
const ISO_29_BIT_REQUEST: u32 = 0x18DA_00F1;
const ISO_29_BIT_REPLY: u32 = 0x18DA_F100;
const TESTER: u32 = 0xF1;
const VAG_29_BIT_REQUEST: u32 = 0x17FC_0000;
const VAG_29_BIT_REPLY: u32 = 0x17FE_0000;

fn is_iso_29_bit_request(id: u32) -> bool {
    id & 0xFFFF_00FF == ISO_29_BIT_REQUEST && (id >> 8) & 0xFF != TESTER
}

fn is_29_bit_request(id: u32) -> bool {
    is_iso_29_bit_request(id) || id & 0xFFFF_FF00 == VAG_29_BIT_REQUEST
}

fn is_29_bit_reply(id: u32) -> bool {
    (id & 0xFFFF_FF00 == ISO_29_BIT_REPLY && id & 0xFF != TESTER)
        || id & 0xFFFF_FF00 == VAG_29_BIT_REPLY
}
// ISO 15765-4: emissions ECUs listen on 0x7E0..=0x7E7 and answer on the ID + 8.
const OBD_REQUEST_IDS: core::ops::RangeInclusive<u32> = 0x7E0..=0x7E7;
const OBD_RESPONSE_IDS: core::ops::RangeInclusive<u32> = 0x7E8..=0x7EF;

fn check_target(target: Target, kind: Kind) -> Result<(), Rejection> {
    match (target, kind) {
        (Target::ObdFunctional, Kind::Obd) => Ok(()),
        // Never a response ID: a request there looks like an ECU's reply to everyone listening.
        (Target::Physical29(id), _) if is_29_bit_request(id) => Ok(()),
        (Target::Physical(id), _)
            if (0x700..=MAX_11_BIT).contains(&id)
                && id != OBD_FUNCTIONAL_ID
                && !OBD_RESPONSE_IDS.contains(&id) =>
        {
            Ok(())
        }
        _ => Err(Rejection::WrongTarget),
    }
}

// The UDS and OBD-II allowlist. Returns None for anything not on it, including malformed lengths.
fn classify_uds(payload: &[u8]) -> Option<(Tier, Kind)> {
    let (&sid, data) = payload.split_first()?;
    // UDS subfunctions use bit 7 to suppress the positive response; it doesn't change the meaning.
    let sub = data.first().map(|b| b & 0x7F);
    let class = match sid {
        0x01 if (1..=6).contains(&data.len()) => (Tier::Read, Kind::Obd),
        0x03 if data.is_empty() => (Tier::Read, Kind::Obd),
        0x04 if data.is_empty() => (Tier::ClearDtc, Kind::Obd),
        0x09 if data.len() == 1 => (Tier::Read, Kind::Obd),
        // Default and extended sessions are reads; programming is flashing.
        0x10 if data.len() == 1 => match sub? {
            0x01 | 0x03 => (Tier::Read, Kind::Physical),
            0x02 => (Tier::Flash, Kind::Physical),
            _ => return None,
        },
        0x14 if data.len() == 3 => (Tier::ClearDtc, Kind::Physical),
        0x19 if !data.is_empty() => (Tier::Read, Kind::Physical),
        0x22 if !data.is_empty() && data.len() % 2 == 0 => (Tier::Read, Kind::Physical),
        // SecurityAccess unlocks coding, so it is as locked as coding.
        0x27 if !data.is_empty() => (Tier::Coding, Kind::Physical),
        0x2E if data.len() >= 3 => (Tier::Coding, Kind::Physical),
        0x3E if data.len() == 1 && sub? == 0x00 => (Tier::Read, Kind::Physical),
        // ECUReset, RoutineControl, RequestDownload/Upload, TransferData, RequestTransferExit,
        // WriteMemoryByAddress: banned whatever their length.
        0x11 | 0x31 | 0x34 | 0x35 | 0x36 | 0x37 | 0x3D => (Tier::Flash, Kind::Physical),
        _ => return None,
    };
    Some(class)
}

// The KWP2000 allowlist (ISO 14230-3). Returns None for anything not on it, including malformed
// lengths. KWP2000 has no suppress-positive-response bit, so every parameter is read unmasked.
fn classify_kwp2000(payload: &[u8]) -> Option<Tier> {
    let (&sid, data) = payload.split_first()?;
    let tier = match sid {
        // Programming and development reprogram; adjustment changes adaptations. No session is a
        // read: ISO 14230-3 leaves 0x80..=0xFF to the manufacturer, so each needs its own rule.
        0x10 if data.len() == 1 => match data[0] {
            0x85 | 0x86 => Tier::Flash,
            0x87 => Tier::Coding,
            _ => return None,
        },
        // The DTC group is optional and its width the manufacturer's (ISO 14230-3).
        0x14 => Tier::ClearDtc,
        // Parameter widths are the manufacturer's (ISO 14230-3).
        0x17 | 0x18 if !data.is_empty() => Tier::Read,
        // Exactly one option or local ID: a transmission mode after it would ask for periodic
        // replies, not one read.
        0x1A | 0x21 if data.len() == 1 => Tier::Read,
        // SecurityAccess unlocks coding; the writes by common and local ID change it, whatever
        // their record's length.
        0x27 | 0x2E | 0x3B if !data.is_empty() => Tier::Coding,
        // responseRequired is 01 (yes) or 02 (no).
        0x3E if matches!(data, [] | [0x01 | 0x02]) => Tier::Read,
        // ECUReset (0x80..=0xFF are manufacturers' resets), the routines, RequestDownload/Upload,
        // TransferData, RequestTransferExit and WriteMemoryByAddress: banned whatever their length.
        0x11 | 0x31..=0x3A | 0x3D => Tier::Flash,
        _ => return None,
    };
    Some(tier)
}
