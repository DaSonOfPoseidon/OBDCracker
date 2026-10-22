//! Vehicle profiles: the manufacturer specifics of one car, as data.
//!
//! A profile says where each module sits on the bus (request and response CAN IDs, addressing,
//! protocol) and which identifiers it can read and how to show them. OBD-II needs no profile.
//!
//! A profile can only narrow what the safety policy allows, never widen it: it has no field that
//! names a service, so every request to a profile's module still goes through
//! `obdcracker_safety::Policy::approve`.
//!
//! See docs/profiles.md#file-format for the file format.
//!
//! ```
//! use obdcracker_profile::Profile;
//!
//! let a7 = Profile::builtin("a7").unwrap();
//! let engine = a7.module("engine").unwrap();
//! assert_eq!((engine.request_id, engine.response_id), (0x7E0, 0x7E8));
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use obdcracker_core::isotp::Addressing;
use obdcracker_core::uds;
use obdcracker_safety::{ModuleIds, NarrowingError, Policy};
use serde::Deserialize;

/// One car's profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// What car this is, e.g. `2014 Audi A7 3.0 TDI (C7)`.
    pub name: String,
    /// The diagnostic CAN bus's bitrate in bit/s: 250000 or 500000.
    pub bitrate: u32,
    /// The modules on the bus.
    #[serde(rename = "module", default)]
    pub modules: Vec<Module>,
    /// Where to look for modules the profile doesn't list, if anywhere.
    pub discovery: Option<Discovery>,
    /// Where to look on 29-bit IDs for modules the profile doesn't list, if anywhere.
    pub discovery_29bit: Option<Discovery29>,
    /// The VAG addresses to try VW TP2.0 channel setups to, if any. Without it, the profile
    /// allows no channel setup.
    pub discovery_tp20: Option<DiscoveryTp20>,
}

/// The VAG addresses to try VW TP2.0 channel setups to ([`Profile::tp20_addresses`]): at least
/// one, none of them 0 (the tester's), none twice.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryTp20 {
    /// The addresses, in the order to try them.
    pub addresses: Vec<u8>,
}

/// A range of 29-bit request IDs to try for modules a profile doesn't list, each answering on its
/// request ID plus a fixed offset. Every candidate must be a 29-bit pair the safety policy
/// accepts, and the range at most [`Discovery29::MAX_IDS`] long.
///
/// See docs/profiles.md#discovery-ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery29 {
    /// The first request ID to try.
    pub first_request_id: u32,
    /// The last request ID to try.
    pub last_request_id: u32,
    /// What to add to a request ID for its reply ID.
    pub reply_offset: u32,
}

impl Discovery29 {
    /// The most request IDs a range may hold: one byte of address, as VAG's scheme has.
    pub const MAX_IDS: u32 = 256;
}

/// A range of request IDs to try for modules a profile doesn't list, each answering on its
/// request ID plus a fixed offset. No candidate's request ID may be any module's or candidate's
/// reply ID.
///
/// See docs/profiles.md#discovery-ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    /// The first request ID to try.
    pub first_request_id: u32,
    /// The last request ID to try.
    pub last_request_id: u32,
    /// What to add to a request ID for its reply ID.
    pub reply_offset: u32,
    /// Where a second, wider pass ends, if there is one ([`Profile::wide_candidates`]). It is
    /// opt-in, and can send on the reply ID of a module that stayed silent in the first pass.
    #[serde(default)]
    pub wide_last_request_id: Option<u32>,
}

/// One module (ECU) on the bus.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    /// A short name, unique within the profile, such as `engine`.
    pub name: String,
    /// The VAG diagnostic address (`01` engine, `19` gateway), on VAG cars only.
    pub vag_address: Option<u8>,
    /// The 11-bit CAN ID requests are sent to.
    pub request_id: u32,
    /// The 11-bit CAN ID the module answers on.
    pub response_id: u32,
    /// The diagnostic protocol the module speaks.
    pub protocol: Protocol,
    /// The sub-address byte for ISO-TP extended addressing, if the module uses it.
    pub extended_address: Option<u8>,
    /// The data identifiers this module can read beyond the standard ones.
    #[serde(rename = "did", default)]
    pub dids: Vec<DidDef>,
}

impl Module {
    /// Each DID with its length, in the order given, to decode a multi-DID read
    /// (`obdcracker_core::uds::decode_dids`). `None` if the profile doesn't give every one's
    /// length.
    #[must_use]
    pub fn did_layout(&self, dids: &[u16]) -> Option<Vec<(u16, usize)>> {
        dids.iter()
            .map(|&id| {
                let length = self.dids.iter().find(|did| did.id == id)?.length?;
                Some((id, usize::from(length)))
            })
            .collect()
    }

    /// How the module is addressed inside CAN frames.
    #[must_use]
    pub fn addressing(&self) -> Addressing {
        self.extended_address
            .map_or(Addressing::Normal, Addressing::Extended)
    }
}

/// A diagnostic protocol a module speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// UDS (ISO 14229) on ISO-TP.
    Uds,
    /// KWP2000 (ISO 14230) on ISO-TP. Nothing reads such a module yet.
    Kwp2000,
    /// VW TP2.0 transport with KWP2000. Nothing reads such a module yet (#142).
    Tp20,
}

/// A readable data identifier and how to show its value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidDef {
    /// The 2-byte identifier.
    pub id: u16,
    /// What it holds, e.g. `VW coding`.
    pub name: String,
    /// How to show the value.
    pub decode: Decode,
    /// The value's length in bytes, if the module always sends this many. It lets several DIDs
    /// be read in one request.
    #[serde(default)]
    pub length: Option<u16>,
    /// The diagnostic session the module reads it in: the default one unless the profile says
    /// `extended`.
    #[serde(default)]
    pub session: DidSession,
}

/// The diagnostic session a module reads a DID in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidSession {
    /// The session a module starts in.
    #[default]
    Default,
    /// The extended diagnostic session (`10 03`).
    Extended,
}

/// How to show a data identifier's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decode {
    /// Printable ASCII.
    Text,
    /// Raw bytes as hex.
    Hex,
}

/// Why a profile was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The text isn't valid TOML, has an unknown field, or a field has the wrong type.
    Toml(String),
    /// The bitrate isn't 250 or 500 kbit/s.
    Bitrate(u32),
    /// A CAN ID is outside 0x700..=0x7FF, or is the OBD-II broadcast ID 0x7DF.
    Id {
        /// The module it belongs to.
        module: String,
        /// The ID.
        id: u32,
    },
    /// Two modules, or one module's request and response, share a CAN ID without each having
    /// its own extended-address byte.
    DuplicateId(u32),
    /// Two modules share a name, ignoring case.
    DuplicateName(String),
    /// Two modules share a VAG address.
    DuplicateVagAddress(u8),
    /// A module lists the same DID twice.
    DuplicateDid {
        /// The module.
        module: String,
        /// The DID.
        did: u16,
    },
    /// A DID's length is 0: every DID value has at least one byte.
    DidLength {
        /// The module.
        module: String,
        /// The DID.
        did: u16,
    },
    /// A module lists a standard DID with another format than ISO 14229-1 gives it (see
    /// [`standard_decode`]).
    StandardDidFormat {
        /// The module.
        module: String,
        /// The DID.
        did: u16,
    },
    /// The profile, a module or a DID has an empty or blank name.
    EmptyName,
    /// A name starts or ends with spaces, so a lookup by its visible text wouldn't find it.
    PaddedName(String),
    /// No built-in profile has this name.
    UnknownBuiltin(String),
    /// A discovery range's first request ID is after its last.
    DiscoveryRange,
    /// The 29-bit discovery range holds more than [`Discovery29::MAX_IDS`] request IDs.
    Discovery29TooLong,
    /// The discovery range doesn't fit the modules: a candidate's request ID is a reply ID, is
    /// outside 0x700..=0x7FF, or is a module's request ID with another reply ID, and so on.
    Discovery(NarrowingError),
    /// The wide discovery range is empty, or isn't within the discovery range's reply IDs (the
    /// only IDs the first pass can show no module answers on), or goes past 0x7FF.
    WideDiscoveryRange,
    /// The TP2.0 discovery list has no address.
    EmptyTp20Discovery,
    /// The TP2.0 discovery list has address 0 (the tester's), or has this address twice.
    Tp20Address(u8),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(message) => write!(f, "invalid profile: {message}"),
            Self::Bitrate(bitrate) => {
                write!(f, "unsupported bitrate {bitrate} (use 250000 or 500000)")
            }
            Self::Id { module, id } => write!(
                f,
                "module {module}: CAN ID 0x{id:X} is outside 0x700..=0x7FF or is 0x7DF"
            ),
            Self::DuplicateId(id) => write!(f, "CAN ID 0x{id:03X} is used twice"),
            Self::DuplicateName(name) => write!(f, "module name {name} is used twice"),
            Self::DuplicateVagAddress(address) => {
                write!(f, "VAG address {address:02X} is used twice")
            }
            Self::DuplicateDid { module, did } => {
                write!(f, "module {module}: DID 0x{did:04X} is listed twice")
            }
            Self::DidLength { module, did } => {
                write!(f, "module {module}: DID 0x{did:04X}'s length can't be 0")
            }
            Self::StandardDidFormat { module, did } => write!(
                f,
                "module {module}: DID 0x{did:04X} is text in ISO 14229-1, so its decode must be text"
            ),
            Self::EmptyName => f.write_str("names can't be empty"),
            Self::PaddedName(name) => write!(f, "name {name:?} starts or ends with spaces"),
            Self::UnknownBuiltin(name) => write!(f, "no built-in profile named {name}"),
            Self::DiscoveryRange => {
                f.write_str("a discovery range's first request ID is after its last")
            }
            Self::Discovery29TooLong => write!(
                f,
                "discovery_29bit: the range holds more than {} request IDs",
                Discovery29::MAX_IDS
            ),
            Self::Discovery(e) => write!(f, "discovery: {e}"),
            Self::WideDiscoveryRange => f.write_str(
                "discovery: the wide range must lie within the discovery range's reply IDs",
            ),
            Self::EmptyTp20Discovery => f.write_str("TP2.0 discovery: no address is listed"),
            Self::Tp20Address(address) => write!(
                f,
                "TP2.0 discovery: address {address:02X} is the tester's or is listed twice"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

/// The ISO 14229-1 identification DIDs, which every module may have without a profile entry.
pub const STANDARD_DIDS: std::ops::RangeInclusive<u16> = 0xF180..=0xF19F;

/// How ISO 14229-1 says a standard identification DID is shown: [`Decode::Text`] for the VIN and
/// the part, software, hardware, system and ODX names. `None` for a DID that can hold any bytes
/// (dates, sessions, and so on) or isn't a standard one.
#[must_use]
pub fn standard_decode(did: u16) -> Option<Decode> {
    uds::did::is_text(did).then_some(Decode::Text)
}

const BITRATES: [u32; 2] = [250_000, 500_000];
const DIAGNOSTIC_IDS: std::ops::RangeInclusive<u32> = 0x700..=0x7FF;
const OBD_FUNCTIONAL_ID: u32 = 0x7DF;

impl Profile {
    /// The names [`Profile::builtin`] accepts.
    pub const BUILTIN: [&str; 1] = ["a7"];

    /// Parses and validates a profile.
    pub fn from_toml(text: &str) -> Result<Self, ProfileError> {
        let profile: Self = toml::from_str(text).map_err(|e| ProfileError::Toml(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// A profile shipped with the crate, by name (see [`Profile::BUILTIN`]).
    pub fn builtin(name: &str) -> Result<Self, ProfileError> {
        match name {
            "a7" => Self::from_toml(include_str!("../profiles/audi-a7-c7.toml")),
            _ => Err(ProfileError::UnknownBuiltin(name.to_owned())),
        }
    }

    /// The module with this name.
    #[must_use]
    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Narrows `policy` to this car's modules ([`Policy::narrowed_to`]) and TP2.0 channel setups
    /// to [`Profile::tp20_addresses`]. A profile can only narrow the policy, never widen it.
    ///
    /// # Errors
    ///
    /// The modules' IDs are inconsistent, as a profile built or changed by hand can be: a request
    /// ID that is also a reply ID, for example.
    pub fn narrow(&self, policy: Policy) -> Result<Policy, NarrowingError> {
        self.narrow_with(policy, &[])
    }

    /// Like [`Profile::narrow`], but also allows each of [`Profile::candidates`], so modules the
    /// profile doesn't list can be looked for.
    ///
    /// # Errors
    ///
    /// As [`Profile::narrow`], counting the candidates as modules.
    pub fn narrow_for_discovery(&self, policy: Policy) -> Result<Policy, NarrowingError> {
        self.narrow_with(policy, &self.candidates())
    }

    /// The addresses to try TP2.0 channel setups to, in order; none without a TP2.0 discovery
    /// list.
    #[must_use]
    pub fn tp20_addresses(&self) -> Vec<u8> {
        self.discovery_tp20
            .as_ref()
            .map_or_else(Vec::new, |discovery| discovery.addresses.clone())
    }

    /// Each request ID in the discovery range with its reply ID, in order; none without one.
    /// One whose reply ID is a listed module's request ID is left out, and so is one past 0x7FF.
    #[must_use]
    pub fn candidates(&self) -> Vec<ModuleIds> {
        let Some(discovery) = self.discovery else {
            return Vec::new();
        };
        let last = discovery.last_request_id.min(*DIAGNOSTIC_IDS.end());
        (discovery.first_request_id..=last)
            .map(|request| ModuleIds {
                request,
                reply: request.saturating_add(discovery.reply_offset),
            })
            .filter(|candidate| {
                self.modules
                    .iter()
                    .all(|module| module.request_id != candidate.reply)
            })
            .collect()
    }

    /// The second, wider pass's candidates ([`Discovery::wide_last_request_id`]): each request ID
    /// after the discovery range with its reply ID, in order, leaving out any whose request or
    /// reply ID a known module uses another way, any OBD-II ID (0x7DF..=0x7EF), and any whose
    /// reply is past 0x7FF. Known modules are the profile's and `found`, which should be
    /// everything the first pass found.
    #[must_use]
    pub fn wide_candidates(&self, found: &[ModuleIds]) -> Vec<ModuleIds> {
        let Some(Discovery {
            last_request_id,
            reply_offset,
            wide_last_request_id: Some(wide_last),
            ..
        }) = self.discovery
        else {
            return Vec::new();
        };
        let known: Vec<ModuleIds> = self
            .module_ids()
            .into_iter()
            .chain(found.iter().copied())
            .collect();
        let obd = 0x7DF..=0x7EF;
        (last_request_id.saturating_add(1)..=wide_last.min(*DIAGNOSTIC_IDS.end()))
            .map(|request| ModuleIds {
                request,
                reply: request.saturating_add(reply_offset),
            })
            .filter(|candidate| {
                DIAGNOSTIC_IDS.contains(&candidate.reply)
                    && !obd.contains(&candidate.request)
                    && !obd.contains(&candidate.reply)
                    && known.iter().all(|module| {
                        *module == *candidate
                            || (module.reply != candidate.request
                                && module.request != candidate.reply
                                && module.request != candidate.request
                                && module.reply != candidate.reply)
                    })
            })
            .collect()
    }

    /// The first pass's candidates to look for again, more patiently, before the wide pass:
    /// those not in `found` whose reply ID one of [`Profile::wide_candidates`]`(found)` would be
    /// sent to. Finding such a module first keeps the wide pass off its reply ID.
    #[must_use]
    pub fn recheck_candidates(&self, found: &[ModuleIds]) -> Vec<ModuleIds> {
        let wide = self.wide_candidates(found);
        self.candidates()
            .into_iter()
            .filter(|candidate| {
                !found.contains(candidate) && wide.iter().any(|w| w.request == candidate.reply)
            })
            .collect()
    }

    /// Each request ID in the 29-bit discovery range with its reply ID, in order; none without
    /// one.
    #[must_use]
    pub fn candidates_29bit(&self) -> Vec<ModuleIds> {
        let Some(discovery) = self.discovery_29bit else {
            return Vec::new();
        };
        (discovery.first_request_id..=discovery.last_request_id)
            .take(Discovery29::MAX_IDS as usize)
            .map(|request| ModuleIds {
                request,
                reply: request.saturating_add(discovery.reply_offset),
            })
            .collect()
    }

    /// Like [`Profile::narrow`], but also allows `extra`: modules discovery found, or candidates
    /// to look for.
    ///
    /// # Errors
    ///
    /// As [`Profile::narrow`], counting `extra` as modules.
    pub fn narrow_with(
        &self,
        policy: Policy,
        extra: &[ModuleIds],
    ) -> Result<Policy, NarrowingError> {
        let mut modules = self.module_ids();
        modules.extend_from_slice(extra);
        Ok(policy
            .narrowed_to(&modules)?
            .narrowed_to_tp20(&self.tp20_addresses()))
    }

    fn module_ids(&self) -> Vec<ModuleIds> {
        self.modules
            .iter()
            .map(|module| ModuleIds {
                request: module.request_id,
                reply: module.response_id,
            })
            .collect()
    }

    /// Checks everything [`Profile::from_toml`] checks. Call it after building or changing a
    /// profile by hand.
    pub fn validate(&self) -> Result<(), ProfileError> {
        let names = std::iter::once(&self.name).chain(
            self.modules
                .iter()
                .flat_map(|m| std::iter::once(&m.name).chain(m.dids.iter().map(|did| &did.name))),
        );
        for name in names {
            if name.trim().is_empty() {
                return Err(ProfileError::EmptyName);
            }
            if name.trim() != name {
                return Err(ProfileError::PaddedName(name.clone()));
            }
        }
        if !BITRATES.contains(&self.bitrate) {
            return Err(ProfileError::Bitrate(self.bitrate));
        }
        // A CAN ID is shared only by modules that each have their own extended-address byte.
        let mut ids: HashMap<u32, Vec<Option<u8>>> = HashMap::new();
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for module in &self.modules {
            for id in [module.request_id, module.response_id] {
                if !DIAGNOSTIC_IDS.contains(&id) || id == OBD_FUNCTIONAL_ID {
                    return Err(ProfileError::Id {
                        module: module.name.clone(),
                        id,
                    });
                }
                let users = ids.entry(id).or_default();
                let sub = module.extended_address;
                if users
                    .iter()
                    .any(|&other| other.is_none() || sub.is_none() || other == sub)
                {
                    return Err(ProfileError::DuplicateId(id));
                }
                users.push(sub);
            }
            // Names that differ only in case count as the same.
            if !names.insert(module.name.to_lowercase()) {
                return Err(ProfileError::DuplicateName(module.name.clone()));
            }
            if let Some(address) = module.vag_address
                && !addresses.insert(address)
            {
                return Err(ProfileError::DuplicateVagAddress(address));
            }
            let mut dids = HashSet::new();
            for did in &module.dids {
                if standard_decode(did.id).is_some_and(|decode| decode != did.decode) {
                    return Err(ProfileError::StandardDidFormat {
                        module: module.name.clone(),
                        did: did.id,
                    });
                }
                if did.length == Some(0) {
                    return Err(ProfileError::DidLength {
                        module: module.name.clone(),
                        did: did.id,
                    });
                }
                if !dids.insert(did.id) {
                    return Err(ProfileError::DuplicateDid {
                        module: module.name.clone(),
                        did: did.id,
                    });
                }
            }
        }
        if let Some(discovery) = self.discovery {
            self.validate_discovery(discovery)?;
        }
        if let Some(discovery) = self.discovery_29bit {
            Self::validate_29_bit_discovery(discovery)?;
            self.narrow_with(Policy::read_only(), &self.candidates_29bit())
                .map_err(ProfileError::Discovery)?;
        }
        if let Some(discovery) = &self.discovery_tp20 {
            if discovery.addresses.is_empty() {
                return Err(ProfileError::EmptyTp20Discovery);
            }
            let mut seen = HashSet::new();
            for &address in &discovery.addresses {
                if address == 0 || !seen.insert(address) {
                    return Err(ProfileError::Tp20Address(address));
                }
            }
        }
        Ok(())
    }

    fn validate_29_bit_discovery(discovery: Discovery29) -> Result<(), ProfileError> {
        let Discovery29 {
            first_request_id: first,
            last_request_id: last,
            reply_offset,
        } = discovery;
        if first > last {
            return Err(ProfileError::DiscoveryRange);
        }
        if last - first >= Discovery29::MAX_IDS {
            return Err(ProfileError::Discovery29TooLong);
        }
        for request in first..=last {
            // An 11-bit ID is no 29-bit candidate, whatever the policy says about it.
            if request <= *DIAGNOSTIC_IDS.end() {
                return Err(ProfileError::Discovery(NarrowingError::Request(request)));
            }
            let candidate = ModuleIds {
                request,
                reply: request.saturating_add(reply_offset),
            };
            Policy::read_only()
                .narrowed_to(&[candidate])
                .map_err(ProfileError::Discovery)?;
        }
        Ok(())
    }

    fn validate_discovery(&self, discovery: Discovery) -> Result<(), ProfileError> {
        if discovery.first_request_id > discovery.last_request_id {
            return Err(ProfileError::DiscoveryRange);
        }
        // `candidates` stops at 0x7FF, so one past it is refused here.
        if discovery.last_request_id > *DIAGNOSTIC_IDS.end() {
            return Err(ProfileError::Discovery(NarrowingError::Request(
                discovery.last_request_id,
            )));
        }
        // Check every ID, not only what `candidates` keeps. A reply ID that is a listed module's
        // request ID is allowed: that is a module found past the range, then listed.
        for request in discovery.first_request_id..=discovery.last_request_id {
            let candidate = ModuleIds {
                request,
                reply: request.saturating_add(discovery.reply_offset),
            };
            Policy::read_only()
                .narrowed_to(&[candidate])
                .map_err(ProfileError::Discovery)?;
            if self
                .modules
                .iter()
                .any(|module| module.response_id == request)
            {
                return Err(ProfileError::Discovery(NarrowingError::RequestIsReply(
                    request,
                )));
            }
        }
        self.narrow_for_discovery(Policy::read_only())
            .map_err(ProfileError::Discovery)?;
        if let Some(wide_last) = discovery.wide_last_request_id {
            // Only IDs the first pass listened on for a reply can be checked by it.
            let first_replies = discovery
                .first_request_id
                .saturating_add(discovery.reply_offset)
                ..=discovery
                    .last_request_id
                    .saturating_add(discovery.reply_offset);
            let wide = discovery.last_request_id.saturating_add(1)..=wide_last;
            if wide.is_empty()
                || !first_replies.contains(wide.start())
                || !first_replies.contains(wide.end())
                || wide_last > *DIAGNOSTIC_IDS.end()
            {
                return Err(ProfileError::WideDiscoveryRange);
            }
            self.narrow_with(Policy::read_only(), &self.wide_candidates(&[]))
                .map_err(ProfileError::Discovery)?;
        }
        Ok(())
    }
}
