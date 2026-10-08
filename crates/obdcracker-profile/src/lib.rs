//! Vehicle profiles: the manufacturer specifics of one car, as data.
//!
//! A profile says where each module sits on the bus (request and response CAN IDs, addressing,
//! protocol) and which identifiers it can read and how to show them. OBD-II needs no profile.
//!
//! A profile can only narrow what the safety policy allows, never widen it: it has no field that
//! names a service, so every request to a profile's module still goes through
//! `obdcracker_safety::Policy::approve`.
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
use serde::Deserialize;

/// One car's profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// What car this is, e.g. `2014 Audi A7 3.0 TDI (C7)`.
    pub name: String,
    /// The diagnostic CAN bus's bitrate in bit/s. It is fixed per car, since a wrong bitrate can
    /// flood the bus with error frames.
    pub bitrate: u32,
    /// The modules on the bus.
    #[serde(rename = "module", default)]
    pub modules: Vec<Module>,
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
    /// KWP2000 (ISO 14230) on ISO-TP. Not supported until the policy is protocol-aware.
    Kwp2000,
    /// VW TP2.0 transport with KWP2000. Not supported until the policy is protocol-aware.
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
    /// Two modules share a name.
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
    /// No built-in profile has this name.
    UnknownBuiltin(String),
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
            Self::StandardDidFormat { module, did } => write!(
                f,
                "module {module}: DID 0x{did:04X} is text in ISO 14229-1, so its decode must be text"
            ),
            Self::EmptyName => f.write_str("names can't be empty"),
            Self::UnknownBuiltin(name) => write!(f, "no built-in profile named {name}"),
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
    const TEXT: [u16; 7] = [
        uds::did::SPARE_PART_NUMBER,
        uds::did::SOFTWARE_NUMBER,
        uds::did::SOFTWARE_VERSION,
        uds::did::VIN,
        uds::did::HARDWARE_NUMBER,
        0xF197, // system name or engine type
        uds::did::ODX_FILE,
    ];
    TEXT.contains(&did).then_some(Decode::Text)
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

    /// Checks everything [`Profile::from_toml`] checks. Call it after building or changing a
    /// profile by hand.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.name.trim().is_empty() || self.modules.iter().any(|m| m.name.trim().is_empty()) {
            return Err(ProfileError::EmptyName);
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
            if !names.insert(module.name.as_str()) {
                return Err(ProfileError::DuplicateName(module.name.clone()));
            }
            if let Some(address) = module.vag_address
                && !addresses.insert(address)
            {
                return Err(ProfileError::DuplicateVagAddress(address));
            }
            let mut dids = HashSet::new();
            for did in &module.dids {
                if did.name.trim().is_empty() {
                    return Err(ProfileError::EmptyName);
                }
                if standard_decode(did.id).is_some_and(|decode| decode != did.decode) {
                    return Err(ProfileError::StandardDidFormat {
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
        Ok(())
    }
}
