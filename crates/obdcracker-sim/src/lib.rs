//! Simulated ECUs for tests. Nothing here touches hardware.
//!
//! A [`SimBus`] is a [`Transport`] whose modules come from a vehicle profile (where each module
//! sits) and a fixture file (what each module answers). Requests reach it the same way they reach
//! a real adapter: only as [`Approved`] requests.
//!
//! ```
//! use std::time::Duration;
//!
//! use obdcracker_core::obd;
//! use obdcracker_safety::{Policy, Target};
//! use obdcracker_sim::SimBus;
//! use obdcracker_transport::Transport;
//!
//! let mut car = SimBus::builtin("a7").unwrap();
//! let vin = Policy::read_only()
//!     .approve(Target::ObdFunctional, &obd::vehicle_info(0x02))
//!     .unwrap();
//! car.send(&vin).unwrap();
//! let reply = car.recv(Duration::from_millis(50)).unwrap();
//! assert_eq!(reply.source, 0x7E8);
//! assert_eq!(obd::decode_vin(&reply.payload).unwrap(), "WAUZZZ4G1EN000000");
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use obdcracker_core::isotp::Addressing;
use obdcracker_profile::{Profile, ProfileError, Protocol};
use obdcracker_safety::{Approved, Target};
use obdcracker_transport::{Error, Response, Transport};

mod ecu;
mod fixture;

pub use ecu::{Ecu, Fault, Session};

/// Why a simulated car couldn't be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// The fixture isn't valid TOML, has an unknown field, or a field has the wrong type.
    Toml(String),
    /// The vehicle profile is invalid or unknown.
    Profile(ProfileError),
    /// The fixture names a module the profile doesn't have.
    UnknownModule(String),
    /// The fixture lists a module twice.
    DuplicateModule(String),
    /// The module can't be simulated yet: only UDS modules with normal addressing can.
    UnsupportedModule(String),
    /// A value doesn't fit its format, such as a VIN that isn't 17 characters.
    Value(String),
    /// A DID that is neither a standard identification DID (0xF180..=0xF19F) nor listed for the
    /// module in its profile.
    UnknownDid {
        /// The module.
        module: String,
        /// The DID.
        did: u16,
    },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(message) => write!(f, "invalid fixture: {message}"),
            Self::Profile(e) => e.fmt(f),
            Self::UnknownModule(name) => write!(f, "the profile has no module named {name}"),
            Self::DuplicateModule(name) => write!(f, "module {name} is listed twice"),
            Self::UnsupportedModule(name) => write!(
                f,
                "module {name}: only UDS modules with normal addressing can be simulated"
            ),
            Self::Value(message) => write!(f, "invalid fixture value: {message}"),
            Self::UnknownDid { module, did } => write!(
                f,
                "module {module}: DID 0x{did:04X} isn't standard or in the profile"
            ),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<ProfileError> for FixtureError {
    fn from(e: ProfileError) -> Self {
        Self::Profile(e)
    }
}

/// A simulated car: every module in a fixture, answering on the IDs its profile gives it.
///
/// A broadcast OBD-II request is answered by every module with OBD-II data, in fixture order.
/// A request to an ID no module listens on gets no reply.
#[derive(Debug)]
pub struct SimBus {
    ecus: Vec<Ecu>,
    sent: Vec<Approved>,
    replies: VecDeque<Response>,
}

// ISO 14229-1 identification DIDs, which every module may have without a profile entry.
const STANDARD_DIDS: std::ops::RangeInclusive<u16> = 0xF180..=0xF19F;

impl SimBus {
    /// Builds the modules `fixture` describes, at the addresses `profile` gives them.
    pub fn new(profile: &Profile, fixture: &str) -> Result<Self, FixtureError> {
        let file: fixture::FixtureFile =
            toml::from_str(fixture).map_err(|e| FixtureError::Toml(e.to_string()))?;
        let mut ecus: Vec<Ecu> = Vec::new();
        for spec in file.ecus {
            let module = profile
                .module(&spec.module)
                .ok_or_else(|| FixtureError::UnknownModule(spec.module.clone()))?;
            // Approved requests carry no extended-address byte yet, so only normal addressing.
            if module.protocol != Protocol::Uds || module.addressing() != Addressing::Normal {
                return Err(FixtureError::UnsupportedModule(spec.module));
            }
            if ecus.iter().any(|ecu| ecu.name == spec.module) {
                return Err(FixtureError::DuplicateModule(spec.module));
            }
            let dids = spec.dids()?;
            if let Some(did) = dids.iter().find(|did| {
                !STANDARD_DIDS.contains(&did.id) && !module.dids.iter().any(|d| d.id == did.id)
            }) {
                return Err(FixtureError::UnknownDid {
                    module: spec.module,
                    did: did.id,
                });
            }
            ecus.push(Ecu {
                request_id: module.request_id,
                response_id: module.response_id,
                obd: spec.obd()?,
                dids,
                dtcs: spec.dtcs()?,
                dtc_format: spec.dtc_format,
                session: Session::Default,
                fault: None,
                name: spec.module,
            });
        }
        Ok(Self {
            ecus,
            sent: Vec::new(),
            replies: VecDeque::new(),
        })
    }

    /// A simulated car shipped with the crate, by its profile's name (see [`Profile::BUILTIN`]).
    pub fn builtin(name: &str) -> Result<Self, FixtureError> {
        let fixture = match name {
            "a7" => include_str!("../fixtures/a7.toml"),
            _ => return Err(ProfileError::UnknownBuiltin(name.to_owned()).into()),
        };
        Self::new(&Profile::builtin(name)?, fixture)
    }

    /// The simulated module with this profile name.
    #[must_use]
    pub fn ecu(&self, name: &str) -> Option<&Ecu> {
        self.ecus.iter().find(|ecu| ecu.name == name)
    }

    /// The simulated module with this profile name, to change its behaviour.
    pub fn ecu_mut(&mut self, name: &str) -> Option<&mut Ecu> {
        self.ecus.iter_mut().find(|ecu| ecu.name == name)
    }

    /// Every request sent so far, oldest first.
    #[must_use]
    pub fn sent(&self) -> &[Approved] {
        &self.sent
    }
}

impl Transport for SimBus {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.sent.push(request.clone());
        let functional = request.target() == Target::ObdFunctional;
        for ecu in &mut self.ecus {
            let listens = match request.target() {
                Target::ObdFunctional => ecu.has_obd(),
                Target::Physical(id) => ecu.request_id == id,
            };
            if !listens {
                continue;
            }
            for payload in ecu.answer(request.payload(), functional) {
                self.replies.push_back(Response {
                    source: ecu.response_id,
                    payload,
                });
            }
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}
