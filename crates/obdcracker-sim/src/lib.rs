//! Simulated ECUs for tests. Nothing here touches hardware.
//!
//! A [`SimBus`] is a [`Transport`] whose modules come from a vehicle profile (where each module
//! sits) and a fixture file (what each module answers). Requests reach it the same way they reach
//! a real adapter: only as [`Approved`] requests. See [`docs/fixtures.md`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/fixtures.md) for the fixture format.
//!
//! ```
//! use std::time::Duration;
//!
//! use obdcracker_core::obd;
//! use obdcracker_safety::{Policy, Protocol, Target};
//! use obdcracker_sim::SimBus;
//! use obdcracker_transport::Transport;
//!
//! let mut car = SimBus::builtin("a7").unwrap();
//! let vin = Policy::read_only()
//!     .approve(Protocol::Uds, Target::ObdFunctional, &obd::vehicle_info(0x02))
//!     .unwrap();
//! car.send(&vin).unwrap();
//! let reply = car.recv(Duration::from_millis(50)).unwrap();
//! assert_eq!(reply.source, 0x7E8);
//! assert_eq!(obd::decode_vin(&reply.payload).unwrap(), "WAU2MBFC6EN093415");
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use obdcracker_core::isotp::Addressing;
use obdcracker_core::tp20::{self, Channel};
use obdcracker_core::{obd, response, uds};
use obdcracker_profile::{Decode, Profile, ProfileError, Protocol, STANDARD_DIDS, standard_decode};
use obdcracker_safety::{Approved, Policy, Target, Tier};
use obdcracker_transport::{Error, Response, Transport};
use tp20_module::Tp20Module;

mod ecu;
mod fixture;
mod tp20_module;

pub use ecu::{Ecu, Fault, Session};

/// Why a simulated car couldn't be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// The fixture isn't valid TOML, has an unknown field, or a field has the wrong type.
    Toml(String),
    /// The vehicle profile is invalid (including one built by hand) or unknown.
    Profile(ProfileError),
    /// The fixture names a module the profile doesn't have.
    UnknownModule(String),
    /// The fixture lists a module twice.
    DuplicateModule(String),
    /// The module can't be simulated yet: only UDS modules with normal addressing can.
    UnsupportedModule(String),
    /// A value doesn't fit its format, such as a VIN that isn't 17 characters.
    Value(String),
    /// The module has OBD-II data but isn't on an OBD-II ID pair (requests 0x7E0..=0x7E7,
    /// replies at the request ID + 8).
    NotObd(String),
    /// A DID that is neither a standard identification DID (0xF180..=0xF19F) nor listed for the
    /// module in its profile (a `[[module.did]]`, or a table of its `[gateway_list]`).
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
            Self::NotObd(name) => write!(
                f,
                "module {name} has OBD-II data but isn't on an OBD-II ID pair (0x7E0..=0x7E7 / +8)"
            ),
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
/// A module leaves a non-default diagnostic session after S3 without a request: 5 s, as
/// ISO 14229-2 gives it, unless [`Ecu::set_s3`] changes it.
/// A VW TP2.0 module ([`SimBus::add_tp20`]) answers a channel setup to its address, and on the
/// channel it gave: the tester's parameters and keep-alives (with its own: block size 15, T1
/// 100 ms, T3 5 ms), KWP2000 requests ([`SimBus::add_tp20_answer`]) in data frames that wait for
/// the tester's ACK after each block of the tester's block size, and the disconnect, once. A
/// request it has no answer for gets `7F <service> 31` if it answers that service otherwise,
/// else `7F <service> 11`.
#[derive(Debug)]
pub struct SimBus {
    ecus: Vec<Ecu>,
    tp20: Vec<Tp20Module>,
    sent: Vec<Approved>,
    replies: VecDeque<Response>,
}

impl SimBus {
    /// Builds the modules `fixture` describes, at the addresses `profile` gives them.
    pub fn new(profile: &Profile, fixture: &str) -> Result<Self, FixtureError> {
        profile.validate()?;
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
            for did in &dids {
                let def = module.dids.iter().find(|d| d.id == did.id);
                let list_table = profile.gateway_list_module().is_some_and(|(owner, list)| {
                    owner.name == module.name
                        && (did.id == list.addresses || Some(did.id) == list.request_ids)
                });
                if def.is_none() && !list_table && !STANDARD_DIDS.contains(&did.id) {
                    return Err(FixtureError::UnknownDid {
                        module: spec.module,
                        did: did.id,
                    });
                }
                let Ok(data) = &did.data else {
                    continue;
                };
                // A standard DID keeps its ISO 14229-1 format even when the profile lists it.
                let text = standard_decode(did.id) == Some(Decode::Text)
                    || def.is_some_and(|def| def.decode == Decode::Text);
                let fits = if did.id == uds::did::VIN {
                    obd::check_vin(data).is_ok() || obd::is_vin_placeholder(data)
                } else {
                    // Text that is only padding decodes as empty.
                    !text || uds::decode_text(data).is_ok_and(|text| !text.is_empty())
                };
                if !fits {
                    return Err(FixtureError::Value(format!(
                        "module {}: DID 0x{:04X} doesn't have its format",
                        spec.module, did.id
                    )));
                }
                // A multi-DID read is split by the profile's lengths, so the value must match.
                if let Some(length) = def.and_then(|def| def.length)
                    && data.len() != usize::from(length)
                {
                    return Err(FixtureError::Value(format!(
                        "module {}: DID 0x{:04X} is {} bytes, but the profile says {length}",
                        spec.module,
                        did.id,
                        data.len()
                    )));
                }
            }
            let obd = spec.obd()?;
            let obd_ids = (0x7E0..=0x7E7).contains(&module.request_id)
                && module.response_id == module.request_id + 8;
            if obd.is_some() && !obd_ids {
                return Err(FixtureError::NotObd(spec.module));
            }
            ecus.push(Ecu {
                request_id: module.request_id,
                response_id: module.response_id,
                obd,
                dids,
                dtc: spec.dtc_service()?,
                raw: spec.raw()?,
                session: Session::Default,
                fault: None,
                s3: ecu::S3_DEFAULT,
                last_request: Instant::now(),
                name: spec.module,
            });
        }
        Ok(Self {
            ecus,
            tp20: Vec::new(),
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

    /// Adds a VW TP2.0 module at `address` that gives `channel` to a channel setup.
    ///
    /// # Errors
    ///
    /// [`FixtureError::Value`] for an address no setup may go to (0, the tester's, or a broadcast
    /// address from 0xF0), one already taken, or a channel a setup reply can't carry (its receive
    /// ID must be 0x300, the one the setup asks for) or whose send ID another module already uses.
    pub fn add_tp20(&mut self, address: u8, channel: Channel) -> Result<(), FixtureError> {
        let reply = setup_reply(channel);
        if Policy::read_only().approve_tp20_setup(address).is_err()
            || tp20::decode_channel_setup(&reply) != Ok(channel)
        {
            return Err(FixtureError::Value(format!(
                "TP2.0 module {address:02X}: no setup reply gives {channel:X?}"
            )));
        }
        let ids = [channel.send_id, channel.receive_id];
        // Every module answers the tester on 0x300, so only the send IDs must differ.
        let taken =
            self.tp20.iter().any(|module| {
                module.address == address || module.channel.send_id == channel.send_id
            }) || self
                .ecus
                .iter()
                .any(|ecu| ids.contains(&ecu.request_id) || ids.contains(&ecu.response_id))
                || ids.iter().any(|id| (0x7DF..=0x7EF).contains(id));
        if taken {
            return Err(FixtureError::Value(format!(
                "TP2.0 module {address:02X}: the address or {channel:X?} is taken"
            )));
        }
        self.tp20.push(Tp20Module::new(address, channel));
        Ok(())
    }

    /// Makes the TP2.0 module at `address` answer the KWP2000 `request` with `answer`.
    ///
    /// # Errors
    ///
    /// [`FixtureError::Value`] if there's no TP2.0 module at `address`, the request isn't a
    /// read the policy would send on a channel or is given twice, or `answer` doesn't answer it
    /// ([`response::kwp2000_answers`]), is response-pending, or is longer than 65535 bytes.
    pub fn add_tp20_answer(
        &mut self,
        address: u8,
        request: &[u8],
        answer: &[u8],
    ) -> Result<(), FixtureError> {
        let fault = |why: &str| {
            Err(FixtureError::Value(format!(
                "TP2.0 module {address:02X}: {why} ({request:02X?} -> {answer:02X?})"
            )))
        };
        let Some(module) = self.tp20.iter_mut().find(|m| m.address == address) else {
            return fault("no such module");
        };
        let read = Policy::read_only()
            .approve(
                obdcracker_safety::Protocol::Kwp2000,
                Target::Physical(0x7E0),
                request,
            )
            .is_ok_and(|approved| approved.tier() == Tier::Read);
        if !read || request.len() > tp20::MAX_SINGLE_FRAME {
            return fault("not a read that fits one frame");
        }
        if module.answers.iter().any(|(asked, _)| asked == request) {
            return fault("the request is given twice");
        }
        let pending = answer.len() == 3 && answer[0] == 0x7F && answer[2] == 0x78;
        if !response::kwp2000_answers(request, answer) || pending || answer.len() > 0xFFFF {
            return fault("not an answer to it");
        }
        module.answers.push((request.to_vec(), answer.to_vec()));
        Ok(())
    }

    /// Makes the adapter lose frame `index` (from 0) of the next answer the TP2.0 module at
    /// `address` sends, as an ELM327 does with a frame that arrives between its prompt and the
    /// next line. Does nothing if there's no module there.
    pub fn lose_tp20_frame(&mut self, address: u8, index: usize) {
        if let Some(module) = self.tp20.iter_mut().find(|m| m.address == address) {
            module.lose = Some(index);
        }
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
        match request.target() {
            Target::Tp20Setup(address) => {
                if let Some(module) = self.tp20.iter_mut().find(|m| m.address == address) {
                    module.open();
                    self.replies.push_back(Response {
                        source: tp20::setup_reply_id(address),
                        payload: setup_reply(module.channel).to_vec(),
                    });
                }
                return Ok(());
            }
            Target::Tp20Channel(id) => {
                let module = self
                    .tp20
                    .iter_mut()
                    .find(|m| m.open && m.channel.send_id == id);
                if let Some(module) = module {
                    let source = module.channel.receive_id;
                    for payload in module.hear(request.payload()) {
                        self.replies.push_back(Response { source, payload });
                    }
                }
                return Ok(());
            }
            Target::ObdFunctional | Target::Physical(_) | Target::Physical29(_) => {}
        }
        let functional = request.target() == Target::ObdFunctional;
        for ecu in &mut self.ecus {
            let listens = match request.target() {
                Target::ObdFunctional => ecu.has_obd(),
                // A profile's IDs say their width, so an 11-bit ID never matches a 29-bit one.
                Target::Physical(id) | Target::Physical29(id) => ecu.request_id == id,
                Target::Tp20Setup(_) | Target::Tp20Channel(_) => false,
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

// A positive answer to a channel setup that gives `channel`, for KWP2000.
fn setup_reply(channel: Channel) -> [u8; 7] {
    // An ID past 16 bits loses its top bytes here, so `add_tp20`'s round trip refuses it.
    let [rx_low, rx_high, ..] = channel.receive_id.to_le_bytes();
    let [tx_low, tx_high, ..] = channel.send_id.to_le_bytes();
    [0x00, 0xD0, rx_low, rx_high, tx_low, tx_high, 0x01]
}
