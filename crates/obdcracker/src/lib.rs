//! Talk to a car's diagnostic bus through any adapter, safely.
//!
//! This crate re-exports the OBDCracker crates, so a project needs only this one dependency.
//! Everything sent goes through [`safety::Policy`]: a transport only accepts an
//! [`safety::Approved`] request, and nothing outside the policy can create one.
//!
//! ```
//! use std::time::Duration;
//!
//! use obdcracker::core::obd;
//! use obdcracker::safety::{Policy, Target};
//! use obdcracker::transport::{DryRun, Mock, Response, Transport};
//!
//! // Ask every emissions ECU for the VIN (OBD-II mode 09 PID 02).
//! let vin = Policy::read_only()
//!     .approve(Target::ObdFunctional, &obd::vehicle_info(0x02))
//!     .unwrap();
//! let mut adapter = DryRun::new(Vec::new());
//! adapter.send(&vin).unwrap();
//! assert_eq!(adapter.into_inner(), b"7DF 02 09 02\n");
//!
//! // Decode the reply. Here a mock adapter plays the engine ECU.
//! let mut adapter = Mock::default();
//! adapter.queue(Response {
//!     source: 0x7E8,
//!     payload: b"\x49\x02\x01WAUZZZ4G1EN000000".to_vec(),
//! });
//! adapter.send(&vin).unwrap();
//! let reply = adapter.recv(Duration::from_secs(1)).unwrap();
//! assert_eq!(obd::decode_vin(&reply.payload).unwrap(), "WAUZZZ4G1EN000000");
//!
//! // Flashing requests are refused at every tier.
//! assert!(Policy::read_only().approve(Target::Physical(0x7E0), &[0x10, 0x02]).is_err());
//! ```

pub use obdcracker_core as core;
pub use obdcracker_safety as safety;
#[cfg(feature = "sim")]
pub use obdcracker_sim as sim;
pub use obdcracker_transport as transport;

// Compiles the README's Rust examples as doctests, so they can't drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
struct ReadmeDoctests;
