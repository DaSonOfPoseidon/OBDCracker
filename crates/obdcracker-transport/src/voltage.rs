//! Stopping a long run of reads when the battery goes flat: a [`VoltageWatch`] that
//! [`crate::sweep::sweep_dids`] and [`crate::discover::discover_with`] take as an option. See
//! [`docs/safety.md#supply-voltage`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/safety.md#supply-voltage).

use std::fmt;
use std::num::NonZeroUsize;

use obdcracker_safety::{SupplyVoltage, VoltageCheck, VoltageThresholds};

use crate::Error;

/// How often the CLI re-checks: every 50 requests.
pub const DEFAULT_INTERVAL: NonZeroUsize = NonZeroUsize::new(50).unwrap();

/// Re-reads the supply voltage ([`crate::Transport::supply_voltage`]) every `interval` requests of
/// a long run, and stops the run when it is [`VoltageCheck::TooLow`].
///
/// The count is of the run's own requests: a session's keepalives aren't counted. The first
/// check is once `interval` requests have been sent and another is still to send, so a run of
/// `interval` requests or fewer is never checked: the caller's own check before the run covers
/// it. A voltage that is
/// unknown, or couldn't be read, doesn't stop the run: a transport that can't measure it
/// (`gs_usb`, SocketCAN) would otherwise never finish one.
///
/// A run never checks inside a TP2.0 channel or an ELM327's monitor: the driver reports no
/// voltage there ([`crate::elm::Elm`]), and TP2.0 discovery isn't watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VoltageWatch {
    /// Where the voltage counts as too low to go on: [`VoltageThresholds::refuse_mv`].
    pub thresholds: VoltageThresholds,
    /// How many requests between checks.
    pub interval: NonZeroUsize,
}

impl VoltageWatch {
    /// A watch with the default thresholds ([`VoltageThresholds::DEFAULT`]) that checks every
    /// `interval` requests.
    #[must_use]
    pub fn every(interval: NonZeroUsize) -> Self {
        Self {
            thresholds: VoltageThresholds::DEFAULT,
            interval,
        }
    }

    // Reads the voltage after `done` requests of the run if a check is due, and says whether it
    // is too low. An error counts as unknown: a transport whose adapter can no longer be trusted
    // fails the run's next request anyway.
    pub(crate) fn stop_after(
        &self,
        done: usize,
        read: impl FnOnce() -> Result<SupplyVoltage, Error>,
    ) -> Option<LowVoltage> {
        if done == 0 || !done.is_multiple_of(self.interval.get()) {
            return None;
        }
        match read() {
            Ok(supply @ SupplyVoltage::Known { millivolts })
                if self.thresholds.check(supply) == VoltageCheck::TooLow =>
            {
                Some(LowVoltage {
                    after: done,
                    millivolts,
                })
            }
            _ => None,
        }
    }
}

impl Default for VoltageWatch {
    fn default() -> Self {
        Self::every(DEFAULT_INTERVAL)
    }
}

/// Why a run stopped: the supply voltage was too low when it was re-checked.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowVoltage {
    /// How many of the run's requests had been sent: the run stopped before the next one.
    pub after: usize,
    /// The voltage it read, in millivolts.
    pub millivolts: u32,
}

impl fmt::Display for LowVoltage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the supply voltage fell to {} after {} requests",
            SupplyVoltage::Known {
                millivolts: self.millivolts
            },
            self.after
        )
    }
}
