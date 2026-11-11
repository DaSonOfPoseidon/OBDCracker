//! Conditions the car has to be in before something long or risky is sent: the first is a steady
//! supply voltage. See [`docs/safety.md#supply-voltage`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/safety.md#supply-voltage).

use std::fmt;

/// The voltage an adapter sees on the OBD port, which is the car's battery or alternator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyVoltage {
    /// The adapter reported it.
    Known {
        /// The voltage in millivolts.
        millivolts: u32,
    },
    /// The adapter can't measure it, didn't answer, or answered something unreadable.
    Unknown,
}

impl fmt::Display for SupplyVoltage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known { millivolts } => {
                let (volts, rest) = (millivolts / 1000, millivolts % 1000);
                if rest == 0 {
                    write!(f, "{volts} V")
                } else {
                    let digits = format!("{rest:03}");
                    write!(f, "{volts}.{} V", digits.trim_end_matches('0'))
                }
            }
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Where a supply voltage counts as low and as too low, in millivolts. A voltage under
/// `warn_mv` is [`VoltageCheck::Low`]; under `refuse_mv` it is [`VoltageCheck::TooLow`]. A
/// voltage equal to a threshold is on its good side: exactly `warn_mv` is [`VoltageCheck::Ok`]
/// and exactly `refuse_mv` is [`VoltageCheck::Low`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoltageThresholds {
    /// Below this the battery is low: a long session may drain it.
    pub warn_mv: u32,
    /// Below this the battery is too low to start something long.
    pub refuse_mv: u32,
}

impl VoltageThresholds {
    /// 12.2 V to warn and 11.8 V to refuse, for a 12 V car with the engine off. Provisional.
    pub const DEFAULT: Self = Self {
        warn_mv: 12_200,
        refuse_mv: 11_800,
    };

    /// How `supply` compares with these thresholds. [`SupplyVoltage::Unknown`] is always
    /// [`VoltageCheck::Unknown`].
    #[must_use]
    pub fn check(&self, supply: SupplyVoltage) -> VoltageCheck {
        match supply {
            SupplyVoltage::Unknown => VoltageCheck::Unknown,
            SupplyVoltage::Known { millivolts } if millivolts < self.refuse_mv => {
                VoltageCheck::TooLow
            }
            SupplyVoltage::Known { millivolts } if millivolts < self.warn_mv => VoltageCheck::Low,
            SupplyVoltage::Known { .. } => VoltageCheck::Ok,
        }
    }
}

impl Default for VoltageThresholds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What [`VoltageThresholds::check`] made of a supply voltage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoltageCheck {
    /// At or above the warning threshold.
    Ok,
    /// Below the warning threshold, at or above the refusal one.
    Low,
    /// Below the refusal threshold.
    TooLow,
    /// The voltage wasn't known, so nothing can be said about it.
    Unknown,
}

/// Something that has to hold before a request that could harm the car, or a long run of them.
///
/// A later tier unlocks only with its preconditions met, so an unknown state must never pass:
/// `satisfied` is true only for a state that was measured and found good.
pub trait Precondition {
    /// What must hold, for a message that says what failed.
    fn describe(&self) -> &'static str;

    /// Whether it holds. False when it couldn't be checked.
    fn satisfied(&self) -> bool;
}

impl Precondition for VoltageCheck {
    fn describe(&self) -> &'static str {
        "the adapter reports a supply voltage at or above the warning threshold"
    }

    fn satisfied(&self) -> bool {
        matches!(self, Self::Ok)
    }
}
