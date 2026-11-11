//! The supply-voltage precondition: where the thresholds fall, and that an unknown voltage never passes.

use obdcracker_safety::{Precondition, SupplyVoltage, VoltageCheck, VoltageThresholds};
use proptest::prelude::*;

fn known(millivolts: u32) -> SupplyVoltage {
    SupplyVoltage::Known { millivolts }
}

fn check(millivolts: u32) -> VoltageCheck {
    VoltageThresholds::DEFAULT.check(known(millivolts))
}

#[test]
fn the_default_thresholds_are_12_2_and_11_8_volts() {
    assert_eq!(VoltageThresholds::DEFAULT.warn_mv, 12_200);
    assert_eq!(VoltageThresholds::DEFAULT.refuse_mv, 11_800);
}

#[test]
fn a_healthy_battery_is_ok() {
    assert_eq!(check(12_600), VoltageCheck::Ok);
    assert_eq!(check(14_400), VoltageCheck::Ok);
}

#[test]
fn exactly_12_2_volts_is_not_low_and_one_millivolt_under_is() {
    assert_eq!(check(12_200), VoltageCheck::Ok);
    assert_eq!(check(12_199), VoltageCheck::Low);
}

#[test]
fn exactly_11_8_volts_is_low_but_not_too_low_and_one_millivolt_under_is_too_low() {
    assert_eq!(check(11_800), VoltageCheck::Low);
    assert_eq!(check(11_799), VoltageCheck::TooLow);
}

#[test]
fn zero_and_the_largest_value_are_checked_like_any_other() {
    assert_eq!(check(0), VoltageCheck::TooLow);
    assert_eq!(check(u32::MAX), VoltageCheck::Ok);
}

#[test]
fn an_unknown_voltage_is_unknown_whatever_the_thresholds() {
    assert_eq!(
        VoltageThresholds::DEFAULT.check(SupplyVoltage::Unknown),
        VoltageCheck::Unknown
    );
    let none = VoltageThresholds {
        warn_mv: 0,
        refuse_mv: 0,
    };
    assert_eq!(none.check(SupplyVoltage::Unknown), VoltageCheck::Unknown);
}

#[test]
fn only_an_ok_voltage_satisfies_the_precondition() {
    assert!(VoltageCheck::Ok.satisfied());
    for failing in [
        VoltageCheck::Low,
        VoltageCheck::TooLow,
        VoltageCheck::Unknown,
    ] {
        assert!(!failing.satisfied(), "{failing:?} passed");
    }
}

#[test]
fn an_unknown_voltage_never_satisfies_the_precondition() {
    let thresholds = VoltageThresholds {
        warn_mv: 0,
        refuse_mv: 0,
    };
    assert!(!thresholds.check(SupplyVoltage::Unknown).satisfied());
}

#[test]
fn a_voltage_prints_in_volts_with_millivolt_precision_and_unknown_says_so() {
    assert_eq!(known(12_600).to_string(), "12.6 V");
    assert_eq!(known(11_799).to_string(), "11.799 V");
    assert_eq!(known(9_050).to_string(), "9.05 V");
    assert_eq!(known(12_000).to_string(), "12 V");
    assert_eq!(known(0).to_string(), "0 V");
    assert_eq!(SupplyVoltage::Unknown.to_string(), "unknown");
}

#[test]
fn a_precondition_names_what_it_needs() {
    assert!(VoltageCheck::Ok.describe().contains("supply voltage"));
}

proptest! {
    #[test]
    fn the_check_is_ordered_by_the_voltage(a in 0u32..30_000, b in 0u32..30_000) {
        let rank = |check| match check {
            VoltageCheck::TooLow => 0,
            VoltageCheck::Low => 1,
            VoltageCheck::Ok => 2,
            VoltageCheck::Unknown => panic!("a known voltage is never unknown"),
        };
        let (low, high) = (a.min(b), a.max(b));
        prop_assert!(rank(check(low)) <= rank(check(high)));
    }

    #[test]
    fn every_known_voltage_is_decided_by_the_thresholds(mv in any::<u32>()) {
        let expected = if mv < 11_800 {
            VoltageCheck::TooLow
        } else if mv < 12_200 {
            VoltageCheck::Low
        } else {
            VoltageCheck::Ok
        };
        prop_assert_eq!(check(mv), expected);
    }
}
