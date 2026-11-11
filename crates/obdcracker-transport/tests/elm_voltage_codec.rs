//! Reading the voltage an adapter prints for `ATRV`: untrusted text, read exactly.

use obdcracker_transport::elm::codec::parse_voltage;
use proptest::prelude::*;

#[test]
fn the_adapters_usual_answers_are_read_in_millivolts() {
    assert_eq!(parse_voltage("12.6V"), Some(12_600));
    assert_eq!(parse_voltage("12.6"), Some(12_600));
    assert_eq!(parse_voltage("12V"), Some(12_000));
    assert_eq!(parse_voltage("9.8V"), Some(9_800));
    // An STN prints two decimals.
    assert_eq!(parse_voltage("12.63V"), Some(12_630));
    assert_eq!(parse_voltage("0.0V"), Some(0));
}

#[test]
fn spaces_and_a_carriage_return_around_the_value_are_ignored() {
    assert_eq!(parse_voltage(" 9.8V"), Some(9_800));
    assert_eq!(parse_voltage("12.6V "), Some(12_600));
    assert_eq!(parse_voltage("  12.6V\r"), Some(12_600));
    assert_eq!(parse_voltage("12.6V\r\n"), Some(12_600));
}

#[test]
fn the_most_the_adapter_can_print_is_read_and_one_more_digit_isnt() {
    assert_eq!(parse_voltage("99.9V"), Some(99_900));
    assert_eq!(parse_voltage("100.0V"), None);
    assert_eq!(parse_voltage("100V"), None);
}

#[test]
fn what_isnt_a_voltage_is_none() {
    for text in [
        "",
        " ",
        "?",
        "NO DATA",
        "V",
        ".V",
        "12.V",
        ".6V",
        "-12.6V",
        "+12.6V",
        "12.6.1V",
        "12.6VV",
        "12.6V junk",
        "12.6 V",
        "12,6V",
        "1 2.6V",
        "12.6v",
        "12.6341V",
        "0x0C",
        "１２.６V",
    ] {
        assert_eq!(parse_voltage(text), None, "{text:?}");
    }
}

#[test]
fn a_very_long_string_of_digits_is_none_not_an_overflow() {
    let digits = "9".repeat(10_000);
    assert_eq!(parse_voltage(&digits), None);
    assert_eq!(parse_voltage(&format!("{digits}.5V")), None);
    assert_eq!(parse_voltage(&format!("12.{digits}V")), None);
    assert_eq!(parse_voltage("4294967295V"), None);
}

proptest! {
    #[test]
    fn any_text_is_a_voltage_or_none_and_never_a_panic(text in any::<String>()) {
        if let Some(millivolts) = parse_voltage(&text) {
            prop_assert!(millivolts <= 99_999);
        }
    }

    #[test]
    fn every_printed_voltage_round_trips(whole in 0u32..=99, tenths in 0u32..=9, suffix in "V?") {
        let text = format!("{whole}.{tenths}{suffix}");
        prop_assert_eq!(parse_voltage(&text), Some(whole * 1000 + tenths * 100));
    }

    #[test]
    fn a_voltage_with_up_to_three_decimals_round_trips(whole in 0u32..=99, millis in 0u32..=999) {
        let text = format!("{whole}.{millis:03}V");
        prop_assert_eq!(parse_voltage(&text), Some(whole * 1000 + millis));
    }
}
