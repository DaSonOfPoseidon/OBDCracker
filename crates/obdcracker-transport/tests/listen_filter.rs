//! `ListenFilter`: the patterns an ELM327's `AT CRA` takes, and no others.

use obdcracker_transport::ListenFilter;
use proptest::prelude::*;

fn parse(text: &str) -> Result<ListenFilter, String> {
    text.parse::<ListenFilter>().map_err(|e| e.to_string())
}

#[test]
fn takes_three_characters_for_11_bit_ids_and_eight_for_29_bit_ones() {
    for text in [
        "7XX", "7E8", "7EX", "XXX", "000", "18DAF1XX", "17FE00XX", "XXXXXXXX", "1FFFFFFF",
    ] {
        let filter = parse(text).unwrap();
        assert_eq!(filter.as_str(), text);
        assert_eq!(filter.is_29_bit(), text.len() == 8, "{text}");
    }
}

#[test]
fn upper_cases_what_it_takes() {
    assert_eq!(parse("7ex").unwrap().as_str(), "7EX");
    assert_eq!(parse("18daf1xx").unwrap().as_str(), "18DAF1XX");
}

#[test]
fn refuses_every_other_length_and_character() {
    for text in [
        "",
        "7",
        "7X",
        "7XXX",
        "7XXXXXX",
        "7XXXXXXXX",
        "18DAF1X",
        " 7XX",
        "7XX ",
        "7 X",
        "7XG",
        "7X-",
        "+7X",
        "7X\n",
        "7É",
        "ＸＸＸ",
        "7X\0",
    ] {
        assert!(parse(text).is_err(), "{text:?}");
    }
}

#[test]
fn refuses_a_first_digit_no_id_of_that_width_has() {
    for text in [
        "8XX", "9XX", "AXX", "FXX", "2XXXXXXX", "9XXXXXXX", "FFFFFFFF",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
    for text in ["7XX", "XXX", "1XXXXXXX", "XXXXXXXX"] {
        assert!(parse(text).is_ok(), "{text}");
    }
}

#[test]
fn the_default_is_every_diagnostic_id() {
    assert_eq!(ListenFilter::default().as_str(), "7XX");
}

proptest! {
    // Whatever parses is a pattern the adapter takes, and writes back as the text it was read
    // from, upper-cased.
    #[test]
    fn whatever_parses_is_a_valid_pattern(text in "\\PC{0,12}") {
        if let Ok(filter) = text.parse::<ListenFilter>() {
            let shown = filter.to_string();
            prop_assert_eq!(&shown, &text.to_ascii_uppercase());
            prop_assert!(matches!(shown.len(), 3 | 8));
            prop_assert!(shown.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b) || b == b'X'));
            prop_assert_eq!(shown.parse::<ListenFilter>().unwrap(), filter);
        }
    }
}
