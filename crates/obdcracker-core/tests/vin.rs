//! VIN decoding: the fields, the model year candidates and the check digit (ISO 3779, 49 CFR 565).

use obdcracker_core::response::Error;
use obdcracker_core::vin::{CheckStatus, Vin, decode};

// The 2014 Audi A7 in the sim fixture: a WMI outside North America, with a correct check digit.
const A7: &str = "WAU2MBFC6EN093415";
// The 49 CFR 565 example: North America, position 7 a digit, check digit X (10).
const NA_DIGIT: &str = "1M8GDM9AXKP042788";
// North America, position 7 a letter, so 2010 to 2039.
const NA_LETTER: &str = "1FTFW1ET9DFC10312";

fn vin(text: &str) -> Vin<'_> {
    decode(text).unwrap()
}

fn with(text: &str, position: usize, byte: u8) -> String {
    let mut bytes = text.as_bytes().to_vec();
    bytes[position - 1] = byte;
    String::from_utf8(bytes).unwrap()
}

fn years(text: &str) -> Vec<u16> {
    vin(text).model_years().as_slice().to_vec()
}

#[test]
fn splits_the_fields() {
    let a7 = vin(A7);
    assert_eq!(a7.as_str(), A7);
    assert_eq!(a7.wmi(), "WAU");
    assert_eq!(a7.vds(), "2MBFC");
    assert_eq!(a7.check_char(), '6');
    assert_eq!(a7.year_code(), 'E');
    assert_eq!(a7.plant(), 'N');
    assert_eq!(a7.serial(), "093415");
    assert_eq!(a7.to_string(), A7);
}

#[test]
fn refuses_what_is_not_a_vin() {
    for text in [
        "",
        "WAU2MBFC6EN09341",
        "WAU2MBFC6EN0934155",
        "wau2mbfc6en093415",
        "WAU2MBFC6EN09341I",
        "WAU2MBFC6EN09341O",
        "WAU2MBFC6EN09341Q",
        "WAU2MBFC6EN09341-",
        "WAU2MBFC6EN09341 ",
        "WAU2MBFC6EN09341\0",
        "WAU2MBFC6EN09341\u{e9}",
        "-----------------",
    ] {
        assert_eq!(decode(text).err(), Some(Error::Malformed), "{text:?}");
    }
}

#[test]
fn one_year_code_names_two_years_outside_north_america() {
    assert_eq!(years(A7), [1984, 2014]);
}

#[test]
fn a_north_american_vin_has_one_year_by_position_7() {
    assert_eq!(years(NA_DIGIT), [1989]);
    assert_eq!(years(NA_LETTER), [2013]);
}

#[test]
fn year_codes_run_a_to_y_then_1_to_9() {
    // I, O, Q, U, Z and 0 are skipped; the sequence repeats every 30 years.
    let codes = "ABCDEFGHJKLMNPRSTVWXY123456789";
    for (i, code) in codes.bytes().enumerate() {
        let i = u16::try_from(i).unwrap();
        let outside = with(A7, 10, code);
        assert_eq!(years(&outside), [1980 + i, 2010 + i], "{}", code as char);
        let old = with(NA_DIGIT, 10, code);
        assert_eq!(years(&old), [1980 + i], "{}", code as char);
        let new = with(NA_LETTER, 10, code);
        assert_eq!(years(&new), [2010 + i], "{}", code as char);
    }
}

#[test]
fn u_z_and_0_are_not_years() {
    for code in *b"UZ0" {
        for text in [A7, NA_DIGIT, NA_LETTER] {
            assert_eq!(years(&with(text, 10, code)), [], "{}", code as char);
        }
    }
}

#[test]
fn position_7_decides_for_north_america_only() {
    // The same year code with a letter at position 7 moves the NA year, and not the other WMIs'.
    assert_eq!(years(&with(NA_DIGIT, 7, b'A')), [2019]);
    assert_eq!(years(&with(NA_LETTER, 7, b'0')), [1983]);
    assert_eq!(years(&with(A7, 7, b'4')), [1984, 2014]);
    assert_eq!(years(&with(A7, 7, b'F')), [1984, 2014]);
}

#[test]
fn north_america_is_wmi_first_character_1_to_5() {
    for first in *b"12345" {
        assert_eq!(years(&with(NA_DIGIT, 1, first)).len(), 1);
    }
    for first in *b"06789ABJSTWZ" {
        assert_eq!(
            years(&with(NA_DIGIT, 1, first)).len(),
            2,
            "{}",
            first as char
        );
    }
}

#[test]
fn computes_the_check_digit() {
    let a7 = vin(A7).check_digit();
    assert_eq!((a7.computed, a7.found), ('6', '6'));
    assert!(a7.matches());

    let x = vin(NA_DIGIT).check_digit();
    assert_eq!((x.computed, x.found), ('X', 'X'));
    assert_eq!(x.status(), CheckStatus::Valid);

    let ones = vin("11111111111111111").check_digit();
    assert_eq!((ones.computed, ones.found), ('1', '1'));
    assert_eq!(vin(NA_LETTER).check_digit().status(), CheckStatus::Valid);
}

#[test]
fn the_check_digit_transliterates_every_letter() {
    // Each letter at position 1 adds its value times 8; position 9 is the digit it must make.
    let values = [
        (b'A', 1),
        (b'B', 2),
        (b'C', 3),
        (b'D', 4),
        (b'E', 5),
        (b'F', 6),
        (b'G', 7),
        (b'H', 8),
        (b'J', 1),
        (b'K', 2),
        (b'L', 3),
        (b'M', 4),
        (b'N', 5),
        (b'P', 7),
        (b'R', 9),
        (b'S', 2),
        (b'T', 3),
        (b'U', 4),
        (b'V', 5),
        (b'W', 6),
        (b'X', 7),
        (b'Y', 8),
        (b'Z', 9),
    ];
    // "1" followed by 16 ones sums to 89; swapping the first character for a letter of value v
    // changes the sum by (v - 1) * 8.
    for (letter, value) in values {
        let text = with("11111111111111111", 1, letter);
        let sum = 89 + (value - 1) * 8;
        let expected = match sum % 11 {
            10 => 'X',
            d => char::from_digit(d, 10).unwrap(),
        };
        assert_eq!(
            vin(&text).check_digit().computed,
            expected,
            "{}",
            letter as char
        );
    }
}

#[test]
fn a_wrong_digit_is_invalid_in_north_america() {
    let wrong = with(NA_DIGIT, 9, b'3');
    let check = vin(&wrong).check_digit();
    assert_eq!((check.computed, check.found), ('X', '3'));
    assert!(!check.matches());
    assert_eq!(check.status(), CheckStatus::Invalid);
}

#[test]
fn a_wrong_digit_is_not_an_error_outside_north_america() {
    let wrong = with(A7, 9, b'3');
    let check = vin(&wrong).check_digit();
    assert_eq!((check.computed, check.found), ('6', '3'));
    assert!(!check.matches());
    assert_eq!(check.status(), CheckStatus::NotRequired);
}

#[test]
fn a_correct_digit_outside_north_america_is_still_not_required() {
    let check = vin(A7).check_digit();
    assert!(check.matches());
    assert_eq!(check.status(), CheckStatus::NotRequired);
}

#[test]
fn a_letter_in_the_check_position_never_matches() {
    // Only 0 to 9 and X are check digits.
    let letter = with(NA_DIGIT, 9, b'A');
    let check = vin(&letter).check_digit();
    assert!(!check.matches());
    assert_eq!(check.status(), CheckStatus::Invalid);
}
