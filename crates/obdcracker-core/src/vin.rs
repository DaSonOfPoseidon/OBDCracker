//! The fields of a vehicle identification number (ISO 3779): the manufacturer code, the model year
//! candidates, the plant and the check digit.
//!
//! What the vehicle descriptor section and the plant letter mean is each manufacturer's, so they
//! are given as the raw characters. See [`docs/usage.md#vin`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/usage.md#vin).

use core::fmt;

use crate::obd::check_vin;
use crate::response::Error;

// Position 10, in order: 1980 and 2010 for the first. I, O, Q, U, Z and 0 are not year codes.
const YEAR_CODES: &[u8; 30] = b"ABCDEFGHJKLMNPRSTVWXY123456789";
const FIRST_YEAR: u16 = 1980;
const CYCLE: u16 = 30;
const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

/// A VIN that passed [`check_vin`]: 17 digits and upper case letters other than I, O and Q.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vin<'a>(&'a str);

/// Checks `text` as [`check_vin`] does and splits it into fields.
pub fn decode(text: &str) -> Result<Vin<'_>, Error> {
    check_vin(text.as_bytes()).map(Vin)
}

impl<'a> Vin<'a> {
    /// The whole VIN.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Positions 1 to 3: the world manufacturer identifier. The first character is the region
    /// (1 to 5 is North America).
    #[must_use]
    pub fn wmi(&self) -> &'a str {
        &self.0[..3]
    }

    /// Positions 4 to 8: the vehicle descriptor section. Its meaning is the manufacturer's.
    #[must_use]
    pub fn vds(&self) -> &'a str {
        &self.0[3..8]
    }

    /// Position 9: the check character, as written.
    #[must_use]
    pub fn check_char(&self) -> char {
        char::from(self.0.as_bytes()[8])
    }

    /// Position 10: the model year code, as written.
    #[must_use]
    pub fn year_code(&self) -> char {
        char::from(self.0.as_bytes()[9])
    }

    /// Position 11: the plant code, as written. Its meaning is the manufacturer's.
    #[must_use]
    pub fn plant(&self) -> char {
        char::from(self.0.as_bytes()[10])
    }

    /// Positions 12 to 17: the sequence number.
    #[must_use]
    pub fn serial(&self) -> &'a str {
        &self.0[11..]
    }

    /// Whether the manufacturer code is North American (first character 1 to 5), where the check
    /// digit and the position 7 year rule are required.
    #[must_use]
    pub fn is_north_american(&self) -> bool {
        matches!(self.0.as_bytes()[0], b'1'..=b'5')
    }

    /// The model years position 10 can mean. Its codes repeat every 30 years. In North America a
    /// digit at position 7 means 1980 to 2009 and a letter 2010 to 2039 (49 CFR 565.15); for every
    /// other manufacturer code both years are candidates, because nothing in the VIN says which.
    /// U, Z and 0 are not year codes, so they give none.
    #[must_use]
    pub fn model_years(&self) -> ModelYears {
        let code = self.0.as_bytes()[9];
        let Some(index) = YEAR_CODES.iter().position(|&c| c == code) else {
            return ModelYears::default();
        };
        let early = FIRST_YEAR + u16::try_from(index).unwrap_or(0);
        let late = early + CYCLE;
        if !self.is_north_american() {
            return ModelYears {
                years: [early, late],
                len: 2,
            };
        }
        let year = if self.0.as_bytes()[6].is_ascii_digit() {
            early
        } else {
            late
        };
        ModelYears {
            years: [year, 0],
            len: 1,
        }
    }

    /// The check digit the VIN's other characters make (ISO 3779, 49 CFR 565.15: transliterated
    /// values, weights by position, the sum modulo 11, 10 written as `X`), beside the one written.
    #[must_use]
    pub fn check_digit(&self) -> CheckDigit {
        let sum: u32 = self
            .0
            .bytes()
            .zip(WEIGHTS)
            .map(|(b, weight)| value(b) * weight)
            .sum();
        let computed = match sum % 11 {
            10 => 'X',
            digit => char::from_digit(digit, 10).unwrap_or('?'),
        };
        CheckDigit {
            computed,
            found: self.check_char(),
            required: self.is_north_american(),
        }
    }
}

impl fmt::Display for Vin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

// The transliteration of a VIN character: digits are themselves; letters run 1 to 8 for A to H,
// 1 to 5 for J to N, 7 for P, 9 for R, and 2 to 9 for S to Z (ISO 3779).
fn value(b: u8) -> u32 {
    match b {
        b'0'..=b'9' => u32::from(b - b'0'),
        b'A'..=b'H' => u32::from(b - b'A') + 1,
        b'J'..=b'N' => u32::from(b - b'J') + 1,
        b'P' => 7,
        b'R' => 9,
        b'S'..=b'Z' => u32::from(b - b'S') + 2,
        _ => 0,
    }
}

/// The model years a VIN's position 10 can mean: none, one or two ([`Vin::model_years`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModelYears {
    years: [u16; 2],
    len: usize,
}

impl ModelYears {
    /// The candidate years, earliest first.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.years[..self.len]
    }

    /// Whether any candidate is in `first..=last`.
    #[must_use]
    pub fn any_in(&self, first: u16, last: u16) -> bool {
        self.as_slice().iter().any(|y| (first..=last).contains(y))
    }
}

/// A VIN's check digit ([`Vin::check_digit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckDigit {
    /// The digit the rest of the VIN makes: `0` to `9`, or `X` for 10.
    pub computed: char,
    /// What position 9 says.
    pub found: char,
    /// Whether the manufacturer code requires the check digit (North America does).
    pub required: bool,
}

impl CheckDigit {
    /// Whether position 9 is the computed digit, whether or not the digit is required.
    #[must_use]
    pub fn matches(&self) -> bool {
        self.computed == self.found
    }

    /// Whether the VIN passes: a mismatch is invalid only where the digit is required.
    #[must_use]
    pub fn status(&self) -> CheckStatus {
        match (self.required, self.matches()) {
            (false, _) => CheckStatus::NotRequired,
            (true, true) => CheckStatus::Valid,
            (true, false) => CheckStatus::Invalid,
        }
    }
}

/// Whether a VIN's check digit passes ([`CheckDigit::status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The digit is required and correct.
    Valid,
    /// The digit is required and wrong.
    Invalid,
    /// The manufacturer code is outside North America, which doesn't require it. Whether the digit
    /// matches is [`CheckDigit::matches`].
    NotRequired,
}
