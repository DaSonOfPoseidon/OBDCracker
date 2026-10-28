//! Positive and negative responses. OBD-II on CAN (ISO 15765-4) and UDS (ISO 14229-1) share the
//! format: a positive reply starts with the request's service ID + 0x40, a negative one is
//! `7F <service ID> <code>`. Reply matching: [`docs/protocols.md#matching-replies-to-requests`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#matching-replies-to-requests).

use core::fmt;

const NEGATIVE: u8 = 0x7F;
const POSITIVE_OFFSET: u8 = 0x40;

macro_rules! nrcs {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $text:literal;)*) => {
        /// A negative response code: why a module refused a request.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Nrc {
            $($(#[$doc])* $name,)*
            /// A code without a name here, kept as received.
            Other(u8),
        }

        impl From<u8> for Nrc {
            fn from(code: u8) -> Self {
                match code {
                    $($code => Self::$name,)*
                    other => Self::Other(other),
                }
            }
        }

        impl Nrc {
            /// The code's byte value.
            #[must_use]
            pub fn code(self) -> u8 {
                match self {
                    $(Self::$name => $code,)*
                    Self::Other(code) => code,
                }
            }

            fn text(self) -> Option<&'static str> {
                match self {
                    $(Self::$name => Some($text),)*
                    Self::Other(_) => None,
                }
            }
        }
    };
}

nrcs! {
    /// The request was rejected for an unspecified reason.
    GeneralReject = 0x10, "general reject";
    /// The module doesn't support the service.
    ServiceNotSupported = 0x11, "service not supported";
    /// The module doesn't support the subfunction.
    SubFunctionNotSupported = 0x12, "subfunction not supported";
    /// The request's length or format is wrong.
    IncorrectMessageLength = 0x13, "incorrect message length or invalid format";
    /// The reply would be longer than the transport can carry.
    ResponseTooLong = 0x14, "response too long";
    /// The module is busy; repeat the request later.
    BusyRepeatRequest = 0x21, "busy, repeat request";
    /// The module's current state doesn't allow the request (e.g. engine running).
    ConditionsNotCorrect = 0x22, "conditions not correct";
    /// The request came in the wrong order (e.g. a key before its seed).
    RequestSequenceError = 0x24, "request sequence error";
    /// A parameter, such as a DID, is unsupported or out of range.
    RequestOutOfRange = 0x31, "request out of range";
    /// The request needs a security access unlock first.
    SecurityAccessDenied = 0x33, "security access denied";
    /// The security access key was wrong.
    InvalidKey = 0x35, "invalid key";
    /// Too many wrong security access keys.
    ExceededNumberOfAttempts = 0x36, "exceeded number of attempts";
    /// Security access is locked out until a delay has passed.
    RequiredTimeDelayNotExpired = 0x37, "required time delay not expired";
    /// The request was received and the real reply will follow; keep waiting.
    ResponsePending = 0x78, "response pending";
    /// The subfunction isn't supported in the current diagnostic session.
    SubFunctionNotSupportedInActiveSession = 0x7E, "subfunction not supported in active session";
    /// The service isn't supported in the current diagnostic session.
    ServiceNotSupportedInActiveSession = 0x7F, "service not supported in active session";
}

impl Nrc {
    /// Whether this is response pending (0x78): the module will answer later, so keep waiting
    /// instead of treating it as a refusal.
    #[must_use]
    pub fn is_pending(self) -> bool {
        self == Self::ResponsePending
    }
}

impl fmt::Display for Nrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.text() {
            Some(text) => write!(f, "{text} (0x{:02X})", self.code()),
            None => write!(f, "negative response code 0x{:02X}", self.code()),
        }
    }
}

/// A module's refusal of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegativeResponse {
    /// The service ID of the refused request.
    pub sid: u8,
    /// Why it was refused.
    pub nrc: Nrc,
}

/// Why a reply isn't a positive answer to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The module refused the request.
    Negative(NegativeResponse),
    /// The reply answers another service; holds the reply's first byte.
    WrongService(u8),
    /// The reply is shorter than its format needs.
    TooShort,
    /// The reply's content doesn't match its format.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negative(nr) => write!(f, "service 0x{:02X} refused: {}", nr.sid, nr.nrc),
            Self::WrongService(sid) => write!(f, "reply is for another service (0x{sid:02X})"),
            Self::TooShort => f.write_str("reply is too short"),
            Self::Malformed => f.write_str("reply is malformed"),
        }
    }
}

impl core::error::Error for Error {}

/// Checks that `reply` is a positive answer to a request for service `request_sid`, and returns
/// the bytes after the reply's service ID.
pub fn positive(request_sid: u8, reply: &[u8]) -> Result<&[u8], Error> {
    let (&sid, rest) = reply.split_first().ok_or(Error::TooShort)?;
    if sid == NEGATIVE {
        // Exactly `7F <service ID> <code>` (ISO 14229-1)
        let [refused, code] = *rest else {
            return Err(if rest.len() < 2 {
                Error::TooShort
            } else {
                Error::Malformed
            });
        };
        if refused != request_sid {
            return Err(Error::WrongService(sid));
        }
        return Err(Error::Negative(NegativeResponse {
            sid: refused,
            nrc: Nrc::from(code),
        }));
    }
    if sid != request_sid.wrapping_add(POSITIVE_OFFSET) {
        return Err(Error::WrongService(sid));
    }
    Ok(rest)
}

// Printable ASCII (spaces allowed) as text, or Malformed.
pub(crate) fn printable(bytes: &[u8]) -> Result<&str, Error> {
    if !bytes.iter().all(|&b| b == b' ' || b.is_ascii_graphic()) {
        return Err(Error::Malformed);
    }
    core::str::from_utf8(bytes).map_err(|_| Error::Malformed)
}

/// Whether `reply` answers `request`, so a late reply to an earlier request isn't mistaken for
/// this one's.
///
/// A positive reply must have the request's service ID + 0x40 and echo what the request asked
/// for, and a request with the suppress-positive-response bit set is answered only after
/// response-pending (see [`answers_after_pending`]). Any `7F <service> <code>` for the request's
/// service answers it. See [`docs/protocols.md#matching-replies-to-requests`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#matching-replies-to-requests).
#[must_use]
pub fn answers(request: &[u8], reply: &[u8]) -> bool {
    matches(request, reply, false)
}

/// Whether `reply` answers `request` from a module that already sent response-pending
/// (`7F <service> 78`) for it.
///
/// The same as [`answers`], except that a request with the suppress-positive-response bit set
/// is answered by its positive reply, as ISO 14229-1 requires after response-pending.
#[must_use]
pub fn answers_after_pending(request: &[u8], reply: &[u8]) -> bool {
    matches(request, reply, true)
}

/// Whether `reply` answers the KWP2000 (ISO 14230-3) `request`. [`answers`] reads UDS, which
/// differs here: see [`docs/protocols.md#matching-replies-to-requests`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/protocols.md#matching-replies-to-requests). A decoder must still check
/// what it reads.
#[must_use]
pub fn kwp2000_answers(request: &[u8], reply: &[u8]) -> bool {
    let Some((&sid, asked)) = request.split_first() else {
        return false;
    };
    match reply {
        [NEGATIVE, refused, _] => *refused == sid,
        [NEGATIVE, ..] => false,
        [first, echo @ ..] if *first == sid.wrapping_add(POSITIVE_OFFSET) => match sid {
            0x21 => echo.first().is_some_and(|got| asked.first() == Some(got)),
            _ => true,
        },
        _ => false,
    }
}

// Whether a `ReadDTCInformation` 0x04 or 0x06 reply `echo` is for the DTC and record `asked`
// for. A reply with no records has none to compare.
fn dtc_detail_echoed(sub: u8, asked: &[u8], echo: &[u8]) -> bool {
    let (Some(dtc), Some(&record)) = (asked.get(1..4), asked.get(4)) else {
        return false;
    };
    let every = record == 0xFF || (sub == 0x06 && record == 0xFE);
    echo.get(1..4) == Some(dtc) && (every || echo.get(5).is_none_or(|&first| first == record))
}

fn matches(request: &[u8], reply: &[u8], pending: bool) -> bool {
    let Some((&sid, asked)) = request.split_first() else {
        return false;
    };
    match reply {
        [NEGATIVE, refused, _] => *refused == sid,
        [NEGATIVE, ..] => false,
        [first, echo @ ..] if *first == sid.wrapping_add(POSITIVE_OFFSET) => match sid {
            0x01 => echo.first().is_some_and(|pid| asked.contains(pid)),
            0x09 => echo.first().is_some_and(|pid| asked.first() == Some(pid)),
            0x22 => echo
                .first_chunk::<2>()
                .is_some_and(|did| asked.as_chunks::<2>().0.contains(did)),
            // Bit 7 is the suppress-positive-response bit; it isn't echoed.
            0x10 | 0x19 | 0x3E => match (echo.first(), asked.first()) {
                (Some(&got), Some(&sub)) => {
                    (pending || sub & 0x80 == 0)
                        && got == sub & 0x7F
                        && (sid != 0x19
                            || !matches!(got, 0x04 | 0x06)
                            || dtc_detail_echoed(got, asked, echo))
                }
                _ => false,
            },
            _ => true,
        },
        _ => false,
    }
}
