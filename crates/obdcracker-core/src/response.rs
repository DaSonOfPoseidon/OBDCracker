//! Positive and negative responses. OBD-II on CAN (ISO 15765-4) and UDS (ISO 14229-1) share the
//! format: a positive reply starts with the request's service ID + 0x40, a negative one is
//! `7F <service ID> <code>`.

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

/// Checks that `reply` is a positive answer to a request for service `request_sid`, and returns
/// the bytes after the reply's service ID.
pub fn positive(request_sid: u8, reply: &[u8]) -> Result<&[u8], Error> {
    let (&sid, rest) = reply.split_first().ok_or(Error::TooShort)?;
    if sid == NEGATIVE {
        let [refused, code, ..] = *rest else {
            return Err(Error::TooShort);
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
