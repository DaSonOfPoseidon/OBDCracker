//! Listening to the bus without sending anything: the types of [`Listen`].

use std::fmt;
use std::ops::ControlFlow;
use std::str::FromStr;
use std::time::Duration;

use crate::{Error, Transport};

/// Which CAN IDs a listen shows, as an ELM327 `AT CRA` pattern: three characters for 11-bit IDs
/// or eight for 29-bit IDs, each a hex digit or `X` for any digit (`7XX` is every diagnostic
/// reply, `7E8` one module, `18DAF1XX` every ISO 15765-4 29-bit reply to the tester).
///
/// The width decides which kind of frame is heard: a 3-character pattern shows only 11-bit
/// frames and an 8-character one only 29-bit frames. Parsing upper-cases the pattern and
/// refuses any other length or character, and a first digit no ID of that width can have (above
/// 7 for 11 bits, above 1 for 29 bits).
///
/// ```
/// use obdcracker_transport::ListenFilter;
///
/// let filter: ListenFilter = "7ex".parse().unwrap();
/// assert_eq!(filter.as_str(), "7EX");
/// assert!(!filter.is_29_bit());
/// assert!("7E".parse::<ListenFilter>().is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenFilter(String);

impl ListenFilter {
    /// The pattern, upper-case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the pattern is for 29-bit IDs (eight characters).
    #[must_use]
    pub fn is_29_bit(&self) -> bool {
        self.0.len() == 8
    }
}

impl Default for ListenFilter {
    /// `7XX`: every 11-bit diagnostic ID.
    fn default() -> Self {
        Self("7XX".to_owned())
    }
}

impl fmt::Display for ListenFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a [`ListenFilter`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidFilter(String);

impl fmt::Display for InvalidFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidFilter {}

impl FromStr for ListenFilter {
    type Err = InvalidFilter;

    fn from_str(text: &str) -> Result<Self, InvalidFilter> {
        let wrong = |why: &str| InvalidFilter(format!("{text:?} isn't a filter: {why}"));
        if !text.is_ascii() {
            return Err(wrong("give hex digits and X only"));
        }
        let pattern = text.to_ascii_uppercase();
        let limit = match pattern.len() {
            3 => b'7',
            8 => b'1',
            _ => {
                return Err(wrong(
                    "give 3 characters for 11-bit IDs (such as 7XX) or 8 for 29-bit IDs (such as \
                     18DAF1XX)",
                ));
            }
        };
        if !pattern.bytes().all(|b| b.is_ascii_hexdigit() || b == b'X') {
            return Err(wrong("give hex digits, and X for any digit"));
        }
        // An uppercase hex digit sorts above `7` or `1` exactly when its value is higher.
        if pattern.as_bytes()[0] != b'X' && pattern.as_bytes()[0] > limit {
            return Err(wrong(if limit == b'7' {
                "no 11-bit ID starts above 7"
            } else {
                "no 29-bit ID starts above 1"
            }));
        }
        Ok(Self(pattern))
    }
}

/// One CAN frame heard while listening.
///
/// `#[non_exhaustive]`, so it can gain fields; build one with [`Heard::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Heard {
    /// How long after the listen began the driver read the frame. When the frame was on the bus
    /// is earlier by an amount the adapter's link decides, which the driver can't see.
    pub elapsed: Duration,
    /// The frame's CAN ID.
    pub id: u32,
    /// Whether the ID is a 29-bit one, so `0x123` can be told from `0x00000123`.
    pub extended: bool,
    /// The frame's data bytes, as the adapter printed them.
    pub data: Vec<u8>,
}

impl Heard {
    /// A frame heard `elapsed` after the listen began.
    #[must_use]
    pub fn new(elapsed: Duration, id: u32, extended: bool, data: Vec<u8>) -> Self {
        Self {
            elapsed,
            id,
            extended,
            data,
        }
    }
}

/// Why a listen that did not fail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenEnd {
    /// The time asked for was up.
    Deadline,
    /// The callback asked to stop.
    Stopped,
}

/// What a listen's callback does with each frame: go on, or stop the listen. An error stops it
/// too and is returned by the listen.
pub type OnFrame<'a> = &'a mut dyn FnMut(&Heard) -> Result<ControlFlow<()>, Error>;

/// A transport that can listen to the bus and send nothing while it does.
///
/// An implementation **must not put any frame on the bus** while it listens, and must acknowledge
/// none (a CAN controller's ACK is a bus-level bit; it has to be in its silent mode) or fail
/// before it listens: a silent tap on a car's bus is the point, and a listener that acknowledges
/// frames is a node on the bus. The only things it may write are commands to the adapter itself.
/// Nothing about a listen is approved by the policy because nothing in it reaches the bus.
///
/// A listen that has returned leaves the transport ready for the next request, which is sent as
/// it would have been before. The adapter's receive filter, and the CAN width after a 29-bit
/// filter, may differ from what they were: a request sets its own.
pub trait Listen: Transport {
    /// Listens for frames the `filter` shows for up to `wait`, handing each to `on_frame` in the
    /// order heard, and returns why it ended.
    ///
    /// # Errors
    ///
    /// The adapter or its driver failed, or can't listen silently; it reported that frames were
    /// lost (an adapter's output buffer overflowed: narrow the filter); it stopped by itself; or
    /// `on_frame` returned an error. The listen has been stopped by then, where the adapter
    /// allows.
    fn listen(
        &mut self,
        filter: &ListenFilter,
        wait: Duration,
        on_frame: OnFrame<'_>,
    ) -> Result<ListenEnd, Error>;
}
