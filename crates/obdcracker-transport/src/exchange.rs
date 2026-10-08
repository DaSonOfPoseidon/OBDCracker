use std::time::{Duration, Instant};

use obdcracker_core::response::{self, Error as ReplyError};
use obdcracker_safety::Approved;

use crate::{Error, Response, Transport};

/// Which replies answer a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Every OBD-II ECU that answers a broadcast request: replies from 0x7E8..=0x7EF, collected
    /// until none has arrived for P2.
    ObdEcus,
    /// One module's reply, from this CAN ID (the vehicle profile's response ID).
    Module(u32),
}

impl Expect {
    fn accepts(self, source: u32) -> bool {
        match self {
            Self::ObdEcus => OBD_RESPONSE_IDS.contains(&source),
            Self::Module(id) => source == id,
        }
    }
}

const OBD_RESPONSE_IDS: std::ops::RangeInclusive<u32> = 0x7E8..=0x7EF;

/// How long to wait for replies, per ISO 14229-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long a module has to answer: 50 ms by default. For a broadcast request, collecting
    /// stops once no reply has arrived for this long.
    pub p2: Duration,
    /// How long a module has to answer after a response-pending reply: 5 s by default. Each
    /// response-pending reply restarts it.
    pub p2_star: Duration,
    /// The most response-pending replies to wait through for one request, so a module that
    /// never stops sending them can't stall the caller: 20 by default.
    pub max_pending: u16,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            p2: Duration::from_millis(50),
            p2_star: Duration::from_secs(5),
            max_pending: 20,
        }
    }
}

/// Sends one request and returns its replies, oldest first.
///
/// Replies from CAN IDs that `expect` doesn't accept are dropped, and so are replies that don't
/// answer this request (see [`response::answers`]), such as a late reply to an earlier one. (An
/// [`crate::Audited`] transport still logs them.) A response-pending reply (`7F <service> 78`)
/// is dropped too, and gives that module P2* to answer; once it has, a broadcast goes back to
/// waiting for a P2 quiet period.
///
/// - [`Expect::ObdEcus`] returns each ECU's first reply, which may be none; repeats are dropped.
/// - [`Expect::Module`] returns the module's one reply, or [`Error::Timeout`] if it didn't answer
///   in time. A request with the suppress-positive-response bit set gets no reply when it
///   succeeds, so it times out here.
///
/// More response-pending replies than [`Timing::max_pending`] give [`Error::Timeout`], and an
/// adapter error is returned as soon as it happens. P2 and P2* are capped at one hour.
pub fn exchange<T: Transport + ?Sized>(
    transport: &mut T,
    request: &Approved,
    expect: Expect,
    timing: Timing,
) -> Result<Vec<Response>, Error> {
    transport.send(request)?;
    let asked = request.payload();
    let sid = asked.first().copied();
    // A broadcast stops once no reply has come for P2 and no ECU is still within its P2*.
    let mut quiet = after(timing.p2);
    let mut still_pending: Vec<(u32, Instant)> = Vec::new();
    let mut pending = 0u16;
    let mut replies = Vec::new();
    loop {
        let deadline = still_pending
            .iter()
            .map(|&(_, until)| until)
            .fold(quiet, Instant::max);
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            break;
        };
        let reply = match transport.recv(left) {
            Ok(reply) => reply,
            Err(Error::Timeout) => break,
            Err(e) => return Err(e),
        };
        if !expect.accepts(reply.source) || !response::answers(asked, &reply.payload) {
            continue;
        }
        still_pending.retain(|&(source, _)| source != reply.source);
        if sid.is_some_and(|sid| is_pending(sid, &reply.payload)) {
            if pending == timing.max_pending {
                return Err(Error::Timeout);
            }
            pending += 1;
            still_pending.push((reply.source, after(timing.p2_star)));
            continue;
        }
        match expect {
            Expect::Module(_) => return Ok(vec![reply]),
            // J1979: each ECU answers a broadcast once. Repeats are dropped and don't extend the
            // wait, so an ECU stuck repeating itself can't keep the exchange open.
            Expect::ObdEcus if replies.iter().any(|r: &Response| r.source == reply.source) => {}
            Expect::ObdEcus => {
                replies.push(reply);
                quiet = after(timing.p2);
            }
        }
    }
    match expect {
        Expect::Module(_) => Err(Error::Timeout),
        Expect::ObdEcus => Ok(replies),
    }
}

// The longest any single wait lasts, so a huge timing can't overflow the clock.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);

fn after(wait: Duration) -> Instant {
    Instant::now() + wait.min(LONGEST_WAIT)
}

fn is_pending(sid: u8, reply: &[u8]) -> bool {
    matches!(
        response::positive(sid, reply),
        Err(ReplyError::Negative(negative)) if negative.nrc.is_pending()
    )
}
