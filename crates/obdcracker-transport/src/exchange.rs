use std::time::{Duration, Instant};

use obdcracker_core::response::{self, Error as ReplyError};
use obdcracker_safety::Approved;

use crate::{Error, Response, Transport};

/// Which replies answer a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Every OBD-II ECU that answers a broadcast request: replies from 0x7E8..=0x7EF.
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
    /// How long after the request every module has to answer or send response-pending: 50 ms by
    /// default.
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
/// Timing follows ISO 15765-4: every module must answer, or send response-pending
/// (`7F <service> 78`), within P2 of the request. A module that sent response-pending has P2*
/// from its latest one to answer. A module that has answered, or let its P2* run out, is done.
/// Replies that break these rules are dropped, and so are replies from CAN IDs that `expect`
/// doesn't accept and replies that don't answer this request (see [`response::answers`]), such
/// as a late reply to an earlier one. (An [`crate::Audited`] transport still logs them all.)
///
/// - [`Expect::ObdEcus`] returns each ECU's answer, which may be none, once every ECU has
///   answered or run out of time.
/// - [`Expect::Module`] returns the module's answer, or [`Error::Timeout`] if it didn't answer
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
    // Every module's first reply is due by here.
    let first_due = after(timing.p2);
    // Modules that sent response-pending, and when their P2* ends.
    let mut pending_until: Vec<(u32, Instant)> = Vec::new();
    // Modules that answered or ran out of time: nothing more from them counts.
    let mut done: Vec<u32> = Vec::new();
    let mut pending = 0u16;
    let mut replies = Vec::new();
    loop {
        let deadline = pending_until
            .iter()
            .map(|&(_, until)| until)
            .fold(first_due, Instant::max);
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
        let now = Instant::now();
        pending_until.retain(|&(source, until)| {
            let expired = until <= now;
            if expired {
                done.push(source);
            }
            !expired
        });
        let was_pending = pending_until.iter().any(|&(s, _)| s == reply.source);
        if done.contains(&reply.source) || (!was_pending && now > first_due) {
            continue;
        }
        pending_until.retain(|&(source, _)| source != reply.source);
        if sid.is_some_and(|sid| is_pending(sid, &reply.payload)) {
            if pending == timing.max_pending {
                return Err(Error::Timeout);
            }
            pending += 1;
            pending_until.push((reply.source, after(timing.p2_star)));
            continue;
        }
        done.push(reply.source);
        match expect {
            Expect::Module(_) => return Ok(vec![reply]),
            Expect::ObdEcus => replies.push(reply),
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
