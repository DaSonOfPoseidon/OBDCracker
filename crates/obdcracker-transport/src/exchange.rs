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
/// Replies from CAN IDs that `expect` doesn't accept are dropped. A response-pending reply
/// (`7F <service> 78`) to this request is dropped too, and extends the wait to P2*.
///
/// - [`Expect::ObdEcus`] returns every reply that arrived, which may be none.
/// - [`Expect::Module`] returns the module's one reply, or [`Error::Timeout`] if it didn't answer
///   in time. A request with the suppress-positive-response bit set gets no reply when it
///   succeeds, so it times out here.
///
/// More response-pending replies than [`Timing::max_pending`] give [`Error::Timeout`], and an
/// adapter error is returned as soon as it happens.
pub fn exchange<T: Transport + ?Sized>(
    transport: &mut T,
    request: &Approved,
    expect: Expect,
    timing: Timing,
) -> Result<Vec<Response>, Error> {
    transport.send(request)?;
    let sid = request.payload().first().copied();
    let mut deadline = Instant::now() + timing.p2;
    let mut pending = 0u16;
    let mut replies = Vec::new();
    while let Some(left) = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
    {
        let reply = match transport.recv(left) {
            Ok(reply) => reply,
            Err(Error::Timeout) => break,
            Err(e) => return Err(e),
        };
        if !expect.accepts(reply.source) {
            continue;
        }
        if sid.is_some_and(|sid| is_pending(sid, &reply.payload)) {
            pending += 1;
            if pending > timing.max_pending {
                return Err(Error::Timeout);
            }
            deadline = deadline.max(Instant::now() + timing.p2_star);
            continue;
        }
        match expect {
            Expect::Module(_) => return Ok(vec![reply]),
            Expect::ObdEcus => {
                replies.push(reply);
                deadline = deadline.max(Instant::now() + timing.p2);
            }
        }
    }
    match expect {
        Expect::Module(_) => Err(Error::Timeout),
        Expect::ObdEcus => Ok(replies),
    }
}

fn is_pending(sid: u8, reply: &[u8]) -> bool {
    matches!(
        response::positive(sid, reply),
        Err(ReplyError::Negative(negative)) if negative.nrc.is_pending()
    )
}
