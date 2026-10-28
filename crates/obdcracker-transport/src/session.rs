use std::fmt;
use std::time::{Duration, Instant};

use obdcracker_core::response;
use obdcracker_core::uds::{self, DiagnosticSession};
use obdcracker_safety::{Approved, Policy, Protocol, Rejection, Target};

use crate::{Error, Expect, Response, Timing, Transport, exchange};

/// How long a module keeps a non-default session without a request, and how often to remind it.
///
/// Any values are safe, they only change what's sent. See docs/scanning.md#extended-session-and-testerpresent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3 {
    /// How long after the last request the module accepted to send `TesterPresent`: 2 s by
    /// default (S3client, ISO 14229-2).
    pub keepalive: Duration,
    /// How long the module stays in the session without a request: 5 s by default (S3server,
    /// ISO 14229-2).
    pub timeout: Duration,
}

impl S3 {
    // Halfway from `keepalive` to `timeout`: the rest is margin for a request on its way.
    fn trusted(self) -> Duration {
        self.timeout
            .saturating_sub(self.timeout.saturating_sub(self.keepalive) / 2)
    }
}

impl Default for S3 {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(2),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Why an [`ExtendedSession`] couldn't enter, keep or leave the session, or send a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The policy refused a session request for this target.
    Policy(Rejection),
    /// The policy doesn't know which CAN ID the module answers on: narrow it to the car's
    /// modules first ([`Policy::narrowed_to`]).
    UnknownReplyId,
    /// The request is for another module than the session's.
    WrongTarget,
    /// The request changes the diagnostic session, which only the session itself may do.
    SessionChange,
    /// The module refused a session request, or its answer to `10 03` wasn't usable; this is its reply.
    Refused(Vec<u8>),
    /// The adapter failed, or the module didn't answer in time.
    Transport(Error),
    /// The module didn't confirm entering the session (`entry`), so it was asked to leave, and
    /// didn't confirm that either (`leave`): it may stay in the extended session until S3 runs
    /// out without a `TesterPresent`.
    Unconfirmed {
        /// Why entering wasn't confirmed.
        entry: Box<SessionError>,
        /// Why leaving wasn't.
        leave: Box<SessionError>,
    },
    /// [`ExtendedSession::end`]'s first `10 01` got no definite answer, and the retry failed
    /// with this. As with [`Left::out_of_step`], a late answer may still arrive: connect again
    /// before sending this module another `10` request.
    Retried(Box<SessionError>),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(rejection) => rejection.fmt(f),
            Self::UnknownReplyId => f.write_str("the module's reply ID isn't known"),
            Self::WrongTarget => f.write_str("the request is for another module"),
            Self::SessionChange => f.write_str("only the session itself changes the session"),
            Self::Refused(reply) => write!(
                f,
                "the module refused the session request: {}",
                crate::hex(reply)
            ),
            Self::Transport(e) => e.fmt(f),
            Self::Unconfirmed { entry, leave } => {
                write!(f, "{entry}; leaving the session then failed too: {leave}")
            }
            Self::Retried(retry) => write!(
                f,
                "`10 01` got no definite answer, then the retry failed: {retry}"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<Error> for SessionError {
    fn from(e: Error) -> Self {
        Self::Transport(e)
    }
}

/// How [`ExtendedSession::end`] returned the module to the default session.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Left {
    /// Whether `10 01` went unanswered and the retry got the answer. The first try's late answer
    /// may have been taken for the retry's, and the retry's own may still arrive. A refusal of
    /// a later `10` request to this module doesn't echo the subfunction, so it can't be told
    /// apart from that leftover: connect again before sending one.
    pub out_of_step: bool,
}

/// Holds one module in the extended diagnostic session (`10 03`) and returns it to the default
/// session (`10 01`) when dropped, so no module is left in the extended session.
///
/// Nothing runs in the background: call [`ExtendedSession::keep_alive`] whenever the caller
/// waits between requests, and it sends `TesterPresent` (`3E 00`) once [`S3::keepalive`] has
/// passed. If the session may have lapsed, `keep_alive` and [`ExtendedSession::exchange`] enter
/// it again first. Every request, keepalives included, goes through the policy and the
/// transport, so an [`crate::Audited`] transport logs them all.
///
/// See docs/scanning.md#extended-session-and-testerpresent.
///
/// ```
/// use std::time::Duration;
///
/// use obdcracker_core::uds::{self, DiagnosticSession};
/// use obdcracker_safety::{Policy, Protocol, Target};
/// use obdcracker_transport::{ExtendedSession, Mock, Response, S3, Timing};
///
/// let mut adapter = Mock::default();
/// for payload in [&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4][..], &[0x62, 0x06, 0x00, 0x01]] {
///     adapter.queue(Response { source: 0x7E8, payload: payload.to_vec() });
/// }
/// let policy = Policy::read_only();
/// let engine = Target::Physical(0x7E0);
/// let mut session =
///     ExtendedSession::enter(&mut adapter, &policy, engine, Timing::default(), S3::default())?;
/// let coding = policy.approve(Protocol::Uds, engine, &uds::read_did(0x0600))?;
/// assert_eq!(session.exchange(&coding)?.payload, [0x62, 0x06, 0x00, 0x01]);
/// session.keep_alive()?; // between requests: sends `3E 00` once 2 s have passed
/// drop(session); // sends `10 01`
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct ExtendedSession<'a, T: Transport + ?Sized> {
    transport: &'a mut T,
    enter: Approved,
    present: Approved,
    leave: Approved,
    reply: u32,
    // The caller's timing, and that extended by the module's P2 and P2* for the session.
    base: Timing,
    timing: Timing,
    s3: S3,
    // Just before the last request the module accepted was sent.
    last: Instant,
    ended: bool,
}

impl<'a, T: Transport + ?Sized> ExtendedSession<'a, T> {
    /// Puts the module at `target` in the extended session. `timing` is used for every exchange
    /// through the session.
    ///
    /// # Errors
    ///
    /// The policy refuses a session request for `target` or doesn't know its reply ID, the
    /// module refuses `10 03` or doesn't answer, or the adapter fails. Unless the module sent a
    /// well-formed refusal, `10 03` may have taken effect, so the module is sent `10 01` then.
    pub fn enter(
        transport: &'a mut T,
        policy: &Policy,
        target: Target,
        timing: Timing,
        s3: S3,
    ) -> Result<Self, SessionError> {
        let approve = |payload: &[u8]| {
            policy
                .approve(Protocol::Uds, target, payload)
                .map_err(SessionError::Policy)
        };
        let enter = approve(&uds::session_control(DiagnosticSession::Extended))?;
        // `3E 00`, not `3E 80`: ELM would wait out its timeout for the suppressed reply.
        let present = approve(&uds::tester_present())?;
        let leave = approve(&uds::session_control(DiagnosticSession::Default))?;
        let reply = enter.reply_id().ok_or(SessionError::UnknownReplyId)?;
        let mut session = Self {
            transport,
            enter,
            present,
            leave,
            reply,
            base: timing,
            timing,
            s3,
            last: Instant::now(),
            // Nothing to leave until the module has entered.
            ended: true,
        };
        match session.request(&session.enter.clone()) {
            Ok(()) => {
                session.ended = false;
                Ok(session)
            }
            // Only a plain refusal says the module stayed in the default session.
            Err(SessionError::Refused(reply)) if plainly_refused(&reply) => {
                Err(SessionError::Refused(reply))
            }
            Err(e) => {
                // No answer doesn't mean the module didn't switch, so leave. An adapter
                // failure then matters more than the missing answer.
                match session.request(&session.leave.clone()) {
                    Ok(()) => Err(e),
                    Err(SessionError::Transport(failure @ Error::Adapter(_))) => {
                        Err(SessionError::Transport(failure))
                    }
                    Err(leave) => Err(SessionError::Unconfirmed {
                        entry: Box::new(e),
                        leave: Box::new(leave),
                    }),
                }
            }
        }
    }

    /// Sends `TesterPresent` if [`S3::keepalive`] has passed since the module last accepted a
    /// request, or enters the session again if it may have lapsed (see [`S3`]). Call it between
    /// requests while the caller waits.
    ///
    /// # Errors
    ///
    /// The module refuses the request or doesn't answer, or the adapter fails.
    pub fn keep_alive(&mut self) -> Result<(), SessionError> {
        if self.lapsed() {
            self.request(&self.enter.clone())
        } else if self.last.elapsed() >= self.s3.keepalive {
            self.request(&self.present.clone())
        } else {
            Ok(())
        }
    }

    /// Sends `request` to the session's module and returns its answer, entering the session
    /// again first if it has lapsed. The answer may be a refusal: it's returned for the caller
    /// to decode, like any other.
    ///
    /// # Errors
    ///
    /// [`SessionError::WrongTarget`] for a request to another module,
    /// [`SessionError::SessionChange`] for a `DiagnosticSessionControl` request, the module
    /// refuses to enter the session again, or doesn't answer, or the adapter fails.
    pub fn exchange(&mut self, request: &Approved) -> Result<Response, SessionError> {
        self.prepare(request)?;
        self.exchange_prepared(request)
    }

    // `exchange`'s checks and re-entry. A failure here means `request` wasn't sent.
    pub(crate) fn prepare(&mut self, request: &Approved) -> Result<(), SessionError> {
        if request.target() != self.enter.target() {
            return Err(SessionError::WrongTarget);
        }
        if request.payload().first() == Some(&uds::DIAGNOSTIC_SESSION_CONTROL) {
            return Err(SessionError::SessionChange);
        }
        if self.lapsed() {
            self.request(&self.enter.clone())?;
        }
        Ok(())
    }

    pub(crate) fn exchange_prepared(
        &mut self,
        request: &Approved,
    ) -> Result<Response, SessionError> {
        let (started, reply) = self.send(request)?;
        // Only a positive answer counts: at worst the next request re-enters needlessly.
        if response::positive(request.payload()[0], &reply.payload).is_ok() {
            self.last = started;
        }
        Ok(reply)
    }

    /// Returns the module to the default session. Dropping the session does the same (one try),
    /// but can't report a failure. Unless the module accepted or plainly refused `10 01`, it's
    /// tried once more, and [`Left::out_of_step`] says whether that retry is what succeeded.
    ///
    /// # Errors
    ///
    /// The module refuses `10 01` or doesn't answer, or the adapter fails. An adapter failure on
    /// either try is returned as it is, as the adapter's state is unknown. Any other failure of
    /// the retry is [`SessionError::Retried`].
    pub fn end(mut self) -> Result<Left, SessionError> {
        // Drop must not send a second `10 01` unobserved.
        self.ended = true;
        let first = self.request(&self.leave.clone());
        match first {
            Ok(()) => Ok(Left { out_of_step: false }),
            Err(SessionError::Refused(reply)) if plainly_refused(&reply) => {
                Err(SessionError::Refused(reply))
            }
            // An adapter failure stands however the retry goes: the adapter's state is unknown.
            Err(first @ SessionError::Transport(Error::Adapter(_))) => {
                let _ = self.request(&self.leave.clone());
                Err(first)
            }
            Err(_) => match self.request(&self.leave.clone()) {
                Ok(()) => Ok(Left { out_of_step: true }),
                Err(e @ SessionError::Transport(Error::Adapter(_))) => Err(e),
                Err(e) => Err(SessionError::Retried(Box::new(e))),
            },
        }
    }

    // Sends one of the session's own requests. Only an accepted one restarts the clock: after a
    // refused `10 03` the module is in the default session, and a `3E 00` would keep it there.
    fn request(&mut self, request: &Approved) -> Result<(), SessionError> {
        let (started, reply) = self.send(request)?;
        let sid = request.payload()[0];
        match response::positive(sid, &reply.payload) {
            Ok(_) => {
                // Older servers send a bare `50 03`; anything else isn't a confirmed entry.
                if request.payload() == self.enter.payload() {
                    match uds::decode_session_timing(&reply.payload, DiagnosticSession::Extended) {
                        Ok(given) => self.timing = extended(self.base, given),
                        Err(_) if reply.payload == [0x50, 0x03] => self.timing = self.base,
                        Err(_) => return Err(SessionError::Refused(reply.payload)),
                    }
                }
                self.last = started;
                Ok(())
            }
            Err(_) => Err(SessionError::Refused(reply.payload)),
        }
    }

    fn lapsed(&self) -> bool {
        self.last.elapsed() >= self.s3.trusted()
    }

    fn send(&mut self, request: &Approved) -> Result<(Instant, Response), SessionError> {
        let started = Instant::now();
        let mut replies = exchange(
            self.transport,
            request,
            Expect::Module(self.reply),
            self.timing,
        )?;
        Ok((started, replies.remove(0)))
    }
}

// A well-formed refusal (`7F 10 <NRC>`): the module stayed in the session it was in.
pub(crate) fn plainly_refused(reply: &[u8]) -> bool {
    matches!(
        response::positive(uds::DIAGNOSTIC_SESSION_CONTROL, reply),
        Err(response::Error::Negative(_))
    )
}

// The caller's timing plus how much longer than ISO 14229-2's defaults the module's P2 and P2* are.
fn extended(base: Timing, given: uds::SessionTiming) -> Timing {
    let standard = Timing::default();
    Timing {
        p2: base.p2.saturating_add(given.p2.saturating_sub(standard.p2)),
        p2_star: base
            .p2_star
            .saturating_add(given.p2_star.saturating_sub(standard.p2_star)),
        ..base
    }
}

impl<T: Transport + ?Sized> Drop for ExtendedSession<'_, T> {
    fn drop(&mut self) {
        if !self.ended {
            self.ended = true;
            // Nothing can report a failure from here; `end` does.
            let _ = self.request(&self.leave.clone());
        }
    }
}
