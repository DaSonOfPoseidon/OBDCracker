use std::fmt;
use std::time::{Duration, Instant};

use obdcracker_core::response;
use obdcracker_core::uds::{self, DiagnosticSession};
use obdcracker_safety::{Approved, Policy, Rejection, Target};

use crate::{Error, Expect, Response, Timing, Transport, exchange};

/// How long a module keeps a non-default session without a request, and how often to remind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3 {
    /// How long after the last request to send `TesterPresent`: 2 s by default (S3client,
    /// ISO 14229-2).
    pub keepalive: Duration,
    /// How long the module stays in the session without a request: 5 s by default (S3server,
    /// ISO 14229-2). Once this has passed, the session is entered again instead.
    pub timeout: Duration,
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
    /// The module refused a session request; this is its reply.
    Refused(Vec<u8>),
    /// The adapter failed, or the module didn't answer in time.
    Transport(Error),
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
        }
    }
}

impl std::error::Error for SessionError {}

impl From<Error> for SessionError {
    fn from(e: Error) -> Self {
        Self::Transport(e)
    }
}

/// Holds one module in the extended diagnostic session (`10 03`) and returns it to the default
/// session (`10 01`) when dropped, so no module is left in the extended session.
///
/// A module drops back to the default session on its own after S3 without a request
/// ([`S3::timeout`]). Nothing runs in the background, because a keepalive can't go out while a
/// request is waiting for its reply on the same adapter. So call [`ExtendedSession::keep_alive`]
/// whenever the caller waits between requests: it sends `TesterPresent` (`3E 00`) once
/// [`S3::keepalive`] has passed since the last request the module accepted. If the session has
/// lapsed anyway,
/// `keep_alive` and [`ExtendedSession::exchange`] enter it again first. (Anything tied to the
/// session, such as security access, would be lost then; reads aren't.)
///
/// Time is measured from just before each request the module accepted was sent, which is no
/// later than when the module restarted S3. A refused or unanswered request doesn't count, so
/// the session is never taken for alive after the module has left it.
/// Response-pending replies keep the session alive during a long wait (ISO 14229-2), so a slow
/// answer needs no keepalive.
///
/// `TesterPresent` is sent as `3E 00`, not with the suppress-positive-response bit (`3E 80`):
/// a suppressed request that succeeds gets no reply, so an ELM adapter would wait out its whole
/// timeout every time. Every request, keepalives included, goes through the policy and the
/// transport, so an [`crate::Audited`] transport logs them all.
///
/// ```
/// use std::time::Duration;
///
/// use obdcracker_core::uds::{self, DiagnosticSession};
/// use obdcracker_safety::{Policy, Target};
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
/// let coding = policy.approve(engine, &uds::read_did(0x0600))?;
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
    timing: Timing,
    s3: S3,
    // Just before the last request to the module was sent.
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
    /// module refuses `10 03` or doesn't answer, or the adapter fails. The module isn't sent
    /// `10 01` then.
    pub fn enter(
        transport: &'a mut T,
        policy: &Policy,
        target: Target,
        timing: Timing,
        s3: S3,
    ) -> Result<Self, SessionError> {
        let approve = |payload: &[u8]| {
            policy
                .approve(target, payload)
                .map_err(SessionError::Policy)
        };
        let enter = approve(&uds::session_control(DiagnosticSession::Extended))?;
        let present = approve(&uds::tester_present())?;
        let leave = approve(&uds::session_control(DiagnosticSession::Default))?;
        let reply = enter.reply_id().ok_or(SessionError::UnknownReplyId)?;
        let mut session = Self {
            transport,
            enter,
            present,
            leave,
            reply,
            timing,
            s3,
            last: Instant::now(),
            // Nothing to leave until the module has entered.
            ended: true,
        };
        session.request(&session.enter.clone())?;
        session.ended = false;
        Ok(session)
    }

    /// Sends `TesterPresent` if [`S3::keepalive`] has passed since the last request the module
    /// accepted, or enters the session again if [`S3::timeout`] has. Call it between requests while the caller waits.
    ///
    /// # Errors
    ///
    /// The module refuses the request or doesn't answer, or the adapter fails.
    pub fn keep_alive(&mut self) -> Result<(), SessionError> {
        let idle = self.last.elapsed();
        if idle >= self.s3.timeout {
            self.request(&self.enter.clone())
        } else if idle >= self.s3.keepalive {
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
        if request.target() != self.enter.target() {
            return Err(SessionError::WrongTarget);
        }
        if request.payload().first() == Some(&uds::DIAGNOSTIC_SESSION_CONTROL) {
            return Err(SessionError::SessionChange);
        }
        if self.last.elapsed() >= self.s3.timeout {
            self.request(&self.enter.clone())?;
        }
        let (started, reply) = self.send(request)?;
        // Only a positive answer counts, so the session is never taken for alive when it isn't;
        // at worst, the next request enters it again needlessly.
        if response::positive(request.payload()[0], &reply.payload).is_ok() {
            self.last = started;
        }
        Ok(reply)
    }

    /// Returns the module to the default session. Dropping the session does the same, but
    /// can't report a failure.
    ///
    /// # Errors
    ///
    /// The module refuses `10 01` or doesn't answer, or the adapter fails.
    pub fn end(mut self) -> Result<(), SessionError> {
        self.ended = true;
        self.request(&self.leave.clone())
    }

    // Sends one of the session's own requests and checks that the module accepted it. Only an
    // accepted one restarts the clock: after a refused `10 03`, the module is still in the
    // default session, and a `3E 00` would keep it there.
    fn request(&mut self, request: &Approved) -> Result<(), SessionError> {
        let (started, reply) = self.send(request)?;
        let sid = request.payload()[0];
        match response::positive(sid, &reply.payload) {
            Ok(_) => {
                self.last = started;
                Ok(())
            }
            Err(_) => Err(SessionError::Refused(reply.payload)),
        }
    }

    // Sends `request` and returns when it was sent, which is no later than when the module
    // restarted S3, with the module's answer.
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

impl<T: Transport + ?Sized> Drop for ExtendedSession<'_, T> {
    fn drop(&mut self) {
        if !self.ended {
            self.ended = true;
            // Nothing can report a failure from here; `end` does.
            let _ = self.request(&self.leave.clone());
        }
    }
}
