//! VW TP2.0: looking for modules ([`probe`]), and KWP2000 reads on a channel one opens
//! ([`ChannelSession`]). See docs/tp20.md.

use std::fmt;
use std::time::{Duration, Instant};

use obdcracker_core::response;
use obdcracker_core::tp20::{self, Channel, Frame, Parameters, Progress, Reassembler};
use obdcracker_safety::{Approved, OpenTp20Channel, Policy, Rejection};

use crate::fingerprint::FingerprintError;
use crate::{Error, Expect, Response, Timing, Transport, exchange};

/// A channel the session hasn't sent on for this long gets a keep-alive before its next request.
pub const KEEP_ALIVE_IDLE: Duration = Duration::from_millis(500);

// The longest message a module can send (its 2-byte length field).
const MAX_MESSAGE: usize = 0xFFFF;
// The most frames the longest message takes, at 7 data bytes a frame.
const MAX_FRAMES_PER_MESSAGE: usize = MAX_MESSAGE.div_ceil(7) + 1;
// A KWP2000 refusal, and its code for response-pending.
const NEGATIVE: u8 = 0x7F;
const RESPONSE_PENDING: u8 = 0x78;

/// How a module answered a channel setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// It opened a channel.
    Channel(Channel),
    /// It refused one, with this opcode (such as 0xD7, no resources).
    Refused(u8),
    /// Its answer couldn't be read: the bytes, as it sent them.
    Undecodable(Vec<u8>),
}

/// What became of a channel a module opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disconnect {
    /// It answered the disconnect.
    Closed,
    /// It didn't answer in time; the module closes an idle channel by itself.
    NoReply,
    /// The policy refused the disconnect, so nothing was sent: the channel's IDs are another
    /// module's, or ones the policy doesn't send a disconnect to.
    NotSent(Rejection),
}

/// A module that answered a channel setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    /// Its address.
    pub address: u8,
    /// How it answered.
    pub answer: Answer,
    /// For a channel it opened, what became of it.
    pub disconnect: Option<Disconnect>,
}

/// Sends a channel setup to each address in turn, and closes each channel a module opens.
/// Returns the modules that answered; a timeout only means nothing is there. Every setup is
/// approved before the first is sent, and each disconnect before it's sent.
///
/// # Errors
///
/// [`FingerprintError::Rejected`], with nothing sent, if the policy refuses an address or one is
/// given twice ([`Rejection::WrongTarget`]), or [`FingerprintError::Transport`] if the adapter
/// fails.
pub fn probe<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    addresses: &[u8],
    timing: Timing,
) -> Result<Vec<Probed>, FingerprintError> {
    let setups = addresses
        .iter()
        .enumerate()
        .map(|(i, &address)| {
            if addresses[..i].contains(&address) {
                return Err(FingerprintError::Rejected(Rejection::WrongTarget));
            }
            policy
                .approve_tp20_setup(address)
                .map(|setup| (address, setup))
                .map_err(FingerprintError::Rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut found = Vec::new();
    for (address, setup) in setups {
        let Some(reply) = answer(transport, &setup, tp20::setup_reply_id(address), timing)
            .map_err(FingerprintError::Transport)?
        else {
            continue;
        };
        let answer = match tp20::decode_channel_setup(&reply.payload) {
            Ok(channel) => Answer::Channel(channel),
            Err(tp20::Error::Refused(op)) => Answer::Refused(op),
            Err(_) => Answer::Undecodable(reply.payload.clone()),
        };
        let disconnect = match &answer {
            Answer::Channel(_) => Some(
                match policy.tp20_channel(&setup, reply.source, &reply.payload) {
                    Ok(channel) => disconnect(transport, policy, channel, timing)
                        .map_err(FingerprintError::Transport)?,
                    Err(rejection) => Disconnect::NotSent(rejection),
                },
            ),
            _ => None,
        };
        found.push(Probed {
            address,
            answer,
            disconnect,
        });
    }
    Ok(found)
}

/// Why a [`ChannelSession`] couldn't open its channel or read on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The policy refused a frame, so it wasn't sent.
    Rejected(Rejection),
    /// The adapter failed.
    Transport(Error),
    /// Nothing answered the channel setup.
    NoAnswer,
    /// The module refused a channel, with this opcode (such as 0xD7, no resources).
    Refused(u8),
    /// The module's answer to the setup or to the tester's parameters couldn't be read: the
    /// bytes, as it sent them.
    Undecodable(Vec<u8>),
    /// The module didn't answer the request in time.
    Timeout,
    /// The module sent response-pending but didn't answer in time, or sent more of them than
    /// [`Timing::max_pending`].
    StillPending,
    /// A frame broke the channel's framing: a sequence number out of order (such as a frame
    /// the adapter lost), an ACK of a frame the tester didn't send, or a frame that has no
    /// place there. The frame's bytes, as the module sent them.
    Framing(Vec<u8>),
    /// A whole message arrived that doesn't answer the request, such as a late answer to an
    /// earlier one: its bytes.
    Unmatched(Vec<u8>),
    /// The module closed the channel (`A8`).
    ClosedByModule,
    /// The channel is closed: after an earlier error, or by the module.
    Closed,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(rejection) => write!(f, "safety policy {rejection}"),
            Self::Transport(e) => e.fmt(f),
            Self::NoAnswer => f.write_str("nothing answered the TP2.0 channel setup"),
            Self::Refused(op) => write!(f, "the module refused a TP2.0 channel ({op:02X})"),
            Self::Undecodable(bytes) => write!(
                f,
                "the module's TP2.0 answer couldn't be read [{}]",
                crate::hex(bytes)
            ),
            Self::Timeout => f.write_str("the module didn't answer on the TP2.0 channel in time"),
            Self::StillPending => f.write_str(
                "the module said it was busy (response-pending) but didn't answer in time",
            ),
            Self::Framing(bytes) => write!(
                f,
                "a TP2.0 frame broke the channel's framing [{}]",
                crate::hex(bytes)
            ),
            Self::Unmatched(bytes) => write!(
                f,
                "the module's TP2.0 message doesn't answer the request [{}]",
                crate::hex(bytes)
            ),
            Self::ClosedByModule => f.write_str("the module closed the TP2.0 channel"),
            Self::Closed => f.write_str("the TP2.0 channel is closed"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// An open VW TP2.0 channel to one module, for KWP2000 reads: see docs/tp20.md#data-transfer.
///
/// Every frame is approved by the policy for the channel the module opened: the tester's
/// parameters, each request's data frame, every ACK, keep-alives and the disconnect. A request
/// goes out as one data frame (at most [`tp20::MAX_SINGLE_FRAME`] bytes); the module's answer
/// may span many, and the session ACKs each frame that asks for one. After any error but a
/// refused request, the channel is closed (`A8`) and every later request gets
/// [`ChannelError::Closed`]: replies may be out of step from then on. Dropping the session also
/// closes the channel, without reporting how that went; [`ChannelSession::close`] does.
#[derive(Debug)]
pub struct ChannelSession<'a, T: Transport + ?Sized> {
    transport: &'a mut T,
    policy: &'a Policy,
    channel: OpenTp20Channel,
    parameters: Parameters,
    timing: Timing,
    // The sequence number of the tester's next data frame.
    sequence: u8,
    reassembler: Reassembler<Vec<u8>>,
    // When the tester last sent on the channel.
    last: Instant,
    open: bool,
}

impl<'a, T: Transport + ?Sized> ChannelSession<'a, T> {
    /// Opens a channel to the module at `address` and exchanges channel parameters. `timing`
    /// is used for every frame through the session.
    ///
    /// # Errors
    ///
    /// The policy refuses the setup or the parameters, nothing answers, the module refuses a
    /// channel or answers with something unreadable, or the adapter fails. Once a channel is
    /// open, a failure closes it again.
    pub fn open(
        transport: &'a mut T,
        policy: &'a Policy,
        address: u8,
        timing: Timing,
    ) -> Result<Self, ChannelError> {
        let setup = policy
            .approve_tp20_setup(address)
            .map_err(ChannelError::Rejected)?;
        let reply = answer(transport, &setup, tp20::setup_reply_id(address), timing)
            .map_err(ChannelError::Transport)?
            .ok_or(ChannelError::NoAnswer)?;
        match tp20::decode_channel_setup(&reply.payload) {
            Ok(_) => {}
            Err(tp20::Error::Refused(op)) => return Err(ChannelError::Refused(op)),
            Err(_) => return Err(ChannelError::Undecodable(reply.payload)),
        }
        let channel = policy
            .tp20_channel(&setup, reply.source, &reply.payload)
            .map_err(ChannelError::Rejected)?;
        let mut session = Self {
            transport,
            policy,
            channel,
            // Replaced by the module's own below.
            parameters: Parameters {
                block_size: 1,
                t1: Duration::ZERO,
                t3: Duration::ZERO,
            },
            timing,
            sequence: 0,
            reassembler: Reassembler::new(vec![0; MAX_MESSAGE]),
            last: Instant::now(),
            open: true,
        };
        let parameters = policy
            .approve_tp20_parameters(&channel)
            .map_err(ChannelError::Rejected);
        match parameters.and_then(|request| session.control(&request)) {
            Ok(parameters) => {
                session.parameters = parameters;
                Ok(session)
            }
            Err(e) => Err(session.abort(e)),
        }
    }

    /// The channel's IDs, as the module gave them.
    #[must_use]
    pub fn channel(&self) -> OpenTp20Channel {
        self.channel
    }

    /// The module's channel parameters, from its latest `A1`.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Sends a keep-alive (`A3`) and reads the module's parameters in answer. [`request`]
    /// sends one itself after [`KEEP_ALIVE_IDLE`] without a frame.
    ///
    /// [`request`]: ChannelSession::request
    ///
    /// # Errors
    ///
    /// As [`ChannelSession::request`].
    pub fn keep_alive(&mut self) -> Result<(), ChannelError> {
        if !self.open {
            return Err(ChannelError::Closed);
        }
        let request = self
            .policy
            .approve_tp20_keep_alive(&self.channel)
            .map_err(ChannelError::Rejected)?;
        match self.control(&request) {
            Ok(parameters) => {
                self.parameters = parameters;
                Ok(())
            }
            Err(e) => Err(self.abort(e)),
        }
    }

    /// Sends the KWP2000 `request` and returns the module's answer, positive or a refusal
    /// (`7F <service> <code>`), once a whole message that answers it has arrived
    /// ([`response::kwp2000_answers`]). Response-pending (`7F <service> 78`) is waited through,
    /// as `timing` allows.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Rejected`] if the policy refuses the request, which leaves the channel
    /// open; otherwise the channel is closed after any error: no answer in time, a frame that
    /// breaks the framing, a message that doesn't answer the request, the module closing the
    /// channel, or an adapter failure. [`ChannelError::Closed`] once it's closed.
    pub fn request(&mut self, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if !self.open {
            return Err(ChannelError::Closed);
        }
        let frame = self
            .policy
            .approve_tp20_request(&self.channel, self.sequence, request)
            .map_err(ChannelError::Rejected)?;
        if self.last.elapsed() >= KEEP_ALIVE_IDLE {
            self.keep_alive()?;
        }
        match self.transfer(&frame, request) {
            Ok(answer) => Ok(answer),
            Err(e) => Err(self.abort(e)),
        }
    }

    /// Closes the channel (`A8`) and says how the module took it.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Closed`], with nothing sent, if it's closed already (after an error, or
    /// by the module); otherwise the adapter failed.
    pub fn close(mut self) -> Result<Disconnect, ChannelError> {
        if !self.open {
            return Err(ChannelError::Closed);
        }
        self.open = false;
        disconnect(self.transport, self.policy, self.channel, self.timing)
            .map_err(ChannelError::Transport)
    }

    // Sends a channel frame the module answers with its parameters, and reads them.
    fn control(&mut self, request: &Approved) -> Result<Parameters, ChannelError> {
        self.last = Instant::now();
        let reply = answer(
            self.transport,
            request,
            self.channel.receive_id(),
            self.timing,
        )
        .map_err(ChannelError::Transport)?
        .ok_or(ChannelError::Timeout)?;
        tp20::decode_channel_parameters(&reply.payload)
            .map_err(|_| ChannelError::Undecodable(reply.payload))
    }

    // Sends one data frame and reads frames until a message answers `request`.
    fn transfer(&mut self, frame: &Approved, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let receive_id = self.channel.receive_id();
        let sid = request[0];
        self.send(frame)?;
        self.sequence = (self.sequence + 1) & 0x0F;
        // Each frame from the module restarts the wait; P2* after response-pending.
        let gap = self.timing.p2.max(self.parameters.t1).min(LONGEST_WAIT);
        let mut deadline = Instant::now() + gap;
        let mut pending: u16 = 0;
        let mut acked = false;
        let mut keep_alives = 0usize;
        // Keep-alives sent that the module hasn't answered yet.
        let mut unanswered = 0usize;
        // The longest answer and as many pending messages, with room for ACKs and keep-alives.
        let frame_limit =
            MAX_FRAMES_PER_MESSAGE.saturating_mul(usize::from(self.timing.max_pending) + 2);
        let mut frames = 0usize;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            // Frames that change nothing (another module's) don't stop the clock.
            if left.is_zero() {
                return Err(if pending > 0 {
                    ChannelError::StillPending
                } else {
                    ChannelError::Timeout
                });
            }
            let reply = match self.transport.recv(left) {
                Ok(reply) => reply,
                // An adapter that stops listening between frames (an ELM327 after its prompt)
                // listens again after a frame the tester sends: a keep-alive, while the module
                // works on an answer it said is pending.
                Err(Error::Timeout)
                    if pending > 0 && keep_alives < usize::from(self.timing.max_pending) =>
                {
                    let keep_alive = self
                        .policy
                        .approve_tp20_keep_alive(&self.channel)
                        .map_err(ChannelError::Rejected)?;
                    self.send(&keep_alive)?;
                    keep_alives += 1;
                    unanswered += 1;
                    continue;
                }
                Err(Error::Timeout) if pending > 0 => return Err(ChannelError::StillPending),
                Err(Error::Timeout) => return Err(ChannelError::Timeout),
                Err(e) => return Err(ChannelError::Transport(e)),
            };
            if reply.source != receive_id {
                continue;
            }
            frames += 1;
            if frames > frame_limit {
                return Err(ChannelError::Framing(reply.payload));
            }
            let framing = || ChannelError::Framing(reply.payload.clone());
            match Frame::parse(&reply.payload).map_err(|_| framing())? {
                Frame::Ack { next, ready } => {
                    // The module acks the tester's one frame once it's ready for it.
                    if next != self.sequence || acked {
                        return Err(framing());
                    }
                    acked = ready;
                    if !ready {
                        // The module isn't ready for more; it acks again once it is.
                        if pending == self.timing.max_pending {
                            return Err(ChannelError::StillPending);
                        }
                        pending += 1;
                        deadline = after(self.timing.p2_star);
                    }
                }
                Frame::Parameters(parameters) if unanswered > 0 => {
                    unanswered -= 1;
                    self.parameters = parameters;
                }
                Frame::Disconnect => {
                    self.open = false;
                    return Err(ChannelError::ClosedByModule);
                }
                Frame::Parameters(_) | Frame::Test => return Err(framing()),
                Frame::Data { .. } => {
                    let message = self.take_data(&reply.payload)?;
                    deadline = after(gap);
                    let Some(message) = message else {
                        continue;
                    };
                    if message == [NEGATIVE, sid, RESPONSE_PENDING] {
                        if pending == self.timing.max_pending {
                            return Err(ChannelError::StillPending);
                        }
                        pending += 1;
                        deadline = after(self.timing.p2_star);
                        continue;
                    }
                    if !response::kwp2000_answers(request, &message) {
                        return Err(ChannelError::Unmatched(message));
                    }
                    return Ok(message);
                }
            }
        }
    }

    // Feeds one data frame, sends the ACK it asks for, and returns the message it completes.
    fn take_data(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, ChannelError> {
        let (message, ack) = match self.reassembler.feed(frame) {
            Err(_) => return Err(ChannelError::Framing(frame.to_vec())),
            Ok(Progress::Pending) => (None, None),
            Ok(Progress::Ack(next)) => (None, Some(next)),
            Ok(Progress::Complete { payload, ack }) => (Some(payload.to_vec()), ack),
        };
        if let Some(next) = ack {
            let ack = self
                .policy
                .approve_tp20_ack(&self.channel, next)
                .map_err(ChannelError::Rejected)?;
            self.send(&ack)?;
        }
        Ok(message)
    }

    fn send(&mut self, frame: &Approved) -> Result<(), ChannelError> {
        self.last = Instant::now();
        self.transport.send(frame).map_err(ChannelError::Transport)
    }

    // Closes the channel after `error`. An adapter failure while closing matters more: the
    // adapter's state is unknown.
    fn abort(&mut self, error: ChannelError) -> ChannelError {
        if !self.open || matches!(error, ChannelError::Transport(Error::Adapter(_))) {
            self.open = false;
            return error;
        }
        self.open = false;
        match disconnect(self.transport, self.policy, self.channel, self.timing) {
            Err(failure @ Error::Adapter(_)) => ChannelError::Transport(failure),
            _ => error,
        }
    }
}

impl<T: Transport + ?Sized> Drop for ChannelSession<'_, T> {
    fn drop(&mut self) {
        if self.open {
            self.open = false;
            // Nothing can report a failure from here; `close` does.
            let _ = disconnect(self.transport, self.policy, self.channel, self.timing);
        }
    }
}

// The longest any single wait lasts, so a huge timing can't overflow the clock.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);

fn after(wait: Duration) -> Instant {
    Instant::now() + wait.min(LONGEST_WAIT)
}

// Sends `A8` on `channel`; a refused or unanswered one is harmless, as the module closes an
// idle channel by itself.
fn disconnect<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    channel: OpenTp20Channel,
    timing: Timing,
) -> Result<Disconnect, Error> {
    let request = match policy.approve_tp20_disconnect(&channel) {
        Ok(request) => request,
        Err(rejection) => return Ok(Disconnect::NotSent(rejection)),
    };
    Ok(
        match answer(transport, &request, channel.receive_id(), timing)? {
            Some(_) => Disconnect::Closed,
            None => Disconnect::NoReply,
        },
    )
}

// The first reply to `request` from `source`, or None if it didn't come in time.
fn answer<T: Transport + ?Sized>(
    transport: &mut T,
    request: &Approved,
    source: u32,
    timing: Timing,
) -> Result<Option<Response>, Error> {
    match exchange(transport, request, Expect::Module(source), timing) {
        Ok(replies) => Ok(replies.into_iter().next()),
        Err(Error::Timeout | Error::StillPending) => Ok(None),
        Err(e) => Err(e),
    }
}
