//! Looking for VW TP2.0 modules: a channel setup to each address, and a disconnect of each channel
//! a module gives. Channels are only opened and closed; no service request goes on them yet
//! (#142).

use obdcracker_core::tp20::{self, Channel};
use obdcracker_safety::{Approved, Policy, Rejection};

use crate::fingerprint::FingerprintError;
use crate::{Error, Expect, Response, Timing, Transport, exchange};

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
/// [`FingerprintError::Rejected`] if the policy refuses an address (nothing is sent), or
/// [`FingerprintError::Transport`] if the adapter fails.
pub fn probe<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    addresses: &[u8],
    timing: Timing,
) -> Result<Vec<Probed>, FingerprintError> {
    let setups = addresses
        .iter()
        .map(|&address| {
            policy
                .approve_tp20_setup(address)
                .map(|setup| (address, setup))
                .map_err(FingerprintError::Rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut found = Vec::new();
    for (address, setup) in setups {
        let Some(reply) = first_reply(transport, &setup, tp20::setup_reply_id(address), timing)?
        else {
            continue;
        };
        let answer = match tp20::decode_channel_setup(&reply.payload) {
            Ok(channel) => Answer::Channel(channel),
            Err(tp20::Error::Refused(op)) => Answer::Refused(op),
            Err(_) => Answer::Undecodable(reply.payload.clone()),
        };
        let disconnect = match &answer {
            Answer::Channel(_) => Some(close(transport, policy, &setup, &reply, timing)?),
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

fn close<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    setup: &Approved,
    reply: &Response,
    timing: Timing,
) -> Result<Disconnect, FingerprintError> {
    let approved = policy
        .tp20_channel(setup, reply.source, &reply.payload)
        .and_then(|channel| Ok((channel, policy.approve_tp20_disconnect(&channel)?)));
    let (channel, request) = match approved {
        Ok(approved) => approved,
        Err(rejection) => return Ok(Disconnect::NotSent(rejection)),
    };
    Ok(
        match first_reply(transport, &request, channel.receive_id(), timing)? {
            Some(_) => Disconnect::Closed,
            None => Disconnect::NoReply,
        },
    )
}

// The first reply from `source` that answers `request`, or None if none came in time.
fn first_reply<T: Transport + ?Sized>(
    transport: &mut T,
    request: &Approved,
    source: u32,
    timing: Timing,
) -> Result<Option<Response>, FingerprintError> {
    match exchange(transport, request, Expect::Module(source), timing) {
        Ok(replies) => Ok(replies.into_iter().next()),
        Err(Error::Timeout | Error::StillPending) => Ok(None),
        Err(e) => Err(FingerprintError::Transport(e)),
    }
}
