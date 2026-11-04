//! ISO-TP flow control for a raw-CAN backend, issued only as the answer to an approved request.
//!
//! A flow control frame isn't a request, so it never goes through [`Policy::approve`]. It is
//! still a frame on the bus, so the only way to get one is [`ReplyWindow`]: it opens from an
//! [`Approved`] request and mints a token only for a real first frame from the module that
//! request addresses. See [`docs/safety.md#flow-control`](https://github.com/DaSonOfPoseidon/OBDCracker/blob/main/docs/safety.md#flow-control).

use std::collections::BTreeMap;

use obdcracker_core::isotp::{
    Addressing, Error, FlowControl, FlowStatus, Frame, MAX_SHORT_PAYLOAD, Progress, Reassembler,
};

use crate::{Approved, Rejection, Target};

// ISO 15765-4: an emissions ECU answers on its request ID + 8.
const OBD_RESPONSE_IDS: core::ops::RangeInclusive<u32> = 0x7E8..=0x7EF;
const OBD_REQUEST_OFFSET: u32 = 8;

/// A flow control frame the policy issued for a module's first frame: continue-to-send, sent to
/// that module's physical request ID. Only a [`ReplyWindow`] can create one, and it is neither
/// `Clone` nor `Copy`, so each token goes out at most once.
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovedFlowControl {
    destination: u32,
    is_29_bit: bool,
    frame: obdcracker_core::isotp::CanData,
}

impl ApprovedFlowControl {
    /// The CAN ID to send the frame to: the physical request ID of the module that sent the
    /// first frame. Never the broadcast ID.
    #[must_use]
    pub fn destination_id(&self) -> u32 {
        self.destination
    }

    /// Whether the frame goes out with a 29-bit CAN ID.
    #[must_use]
    pub fn is_29_bit(&self) -> bool {
        self.is_29_bit
    }

    /// The frame's data bytes, unpadded: `30 00 00`.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.frame.as_bytes()
    }
}

/// What [`ReplyWindow::feed`] made of one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum FeedOutcome {
    /// Not from a module this window answers, or (with no known reply ID) not a frame it can
    /// use. Foreign traffic is normal on a bus, so this is not an error.
    Ignored,
    /// The frame was taken; keep feeding frames.
    Pending,
    /// A whole reply has arrived.
    Complete {
        /// The CAN ID it came from.
        source: u32,
        /// The reassembled reply, service ID first.
        payload: Vec<u8>,
    },
    /// Send this flow control frame to the module, then keep feeding frames.
    SendFlowControl(ApprovedFlowControl),
    /// A first frame arrived, but the request has no known reply ID, so there is no module to
    /// answer with flow control. Nothing was started or minted; the backend can report that a
    /// multi-frame reply needs a known reply ID if no valid reply arrives.
    NoFlowControl {
        /// The CAN ID the first frame came from.
        source: u32,
    },
}

// Which sources a window answers, and where their flow control goes.
#[derive(Debug)]
enum Sources {
    // The broadcast: an emissions ECU on 0x7E8..=0x7EF, answered on its ID - 8.
    Broadcast,
    // One module on a known reply ID, answered on the request's own target ID.
    Module {
        reply: u32,
        request: u32,
        is_29_bit: bool,
    },
    // A physical request with no known reply ID: no source can be matched.
    Unknown,
}

/// The replies to one approved request, reassembled, with the flow control they need.
///
/// It accepts frames from the module the request addressed (or, for the broadcast, from any
/// emissions ECU), reassembles each source's reply, and returns a flow control token when a
/// first frame calls for one. A token is minted only when all of these hold:
///
/// 1. The reassembler asked for flow control: a real first frame or block boundary.
/// 2. The source matches the request: for the broadcast, `0x7E8..=0x7EF`; for a physical target,
///    its [`Approved::reply_id`].
/// 3. The destination is that source's physical request ID: the source minus 8 for the
///    broadcast (never 0x7DF), or the request's own target ID.
/// 4. The status is continue-to-send. Wait and overflow are never minted.
///
/// A physical target with no known reply ID ([`Approved::reply_id`] is `None`) never gets a
/// token. A single frame from any source still completes, so **the caller must check the
/// reply's echoed service and ID**, as `exchange` does, because the window can't tell who sent
/// it. A first frame gives [`FeedOutcome::NoFlowControl`], and consecutive frames are ignored.
///
/// A reply of up to [`MAX_SHORT_PAYLOAD`] bytes fits. A first frame that announces more (the
/// 32-bit length escape) is an [`Error::Overflow`]: no token, so the module never sends the rest.
///
/// A window doesn't expire. Drop it when the transfer ends.
#[derive(Debug)]
pub struct ReplyWindow {
    sources: Sources,
    reassemblers: BTreeMap<u32, Reassembler<Vec<u8>>>,
}

impl ReplyWindow {
    /// Opens a window for the replies to `request`.
    ///
    /// # Errors
    ///
    /// [`Rejection::WrongTarget`] for a TP2.0 request: TP2.0 acknowledges its own frames and has
    /// no ISO-TP flow control.
    pub fn open(request: &Approved) -> Result<Self, Rejection> {
        let sources = match request.target() {
            Target::Tp20Setup(_) | Target::Tp20Channel(_) => return Err(Rejection::WrongTarget),
            Target::ObdFunctional => Sources::Broadcast,
            target @ (Target::Physical(_) | Target::Physical29(_)) => match request.reply_id() {
                Some(reply) => Sources::Module {
                    reply,
                    request: target.can_id(),
                    is_29_bit: target.is_29_bit(),
                },
                None => Sources::Unknown,
            },
        };
        Ok(Self {
            sources,
            reassemblers: BTreeMap::new(),
        })
    }

    /// Takes the data bytes of one CAN frame, received from CAN ID `source`.
    ///
    /// # Errors
    ///
    /// The ISO-TP error for a frame from a module this window answers that doesn't parse or fit
    /// its transfer. That module's transfer is dropped; the other modules' are untouched.
    pub fn feed(&mut self, source: u32, bytes: &[u8]) -> Result<FeedOutcome, Error> {
        let destination = match self.sources {
            Sources::Unknown => return Ok(Self::feed_unknown(source, bytes)),
            Sources::Broadcast if OBD_RESPONSE_IDS.contains(&source) => {
                (source - OBD_REQUEST_OFFSET, false)
            }
            Sources::Module {
                reply,
                request,
                is_29_bit,
            } if source == reply => (request, is_29_bit),
            Sources::Broadcast | Sources::Module { .. } => return Ok(FeedOutcome::Ignored),
        };
        let reassembler = self
            .reassemblers
            .entry(source)
            .or_insert_with(|| Reassembler::new(vec![0; MAX_SHORT_PAYLOAD], Addressing::Normal));
        match reassembler.feed(bytes)? {
            Progress::Pending => Ok(FeedOutcome::Pending),
            Progress::Complete(payload) => Ok(FeedOutcome::Complete {
                source,
                payload: payload.to_vec(),
            }),
            Progress::SendFlowControl(asked) => {
                // Continue-to-send is the only status a token has.
                let frame = FlowControl {
                    status: FlowStatus::ContinueToSend,
                    ..asked
                }
                .encode(Addressing::Normal)?;
                Ok(FeedOutcome::SendFlowControl(ApprovedFlowControl {
                    destination: destination.0,
                    is_29_bit: destination.1,
                    frame,
                }))
            }
        }
    }

    // With no known module, only a whole single frame is of use, and nothing is ever started.
    fn feed_unknown(source: u32, bytes: &[u8]) -> FeedOutcome {
        match Frame::parse(bytes, Addressing::Normal) {
            Ok(Frame::Single(payload)) => FeedOutcome::Complete {
                source,
                payload: payload.to_vec(),
            },
            Ok(Frame::First { .. }) => FeedOutcome::NoFlowControl { source },
            _ => FeedOutcome::Ignored,
        }
    }
}
