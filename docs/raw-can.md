# Raw CAN

The [`gsusb`](gsusb.md) and [`socketcan`](socketcan.md) backends put ISO-TP and [VW TP2.0](#vw-tp20) frames on the bus
themselves, with no adapter doing the framing. They share one transport, `RawCan`, in `crates/obdcracker-transport/src/raw/`, over a crate-private `CanPort` trait (set
filters, write one frame, read a frame or bus event). Only `RawCan` calls `CanPort::write`, and it writes only the
frames of an approved request (a TP2.0 frame is an approved request too) and the flow control frames `obdcracker-safety`
mints, so no importer can put a raw frame on the bus. The requirements come from other projects' field reports (#42).

## Frames

- Every ISO-TP frame is padded to 8 bytes with `0xAA`, as ISO 15765-4 requires; many ECUs drop a shorter one
  (`TxFrame::padded`). A VW TP2.0 frame is the opposite: it goes out at its own length, with nothing added
  (`TxFrame::exact`, [below](#vw-tp20)). A port sends the DLC the frame carries (`TxFrame::bytes`), never a fixed 8.
- A port confirms a frame went out before `write` returns, and `RawCan` sends the next one only after that, so a
  transfer's frames can't pass each other (PCAN with several TX mailboxes did, python-can-isotp #66). A frame that
  isn't confirmed is an error and ends the transfer.
- Receiving, `RawCan` feeds frames to a `ReplyWindow` opened from the approved request. A frame whose ID width differs
  from the request's is ignored, so a 29-bit frame never reads as an 11-bit module's. The echo check on a reply
  (service, DID) stays with the caller, as for every transport.
- A request is sent as one frame or as a segmented transfer. A multi-frame request needs a known reply ID (the module
  that sends its flow control); without one it is refused before any frame goes out. A reply with no known reply ID
  gets no flow control; `recv` times out as usual and the audit log gets a status line saying why.

## Separation time

STmin 0 never sleeps. A gap of 2 ms or less is spun, and a longer one is slept except for its last 2 ms, which are
spun. Windows timers round up to about 15 ms, so a sleep may overshoot, which only lengthens a gap that is a minimum.
The gap counts from when the port confirmed the previous frame (or from the flow control frame that allowed the block),
not from before the write, so a slow port's confirmation doesn't eat it.

## Waiting for flow control

The module has 1 s (ISO 15765-2's N_Bs) to send flow control; each wait frame restarts that, and an eleventh wait
frame in a row ends the transfer. An overflow status ends it at once. A timeout, a wait limit or an overflow is an adapter
error. Frames from other IDs while waiting are ignored, and the wait still ends on time under a flood.

## Filters and overruns

Before each request is written, `RawCan` sets the port's filters from the approved target: the broadcast takes
`0x7E8..=0x7EF`; a physical target its reply ID, at its width; a physical target with no known reply ID the 11-bit
diagnostic range `0x700..=0x7FF` (or any 29-bit ID). A port with no hardware filtering may hand over more, as
`RawCan` checks every frame itself. Frames left over from the last request are read and dropped first (and logged as
unread lines), so a late reply can't answer the next request. The drain reads at most 256 frames, then one more to see
whether the queue is empty. If that 257th frame exists, the send fails with an adapter error and writes nothing,
because what is left could be a late reply. The 257th frame is logged like the others. The frames behind it stay
queued, and the next send drains them, so none of them answers a request.

A receive overrun is an adapter error, and what was half-received is dropped: it never reads as a short reply. The
overrun does not latch.

A reply that never completed (a first frame and then silence), and a reply that completed but nobody took, are reported
as unread lines when the next request starts, the transfer fails, or the transport is settled (`Audited` does that when
it is dropped). A reply that the same module's next frame abandons (a new single or first frame, or a bad frame, such as a
consecutive frame with the wrong sequence number) is reported as soon as that frame arrives, together with the bad
frame itself, so the reply that follows doesn't take its bytes with it. Frames kept from other modules stay kept. A failed `send`
leaves no early answer to be returned by a later `recv`.

A flow control that isn't confirmed, one the caller's `before_send` refuses, and a port read that fails (not a timeout)
each end the transfer: the module may send the rest anyway, or frames may be lost, and neither can complete a reply the
caller was told failed.

## Bus state

Bus-off, error-passive and an error frame are errors, and each **latches**: `send` and `recv` fail with the same
message, and nothing more is written (not even flow control a reply asked for). A node sending into a bus it is
disrupting is the main way a diagnostic tool affects a running car. Only a new connection clears it.

## VW TP2.0

A channel setup, or a frame on a channel a module opened, that the policy approved (`Protocol::Tp20Channel`, see
[tp20.md](tp20.md)) goes out as **one frame** of exactly the approved bytes on the approved ID, at 11 bits: the setup is
7 bytes on `0x200`, a parameters frame 6, a keep-alive, ACK and disconnect 1, a request's data frame 3 plus the request.
There is no segmentation, flow control, padding or separation time, because TP2.0 does its own sequencing, ACKs and
timing in `tp20::ChannelSession`, which only needs `send` and `recv` and runs over this transport as over the ELM
driver. The ELM driver sends the same bytes (`AT V1`, variable DLC; [elm327.md](elm327.md#vw-tp20-channel-frames)), and
the vcan test checks the kernel takes them at those lengths.

- **One frame in flight, confirmed before `send` returns,** the bus-off latch, listen-only (the port refuses every
  write) and `&Approved` only are the ISO-TP rules, unchanged. A frame that isn't confirmed is an error and ends the
  conversation.
- **Receiving:** every frame from the conversation's source, at 11 bits, is a reply **as the module sent it**, with
  its own length: not parsed, not reassembled, not padded or trimmed. The source is the setup answer's ID (`0x200` plus
  the address) after a setup, and the channel's receive ID (`0x300`) after a frame on the channel. A frame from any other
  ID, or a 29-bit one with the same number, is ignored, and a flood of them can't hold `recv` past its timeout. `recv`
  waits its whole timeout, so the session never sees the early timeout an ELM327's prompt gives.
- **A module that pads its frames** (an ACK `B1 AA AA AA AA AA AA AA`, a setup answer of 8 bytes) is not understood: the
  decoders check every length, as they do over the ELM driver, so the session closes the channel (`Framing`,
  `Undecodable`). The passenger door's setup answer and disconnect (session 6) were exact lengths; whether its other
  frames are is for the next car session to confirm.
- **Filters:** the setup answer's ID only, then the channel's receive ID only, then the ISO-TP reply IDs again when an
  ISO-TP request follows, each set when it changes.
- **What is dropped and what is kept.** A *setup* starts a conversation like an ISO-TP request does: the frames the last
  one left are read and dropped (and logged as unread) before it is written, so a late data frame of a closed channel,
  which arrives on the same `0x300` as the next channel's, can't pass for it. A frame *on an open channel* continues the
  conversation: the frames already queued (the module's ACK, its next data frame) are **kept** for the session to read next,
  because the session ACKs a frame while the module may already be sending the next. Before such a frame is written the
  port is still read once to its end, so a bus fault queued behind them latches before anything goes out; the same
  bound as the drain applies (256 events, the 257th handled first and logged), and a queue past it fails the send. An
  overrun in the middle of a channel ends the conversation (a lost frame would break the session's sequence numbers).
  After an ISO-TP request, TP2.0 frames from the old channel's ID are nobody's reply.

## Not here yet

- Checking the bitrate listen-only before going active (#42, requirement 5) belongs to each backend's connect step.
  `gsusb` does it ([details](gsusb.md#the-bitrate-check)). `socketcan` can't: the kernel owns the interface, so it only checks
  that the bitrate the interface reports is the one asked for, and never sets it ([details](socketcan.md#connecting)).
