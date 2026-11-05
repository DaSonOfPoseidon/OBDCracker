# Raw CAN

The `gsusb` and `socketcan` backends put ISO-TP frames on the bus themselves, with no adapter doing the framing. They
share one transport, `RawCan`, in `crates/obdcracker-transport/src/raw/`, over a crate-private `CanPort` trait (set
filters, write one frame, read a frame or bus event). Only `RawCan` calls `CanPort::write`, and it writes only the
frames of an approved request and the flow control frames `obdcracker-safety` mints, so no importer can put a raw frame
on the bus. The requirements come from other projects' field reports (#42).

## Frames

- Every frame is padded to 8 bytes with `0xAA`, as ISO 15765-4 requires; many ECUs drop a shorter one. `TxFrame` has
  no shorter form.
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
unread lines), so a late reply can't answer the next request. If more than 256 are queued, the send fails instead:
what is left could be a late reply.

A receive overrun is an adapter error, and what was half-received is dropped: it never reads as a short reply. The
overrun does not latch.

A reply that never completed (a first frame and then silence), and a reply that completed but nobody took, are reported
as unread lines when the next request starts, the transfer fails, or the transport is settled (`Audited` does that when
it is dropped). A reply that the same module's next frame abandons (a new single or first frame, or a bad frame) is
reported as soon as that frame arrives, so the reply that follows doesn't take its bytes with it. A failed `send`
leaves no early answer to be returned by a later `recv`.

A flow control that isn't confirmed, one the caller's `before_send` refuses, and a port read that fails (not a timeout)
each end the transfer: the module may send the rest anyway, or frames may be lost, and neither can complete a reply the
caller was told failed.

## Bus state

Bus-off, error-passive and an error frame are errors, and each **latches**: `send` and `recv` fail with the same
message, and nothing more is written (not even flow control a reply asked for). A node sending into a bus it is
disrupting is the main way a diagnostic tool affects a running car. Only a new connection clears it.

## Not here yet

- Checking the bitrate listen-only before going active (#42, requirement 5) belongs to each backend's connect step.
- VW TP2.0: a TP2.0 request, setup or channel frame is refused with an adapter error naming #259.
- The public backends (`gsusb`, `socketcan`) with their own `compile_fail` doctests that no importer can write a frame.
