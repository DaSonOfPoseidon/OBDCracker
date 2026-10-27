# Scanning

How `scan`, `scan_with` and `sweep_dids` (in `crates/obdcracker-transport`) read a car. Everything here is read-only:
every request is approved by the policy before the first is sent. The audit log (the `Audited` wrapper, which the CLI
uses; a library caller must wrap the transport itself) records each one before it goes out.

## Module discovery

OBD-II emissions ECUs are found by broadcast: each mode 01 PID, mode 09 PIDs 00 and 0A and mode 03 go to the
functional address, and every CAN ID that answers is an ECU. Other modules are not discovered by `scan`; the caller
gives it the modules to read (from a vehicle profile).

Supported PIDs are read as a chain of bitmaps (PID 00, 20, 40, ... E0). Each ECU's chain follows only the bitmaps
that ECU says it supports, and ends at a bitmap that is missing or garbled even while another ECU's chain keeps the
requests going. A bad first bitmap makes the ECU's whole PID list an error; a bad later one cuts the list short
(`ObdEcu::pids_cut_short`) and no PID from that page on is read. Which PIDs get asked depends on the bitmaps, so all
256 mode 01 requests are approved up front.

## DID batching

Each module is read for `SCAN_DIDS`, then the DIDs its profile adds (`ScanModule::extra_dids`), each once. A DID
takes its first extra entry's length and session, and its format unless ISO 14229-1 makes it text (`did::is_text`);
F190 must be a VIN or the placeholder for none.

DIDs with a known length are read up to three in one `22` request (7 bytes, one CAN frame, which every adapter driver
can send), and as many as fit in `MAX_REPLY` (4095 bytes, the most a short ISO-TP first frame declares) of reply. A multi-DID reply doesn't say where each value
ends, so the layout comes from the profile's lengths. The module may leave out DIDs it doesn't support, but those it
sends must come in the order asked, each at its length, with nothing left over; anything else is malformed.

DIDs a batch left out, and all of them if the batch was refused or didn't fit, are read again one at a time. These
single reads must be exactly the profile's length. The batch's reply can arrive late (after a timeout, or after a late
refusal to an earlier read was taken for its answer, since refusals echo no DID) and pass for the first DID's answer
with the others' bytes as its value. A value of another length, such as another ECU variant's, is malformed until the
profile is fixed. A DID with length 0 is read alone, as every DID value has at least one byte.

`ModuleScan::answered` is true if the module said anything at all, a refusal included, including a batch that was
answered and then read again singly, so it can be true while every value is `NoReply`.

## DTCs

Scan asks for DTCs with `FAULT_MASK` (0xAF): failed, failed this cycle, pending, confirmed, failed since last clear
and warning lamp. The "not tested" bits are left out, since with them a module lists every DTC it has never tested,
which on the A7 is its whole table (#49). Only status bits the module says it supports count, so a module that
ignores the mask can't list untested DTCs.

## Extended session and TesterPresent

`scan` reads DIDs whose profile session is extended only with `ScanOptions::extended`. Without it they are
`ReadError::NeedsExtendedSession`. With it, a module that has such DIDs and answered something in
the default session is put in the extended session after its other reads (`10 03`), kept there with `TesterPresent`
(`3E 00`) and returned to the default session (`10 01`). A module that answered nothing isn't there, so no session is
entered for it. `sweep_dids` doesn't consult profile sessions: without `SweepOptions::extended` every DID is read in the
default session, and with it the whole range is read in the extended one.

The session's own requests are approved before anything is sent, and the policy must know the module's reply ID
(narrow it with the vehicle profile), or `FingerprintError::Session` is returned with nothing sent.

A module drops back to the default session on its own after S3 without a request (`S3::timeout`, 5 s by default,
S3server in ISO 14229-2). Nothing runs in the background, because a keepalive can't go out while a request is waiting
for its reply on the same adapter. `ExtendedSession::keep_alive` is called before each request: it sends
`TesterPresent` once `S3::keepalive` (2 s by default, S3client) has passed since the module last accepted a request.
If the session may have lapsed, it and `exchange` enter the session again first. Anything tied to the session, such as
security access, would be lost then; reads aren't.

The session is trusted only until halfway between `keepalive` and `timeout` (3.5 s by default). A request takes time to
reach the module, so one sent later could arrive after the module left the session, and a module in the default
session answers `TesterPresent` too, so that wouldn't show. From then on the session is entered again instead. Any S3
values are safe, they only change what's sent: with `keepalive` at or above `timeout`, `TesterPresent` is never sent
and the session is entered again once `timeout` has passed; a zero `keepalive` sends `TesterPresent` on every call; a
zero `timeout` enters the session again before every request.

Time is measured from just before each request the module accepted was sent. The module restarts S3 when it has sent
its answer, which is somewhere between then and when the answer arrives, and an ELM adapter can take seconds to print
a long one. So an answer that took longer than the margin is followed by a new `10 03` before the next request, even
though response-pending replies kept the session alive meanwhile. That costs session state, never a read sent into the
default session. A refused or unanswered request doesn't restart the clock: after a refused `10 03` the module is
still in the default session, and a `3E 00` would keep it there. Only a positive answer counts.

The module's positive answer to `10 03` gives its P2 and P2* for the session. Where they're longer than ISO 14229-2's
defaults (50 ms, 5 s), the session adds the difference to the caller's `Timing`, keeping any allowance the caller made
for its adapter. Older servers answer a bare `50 03`, which keeps the caller's timing.

`TesterPresent` is sent as `3E 00`, not with the suppress-positive-response bit (`3E 80`): a suppressed request that
succeeds gets no reply, so an ELM adapter would wait out its whole timeout every time.

Leaving: dropping an `ExtendedSession` sends `10 01` once and can't report a failure; `end` reports it, and retries
`10 01` once unless the module accepted or plainly refused it (`7F 10 <NRC>`, a definite answer that it stayed where it
was). An adapter failure on the first try is returned however the retry goes, as the adapter's state is unknown. If
entry wasn't confirmed (anything but a plain refusal; the module may have switched and only its reply been lost), the
session sends `10 01` straight away, and `SessionError::Unconfirmed` means that failed too: the module may stay in the
extended session until S3 runs out.

## When a session fails

A failure to enter, keep or use the session loses only the values it was for; values already read stay. The exception
is an adapter failure, which makes `scan_with` return an error with no `Scan`.

| Failure | Effect |
|---|---|
| The module doesn't answer (timeout) | those DIDs are `NoReply` |
| Response pending past the limit | those DIDs are `StillPending` |
| The module refuses `10 03` or `3E 00`, or its answer's timing can't be decoded | those DIDs are `SessionRefused` with the reply |
| `10 03` unconfirmed, then `10 01` unconfirmed | as the entry's failure; the module leaves the session itself after S3 |
| The adapter fails | the scan stops with an error |
| The policy lacks the reply ID or refuses a session request | `FingerprintError::Session` or `Rejected`, nothing sent |

A module that doesn't confirm `10 01` at the end is left to return after S3.

## Sweeps

`sweep_dids` sends one `22` per DID over a range (up to 65 536). It keeps what it found when it stops.

- A DID refused as out of range (NRC 0x31) isn't there and isn't listed.
- A DID with no final answer (no reply, or response-pending past `Timing::max_pending`) is listed as `NoReply` or
  `StillPending` once the module answers a later read or the range ends. If the sweep stops first, those reads aren't
  listed and `Stop::at` is the first of them: at `QUIET_LIMIT` (3) in a row, which means the module is gone or stuck,
  when the adapter fails, or when the extended session's keepalive or re-entry fails.
- UDS refusals don't name the DID. After an unanswered read, a later refusal or undecodable reply may be the late
  answer to it, even past answers that were plainly this connection's own, so the sweep stops (`Why::Unmatched`) with
  `Stop::at` on that DID. `Sweep::out_of_step` says a read went unanswered, so connect again before reading from the
  module again.
- A refusal of `22` itself (service not supported, in this session or at all, bad format, or busy) stops the sweep:
  every later read would get the same, and asking the next DID at once would only keep a busy module busy.
- A general reject (NRC 0x10) gives no reason, so it may be every DID's answer: that DID is listed and the sweep stops
  before the next, so going on always gets further.
- With `SweepOptions::extended`, the extended session's keepalive or re-entry may fail before a read goes out. That DID
  isn't reported to `progress` and the sweep stops there, since a caller checkpointing on progress would otherwise
  skip it. Resume from `Stop::at`.
- With `SweepOptions::patient`, the transport waits longer for each reply (`Transport::patient`), so a module's slow
  answer lands on the read it answers instead of the next. Nothing extra is sent: asking the DID again after a
  timeout would leave one of its two answers queued for the next read. Patience is set after every request is
  approved and ends afterwards whatever happens. Failing to set it stops the sweep before anything is sent, and
  failing to end it is a `Why::Adapter` stop.
- If leaving the session fails, `Sweep::still_extended` says why the module may still be in it. When the adapter fails
  on `10 01`, `still_extended` stays `None` and `Sweep::stop` is `Why::Adapter`; the module may still be in the session.
