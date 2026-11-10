# Design: sending requests over 7 bytes on an ELM327 with `AT CAF0`

Status: **proposed, not implemented.** This note is for approval before any code (#214). It is unit 1 of 3: unit 2
builds it, unit 3 (#308) adds an option that forces it on an STN so the OBDLink can test it.

A plain ELM327 sends one CAN frame per request line (up to 7 bytes) and has no segmenting of its own, so the driver
refuses a request longer than that ([`elm327.md`](../elm327.md#limits)): a UDS `22` read of 4 DIDs is 9 bytes and can't
go out. With CAN auto formatting off (`AT CAF0`) each line the driver writes is one raw CAN frame, so the driver can
write the ISO-TP first frame and consecutive frames itself and wait for the module's flow control. The risk is the one
the issue names: a misheard consecutive frame is a raw frame on the bus, and a lost flow control has to stop the
transfer cleanly. The rest of this note is how each is handled.

## What you are approving

1. **When it applies.** A request of 8 to 44 bytes, to one module whose reply ID is known, 11- or 29-bit, normal
   addressing, on an adapter that isn't an STN (unit 3: or an STN when the option forces it) and has shown it echoes each
   character as it reads it. Anything else is refused before a byte is written, as today.
2. **The frames** come from core's `isotp::Segmenter`, are padded to 8 bytes by the driver with the adapter's own
   filler byte (PP 26), and are written one line each: a frame's digits, the echo checked, then the carriage return.
3. **No consecutive frame goes out before the module's flow control proves it received the first frame.** If the
   adapter ignored `AT CAF0` (a clone that answers `OK` to anything), a real ELM327 refuses the 8-byte line, and a clone
   that sends it anyway sends only a first frame, which is harmless (section 4).
4. **Everything is bounded and fails closed**: at most 7 frames, 10 wait frames in a row, 500 ms between two frames,
   30 s in all. A failure sends nothing more, puts the adapter back to `AT R1`, and the driver sends nothing for
   1.25 s so the module drops the half transfer first.
5. **The adapter's own flow control answers the module's reply**, unchanged; the answer is read by the existing code.
6. **The audit log** shows the request once, then every frame written and every flow control read.

Decisions in this note that aren't forced by the datasheet, so they're yours to change: the padding byte (item 2), the
numbers in item 4, switching modes lazily (section 8), refusing a broadcast, and shipping this on by default for
plain ELM327s although no plain ELM327 has run it yet (Open questions, 1).

## Sources

ELM327 facts are cited with the page of **ELM327DSJ** (the datasheet for firmware v2.1, 94 pages), written `DSJ p. N`.
The pages `elm327.md` cites are from another edition (ELM327DS v2.0) and run a page or two off, so don't look one up
by the other's number. Everything the design needs exists in every version this driver accepts: `AT CAF0` and `AT R0`
are in v1.0, and the `AT FC` modes and PP 26 in v1.1 (version history, DSJ p. 90). ISO 15765-2's timers (N_Bs,
N_Cr) and its rule that functional addressing carries only single frames are from the standard, not the datasheet;
`raw-can.md` already uses N_Bs.

## 1. When it applies

All of these, checked before anything is written; each failure is an `Error::Adapter` and leaves the driver usable:

- The payload is 8 to 44 bytes. 44 is `STPX_MAX`, so both multi-frame paths have one limit, and a transfer is at most 7
  frames (the first frame carries 6 bytes, each consecutive frame 7: 44 bytes is a first frame and 6 consecutive ones).
  1 to 7 bytes is one frame, as today.
- The adapter isn't an STN (`self.stn.is_none()`): an STN has `STPX`. Unit 3 adds the option.
- `early_echo == Some(true)`: the line guard below needs an adapter that echoes characters as it reads them, which only
  an earlier request shows (the same condition as `STPX` and TP2.0 raw mode).
- The target is physical with a known reply ID (`Approved::reply_id()` is `Some`). The reply ID is how the flow
  control is recognised, and the receive filter is narrowed to it. A broadcast (0x7DF) is refused: ISO 15765-2
  allows only single frames in functional addressing, and there is no single module to send flow control. The
  raw backend refuses it too (`raw-can.md`).
- Normal addressing. Extended addressing (a Toyota sub-address, #112) is refused until it lands; `Segmenter` already
  takes it, so what's missing is the address byte and the flow control data.
- PP 26's value is known (section 2).
- Not a TP2.0 frame: those are `Protocol::Tp20Channel` and take the existing raw path (section 8).

Both ID widths work: the header, flow control header and filter are set by the existing `set_target`, and a frame
line is 29 or 37 characters when printed.

## 2. The frames

- **Built by core.** `Segmenter::new(payload, Addressing::Normal)` and its `step()` loop give the first frame, then
  `Step::WaitForFlowControl` and `Step::Send(frame)` for the consecutive frames. `Segmenter::flow_control(fc)` takes
  each flow control the driver reads; a `Wait` leaves it waiting. The driver has no segmenting code of its own.
- **Padded by the driver to 8 bytes.** `Segmenter` returns each frame unpadded (`CanData::as_bytes`), and the
  adapter would pad a short line itself (`CAF0` "will add some trailing 'padding' bytes to ensure that the required
  eight data bytes are sent", DSJ p. 14; "eight for ISO15765", p. 44), but then the bus would carry bytes the audit log
  doesn't show. A frame is its length as well as its bytes (`pitfalls.md`), so the driver writes all 16 digits and the
  adapter pads nothing. A line of 8 bytes has a second use: an adapter still in `CAF1` refuses it (section 4).
  **Filler: the value of PP 26** (default `00`, "the ELM327 uses '00' by default", DSJ p. 68; table on p. 72), which
  is what the same adapter puts after a single frame in `CAF1`, so the module sees the same padding for a short
  request and a long one. The `AT PPS` summary the driver already reads shows it as `26:00 F`
  (value, then `N` on or `F` off; DSJ p. 68): the filler is the value if `N`, else `00`. An adapter that answers `?`
  to `AT PPS` has no parameters, so `00`. A printed summary that omits PP 26 refuses segmenting (not connecting), as
  `check_defaults` does for the four it needs. Alternative: a fixed `0xAA` like the raw backend (`raw-can.md#frames`);
  rejected because the A7 modules are known to answer padded-with-`00` single frames, and #306 lists padding as a suspect.
- **Lines** are the frame's 16 upper-case digits with no spaces, the form every request is written in. No `AT AL` is
  needed for 8 data bytes (DSJ p. 44), and `AT V` isn't touched: a line of 8 bytes is not padded either way.
- **Golden frames** (a payload of bytes `00 01 02 ...`, filler `00`):

| Payload | Frames written, in order |
|---|---|
| 8 bytes | `10 08 00 01 02 03 04 05`, `21 06 07 00 00 00 00 00` |
| 9 bytes, `22 F1 87 F1 88 F1 89 F1 91` (the car test) | `10 09 22 F1 87 F1 88 F1`, `21 89 F1 91 00 00 00 00` |
| 13 bytes | `10 0D 00 .. 05`, `21 06 .. 0C` (a full consecutive frame, no padding) |
| 14 bytes | `10 0E 00 .. 05`, `21 06 .. 0C`, `22 0D 00 00 00 00 00 00` |
| 44 bytes | `10 2C 00 .. 05`, `21 06 .. 0C`, `22 0D .. 13`, `23 14 .. 1A`, `24 1B .. 21`, `25 22 .. 28`, `26 29 2A 2B 00 00 00 00` |
| 45 bytes | refused, nothing written |

## 3. The command sequence

Three adapter settings take part: `AT CAF0` (frames are written raw), `AT R0` and `AT R1` (whether the adapter waits
for a reply after a frame), and the `X` interrupt. Each is used for what its command says and nothing else.

**Why `AT R0`.** After every line the adapter listens for its whole timeout, `AT ST FF` is about 1 s (DSJ p. 27), and
again after each reply it prints (p. 30: "As long as messages continue to be received, the ELM327 will continue to reset
this timer"). A consecutive frame that expects no reply would make the transfer 1 s per frame, past the module's
1 s N_Cr after the first. `AT R0` is the datasheet's way out: "the IC will not wait for a reply from the vehicle after
sending a request, and will return immediately to wait for the next RS232 command" (DSJ p. 23). It prints nothing for
a send that worked, and says so if it failed. The datasheet's warning, that "the vehicle may have difficulty if it is
expecting an acknowledgement and never receives one", is about protocols where the tester answers each message (it
names J1850 PWM, p. 32); a consecutive frame inside a block asks the module for no reply, and the CAN-level
acknowledgement is the controller's (section 11). So `AT R0` goes on before the consecutive frames that are
inside a block, and `AT R1` before the one that needs the module's reply (the flow control for the next block, or the
answer after the last frame).

**Why `X`.** The first frame is sent with `AT R1`, so the adapter listens and prints the module's flow control, then
goes on listening for its timeout, which restarts after every frame it prints (DSJ pp. 27, 30). The next frame can't
wait for that: a character written then interrupts the adapter anyway (DSJ p. 9: an RS232 character interrupts it, and
"software should always wait for either the prompt character"). The driver does what it does for a TP2.0 frame on an
open channel ([`elm327.md`](../elm327.md#vw-tp20-channel-frames)): it writes `X` (discarded, DSJ p. 48), reads
`STOPPED` and the prompt, and if the prompt came first, ends the `X` line with `XX\r` so the adapter refuses it
(`INTERRUPT`, `KILL`). Stopping on the first flow control also lets the listen cover **wait frames** (section 5): the
adapter prints each as it comes without leaving the listen.

**Sequence**, for a 14-byte payload `00 01 .. 0D` (a first frame and two consecutive frames) to 7E1, block size 0. `<`
is what the adapter prints (the echo of each line comes first and is left out). `AT CAF0` is only sent when the
adapter isn't in `CAF0` already, and `AT R0`/`AT R1` only when the setting has to change:

```
ATCAF0                 <OK          guarded (section 4); stays on until a request that isn't segmented
ATSH7E1 .. ATCRA7E9                 as today (set_target): header, flow control header and data, filter
100E000102030405       <7E9 30 00 00 00 00 00 00 00      first frame, R1: the adapter prints the flow control, keeps listening
X                      <STOPPED, <>                      stops the listen
ATR0                   <OK          the consecutive frame inside the block waits for nothing
21060708090A0B0C       <>           echo, then the prompt at once
ATR1                   <OK          the next frame needs the module's answer
220D000000000000       <7E9 10 ..   last frame: from here `recv` reads the answer, as for any request
```

An 8- to 13-byte request has one consecutive frame, so it is first frame, flow control, `X`, last frame, with no
`AT R0` or `AT R1`. A 14-byte request is the first with a consecutive frame inside a block.

**Block size above 0.** The last frame of a block uses `R1` and is followed by a flow control read and an `X`, as the
first frame is. With block size 1 every consecutive frame is the last of its block, so `AT R0` is never sent.
The driver learns which frame is last of its block from the `Segmenter`: after it hands over a frame, a clone of it
says whether the next step is `Send` (inside the block), `WaitForFlowControl` or `Done`.

**Cost.** Estimates by arithmetic, not measurements: 10 bits per character, so 1.04 ms at 9600 baud and 0.087 ms at
115200, plus the OBDLink EX's measured 3 to 15 ms before a character echoes (#54, `elm327.md`). One consecutive frame
line in `R0` is about 20 characters and the echo wait; `AT R0`/`AT R1` about 11 characters and the echo wait; the
first frame with the flow control and `X` about 58 characters and the echo wait (66 with a 29-bit ID).

| Request | 9600 baud | 115200 baud |
|---|---|---|
| 9 bytes: first frame, flow control, `X`, one consecutive frame | 84 to 108 ms | 13 to 37 ms |
| 14 bytes: adds `AT R0`, `AT R1` | 137 to 197 ms | 25 to 85 ms |
| 44 bytes: first frame, 6 consecutive frames | 232 to 340 ms | 44 to 152 ms |

These are the time to write the last frame, before the module's answer, and the module's STmin only adds to them
(section 6). Rejected: `R1` for every frame (about 1 s each); `AT ST` shortened for the consecutive frames (the same
setting also bounds the flow control wait, so it would be set and restored around every phase, and the flow control
wait could no longer be a full second); and a response-count digit on the first frame (DSJ p. 32: "a single hex digit
after the OBD request bytes" makes the adapter return after that many replies), which would save the `X` but can't
see wait frames, since the adapter is idle after the prompt and loses what the module sends next. It is the first
thing to try if the car test shows the `X` is a problem.

## 4. The echo guard

Every frame line is written like a request ([`elm327.md`](../elm327.md#safety)):

1. Write the 16 digits without the carriage return (`write`, then `check_early_echo`): read the echo for up to
   `ECHO_WAIT` (1 s) and compare it with what was written.
2. A match: write the carriage return. A mismatch or no echo: write `KILL` (`XX\r`), which the adapter refuses with `?`
   so nothing reaches the bus (no single flipped bit of `XX\r` leaves a line of hex digits), and **break the driver
   down**: the adapter heard something else and its state is unknown.
3. After the carriage return, the adapter's echo of the whole line is compared again, as `reply_line` does, and the
   line must be followed by the prompt and nothing else (in `R0`), or by the flow control and the prompt (section 5).

A misheard line is therefore never sent. **What a killed frame leaves on the bus:** the first frame and any consecutive
frames before it, nothing after. A module that has received part of a transfer waits for the next frame for N_Cr
(1 s, ISO 15765-2) and then drops it, so a partial transfer is never acted on; section 7 keeps the driver from
sending another request into that window.

The guard needs the adapter to echo as it reads. `AT CAF0` and `AT CAF1` have one non-hex letter, the `T`, so a flipped
bit could make them a bus request and they are written with `guarded_command`; `AT R0` and `AT R1` have two (`T` and
`R`), so no single flip leaves a line of hex digits, and they go as `expect_ok` does for `ATR1` in the setup. A flip
into another setting (`ATR0` to `ATS0`) is caught by the echo check after the fact, as for every setting. The tests
flip every bit of every character of every line this adds, and of its carriage return.

**If the adapter ignores `AT CAF0`.** Some clones answer `OK` to commands they don't implement. Every line this
feature writes is 8 bytes, and an ELM327 in `CAF1` refuses more than 7 ("Attempts to send more bytes will result in an
error", `?`, DSJ p. 30), which the driver takes as unexpected output and stops: nothing reaches the bus. A clone that
sent the 8 bytes anyway would add a PCI byte to the first frame: `07 10 LL ...`, a single frame of service `0x10`
(diagnostic session control) with the request's length byte as the session. That byte is 8 to 44 (`0x08..=0x2C`), a range
ISO 14229-1 reserves, so the module refuses it, and the driver, which expects flow control, fails the request
("answered the first frame with `7F 10 12`", section 10). A consecutive frame is only written after a flow control,
which only a received first frame produces, so no consecutive frame reaches the bus. TP2.0's raw mode trusts `AT CAF0`
the same way; the first frame acting as a canary is new here.

## 5. Flow control

After the first frame (and after the last frame of each block), the driver reads lines until it has what it needs.
Every line is classified by the existing `reply_line` (a frame from outside the filter, a status such as `CAN ERROR`,
or text breaks the driver down as always); a frame line's ID must be the reply ID, which the filter already enforces,
and its data goes through `isotp::Frame::parse(data, Addressing::Normal)`.

| What was read | What the driver does |
|---|---|
| `Frame::FlowControl` with `ContinueToSend` | Feed it to `Segmenter::flow_control`, stop listening (`X`), carry on. |
| `FlowControl` with `Wait` | Count it, keep reading in the same listen. An 11th in a row fails the request (the raw backend's limit, `raw-can.md`). |
| `FlowControl` with `Overflow` | Stop listening, fail the request: the module can't take it. |
| A flow control status 3 to 15 (`Error::Unsupported`), or one shorter than 3 bytes | Stop listening, fail the request. |
| Any other frame (a single frame such as `7F 22 13`, a first or consecutive frame, an invalid PCI) | Stop listening, fail the request: the module didn't ask for the rest. |
| `NO DATA` and the prompt | Fail the request: no flow control came within `AT ST` (about 1 s, the same as ISO 15765-2's N_Bs). |
| A line after the accepted `ContinueToSend` and before `STOPPED` | Fail the request; no consecutive frame has been sent. |

So **exactly one `ContinueToSend`**, preceded by at most 10 `Wait`s, and nothing else, passes. A `Wait` listen is
bounded by the adapter's own timeout per frame (each frame it prints restarts it, DSJ p. 27), by the limit of 10, and
by the transfer limit (section 6). Flow control frames are logged (section 9). This is the same shape as
`a_module_that_sends_no_flow_control_fails_only_that_request` for the STN: the failure is that request's, the adapter
is back at its prompt with its settings, and the driver goes on (it is returned from `send`, since there is no
`recv` to wait for: nothing was sent that expects an answer).

With `AT R0` the adapter isn't listening, so **a frame the module sends between the flow control and the last frame
is lost**, as frames "between the prompt and the next line are lost"
([`elm327.md`](../elm327.md#vw-tp20-channel-frames)), and the audit log can't show it. A module sends nothing then in
a transfer that is going right; if it aborts, the missing answer is the evidence.

## 6. Pacing and bounds

- **STmin.** The flow control's STmin, from `Segmenter::st_min()`, is the least gap between two consecutive frames.
  A value `0xF1..=0xF9` is 100 to 900 µs and the driver rounds it up to 1 ms; a reserved value (`0x80..=0xF0`,
  `0xFA..=0xFF`) is 127 ms, as ISO 15765-2 requires and core's `decode_st_min` does. The driver measures from when it
  wrote the previous frame's carriage return and waits before writing the next frame's first character (so the gap is
  at least STmin plus the time the line takes to write). The first consecutive frame after a flow control isn't held
  for it: STmin is between consecutive frames, and the `X` and `AT R0` come first anyway.
- **The gap bound.** Every gap between two frames the driver writes, from one carriage return to the next, or from
  reading the flow control to the first consecutive frame's, must stay under **500 ms**, half of N_Cr, which allows for the
  adapter's handling and a late wake-up of the host. The check is made after the digits are echoed and **before the carriage
  return**: if the gap has already passed 500 ms, the driver writes `KILL` instead and fails the request. A held line is
  bounded: the adapter drops an unfinished line after about 20 s (DSJ p. 8), and an STN holds one indefinitely, but this
  one is released or killed within 500 ms. At the largest STmin, 127 ms, plus the line's time, the bound isn't reached
  even at 9600 baud.
- **The transfer limit**, **30 s** from the first frame's carriage return, checked before each frame and each read:
  7 frames and at most 7 flow control waits of 10 wait frames each could otherwise add up to over a minute. A slow
  Wi-Fi or Bluetooth link that can't meet the gap bound fails on the gap bound first.
- **Reads** are bounded as they are today: the adapter's silence watchdog (`SILENCE_MARGIN`), `COMMAND_WAIT` for the
  `X`, and `ECHO_WAIT`.
- **Writes** go through `write`, which is already bounded.

## 7. Stopping

Any failure after the first frame's carriage return stops the transfer where it is:

1. **Nothing more is written** except what puts the adapter back: `X` if it is still listening (section 3), and
   `ATR1` if `AT R0` is on. `Elm` keeps `responses_off`, set before `ATR0` is written (a command that fails may
   still have taken effect) and cleared only by an `OK` to `ATR1`; `send` writes `ATR1` first while it is set, and a
   failure to restore it breaks the driver down. So a failed transfer never leaves the adapter waiting for no reply.
2. **The module drops the partial transfer.** It waits N_Cr (1 s) for the next consecutive frame, or for one after its own
   flow control. The driver then keeps `hold_until = last frame written or flow control read + 1.25 s` (N_Cr plus
   250 ms), and `send` sleeps until it before it writes anything, so a later request can't be taken as the rest of
   this one. Nothing is held after a successful transfer, whose last frame completes the module's request.
   A later request begins with a single or first frame, which ISO 15765-2 makes a receiver treat as new; the hold is for
   a module that doesn't. A failed transfer costs the next request at most 1.25 s.
3. **Breaking down the driver stops everything** (the echo mismatch, a missing prompt, a `?`, anything the adapter
   shouldn't print, the link failing): every later call fails without writing, and the user reconnects. A new `Elm`
   doesn't know the hold, so it isn't relied on; its reset (`AT Z`, about a second, `elm327.md#timing`) and setup come
   first.
4. If a carriage return was itself corrupted, the line is held unsent and the driver stops writing, so only a
   reconnect's carriage return could release it, long after the module dropped the transfer and ignores a consecutive
   frame outside one (ISO 15765-2).

## 8. The answer, switching back, and TP2.0

**The answer.** The last frame is written by the same tail as any request (`echo` set, `busy`, `sent`), so `recv`
reads the answer. In `CAF0` the adapter prints received frames raw; with headers on `CAF1` does too ("the received
bytes will appear much like in the `CAF0` mode", DSJ p. 14), which is the form the driver parses and reassembles with
core's `Reassembler` already, so reading is unchanged. **Flow control for the module's multi-frame answer is the
adapter's own**, `AT CFC1` as always: "Flow Control messages are automatically generated ... as long as the CFC
setting is on (it does not matter if auto formatting is on or not)" (DSJ p. 14), and only for protocol ISO 15765-4
(p. 60). Where it goes is the same as in `CAF1`, set by `set_target` before the first frame: mode 1 to the request ID
for a target on a plain ELM327 (the adapter is paced there, so the gap is above 0 and `set_target` picks it,
`elm327.md#flow-control-per-target`), because mode 0's ID isn't documented for other modules and mode 2 copies the
first frame's own ID (DSJ p. 60; the `pitfalls.md` entry "Read a mode's paragraph"). The driver does none of its own:
one place sends flow control. The transfer needs `AT CFC1` and `AT V0` as they are, so
**segmenting is not TP2.0's raw mode**: it doesn't turn them off.

**Why not `CFC0`.** TP2.0 turns flow control off because its frames can look like a first frame. Here the frames
the adapter receives while it listens are the module's flow control (`3x`) and its answer, and a first frame in the
answer should be answered.

**Two things differ from `CAF1` when reading.** `CAF1` ignores a frame with an invalid PCI byte, and `CAF0` prints it
(DSJ p. 14), and `CAF0` prints `RTR` for a remote frame. Both reach the driver now: `feed` drops an invalid PCI like any
bad frame ("a bad frame drops only its module's transfer"), so the request times out as it would have when `CAF1` hid
the frame, and an `RTR` line is text, which `reply_line` treats as unexpected output and breaks the driver down. Both
are tested (section 12).

**Switching back.** `Elm` gets `segmenting`, true while `AT CAF0` is on for this feature, and `send` switches **lazily**, as it
does for TP2.0: `ATCAF1` is written before the next request that isn't segmented (and `ATCAF0` before the next one that is),
so a scan's run of 4-DID reads stays in `CAF0` and pays for the switch once. A single-frame request must never be written
in `CAF0` (it would go raw, with no PCI byte), so the check is in `send`, before anything is written, for every request.

| From, to | Commands |
|---|---|
| ISO-TP, segmented | `ATCAF0` |
| segmented, ISO-TP | `ATCAF1` |
| TP2.0 raw, segmented | `RAW_OFF` (with the ACK setting back and `sync_adaptive`), then `ATCAF0` |
| segmented, TP2.0 raw | `ATCAF1`, then `RAW_ON` and the ACK setting |

A transition passes through plain ISO-TP, so each switch changes only what its command says.

**Adaptive timing.** `adaptive_wanted` gains `&& !self.segmenting`, and `sync_adaptive` runs after each switch. A plain
ELM327 is always paced, so adaptive timing is off already and nothing is sent; an STN at 115200 baud or more isn't paced
(unit 3), and a learned timeout of 45 to 80 ms could end the flow control wait before a slow module answers (#218), so it
is turned off while segmenting, by the one rule for `AT AT0`/`AT AT1`.

## 9. The audit log

- **The request is logged once, before anything is sent**, as every request is (`Audited::send` writes the `tx` line
  with the payload, then calls the driver). The frames below are derived from that payload by `Segmenter` and the
  filler, so nothing goes on the bus that the policy didn't approve.
- **Each frame is an event.** A new `LinkEvent::Frame { at, sent, id, data }` (the enum is `#[non_exhaustive]`), with
  an arm in `record_events`: `"dir":"tx_frame"` for a frame the driver wrote and `"dir":"rx_frame"` for a flow control it
  read, each with the ID and the 8 data bytes as `"payload"`, the form `frame_fields` already gives. A `tx_frame`
  is noted when its carriage return is written, so a frame that may be on the bus is logged even if the next read
  fails; a line that was killed (the echo didn't match) is logged as a `LinkEvent::Command` with the digits written and
  what echoed, as `guarded_command` does, and not as a frame. `AT CAF0`, `AT R0`, `AT R1`, `X` and `STOPPED` are
  `Command` events as they are today. `record_events` runs when `send` fails too, so a partial transfer shows
  everything that was written.
- **What isn't logged**: the adapter's own flow control for the module's answer (not logged today either,
  `elm327.md`), and any frame the module sent while the adapter wasn't listening (section 5).
- Events are kept up to `MAX_EVENTS` (4096) until taken; a transfer adds at most about 40 (7 frames, 7 flow control
  reads, a dozen commands and their `STOPPED`s), and the existing `Lost` count covers overflow.

## 10. Failures

Each is an `Error::Adapter` from `send`. "Usable" means the adapter is back at its prompt in `AT R1`, `hold_until` is
set (section 7), and the next request works; "broken" means every later call fails. `{id}` is the module's reply ID, `{n}`
the request's length, `{k}` the frame's number.

| Failure | Message | Driver |
|---|---|---|
| 45 bytes or more | `a {n}-byte request doesn't fit this driver's limit (44 bytes where it sends in segments, 7 on other adapters)` | usable, nothing written |
| Broadcast, or no reply ID | `a {n}-byte request to {target} can't be sent in segments: there is no one module's flow control to wait for` | usable, nothing written |
| Echo not yet shown | the existing `needs an adapter that echoes each character as it reads it ...; send a single-frame request first` | usable, nothing written |
| PP 26 missing | `ATPPS didn't list PP 26, the filler byte, so the padding of a request sent in segments is unknown` | usable, nothing written |
| Echo mismatch or none, any line | `the adapter echoed {shown} instead of {line}; the request wasn't sent` | broken; nothing sent for that line |
| No flow control | `{id} sent no flow control for the first frame of a {n}-byte request (the adapter said NO DATA); nothing more was sent` | usable |
| Not flow control | `{id} answered the first frame of a {n}-byte request with {line} instead of flow control; nothing more was sent` | usable |
| Overflow | `{id} can't take a {n}-byte request (flow control said overflow); nothing more was sent` | usable |
| Unusable flow control | `{id} sent a flow control frame this driver can't use: {line}; nothing more was sent` | usable |
| Too many waits | `{id} kept a {n}-byte request waiting: more than 10 wait flow controls in a row; nothing more was sent` | usable |
| Extra frame | `{id} sent {line} after its flow control, before the rest of the request; nothing more was sent` | usable |
| Gap too long | `{ms} ms passed before frame {k} of {m} could be sent, and a module drops a transfer after 1000 ms between frames; nothing more was sent` | usable |
| Transfer limit | `a {n}-byte request took more than 30 s to send; nothing more was sent` | usable |
| `BUS BUSY`, `BUFFER FULL` or `<DATA ERROR`, mid-transfer | `the adapter said {status} while sending frame {k} of {m}; nothing more was sent` | usable |
| `CAN ERROR`, `ERRxx`, a reset, `?`, text, a frame from outside the filter, a missing prompt, the link | the existing message for each | broken |
| `ATR1` can't be restored | `the adapter wouldn't go back to waiting for replies: {answer}` | broken |

## 11. What this doesn't change

- **ACKs.** `AT CAF0`, `AT R0`, `AT R1` and `X` don't touch the CAN acknowledgement setting: the adapter acknowledges
  frames it hears while it listens after a request, and its monitor is silent unless `AT CSM`/`STCMM` say otherwise
  (DSJ p. 16; [`elm327.md`](../elm327.md#vw-tp20-channel-frames), `pitfalls.md` "A silent listener ..."). Segmenting
  never monitors, so that setting stays at its default, and the module acknowledges the tester's frames as it does for
  any request. In `R0` the adapter isn't listening, which would matter for ACKs only if the module sent a frame then;
  it sends none in a transfer that goes right (section 5).
- The policy, `Approved`, and the tiers. Segmenting is how a transport sends an approved payload, not a way to send
  another: the frames are a function of the payload, the filler and the flow control.
- The receive filter, the header and the flow control setup (`set_target`), the 7-byte and `STPX` paths.
- What `check_defaults` refuses at connect. PP 26 is only read, and a missing one refuses this feature, not the connection.

## 12. Tests unit 2 must have

In `tests/elm.rs` against `fake_elm.rs`, which first has to learn the adapter's behaviour here (the last bullet but one):

- **Golden frames**: each row of section 2's table, with the exact lines written and the commands around them
  (`ATCAF0` once, `AT R0`/`AT R1` where section 3 puts them, `X`); 45 bytes refused with nothing written; a 29-bit
  request; filler `AA` with PP 26 on, `00` with it off or absent from a `?` summary, and refusal when a summary omits it.
- **Bit flips**: for every frame line (first and each consecutive) flip every bit of every character and of the
  carriage return, and check that no frame reaches the bus (the fake's `sent` list), the driver breaks down, and the
  line ended in `XX`. The same for `ATCAF0`/`ATCAF1`, which are written the way a request is.
- **Kill mid-transfer**: the link fails after the carriage return of frame 2, and after the echo of frame 3 (no carriage
  return); nothing more is written, the adapter gets `ATR1` if `AT R0` was on, and the driver is usable or broken as
  section 10 says.
- **Flow control**: none (`NO DATA`); a wrong ID (breaks down through the filter check); a single frame `7F 10 12`; a
  first frame; a consecutive frame; a status 3, 8 and 15; a 2-byte flow control and a 3-byte one; overflow; 1, 10 and
  11 waits then `CTS`; `CTS` then an extra frame before `STOPPED`; the `X` meeting the prompt (the `XX` path).
- **Block size 0 and 1**, and 2 with 5 consecutive frames; STmin `0`, `0x05`, `0x7F`, `0xF5` (rounded up to 1 ms),
  `0x80` and `0xFA` (127 ms): the gap between carriage returns, with a clock the test sets, is at least the STmin.
- **Bounds**: a link that is slow enough to exceed 500 ms between two frames (the frame isn't sent, the line is killed);
  the 30 s transfer limit and the 1.25 s hold (they are fields with defaults the test can shorten, and one test checks
  the defaults); a request right after a failed one waits out the hold, and one after a success doesn't.
- **`AT R0` is restored** on every failure path, and a failed `ATR1` breaks the driver down; `responses_off` is set
  before the `ATR0` line is written.
- **A multi-frame answer** to a segmented request (the adapter's flow control to the request ID and the module goes on),
  one with an invalid PCI (dropped, the request times out), one with `RTR` (the driver breaks down), and one with
  `<DATA ERROR`; a single-frame answer; a negative response.
- **Modes**: a single-frame request after a segmented one gets `ATCAF1` first; TP2.0 frames before and after, through
  ISO-TP, in both orders, with the ACK setting and adaptive timing as `sync_adaptive` says; two segmented requests in a
  row send `ATCAF0` once.
- **A fake that models two nodes and where the flow control goes**, as `fake_elm.rs` does for the TP2.0 monitor: a
  module with an ISO-TP receive state (first frame, sequence numbers, block size, STmin check, N_Cr drop after
  1 s) that sends flow control to the adapter and its answer after the last frame; the adapter with `CAF0`, `R0`/`R1`,
  the listen and `X`/`STOPPED`, frames it hears while idle lost, and its own flow control for the answer's first frame
  going where `AT FC` says, so a transfer passes only if the flow control reaches the module's request ID and a
  frame sent too late is dropped by the module. A second module's frames interleaved, to check the filter. The test
  that proves it: a driver that sent the consecutive frames without waiting for the flow control fails against it.
- **Audit log**: the request once before the first frame; each `tx_frame` and `rx_frame` in order with the commands
  between; a failed transfer's partial frames; the killed line as a `Command`; `Lost` when events overflow.

## 13. Forcing it on an STN (#308)

Unit 3. An STN has `STPX`, so it takes the path above only when a **library option and a CLI flag** say so, both off
by default; their names are unit 3's (the library's in the style of the other connect options, the CLI's documented in
`usage.md`). With the option set, a request of 8 to 44 bytes on an STN goes through this note's path instead of `STPX`,
with every check of section 1, and 1 to 7 bytes goes as today. The option is **recorded in the audit log before the
first request of the session**, so a log can say how a frame was sent (#304 goal 4 checks it). What an STN does
differently (padding, the listen ending at the prompt, any `FC RX TIMEOUT`-like status in `CAF0`) is Open questions, 3.

## 14. Car test (#304 goal 4)

After goal 3, through the tool with the policy and `--audit-log a7s10-caf0.jsonl`, once #308 merges: the forced
option on the OBDLink, a 4-DID read `22 F187 F188 F189 F191` to the transmission (7E1 to 7E9) and the gateway (710 to
77A), not the engine (#306). It also needs `docs/usage.md`'s name for the flag. Expected in the log:

- the option shown as forced, then the request once: `tx` with the 9-byte payload;
- `ATCAF0` and its echo, then `tx_frame 10 09 22 F1 87 F1 88 F1`, an `rx_frame` for the module's `30 xx yy ...`,
  `X` and `STOPPED`, then `tx_frame 21 89 F1 91 00 00 00 00` (the filler may be the adapter's PP 26 value), and the answer
  (`62 F1 87 ...`, or `7F 22 ..`) matching the same DIDs read one at a time in goal 1;
- the time between consecutive `tx_frame` lines is at least the flow control's STmin, and from the `rx_frame` to the first
  consecutive frame well under 500 ms (the estimates in section 3 against the real ones, which the 500 ms bound should be
  judged on);
- **`ATCAF1` is written before the next single-frame request, not right after this one** (section 8): a following
  single-frame read still works, and its log has `ATCAF1` first. Goal 4's text says it is "back in its normal mode"
  after the read, which should read "before the next single-frame request" when #308 merges.

If goal 3 shows neither module sends flow control for `STPX`, skip this: the result wouldn't tell anything about CAF0.
Because the OBDLink is an STN, this doesn't test a plain ELM327's `AT R0` or `X` (Open questions, 1).

## Open questions

1. **Nothing here has run on a plain ELM327.** The design follows the datasheet; the only hardware is an OBDLink EX
   (an STN), which the option in #308 can exercise but which isn't the adapter this is for. The claims a plain ELM327
   could still falsify: that a line sent in `R0` prints only its echo and the prompt; that the adapter prints a
   `CAF0`-sent first frame's flow control and then keeps listening, so `X` is needed; that `X` stops that listen with
   `STOPPED` (DSJ p. 9 says it will); that a clone honours `AT R0` and `AT CAF0` (the first is made safe above, the second
   by the first frame, but a clone that doesn't implement `AT R0` makes every transfer fail on the gap bound). When
   unit 2 lands, `adapters.md` should say "datasheet only" for plain ELM327s. **Your call:** ship it on for plain ELM327s
   anyway (the failure modes are closed: refusal, a failed request, or a stopped driver), or keep it off until someone
   runs a plain ELM327 or a clone through it.
2. **The datasheet edition.** Pages in this note are DSJ's (v2.1); `elm327.md` cites v2.0's. The behaviours used here
   are in v1.0 to v1.1, but v2.0's own edition wasn't available to check, and fixing `elm327.md`'s pages is out of this
   note's scope.
3. **STN differences** (unit 3, #308): an STN may pad with its own byte whatever PP 26 holds, ends a raw listen at the
   prompt after the first frame (the `X` then finds the prompt and writes nothing, `interrupt` handles it), and may print
   something like `FC RX TIMEOUT` for a first frame sent in `CAF0`. Unit 3 finds out on the OBDLink and records it here.
4. **Whether the engine's silence (#306) is padding.** A first frame padded with `00` goes to the transmission and the
   gateway in the car test; if they answer here and not to `STPX`, the STN's own padding is the suspect.
5. **STmin before the first consecutive frame.** ISO 15765-2 puts STmin between consecutive frames; a module that also
   wants it after its flow control would be seen as the transfer stalling, not as a bad frame, and the car test shows it.
