# Design: hearing a TP2.0 answer that starts right after the module's ACK on an STN

Status: **method approved for building (#333), built, not yet run on the car.** The research and the failing replay
of car session 11 came first; the fix is in the same PR. Section 5 is what the car still has to confirm (#334).

On an OBDLink (STN2232) a TP2.0 module ACKs the tester's data frame and starts its multi-frame answer a few
milliseconds later. The STN ends its listen with its prompt after the ACK, the driver then writes `STM`, and the
module's first frames arrive before `STM` is running. They are lost, the next frame heard has the wrong sequence
number, and the session closes the channel ([`elm327.md`](../elm327.md#vw-tp20-channel-frames), "Frames between the
prompt and the next line are lost"). Session 11 showed it on both modules that answer `22 F1 87` in more than one
frame, in all three passes.

## What you are approving

1. **The method (section 3):** on an STN, write a channel data frame or ACK and `STM` as one batched line
   (`<frame digits>|STM`, OBDLink Batched Commands, `STBC 1`), so the STN starts monitoring itself when the frame's
   listen ends, with no round trip to the host in between. `STBC 1` is probed when raw mode starts and only an exact
   `OK` counts.
2. **A fallback order (section 3)** if session 12 shows the batch doesn't work on the car's firmware.
3. **What isn't changed:** the frame's bytes, the policy and audit path, and a plain ELM327's byte stream (section 4).
4. **What session 12 (#334) must check** before the fix is called done (section 5).

Decisions in this note that aren't forced by a source, so they're yours to change: preferring the batch over `ATR0`
(section 2, d and e), rejecting a TP2.0-level recovery (section 2, g), and leaving the batching switched on for the
whole of raw mode rather than per frame (section 3).

## Sources

- **FRPM:** the OBDLink Family Reference and Programming Manual, rev. F (August 29, 2025), 78 pages, fetched from
  `https://www.scantool.net/scantool/downloads/98/stn1100-frpm.pdf`. Cited as `FRPM section, p. N of 78`.
- **DSJ:** the ELM327 datasheet for firmware v2.1, as in [`elm-caf0-segmenting.md`](elm-caf0-segmenting.md).
- **Car logs:** session 11 (#316), `a7s11-tp20-pass1.jsonl` to `pass3.jsonl`, in the
  [gist](https://gist.github.com/DaSonOfPoseidon/af72c4c09e3eeea53f4a52478c2d4d85). Times are the audit log's
  `ts_ms`, in milliseconds from the tester's `tx` entry. An entry is logged before its bytes are written.
- **TP2.0:** Jared Wiltshire's description, `https://jazdw.net/tp20` (hobbyist, from traces; no standard is public),
  and its copy in the OVMS-3 repository (`vehicle/OVMS.V3/components/vehicle/docs/VW-TP-2.0.txt`).
  [`tp20.md`](../tp20.md) is what this repo already took from them. SAE J2819 is the standard and is paywalled: not
  read.

A claim with none of these behind it is marked **unverified**.

## 1. Why the frames are lost

Module 52 (4DB to 300), pass 1, `22 F1 87`. The module answers in three frames, sequence 2 (`22 ..`), 3 (`23 ..`) and
4 (`14 47 20`, the last, which asks for an ACK), 14 bytes of payload in all:

| ms | entry |
|---|---|
| 0 | `tx 4DB 12 00 03 22 F1 87` (logged first; the `X` that stopped the previous listen follows at +1) |
| 51 | `rx 300 B3`, the module's ACK |
| 52 | `cmd STM`, logged as the driver starts writing it |
| 83 | `rx 300 14 47 20`: sequence 4 where 2 was due. The frames before it were never printed. |
| 83 | `tx 4DB A8`: the session closes the channel |

Module 20 (518 to 300): ACK at +35, `STM` at +37, `23 30 39 30 37 30 36 33` (sequence 3) at +68 with `300 14 43 47`
right behind it, unread. Its sequence-2 frame was lost, and its data, `4G0907063`, says it was the answer to `F187`.
Passes 2 and 3 show the same on module 20 and on module 52 pass 2. Pass 3 on module 52 is different and
**unexplained**: `14 47 20` came 176 ms after the ACK, not 32. The single-frame answers (`10 89`, `1A 9B`) come about
160 ms after the ACK on both modules and are heard.

What the numbers say, and what they don't:

- **The host is fast; the STN isn't.** `STM` is written 1 to 2 ms after the ACK is read, yet the frames sent in the
  next 10 to 30 ms are lost. A setting command takes 15 to 17 ms from one log entry to the next in this log
  (`ATFCSM1`, 23 samples: 15 to 17; `ATSH200`: 14 to 15; `X`: 17). `STM` is written like them (its echo is checked
  before its carriage return, [`elm327.md`](../elm327.md#safety)), so the echo round trip is a likely part of the
  window. That is an inference: the log has no prompt lines, so the time the STN printed its prompt, and the time `STM`
  took effect, are unknown.
- **When the module starts is also unknown.** Its answer follows its ACK by less than the 32 ms at which the third
  frame was heard, and the log doesn't say how soon. The tester asked for 5 ms between frames (`A0 0F 8A FF 32 FF`,
  [`tp20.md`](../tp20.md)), and the two frames of module 20 are logged in the same millisecond. Treat the module's first
  data frame as arriving within a few milliseconds of its ACK.
- **The module's ACK is about 18 ms after the carriage return.** The tester's `tx` entry comes before the `X`
  interrupt and the 16 ms echo wait, which together are about 33 ms of the 35 to 52 ms to the ACK.
- **Why the STN prints a prompt after one frame is not documented.** The FRPM says the opposite: "After OBDLink
  receives an OBD frame, it waits a preset amount of time (called a 'timeout') for the next frame, before printing the
  command prompt", with adaptive timing off ("fixed timeout") and "will always wait the maximum time defined by the
  ATST/STPTO timeout for the first frame" (section 7.2 `ATAT`, p. 12 of 78). The driver sets `ATAT0` and `ATST FF` in
  raw mode, and car sessions 8 and 11 still show the prompt after one frame (#227). The rule may depend on the IDs
  (the setup on `0x200` did need `X`). **Unverified**, and the design below doesn't depend on it.
- **The adapter acknowledges the frames it loses.** A frame nobody acknowledges is repeated by the module's CAN
  controller until it is (31 times in session 9, #301), so a frame lost here was acknowledged on the bus and dropped by
  the STN's firmware, which `lost_frames` in the fake models. **Unverified** on the car, but consistent with frames 2
  and 3 never appearing.

## 2. Candidates

### a. Pipelining `STM`: write `STM\r` without waiting for its echo

Source: none needed, it's a driver change; the echo rules are [`elm327.md`](../elm327.md#safety) and
[`pitfalls.md`](../pitfalls.md) ("check the echo of everything written").

- **What it buys.** About 16 ms of the window, if the echo wait is what it looks like.
- **Why it isn't enough.** The host still has to read the prompt first and the STN still has to parse the line, so the
  window can't be less than the link's round trip, and the module's first data frame follows its ACK within a few
  milliseconds. It makes the loss rarer, not impossible, and a fix that is right most of the time hides the bug until a
  loaded car session.
- **What it costs.** The echo check is what stops a misheard line from being a bus request. `STM` has two non-hex
  letters, so one flipped bit can't make it one ([`elm327.md`](../elm327.md#vw-tp20-channel-frames)), but the rule
  ("check before the carriage return") would then have an exception to explain.
- **Verdict: rejected as the fix.** Worth reconsidering only as a refinement of the fallback in section 3.

### b. `STPX` with `r:` and `t:`

Source: FRPM section 8.6, p. 36 of 78. `STPX` takes `d:` (data), "`t` Response timeout. If specified, overrides value,
set by STPTO command. ATAT setting is still obeyed." and "`r` Expected response count. Overrides ATR command setting."
It "will turn on segmentation but will revert segmentation back to its previous state (on or off) after sending the
message."

- **For:** a response count might make the listen last for N frames whatever rule ends it after one.
- **Against:** the manual doesn't say how a count ends a listen, whether the listen ends on the count or the timeout,
  what `r:` does with `CAF0`, or what turning segmentation on does to a raw 8-byte frame. `STPX` has never carried a
  raw frame here (a channel frame is "never `STPX`", [`elm327.md`](../elm327.md#multi-frame-requests)). And the count
  is the number of frames in the answer, which the tester doesn't know when it sends: a count that's too small ends
  the listen mid-answer and the same loss follows, one that's too large leaves the STN listening until the timeout
  and the next frame has to interrupt it (as today).
- **Other settings that end a raw listen:** none in the FRPM. `STCSEGR` is receive segmentation of multi-frame
  *ISO-TP* messages, `STCFCPA` adds flow control address pairs (section 8.8, p. 38 of 78), and `STPTO` (section 8.6,
  p. 35: "0: timeout is infinite") sets how long the listen lasts, not why it ends after one frame.
- **Verdict: rejected**, on the manual's silence. A session-12 probe could try it only if the batch and `ATR0` both fail.

### c. Periodic messages while monitoring

Source: FRPM section 8.14, p. 51 of 78: "The CAN monitoring mode, set by STCMM, will affect whether messages are sent while
monitoring (STM or STMA)." A channel frame could be added as a periodic message (`STPPMA`) and the STN left monitoring.

- **Verdict: rejected.** The STN would repeat the frame every period until it's cleared, so the tester could no longer
  promise that a frame goes out exactly once, and the audit log couldn't see each repeat. Nothing else in this driver
  sends a frame the driver doesn't write itself.

### d. `ATR0` and then `STM`

Source: FRPM section 7.2 `ATR`, p. 17 of 78: "By default, after sending an OBD request, OBDLink waits for, acknowledges (if
applicable), and prints the OBD responses before returning to the command prompt. If the ATR0 option is enabled,
OBDLink will send the request, and immediately return to the command prompt – without acknowledging or printing any
responses." The same setting on an ELM327 is DSJ p. 23, and the driver already uses it for the frames of a segmented
request ([`elm-caf0-segmenting.md`](elm-caf0-segmenting.md), section 3).

- **For:** the prompt comes before the module's ACK, so `STM` can be running by the time the module answers, with no
  dependence on why the STN ends a listen. Documented, and the driver already has `set_responses`.
- **Against:**
  - The host still writes `STM` after the prompt, so the window moves to the start of the frame's wait instead of
    closing: `STM` is up about 16 to 20 ms after the carriage return, and the module's ACK comes about 18 ms after it.
    The ACK may be lost (the session doesn't need it: only a data frame's sequence is checked, `tp20.rs`
    `Frame::Data`), but so may the module's reply to a frame it answers fast: its `A1` to an `A0` or `A3` comes about
    15 ms after the carriage return (`A3` at +31 ms from its `tx` entry in session 8, #227).
  - So `ATR0` would be right only for data frames (opcode 0x0 to 0x3) and ACKs, and the single-frame `A0`, `A3` and
    `A8` would keep `ATR1`. Each switch is a 16 ms command, in the T1-bound path of a channel.
  - "Without acknowledging" is the manual's word for what the STN does about replies; whether it also stops the
    CAN-level acknowledgement of the module's frames between the prompt and `STM` is **unverified**.
- **Verdict: the fallback** if the batch isn't available, for data frames only.

### e. Batched commands: `<frame>|STM` (recommended)

Source: FRPM section 16.0, pp. 73 to 74 of 78, and section 8.15, p. 52 of 78 (added in rev. F):

- "OBDLink devices feature a command batching system that allows users to concatenate multiple commands and OBD
  messages/requests into a single prompt" (16.0).
- "Individual commands or messages are separated using the pipe (|) character. The complete batch must be terminated
  with a carriage return (\r)." "Commands are processed sequentially from left to right." (16.2.1)
- "Inserting commands such as ATMA, STMA, or STM in the middle of a batch is not recommended. [...] If you wish to
  begin indefinite monitoring after completing a batch, you may safely place ATMA, STMA, or STM at the end of the
  batch." (16.1)
- "If any command in the batch produces an error message, other than NO DATA, batch execution will terminate
  immediately. NO DATA is not considered a terminating error and will not interrupt batch processing." (16.2.3)
- `STBC 0|1`: "Disable or enable Batched Commands parsing. Default is 0"; the setting is in volatile memory and "will not
  survive a reset or power cycle" (8.15). The command buffer is 1024 characters. While batching is on, the commands
  that take an ASCII string (`AT@3`, `STSATI`, `STBTDN`, `STS@1`, `STSDI`) answer `?`; the driver sends none of them.
- Output: each element's answer follows the one before it after a `|` (the "Verbose" format, `STBCOF 0`, the default:
  `OK |OK |7E8 06 41 ..`), and the batch ends with one prompt (16.2.2, 8.15).

How it closes the window: the frame is the first element and `STM` the last. The STN transmits the frame, listens as
it does today (whatever rule ends that listen, section 1), and goes on to `STM` itself. The time between the end of the
listen and the start of monitoring is the STN's own processing, not a round trip over the link, the echo check or the
host's reaction. If the STN doesn't end its listen early, the listen prints the answer anyway and `STM` starts after
it, so the method is right either way.

- **Against:**
  - The FRPM's examples are OBD requests in `CAF1` (`0100 1`). That a raw `CAF0` frame is a valid element, and how long
    the STN takes to go from a listen to `STM`, are **unverified**. If the switch isn't quick enough the loss is rarer,
    not gone, and session 12 shows by how much.
  - Whether the car's firmware has it is **unverified**: rev. F "adds" section 16, the car's STN2232 reports v5.12.4
    ([`elm327.md`](../elm327.md#timing), #54), and the manual doesn't say which firmware first took `STBC`. An STN
    that answers `?` to `STBC 1` has no batch, and the driver then does what it does today.
  - The output has a `|` where the monitor's first line starts (position **unverified**), so the driver's line parser
    must accept it from this one place and nowhere else.
  - A prompt no longer follows the frame's own answer: the driver knows it is monitoring from the moment it writes the
    line, instead of when it reads the prompt (`recv`'s `Event::Prompt` branch).
  - An `X` that arrives while the frame's listen is still running has no documented effect on a batch. The manual
    says a monitor that is interrupted (`STOPPED`) may abort "the remainder of the batch" (16.1), which is the end of
    this one anyway. The driver assumes an `X` ends the whole batch, reads `STOPPED` and the prompt as `interrupt`
    does today, and writes the next frame as a new batch; **unverified**, session 12 checks it.
- **Verdict: recommended.** It's the one candidate with no host round trip between the frame and the monitor, it is in
  the manual in terms ("safely place [...] STM at the end of the batch"), and it doesn't depend on the unexplained
  early prompt.

### f. A plain ELM327 (`ATMA`)

Source: DSJ p. 30, "As long as messages continue to be received, the ELM327 will continue to reset this timer"
([`elm-caf0-segmenting.md`](elm-caf0-segmenting.md), section 3), and [`elm327.md`](../elm327.md#timing): with `AT AT0`
the listen after a request lasts `AT ST` after every frame, so a module that answers within about 1 s of its ACK is
heard whole in the request's own listen, and the re-arm only happens after a second of silence. It has no `STBC`, and
this design leaves its byte stream as it is. **Unverified on the car**: only an OBDLink has run TP2.0 here
([`adapters.md`](../adapters.md)).

### g. A TP2.0-level recovery

The idea: a receiver that sees sequence 4 where 2 was due could ACK the sequence it expects (`B2`) so the module
sends again. **Rejected: no source says the module would.**

- Wiltshire's page lists the opcodes and says an ACK means "ready for next packet" (`0xB`) or "not ready" (`0x9`). It
  says nothing about the sequence number in an ACK (by example it is the next one expected: the last frame `14` is
  answered `B5`), and nothing on a repeat or on what a receiver does on a sequence error. Its only loss-related item is
  `0xA4`, "Break, receiver discards all data since last ACK", which the sender uses. The OVMS-3 copy says the same.
- Two open-source receivers: `JacekGreniger/stm32-vagcanlogger` (`sw/vwtp.c`) accepts a data frame only if its sequence
  is the expected one and sets `VWTP_FRAME_ERROR` otherwise, ending the transfer; `seishuku/teensycanbusdisplay`
  (`vwtpkwp2k.c`) never checks it ("This probably should track packet sequence"). Neither repeats anything. Their
  licences weren't checked, and nothing was copied.
- The session's own check ([`tp20.md`](../tp20.md); `tp20.rs`, `Frame::Data`) therefore stays exact: a frame that isn't
  the next is a framing error, whether it comes from a gap, a duplicate or a module that lost its place.

## 3. Recommendation

**Primary: (e), on an STN only, and only if the STN took `STBC 1`.**

```
                                  one time, with the other raw-mode switches
STBC1                             <OK        batching on (FRPM 8.15); only an exact OK counts

                                  a data frame or an ACK on an open channel, as one line
1000021A9B|STM                    <1000021A9B|STM      echo of the digits, checked, then of |STM, checked, then CR
                                  <300 B1 |300 22 .. |300 23 .. |300 14 47 20   frames, the monitor's after a `|`
```

- **The probe.** Entering raw mode on an STN sends `STBC 1`, written like the other switches (echo checked before the
  carriage return; `S` and `T` are non-hex, so one flipped bit can't make a bus request). An exact `OK` turns batching
  on. Any other answer (`?`, nothing that parses as an answer, anything else) keeps today's prompt-then-`STM` path
  exactly, and `STBC` isn't sent again that session. Leaving raw mode sends `STBC 0` if it was turned on and checks
  its `OK` the same way (anything else fails the adapter closed). A plain ELM327 is never sent `STBC`. Both commands
  and their answers are logged as commands. If the adapter doesn't answer the probe at all, the driver fails it closed
  as it does for any command, since the same adapter can't take the next one either.
- **Which frames.** A data frame (opcodes `0x0` to `0x3`) and an ACK (`0xB`). A data frame is answered by the module's
  ACK and then its answer. An ACK of a block's last frame (`0x0`, more to follow) is answered by the next block, which
  is the same gap, and the driver can't tell it from the ACK of a last packet, so every ACK is batched; the monitor
  after the last one runs until the next frame stops it, as the re-arm's monitor does. The parameters (`A0`), the
  channel test (`A3`) and the disconnect (`A8`) are answered by one frame, which their own listen prints (a keep-alive
  sent while an answer is pending is answered by one `A1` too), so they aren't batched. The setup and every other
  request are as before.
- **The line.** The approved payload's digits, then the constant `|STM`. The digits are the ones sent today, so the
  frame on the bus doesn't change. They are echoed and checked *before* `|STM` is written, then `|STM` is, then the
  carriage return: with the pipe in the line, `XX` after a misheard digit would end only the last element, and the
  damaged digits would run as an element of their own (section 4).
- **After the carriage return** the driver is monitoring and logs the `STM` as a command, as for a monitor it starts
  itself. The adapter prints the frame's own replies, then, with the pipe in front, the monitor's frames, and no prompt
  until the driver stops it. The pipe is accepted once, as a prefix of the first line after the frame's, or alone on a
  line, only while a batched line is in progress; a `|` anywhere else is unexpected output. The manual's examples put it
  before each later element's first output line (8.15), which is the one place taken.
- **A prompt before the pipe is seen** means the batch ended without its monitor (an error before `STM`, or it was
  dropped): the driver starts `STM` itself, as it does for an adapter without batching, and the frame that lost nothing
  more than the re-arm would. A prompt after the pipe is the monitor stopping on its own, a failure, as for any monitor.
- **An `X` while the frame's listen is still running** (the module's ACK is slow, and the next frame goes out) has no
  documented effect on a batch. The manual says an interrupted monitor may abort "the remainder of the batch" (16.1).
  The driver assumes the worst, that `X` ends the whole batch with no `STM`, and reads `STOPPED` and the prompt as
  `interrupt` does for a listen: the adapter is idle, the flags are cleared, and the next frame is a new batch. If the
  STN instead goes on to `STM`, no prompt comes and `interrupt` fails the adapter closed after `COMMAND_WAIT`, as for any
  adapter that doesn't stop. The fake models the worst case (`an_interrupt_before_the_batch_reaches_its_monitor_...`),
  and session 12 shows which it is.
- **Today's re-arm stays** for an STN that refuses `STBC` and for a plain ELM327, so `recv`'s comment about the lost
  frames is reworded to say which adapters still have the gap, not removed.

**Fallback, if session 12 finds no usable batch** (`STBC` refused, or a raw frame isn't a batch element, or the monitor
starts late): (d) for the data frames, with `ATR0` set when the channel's first data frame goes out and `ATR1` before
anything else, and (a) as a refinement of the `STM` write only if the log shows the echo wait as the cause. Both are
smaller wins, and the design should be reopened before building either.

## 4. Safety, policy and the audit log

- **No new frame and no new send path.** The batch is built inside `Elm::send` from an `Approved`, as the `STPX` line is
  today. A frame still comes only from the policy (`approve_tp20_request`, `approve_tp20_ack`, and the rest, unchanged),
  and a transport still takes only `&Approved`. The suffix is a constant, so a caller can't put anything after the
  frame, and only a data frame or an ACK on a channel gets it.
- **The frame's bytes don't change**, and the audit log still logs the request (its payload) before it is sent. The
  `STM` it starts is logged as a command when the line is written, as `start_monitor` does now, the `STBC` probe and
  its answer are logged as commands, and every frame the monitor prints is logged like any reply.
- **Every bit-flip is covered by the echo check, with one more case than before.** The digits are echoed and compared
  before `|STM` is written, and `|STM` before the carriage return; a mismatch ends the line with `XX\r`
  ([`elm327.md`](../elm327.md#safety)).
  - A flip in the digits is ended into `<damaged>XX`, which isn't hex: nothing is sent, as today.
  - A flip in `|STM` ends `<checked digits>|<damaged>XX`, and the checked digits are a complete first element. The
    adapter runs it: **the approved frame goes out once**, the second element is refused with `?`, and the driver stops.
    The same happens when a flip turns the `M` into a carriage return (`0x4D ^ 0x40`). It is never another frame: the
    digits were checked first. A test flips every bit of the whole line and asserts exactly this (`on_bus` is empty or
    the approved frame).
  - The carriage return's own flip leaves the line held, unrun. The next write is `X`, which gets no `STOPPED`, and
    the driver fails the adapter closed (the class in [`pitfalls.md`](../pitfalls.md) for every line).
  - Checking the whole line before the pipe was the first draft's mistake: `XX` would have ended only the last
    element, leaving damaged digits as a first element the adapter sent. It is a new entry in `pitfalls.md`.
- **ECU replies are still untrusted.** The sequence check, the frame limit and the ID filter are unchanged: the fix
  puts frames in front of the session, it doesn't loosen what the session does with them.

## 5. What session 12 (#334) must check

1. **Does the OBDLink EX (STN2232 v5.12.4) have `STBC`?** `STBC 1` answers `OK`, and `STBC 0` puts it back. If it answers
   `?`, record the firmware ID (`STI`) and stop: the fallback applies (the driver already does what it did before).
2. **Is a raw `CAF0` frame a valid batch element?** A batched channel frame on an open channel, first with a harmless
   one (a channel test is never batched by the driver, so use a data frame `10 89`), then with each read: the audit log
   shows the frame, the `STM` and every frame the module sent, with timestamps. The module has to ACK the frame
   (`B1`): that shows the frame was transmitted, not dropped for the batch.
3. **Where does the `|` land?** On the first monitored line (`|300 22 ..`), on a line of its own, or not at all. The driver
   takes it once in the first two places and tolerates the third; a line the log shows with it anywhere else is the thing
   to report.
4. **What does `X` do to a batch?** Send the next frame while the module's ACK is still pending (a slow module, or the
   `A3` right after a data frame): does the adapter print `STOPPED` and its prompt with no monitor (what the fake models), or
   does it go on to `STM` (the driver then fails closed after 2 s)?
5. **How fast does the STN go from its listen to `STM`?** The time from the module's ACK to its first data frame and to
   the frames after it, which the session 11 log couldn't give. `22 F1 87` on 52 and on 20 read whole (`62 F1 87` and
   11 bytes on 52), in all three passes, with no framing error and nothing in `lost`. If a frame is still missing, this
   is the number that says how far the STN's own switch is from instant.
6. **No `CAN ERROR`, no repeated frame:** the monitor still acknowledges (`STCMM 1`, #301).
7. **A module that never answers:** one timeout, the monitor still up, no frame written.
8. **Raw mode ends with `STBC 0` and `OK`**, and the next ISO-TP request is read as before.
9. The plain-ELM327 path isn't reachable on this car (the OBDLink is an STN): the test for it is the exact byte stream in
   the fake, and `adapters.md` keeps saying the timing on a real module is rechecked.

## Open questions

1. **Why the STN ends a raw listen after one frame.** The manual says it shouldn't. Not needed for the fix, but
   `docs/elm327.md` should not call it "the STN's rule" without saying nobody knows it.
2. **Pass 3, module 52: `14 47 20` at +176 ms.** A repeat by the module, a later answer or something else.
3. **The module's own T3 and its answer time.** Neither is in the log. Section 5, item 2 measures them.
4. **Whether `lost_frames` is the real behaviour** (an acknowledged frame dropped by the STN), or the frames are never
   received. The same fix applies, but the fake's wording depends on it.

## The tests, and what they do and don't show

`tests/elm.rs` replays the session 11 exchange for each module: setup, parameters, `10 89`, `1A 9B`, `22 F1 87`
(`..._heard_whole_module_52` and `..._module_20`). They failed before the fix with the car's own error
(`Framing([14, 47, 20])` on 52, `Framing([23, 30, 39, ...])` on 20), and pass with the batch. They also passed with
`FakeElm::monitor_startup` at zero before it, which is how to tell the failure was the window and not the replay.
`with_batching_refused_the_old_gap_remains` runs the same replay on an STN whose `STBC` answers `?` and shows the old
gap on record (the framing error again).

- The fake gets `monitor_startup`: how long after its command line `STM` or `ATMA` takes to print. A frame that reaches
  the adapter before then goes to `lost_frames`. It is zero by default, so the tests that time the module's frames from
  the monitor's start (`delay_from_monitor`, #297) are unchanged, and the replays set 45 ms. A batch's `STM` starts at
  once, as the STN's own switch (`stbc` and `batch_*` knobs: `stbc_unsupported`, `stbc_says`, `batch_drops_monitor`,
  `batch_pipe`).
- The module's frames are scheduled from its own ACK, 60 ms after the tester's frame, and not from `STM`. That is the
  difference from `a_tp20_answer_right_after_the_ack_is_heard_and_acked`, which passes because it counts from `STM` and
  so can't lose a frame while the driver re-arms ([`pitfalls.md`](../pitfalls.md)).
- The times are wider than the car's (45 ms against about 16 to 20; the first lost frames 10 and 20 ms after the ACK,
  the heard one 100 ms) so a loaded test thread can't move a frame across the monitor's start. They replay what the
  car showed, not its exact timing, and the part number's first bytes are invented. With batching the replays no longer
  depend on that margin, since the monitor starts with the frame's listen.
- The fake can't say how fast a real STN goes from its listen to `STM`; it makes it instant. Section 5, item 5, is what
  measures it.
