# Pitfalls

Classes of bug that reviews have caught in this codebase. **Read this before making any change**, and check your
change against every item that applies before you push. When a review finds a new class of problem, add it here in the
same PR as the fix.

Each entry names the class, what to check, and where it bit us.

## How to review

- **Review the whole diff on every push**, not just the fix a reviewer asked for. On PR #9, checking only each fix
  took three Codex rounds and 8 findings that one full pass would have caught.
- **Sweep the whole class, not the one instance.** When a finding says "field X accepts duplicates", check every
  field, list and function for the same problem. PR #9: one duplicate-DID finding led to duplicate-DTC and
  duplicate-PID findings in later rounds.
- **Re-read your own fixes** for the same class. A fix for one ECU's P2* deadline (PR #9) still let an ECU that had
  already answered reopen the wait.
- **On the third patch to the same logic, stop and rebuild it from the standard.** `exchange`'s broadcast timing took
  four rounds of patches to a home-made "quiet period" (PR #9). ISO 15765-4's own model (P2 from the request, P2* per
  pending module, a module is done once it answers) closed every hole at once.
- **Try the edge values** for every input a caller, file or ECU controls: 0, 1, the maximum, one past it, empty,
  blank, duplicated, wrong case, malformed.

## Data files and parsed input (profiles, fixtures)

- **Duplicates.** Every list with an identity must reject repeats: names, CAN IDs, VAG addresses, DIDs, DTCs and PIDs.
  Otherwise `find` silently takes the first one and a map silently keeps the last. Check `HashSet::insert` /
  `BTreeMap::insert` return values.
- **Aliases of the same key.** `"0c"` and `"0C"` are different strings but the same PID. Normalize before checking
  for duplicates.
- **`from_str_radix` accepts a leading `+`.** Check that every character is a digit (`is_ascii_hexdigit`) before
  parsing.
- **Validate what was written, not what a filter leaves.** Once `candidates` skipped IDs that answer on a listed
  module's request ID, a discovery range of just 0x7DF (the broadcast) filtered down to nothing and passed. Check
  every raw value in a range, then filter.
- **Validate against the real decoder.** Data the tool will decode must pass the decoder that reads it: VIN characters,
  mode 01 PID widths, text DIDs. Round-trip through `obdcracker-core` rather than re-implementing the rule.
- **A fixed-size array field takes extra elements.** serde reads `[2012, 2014, 2018]` into a `[u16; 2]` without
  complaint, so a profile's `years = [first, last]` accepted a third number. Read it as a `Vec` and convert
  (`VinRule::years`), and test a list one element too long and one too short (#102).
- **Respect the wire format's limits.** A count stored in a `u8` (mode 03, mode 09) or a `u16` (UDS DTC count) caps
  the list. Reject the input; don't saturate with `unwrap_or(MAX)`, which makes two replies contradict each other.
- **A page limit fails only when a page past it has entries.** A list that fills its last allowed page may end exactly
  there. Erroring as soon as that page is full calls a list of exactly the limit too long. Read one page past the limit
  and fail only if it isn't empty, and test both the exact limit and one past it (`update`'s release list, #291).
- **Standard data has a format whether or not a profile lists it.** F190 must be a VIN, and
  F187/F188/F189/F191/F197/F19E must be text (ISO 14229-1). Skipping validation because there's no `DidDef` let
  `hex = "FF"` pass as a VIN, and letting a `DidDef` replace the check let `F190 text = "abc"` through. A profile
  can't declare a standard DID in another format either (`standard_decode`). The rule cuts both ways: a standard
  DID with *no* fixed format (F18B's BCD date) must take the profile's format, and every reader of a text DID must
  apply the same check as the others. Scan forced F18B to text and read F190 with the plain text decoder, so a
  printable date showed as a string and `62 F1 90 61 62 63` as the VIN `abc` (#50, #51). Keep the list in one place
  (`uds::did::is_text`, `obd::check_vin`).
- **Cross-check related sources, both ways.** Fixture vs profile: every DID is standard or in the profile, values
  match the profile's `decode`, and OBD-II data only sits on OBD-II ID pairs (0x7E0..=0x7E7 → +8). And profile vs
  fixture: every DID the car answered (it has a length) is in the fixture, or the sim refuses what the car didn't.
  Checking one direction only let the transmission's F1AA and six new gateway DIDs go missing (PR #127, Codex).
- **Check data against the real replies, not against another hand-made file.** The instruments' F19E got the
  reply's length (24, with `62 F1 9E`) instead of the data's (21), in both the profile and the fixture. The cross-check
  between them passed, because both were wrong the same way, and the car's correct reply then read as malformed
  (#62). Keep the car's replies as test data (`crates/obdcracker-profile/tests/data/a7-did-replies.txt`) and
  check every value derived from them against it.
- **An importer must fail on a line it can't read, not skip it.** `scripts/import-opendbc.sh` matched only
  `b'...'` literals, so opendbc's one `b"..."` Hyundai reply (it holds a `'`) would have dropped out of a fixture
  without a word. Accept every form the source uses, and exit with the line when one still doesn't parse (#12).
  The same went for keys: only `(Ecu.x, 0x7e0, None)` was read, so every Toyota reply behind a sub-address (0x750)
  was skipped, and a key it couldn't read left the next replies filed under the previous one. A car, key or reply
  line that isn't read exactly ends the import.
- **A value with its prefix stripped doesn't say which request it answered.** opendbc keeps Toyota's identification
  replies without the `49 04`, `62 F1 81` or `5A 88 01` it stripped, and asks one ECU all three ways. Rebuilding a
  prefix is a guess, so make it from facts the data carries (the count byte, the length, the address), fail the
  import on a shape it doesn't fit, and decode the rebuilt reply with the codec of that request in a test with the
  expected text written by hand from the source (#12).
- **Public fields bypass the parser.** Anything with `pub` fields can be built or edited by hand, so consumers must
  re-validate (`Profile::validate`), or the type must make invalid values impossible.
- **Empty, blank and padding-only values** are input too: names, text DIDs, CALIDs. `"   "` is not empty but
  decodes as `""`, and so does `hex = "20 20"` for a text DID. Codes that are padding or wildcards aren't codes:
  P0000 in mode 03, and 0x000000 and 0xFFFFFF ("all groups") in UDS.
- **But check real modules before calling padding malformed.** A list slot can be legitimately empty: the A7's
  engine answers mode 09 PID 04 with five CALIDs, one of them all 0x00 (CVN 00000000). Rejecting it threw away
  the four real ones (#46). Model an empty slot explicitly (`None`), and still reject one that isn't text. The
  same goes for a VIN: three A7 modules answer F190 with 17 dashes, which scan called malformed (#63).
- **Names are keys.** If lookups are exact, reject names with surrounding spaces rather than trimming them in one
  place only, and treat names that differ only in case as duplicates.
- **Escape what you write, too.** A format built by hand (JSON Lines, TOML) must escape every string it
  interpolates, or one quote or backslash breaks the file for every reader. The audit log wrote the link name raw, so
  a Windows port such as `\\.\COM10` made invalid JSON. Test by parsing the output back with a real parser (#2).
- **A document read back must say one thing, spelled one way.** The JSON result types (`transport::json`, #100) first
  used `#[serde(flatten)]` on a `value`/`error` enum, which takes the first key and ignores the other, so an entry with
  both read as a value, and the derived enum that replaced it refused any key a later version adds, against the format's
  "unknown entries are ignored" rule. Parse such an object's entries by hand, ignore unknown ones, refuse two or none,
  and test with a document that has both and one with an extra entry on every such object. A number JSON can't hold
  (NaN, infinity) is written as `null`: refuse to write it. Refuse a spelling the writer never writes (lower-case hex,
  a 3-digit CAN ID over 0x7FF, an 8-digit one that 3 digits hold, `P4000`), or two spellings of one value get in. A
  proptest that reads arbitrary text and checks that whatever it accepts writes back to that same text covers the last
  kind.
- **Quote for a shell with an allowlist, not a denylist.** The sweep's resume command refused Windows words with
  `$ % ! "` and double-quoted the rest, but PowerShell also reads typographic quotes (`“`, `’`) as quotes, so a
  crafted path could still end the quoting. Write a word only if every character is known plain; otherwise print
  no command at all (PR #76).
- **Don't over-restrict.** Know the protocol before rejecting something: Toyota body modules legitimately share
  CAN ID 0x750 with different extended-address bytes.
- **A comparison must not pick between repeats.** `diff` documented "the last entry wins" for a hand-edited document
  that lists a DID twice, so old `F189 = 0005` against new `[0006, 0005]` printed `no changes` and exited 0. A tool
  that reads a file back and then decides something from it refuses a repeated ECU, module, DID or DTC, and a test
  makes the repeat conflict with the other side (#100).
- **Two different values must never print the same.** The diff text showed a DID's text bare, its bytes as `[01]` and
  its absence as `(absent)`, so the text `[01]` or `(absent)` read as bytes or as a missing DID. Quote the one kind that
  has no delimiter of its own (and escape the quote), and write a golden test for each pair that could collide (#100).
- **A note about what was left out compares with what was asked for.** Two sweeps of `0600-0700` that both stopped at
  `0664` shared the same covered range, so the "compared less than they read" note compared the result with itself and
  stayed silent. Compare the covered range with each request, not with the other result (#100).

- **State computed on read must also be stored.** The sim's `session()` reported a lapsed session as default
  without storing it, so raising S3 afterwards brought the expired session back (#68, Codex). Write the derived
  state back before changing anything it depends on.

## Arithmetic and time

- **Compare against a limit before incrementing.** `pending += 1; if pending > max` overflows when a caller sets
  `max = u16::MAX`, which panics in debug and wraps in release (PR #9, `Timing::max_pending`).
- **`Instant + Duration` panics on overflow.** Clamp any caller-supplied duration before adding it (`exchange` caps
  each wait at one hour).

## Talking to ECUs

- **Every wait on the bus must be bounded by something the ECU can't extend forever.** Count response-pending
  replies; accept one answer per ECU for a broadcast (J1979); ignore repeats without extending the wait. A test with a
  transport that never stops sending proves it (PR #9: an ECU repeating its VIN reply hung `exchange` forever). A
  loop that skips input it doesn't use, such as another module's frames, must still check its deadline: the TP2.0
  session's first draft only checked it inside `recv`, so a flood from another ID never ended (#142).
- **Keep limits per source, too.** One shared `max_pending` counter let one stuck ECU throw away every other ECU's
  answer to a broadcast. Count per ECU, and drop only the one that goes over (PR #9).
- **Keep timers per source.** Each pending ECU gets its own P2*. One global "latest deadline" lets a late ECU in:
  both an ECU whose own P2* ran out, and an ECU that never went pending but answers after P2 while another ECU's
  P2* keeps the loop open, or after a pending ECU's answer restarted a shared timer.
- **Keep a multi-step broadcast's progress per source.** `scan` follows the mode 01 bitmap chain (00, 20, 40, …)
  for as long as any ECU advertises the next page. One ECU's answer to a page it never advertised, or a page after
  its own chain broke, was still counted. Accept a page from an ECU only if that ECU said it comes next (#48, Codex).
- **Deadlines must shrink back** once the reason to extend them is gone (P2 again after the pending ECU answers).
- **Decode a reply as an answer to the request that got it.** One `SessionError::Refused` carries replies to both
  `10 03` and `3E 00`; decoding every one as a `10` answer turned a `7F 3E 22` into "wrong service". Take the
  service from the reply, or keep the request with it.
- **Splitting a list to process it in groups reorders it.** `scan` read extended-session DIDs after the others and
  appended them, so values left their documented order. Put them back in the original order after the last group.
- **Cleanup that runs on drop can't report a failure.** A guard's `Drop` sends `10 01`, but nothing sees what
  happened, so an adapter that failed there went unnoticed and a module that refused to leave the session looked
  fine. Where the outcome matters, clean up explicitly and pass the result on alongside the original failure (both
  can matter: `SessionError::Unconfirmed`); leave `Drop` as the last resort. And a last resort shouldn't repeat
  cleanup the caller already did: `Audited`'s drop settled again after an explicit `settle()`, so a broken adapter's
  failure was logged twice (#83). Track whether anything happened since. Nor should explicit cleanup hand its own
  retry to `Drop`: `ExtendedSession::end` left the guard armed after an unanswered `10 01`, so the retry's adapter
  failure was lost (#80). Retry inside the explicit call and disarm the guard.
- **Report progress only for work that happened.** A sweep called `progress(did)` even when the session's keepalive
  failed before the read was sent, so a caller checkpointing on it would skip a DID that never reached the bus (#81).
- **"Busy, repeat request" (NRC 0x21) isn't an answer.** Recording it as the DID's value and moving on misses the
  DID and keeps a busy module busy. Stop or wait, then ask again.
- **A refusal doesn't say which request it refuses.** UDS `7F 22 31` names the service, not the DID, so after a read
  times out its late refusal can arrive as the next read's answer. Asking again doesn't fix it: the retry takes the
  first answer, and the duplicate's answer is left queued for the read after. Once replies may be out of step, they
  stay so for the rest of the connection, even past answers that plainly match: stop at the next one that can't be
  matched, and resume on a fresh connection from there. A run that *ends* out of step must say so too
  (`Sweep::out_of_step`, #82), or the caller's next read on the same connection can take the late refusal as its
  answer. That includes a retried cleanup request: `ExtendedSession::end` reported a clean leave when its `10 01`
  retry took the first try's late `50 01`, leaving the retry's own answer queued (#121, Codex). Anything short of a
  definite answer after a timeout leaves the connection out of step, a failed retry included (#121, gate), but a
  definite answer to the first try leaves it in step, so the result must say which (`SessionError::Retried`), and
  a note about it must show whether or not the run stopped.
- **A reply can't change what the request already fixed.** A TP2.0 channel setup asks to be answered on 0x300, but
  `decode_channel_setup` took any valid receive ID, so a reply giving 0x301 read as an open channel the policy then
  wouldn't close (#153). When the request names a value the reply repeats, check it equals the request's, not just
  that it's well formed.
- **A count inside a reply must be backed by the bytes after it.** A UDS snapshot record holds its number, how many
  identifiers follow, then each identifier's 2-byte DID and data. `decode_dtc_snapshots` only refused a record number
  alone, so `59 04 00 16 A0 01 01 01` (one identifier, no DID) read as data (#143). Where a count's items have a
  known least size, check the bytes left can hold that many before accepting the reply, and count every part of an
  item: the first fix checked only the DID, so a DID with no data passed (PR #167, Codex). A count of 0 is an edge
  value too: a snapshot record of no identifiers is malformed (python-udsoncan 1.26.1 refuses it too:
  `ReadDTCInformation.interpret_response` raises `InvalidResponseException` for a record with
  `number_of_did == 0`).
- **Match a reply to its request by what it echoes**, not only the service ID: the PID (mode 09), a requested PID
  (mode 01), a requested DID (0x22), the subfunction, and every field the reply repeats, such as the DTC of a
  `19 04`/`19 06` reply: matching those by subfunction alone took a late answer for another DTC (#141, Codex). A late
  reply to an earlier request has the same SID (`response::answers`).
- **A deadline on the far side of the bus needs a margin for the trip, and the earliest safe time.** The guard
  checked S3 against its own clock, so a `3E 00` sent just in time could reach the module after its session
  lapsed. The module answered it in the default session anyway, so nothing showed. The next fix timed S3 from
  the answer's arrival, but an ELM can take 18 s to print a long answer the module sent at once. When you can't
  see when the other side acted, take the earliest moment it could have (the request), and stop trusting the
  deadline early enough for the next message to get there. Pick the failure that costs least: a needless `10 03`,
  not a read sent into the default session (#68, three Codex rounds).
- **A host timestamp is not when the other side acted, and a bound must hold in the dangerous direction only.**
  Timing the module's S3 from when a reply was read, or from the read less the print time at the link's nominal
  rate, trusts a session that may have lapsed: an adapter prints slower than its baud rate, USB adds latency, and a
  caller that reads late finds bytes that arrived long before the read. `Response::bus_time` assumes half the rate, adds
  a fixed allowance, never goes before the request, and falls back to the last time the link was drained when a read
  may have found data waiting (`docs/elm327.md#when-a-reply-left-the-bus`). Test both directions: a slow module on a
  fast link keeps the session, and a long answer printed at the link's full speed doesn't (#69).
- **Use the limits the other side declares.** A module's `50 03` gives its own P2 and P2*; ignoring them timed
  out a module that said it needs 100 ms. Extend the caller's timing by the excess over the standard defaults,
  so an adapter's allowance stays on top (#68, Codex). The same holds for a gap it asks for: the TP2.0 session kept
  the module's T3 but sent frames as fast as they came (PR #183, Codex). A value decoded and stored but never read
  is a sign. And the tester's own wait for it mustn't eat into the time the module was given. Bound a limit only by
  the deadlines of the frames it actually governs: capping every frame's T3 wait at T1, which only limits ACKs, sent
  requests and `A8` early (PR #183, gate). Count a minimum gap from when the frame went out, after `send` returns:
  stamped before, an adapter's own work in `send` (an ELM's settings and echo) ate the gap (PR #183, Codex).
- **Keep cleanup armed until it has worked.** `end()` marked the guard finished before sending `10 01`, so a
  failed send left nothing to retry it, and `end` had consumed the guard. Disarm only after a definite answer
  (#68, Codex).
- **The suppress-positive-response bit (bit 7) is not echoed.** It applies to every UDS service with a subfunction,
  0x19 included. A request with the bit set gets no positive reply, so only a refusal answers it; masking the bit
  off instead lets a late positive reply to an earlier, unsuppressed request through. A refusal is still sent when
  the bit is set, and **after response-pending (0x78) the final positive reply is sent even with the bit set**
  (ISO 14229-1), so it answers the request then (`response::answers_after_pending`). Check claims about the
  standard against a source before writing them down; this entry first said 0x19 had no such bit, then missed the
  0x78 exception (PR #9, PR #11).
- **No answer isn't no effect.** A request that timed out may still have reached the module and taken effect;
  only its reply may be lost. Undo what it could have done: `ExtendedSession::enter` sends `10 01` after an
  unanswered `10 03`, and skips it only for a well-formed refusal (`7F 10 <NRC>`) (#68, Codex and the review
  gate). The reverse holds too: never count an
  unanswered or refused request as having worked (the guard's S3 clock only restarts on positive replies).
- **A DTC status mask of 0xFF isn't "every stored fault".** The "test not completed" bits (4 and 6) are set on every
  code a module hasn't tested yet, so `19 02 FF` returns its whole DTC table: about 330 codes across four A7
  modules, none failed, pending or confirmed (#49). Ask for the fault bits (`FAULT_MASK`, 0xAF), and still filter
  the reply by them and the module's availability mask, in case a module ignores the mask (#52).
- **Functional requests get fewer refusals.** ISO 14229-1: a server doesn't send NRC 0x11, 0x12, 0x31, 0x7E or
  0x7F to a functionally addressed request; it stays silent. A simulated module must too.
- **What an adapter prints is untrusted text that reaches a terminal.** Anyone in range of a Wi-Fi adapter can make
  it print escape sequences. Replace control and non-ASCII characters where the text comes in
  (`elm::codec::LineSplitter`), not at each place that prints it (M3 branch, security review). A USB device's product
  and serial strings are the same: the gs_usb device list shows only printable ASCII, and the serial a user types is
  compared in that form (`gsusb::select::printable`, #246).
- **An adapter can lose its settings mid-session** (brownout, internal error). Cached state, such as the header or
  "protocol already set", is then wrong, and a request could make it search for a protocol. Treat any sign of a reset
  as unknown state and stop, **everywhere output is read**: replies, answers to setup commands, and output you're
  only draining to get to the next prompt. The first fix checked replies only; the review gate found the drain
  (M3 branch). Output you can't read counts too: an overlong line could hide any of these (M3 branch, Codex).
- **Check for output the device shouldn't have sent before writing to it,** including what's already buffered past
  the prompt you stopped at, on every write path. A reset that arrives right after a prompt is otherwise only seen
  after the next request went out. The first fix covered writes after `ready()` but not the request written right
  after the header commands (M3 branch, Codex). Read until the deadline, not until the first read: bytes that make
  no event (a stray NUL) aren't silence. And write down the window no check can close (a reset still in flight when
  you write), so reviews stop at the limit instead of chasing variants.
- **Once the driver has failed closed, nothing more may reach the adapter, including any step that runs before the
  usual check.** `send` interrupted a TP2.0 channel's listening (`X`) before `ready()` checked `broken`, so an
  adapter already in an unknown state got one more write (#185, Codex). Check the failure state first on every path
  that can write.
- **Don't ask for an answer that looks like a failure.** `ATI` answers with the same banner a reset prints, so a
  reset during `info` looked like an answer. Take such values once, when they can't be confused (the reset banner),
  and treat them as failures everywhere else (M3 branch, Codex).
- **A truncated answer must not pass as a complete one.** Accepting any well-formed subset of `AT PPS` let a cut-off
  summary skip the parameters that mattered. Require every entry you check (M3 branch, Codex).
- **Output the driver could never have caused is evidence its assumptions broke.** `STOPPED` outside the two
  interrupts the driver makes (`docs/elm327.md`), or a frame from an ID the receive filter excludes, means something
  else wrote to the adapter or it lost a setting. Stop, don't ignore it as noise (M3 branch, Codex).
- **Widening a parser reclassifies lines other code diagnoses.** Once the ELM codec read four header bytes as a
  29-bit ID, a headers-off data line after a reset (`03 62 F1 87 34`) parsed as a frame from 0x0362F187, and the
  driver's "unexpected output" diagnosis became a misleading receive-filter one (#146). When a parser accepts more,
  check what used to fall through to the other branches, and check the result against the state the driver set
  (here the ID width).
- **Check which chip version a command needs.** `AT CRA` with `X` digits is ELM327 v2.0+; most adapters say v1.4b
  or v1.5. Look it up in the datasheet's version history before relying on a command (M3 branch).
- **One flipped bit on a serial line can turn a command into a bus frame.** An ELM327 sends any line of hex digits to
  the bus, ignoring spaces and control characters, so `ATE0` with its `T` flipped to `D` is the request `AD E0`.
  "Contains a non-hex letter" isn't enough: no single flip of any byte, the carriage return included, may leave a line
  of hex digits, and a test must flip every bit of every command. Check the echo of everything written, and rely on
  defaults you've verified (`AT PPS`) rather than sending a risky command to set them (M3 branch, Codex).
- **A flipped bit can delete a character, not just change it.** The ELM327 ignores control characters and takes a
  trailing odd digit as a response count, so a digit flipped to a control character drops out and shifts the rest of
  the line by a nibble: `22 F1 87` becomes `2F 18 7`. When reasoning about corruption, count deletions as well as
  substitutions, and check what the device does with the result (#19).
- **Don't rely on a device to throw away a half-written line.** The ELM327 datasheet says an unfinished line is
  discarded after about 20 s, but the STN in an OBDLink EX holds it until the next carriage return, whenever that
  comes (#54). Checking a request's echo before its carriage return (#34) only helps if a bad line is then ended
  explicitly with something the adapter refuses (`XX\r`), not left for the next command to finish.
- **Weigh a mitigation against what it costs.** Refusing every request with a dangerous one-bit-flip neighbour
  (PR #31) refused most ordinary reads to guard against a bit error on the few centimetres of UART behind an adapter's
  USB chip. Estimate how likely the failure is and what it would actually do (one frame can't flash a module), and look
  for a fix at the source (checking the echo before the carriage return, #34), before building defences (#19).
- **Datasheet examples aren't byte-exact.** Real ELM327s print a space after every byte, the last one included; the
  datasheet's typeset examples don't show it. Test parsers against an implementation you didn't write
  (ELM327-emulator), not only against fakes built from the same reading of the datasheet (M3 branch, #13).
- **A value a standard leaves to the manufacturer isn't a standard value.** The first KWP2000 allowlist made `10 81`
  a read as "the standard session", but ISO 14230-3 leaves the diagnostic modes 0x80..=0xFF to each manufacturer, so on
  some make it could mean anything; and it fixed widths for `17`/`18` parameters the standard also leaves to them,
  refusing valid reads, and a 2-byte clear-DTC group the standard makes optional (#137, Codex). The same goes for
  replies: what follows `5A` is the manufacturer's record, so matching it on an echoed option would drop valid answers.
  The other side of that: code that knows the make must check what the generic match left open. The VAG
  identification display skipped `5A`'s first byte as the `9B` echo without checking it, so `5A 90 …` showed as
  the `9B` identification (PR #183, Codex).
  Before relying on a parameter, find its row in the standard's table; if it's the manufacturer's, it needs a
  profile-specific rule.
- **A new protocol reaches past the allowlist.** Approving KWP2000 requests wasn't enough: `exchange` still matched
  their replies as UDS, so KWP2000's bare `7E` answer to `3E 01` was dropped as not answering it (#137, Codex). Follow
  a request through everything that reads its reply: matching, response-pending, decoding.
- **A fresh state machine takes any starting point, so give it the one the protocol fixes.** The TP2.0 reassembler
  starts at whatever sequence number comes first, so with a channel's first frame lost, `11 00 02 5A 9B` (a later
  frame that happens to look like a whole message) read as a complete, truncated answer (PR #183, Codex). Where the
  protocol says where numbering starts (0 on a new channel), check the first one against it.
- **After dropping a message, skip to its end.** TP2.0 marks only a message's last frame, so a reassembler that
  forgot a bad message at once read its next frame as a new message: `31 00 02 AA BB` became a 2-byte reply. On an
  error mid-message, drop frames through the next one marked last (PR #149).
- **A request built from a reply needs proof of that reply.** `approve_tp20_disconnect` took any two IDs, so a
  caller could aim `A8` at CAN ID 0. When an approval follows from what a module answered, take a token only the
  policy can build from that answer (`OpenTp20Channel`), and check its IDs against what
  the request asked for (PR #149).
- **Don't confuse a transport limit with a protocol limit.** 4095 bytes is ISO-TP's short first-frame length, not a
  UDS maximum; the 32-bit escape carries more.
- **A policy widened for one pass mustn't outlive it.** Discovery returned the policy that allowed its whole candidate
  range, and the TP2.0 pass reused it, so every channel ID in that range counted as a module's and its disconnect was
  refused. Hand later passes a policy narrowed to what was actually found (PR #149).
- **An early exit skips what else was asked for.** `scan` returned "nothing answered" before the TP2.0 pass when no
  ISO-TP module replied, which is when TP2.0 matters most. Run every requested pass, then decide the exit code
  (PR #149).
- **A CAN ID means nothing without its width.** A 29-bit frame with ID `0x7E8` and an 11-bit one with `0x7E8` are
  different frames, but `ReplyWindow::feed` takes a bare number. `RawCan` compares the frame's width with the request's
  before feeding it (`docs/raw-can.md#frames`). Any code that matches received IDs against an expected one must carry
  the width with it.
- **A loop that waits on a flood needs its deadline checked after every frame it skips.** A receive loop that only
  stops when the port times out never ends on a bus full of other modules' frames. The raw-CAN core checks the clock
  after every frame, and its flood tests hang (the container must be killed) if that check is removed.
- **A bounded drain that hits its bound hasn't drained.** `RawCan` reads stale frames before a request, up to 256; at
  the limit it carried on, so a late reply further back in the queue could answer the new request. Fail when the bound
  is hit, and read once more than the bound so a queue of exactly that size still passes (PR #261, Codex).
- **Handle every event before a limit rejects it.** The drain counted the 257th stale event and failed before looking
  at it, so a bus-off right behind 256 stale frames never latched, and the next send found an empty queue and wrote
  into the faulted bus. Latch, then apply the limit; and when the event is the fault, report the fault (PR #261, Codex).
  Record the event too: the frame that trips the limit was read and is gone, so it goes into the log (or the `lost`
  count) before the error returns (#264).
- **A transfer ends on every path that leaves the peer able to go on.** An unconfirmed flow control, a `before_send`
  that refuses, or a failing port read returned an error but kept the reply window open, so the module's consecutive
  frames, sent after all, completed a reply from a transfer the caller was told had failed. Every error path out of a
  receive drops the window; test it by delivering the rest of the transfer afterwards (PR #261, Codex).
- **Don't delete saved evidence when a later event completes.** Frames of an unfinished reply are kept for the log. A
  completing frame cleared everything kept for its source, though a single frame completes a *new* transfer and
  abandons the old one, whose frames it then erased. Report what the new frame abandons first, whatever the frame
  is (a malformed or empty one abandons too), and only then clear what the completion consumed (PR #261, Codex).
  A bad frame that parses as a consecutive frame (wrong sequence number) ends its transfer too: report it and what it
  ended as it arrives, not at the next request, as `docs/raw-can.md` promises (#263).

## Links and adapters

- **An audit log that sees only what the code reads misses the evidence.** The ELM driver dropped reply lines nobody
  read before the next request, and adapter commands never reached the log, so a late reply or a changed setting left
  no trace. Log what the adapter did, not just what the caller used, and log a command that failed too: the raw-mode
  switch skipped its log entry when an echo check failed, the case where the adapter may have heard something else
  (PR #149).
- **An adapter's learned timeout can hide a slow module.** The ELM327's adaptive timing (`AT AT1`) shortens its wait
  to fit the modules that answered fast, so a module that wakes slowly reads as absent. Before acting on "nothing is
  there", as discovery's wide pass does, look again with the adapter's longest wait. The same held after a TP2.0
  module's ACK: the adapter had learned ~45 to 80 ms from the setup replies, printed its prompt, and the session
  took that early `Timeout` for the module's and gave up ~36 ms after the request, with its own wait still running (#218). A timeout before your own
  deadline is the transport's, not the peer's: keep listening (re-arm) until the deadline. And when two features
  each switch the same adapter setting (raw mode and a patient window both want adaptive timing off), keep one rule
  for the setting rather than each sending its own on and off, or one undoes the other.
  The re-arm itself was the next bug (#227): an STN ends a raw listen after one frame, and the session re-armed it by
  sending an `A3` keep-alive, which leaves a gap in which the module's answer is lost and can make the module drop the
  channel as a test it didn't expect. Make the adapter listen without sending (the driver monitors the bus, `STM` or
  `AT MA`), and check what a mode does with the filter you set: on an STN `AT MA` and `STMA` pass every ID. A state that has no prompt of its own (a monitor) makes every prompt a failure: check each path
  that reads one, not only the wait, or the adapter's cached state outlives a monitor that ended unseen (Codex).
- **A silent listener on a bus where it's the only receiver makes the sender repeat and error out.** A CAN
  frame needs one node to acknowledge it. Behind the gateway the diagnostic bus has two nodes, the module and the
  adapter, so an adapter whose monitor stays silent (`STCMM 0`, `AT CSM 1`, the default) leaves every frame of the
  module's unacknowledged: the module sent `300 10 00 03 7F 1A 11` 31 times and the adapter said `CAN ERROR`, with
  the answer never read (car session 9, #301). Silent on the bus is for a bus other nodes already acknowledge on;
  anything that listens to a module it talks to must acknowledge, and a setting the adapter refuses is a failure,
  not a reason to listen silently. Check it for any new listen-only or monitor feature (#104, `gsusb` listen-only
  on the OBD port), and model it in the fake as two nodes, or its tests pass on a bus no car has.
- **Check that a fix changes what the logs show.** Discovery's "waiting longer" recheck turned adaptive timing off,
  but an STN always waits its whole timeout for a first reply, so in #86 the recheck waited the same 1.09 s per
  silent ID as the first pass (#87). Read the datasheet for what a setting changes, and compare the real audit log's
  timings before and after. A longer wait needs a longer timeout (`STPTO` on an STN), and a silence watchdog sized
  for the old timeout must grow with it.
- **Every read and write on a link needs a bound, not just the bus waits.** A peer that stops reading blocks a write
  forever once buffers fill (set a write timeout), and some calls ignore that timeout altogether: serial2's `flush`
  waits for the OS queue to drain with no limit. Check each I/O call's docs for what its timeout covers (M3 branch,
  Codex). A connect timeout must cover the name lookup too: `to_socket_addrs` blocks for as long as DNS takes, so
  look the host up on another thread under the same deadline (M3 branch, Codex).
- **Bound what you collect, not just each piece.** Each line was capped at `MAX_LINE`, but a command's answer
  collected lines until its deadline, so an adapter streaming `A\r` could exhaust memory in two seconds. Cap the count
  too, and check every loop that accumulates (M3 branch, Codex).
- **Timeouts must cover the link, not only the bus.** At 9600 baud a 4095-byte reply takes about 18 s just to print,
  so a P2 sized for the ECU timed out mid-reply. When one timer gets the allowance, give it to every timer that can
  wait for the same data: P2, P2* and the wait for a request to finish were fixed in three rounds instead of one
  (M3 branch, Codex). The fourth round (several modules' replies) showed the model was wrong: when the device says
  when it's done (the ELM prompt), bound silence, not total time. The driver now fails an adapter quiet for longer
  than its own timeout allows, and keeps a total limit only for one that never stops printing.
- **A size measured on one ID width is wrong for the other.** The ELM pacing gap and P2's print allowance were sized
  from an 11-bit frame line (29 characters); a 29-bit line is 37, so a long 29-bit reply overflowed the adapter's
  buffer at 9600 baud. When a new ID width, header or format lands, grep for every constant derived from a line's or
  frame's length and size it for the longest one (PR #147, Codex).
- **A watchdog counts only the time you spend waiting, added up across calls.** The silence clock started at `send`,
  so a caller that read 8 s later found a healthy adapter "hung" without reading the reply waiting on the link.
  Restarting it on every call then let a caller polling in 1 s steps never trip it. Sum the time spent in each wait,
  and measure the whole wait, not just the `read` inside it (a fake link returns at once) (M3 branch, review gate).
  When bytes arrive, restart from the last byte, not from the end of the wait it came in: a wait that heard one
  stray NUL still ended in silence, and discarding it let bytes just under twice the limit apart run forever (M3
  branch, Codex).
- **A log of what was heard must cover what was half-used.** The audit log reported lines left unread at the next
  request, but frames already fed to a reassembler for a reply that never completed (another module's interleaved
  frames, a transfer dropped mid-way, a sixteenth-plus sender) and status lines such as `NO DATA` vanished. Keep each
  input's raw form until it's part of something logged, and report it when it's dropped (PR #78). But log each line
  as what it was: `NO DATA` *is* the answer that ended a request, and logging it as unread buried the few real unread
  lines among 126 of them in car session 4 (#88).
- **Don't hand back stale data to make a log complete.** Replies drained before the next request aren't returned:
  queueing them would let a late reply to a repeated request pass for a fresh one. Document what the audit log
  records instead (M3 branch, Codex).
- **Pin external test tools exactly, and check the pin installs from scratch.** PyPI's ELM327-emulator 4.0.0 sdist
  reports `4.0.0.post57`, which uv refuses; it only worked locally from a cached build. CI installs a pinned git
  commit (M3 branch).
- **A shared buffer fills at the sum of its sources' rates.** Pacing each module's frames to the link's speed keeps
  one reply from overflowing the ELM327's buffer, but a broadcast can get long replies from 8 ECUs at once (PR #70,
  Codex). Size a rate limit for every source that can send at once, and make a fake interleave concurrent senders,
  not print each in turn.
- **A wrapper that forgets a defaulted `Transport` method silently takes the default.** `Transport::broadcasts_can_overflow`
  defaults to false, so an `Audited` that didn't forward it made every audited ELM327 session (the CLI's only kind) take
  the broadcast path that overflows, with nothing failing to compile (#71). When a trait gains a defaulted method that
  changes behaviour, grep for every non-test `impl Transport for` wrapping another transport, forward it, and add a
  test that fails when the forward is removed.
- **Read a mode's paragraph, not just its summary chart.** The ELM327's flow control chart says mode 2 has the adapter
  provide the ID bits; the text says they're copied from the First Frame unchanged, so flow control for 0x7E8 goes to
  0x7E8 and the ECU stalls. The first fix for broadcast pacing used mode 2, and a fake that only recorded that flow
  control happened passed it (PR #70, Codex). Model where a frame goes, not just that it was sent.
- **Trust what an adapter does, not what it says it is.** Clones claim `v1.5` (never released) or `v2.1` and refuse
  v2.0 commands, and any answer to `STI` that wasn't `?` counted as an STN chip, which would have exempted a clone
  from pacing (#23, #44). Decide on behaviour you've checked, match identification answers exactly (`STN…`), and
  name the claimed version in the error when a command it should support is refused.
- **Emulators have quirks too.** ELM327-emulator prints `SEARCHING...` on the first `01 00` even with a fixed
  protocol, which a real adapter doesn't; the test reads PID 20 instead. Note each workaround where it's made
  (M3 branch).
- **A mode switch changes only what its command says.** `AT CAF0` turns off ISO-TP formatting, but the adapter
  still pads every frame to 8 bytes (`AT V1` stops that) and still answers anything that looks like a First Frame
  with flow control of its own (`AT CFC0`). When a new mode relies on the adapter not doing something, find every
  datasheet feature that does it and turn each off, and make the fake adapter do what the real one does by default
  (PR #149).

- **A feature gated on state an earlier request sets never works as a process's only request.** Sending over 7 bytes
  needs the adapter to have shown it echoes each character (`early_echo`), which only a first request shows, and
  every driver test started from a `warmed` connection that had sent one. The CLI's `read-dids`, a fresh process
  with one long request, would have been refused every time (#308). For each feature that depends on state the
  driver learns, run it as the first and only request of a connection (the TCP fake in `cli.rs`, not `warmed`), and
  have the command send the cheapest safe request first where it can't.
  That first request is a request like any other: check the input before it, and don't go on after it went
  unanswered (a late answer to it could pass for the next one's).

- **A read path that collects lines to fail on them must still log them.** The segmenting driver stops the adapter's
  listen after the flow control and fails the request if the module printed another frame first, but it kept those
  lines for itself, so the frame that failed the request, and the `NO DATA` or `BUS BUSY` that ended another, were in no
  audit event. Anything a loop reads and acts on is reported as it would have been had nobody acted on it (`unread` or
  `status`, or the frame event for a frame it uses), and a test takes the events after each failure (#214).

- **A filter set for replies also hides what you sent.** The kernel applies a SocketCAN socket's receive filter to the
  copies of its own frames, so with the transport's filter on the reply IDs the driver's echo of a request (the only
  proof it went out) never arrived, and every write timed out. The port adds the sent frame's own ID to the kernel's
  filter while it waits, and the fake interface keeps the kernel's filter rules so a test fails without it (#108).
- **A loss counter shows only on the next delivery.** `SO_RXQ_OVFL` puts the socket's drop count on the frames queued
  after a loss. A flood that fills the queue and ends shows nothing until another frame is queued, so a test must send one
  more after the queue is drained, and a caller can't tell a lost last frame from silence: the reply times out (#108,
  `docs/socketcan.md#receiving`).
- **A name from the user that becomes a path is validated first.** The SocketCAN interface name is joined into
  `/sys/class/net/<name>/...`, so `..` or `a/b` would read another file. Allow printable ASCII without `/` and `:`, at
  most 15 characters (the kernel's own limit), and not `.` or `..`, before anything is read; read sysfs values with a size
  cap and parse them strictly (`0x` and hex digits, or digits, and one newline), without echoing the content back (#108).
- **A fake that returns early hides a deadline.** The first fake interface returned "nothing" after 2 ms whatever it was
  asked to wait, so a write that gave up on the first empty read passed its tests, and would have waited far too little
  against the real socket, which only returns early on an interrupt. A fake must keep the contract it stands in for (wait
  the full timeout before saying nothing came), and the port must decide from the clock, not from one empty read (#108).

- **Writing no frame isn't being silent on the bus.** A CAN controller acknowledges every frame it receives with a
  dominant bit, so a "listen-only" session that only refuses to send still shows on the car's bus unless the
  controller is itself in listen-only mode. A backend that can't set that mode (SocketCAN never changes the interface)
  must say so when the interface isn't in it, in the audit log and to the user, rather than promise a silent tap (#108).
- **A frame is its length as well as its bytes.** SocketCAN's echo check compared the data bytes of the frame in flight
  (always 8) with the received ones, so a VW TP2.0 setup sent at DLC 7 never matched its own echo and every write timed
  out; and the same bytes at another length would have matched. Anything that matches or builds a frame (echo check,
  golden frames, a fake's reaction) carries the DLC, and a test sends one frame shorter than 8 through every path
  (echo, transmit counter, USB), not only the padded form (#259).
- **A drain before a send must not eat the conversation it sits in.** The ISO-TP drain throws away what the last request
  left, which is right between requests and wrong between the frames of one TP2.0 channel, where the module's ACK or next
  data frame may already be queued when the tester sends its own ACK. A frame on an open channel reads the port to its
  end (so a bus fault still latches before the write) and keeps the channel's frames for the session; only a new setup
  drops what the last channel left. A reader that must never lose a frame has to say, per path, which of the two it
  is (#259).

## Docs vs code

- **After every fix, re-read the doc comments on what changed** ("returns every reply", "capped at", "fixture
  order") and the PR description. Fixes silently make them false.
- **A comment moved into `docs/` loses the item it sat on.** Next to one function, "reads them with
  `ScanOptions::extended`" or "also allows the candidates" was clear; in a reference page it reads as true of every
  entry point, ID width and PID. Name the function (`scan_with`, not `scan`), the case (11-bit vs 29-bit, known vs
  unknown PID) and every exception the code makes (PRs #157, #158, Codex).
- **A data change makes the docs' sample output false.** Filling in the A7 profile's VAG addresses changed what the
  sim scan prints, but `docs/usage.md` still showed the old counts and `not in profile` lines. When a profile or
  fixture changes, grep `docs/` for the numbers and lines the sim prints, and compare the example with a real run
  (#211, gate).
- **A dropped check leaves its prose claim behind.** A pitfall still said `--baud` requires `--serial` after the
  `requires` went (#219). A scanning page claimed "every length is checked" although the address table's length was
  never checked (#209). A script header said only a blocker query could fail the script, though a failed `git fetch`
  does too (#205). When a change adds, drops or relaxes a check, a `requires` or a limit, grep `docs/`, `README.md` and
  the comments for the old wording, and check each claim against the code.
- **A message names one cause for a flag several causes set.** `Sweep::out_of_step` is set by a timed-out read and by a
  `10 03` that got no plain refusal, but the sweep note said "a request timed out", so the second case was reported
  as a timeout (#203, gate). When a message names a cause, grep for every place that sets the flag it
  reports, and name the cause in terms that cover all of them.

## Tests

- **A test that never ends gets the container OOM-killed** (1 GB cap) rather than failing cleanly. Run termination
  tests under `timeout`, and treat `SIGKILL` as "it hangs".
- **A build that runs out of memory looks like a slow one.** Under the host's 1 GB default container cap, a
  parallel rustc build on 24 cores was SIGKILLed crate by crate and ran for over 5 minutes before failing (#126).
  `scripts/cargo.sh` sets its own limit; look for `signal: 9` in the output before calling a run hung.
- **`timeout` around `scripts/cargo.sh` stops only the Docker client.** The container goes on running the hung test.
  Kill it with `docker kill` (find it with `docker ps --filter ancestor=rust:1-slim`).
- **A second guard hides the first.** `GsUsb::send` refuses in listen-only mode, and so does the port under it, so
  deleting either check left every test green. Assert something only the outer guard prevents (here, that the refused
  send never read from the device), and mutate each guard away to see a test fail (#246).
- **Termination needs an adversarial transport**: one that repeats forever, sends pending forever, or sleeps through
  each wait. `Mock` returns `Timeout` as soon as it's empty, so it can't show a hang, and a test that expects
  `Timeout` from it passes whether or not the limit works. Count what the transport handed out, and check that
  breaking the code makes the test fail.
- **Use values the standard leaves free for "unknown" cases.** A test that a PID the decoder doesn't know takes any
  length used PID 0x10, which J1979 defines as 2 bytes; use a reserved PID.
- **Inject faults where the real device would produce them.** Once the driver checked the echo, tests that injected a
  reset message ahead of the echo still passed, but on the echo check instead of the reset check they were for
  (M3 branch).
- **A rule change can make old tests' scenarios illegal.** When you tighten behaviour, re-read the existing tests
  that exercise it. PR #9: dropping late replies made a P2* test's ECU go pending too late to count.
- **Timing tests need margins and repeat runs.** Leave tens of milliseconds between events that must fall on either
  side of a deadline, and run the test several times before trusting it.
- **A scripted delay measured from the request races the test thread.** The fake adapter's TP2.0 frames were due
  5 ms after the request, so a test thread descheduled before its next `recv` found them already lost (7 of 50 runs
  under load, #297). Count the delay from the event the test is about (`FakeElm::delay_from_monitor`: the adapter
  starts monitoring), and run the test 50 times under 24 busy loops before trusting a short gap.
- **A fake that only counts the failure case makes an ordering assertion vacuous.** The `gs_usb` fake's `overlapped`
  counter rose only after a frame it had been told never to confirm, so `assert_eq!(overlapped, 0)` after a successful
  transfer passed even with the wait for the confirmation deleted, and the SocketCAN session test asserted only the
  final counter. Make the fake see the thing itself (a write made while an earlier confirmation was still unread),
  mutate the wait away to watch the test fail, and add a test that the fake counts it (#42).
- **A wall-clock bound on a shared runner needs the fastest of many, not every one.** A runner can stall a thread for
  tens of milliseconds at any moment, so "this gap took under 5 ms" fails at random, and `elapsed() < 1ms` on a no-op
  did. Assert the hard bound (never short) on every measurement and the budget on the minimum of dozens, and keep the
  test out of the required `check` job (`#[ignore]`, run by its own job). Put a sleep where the code should spin to
  see the test fail (#42).
- **A CI job that runs tests by name filter passes when the filter matches nothing.** `cargo test` reports
  `0 passed` as success, so a renamed test or module turns the job into a no-op. List what the filters match, fail
  below a floor, and require the run's `N passed; 0 failed; 0 ignored` to equal the list (`ci.yml`, `timing-windows`, #42).
- **No dev-dependency cycles across the `Transport` trait.** `obdcracker-transport` tests can't use `obdcracker-sim`:
  a cycle builds two copies of the trait. Put integration tests in the downstream crate.
- **A fake service accepts any path, so check each path form against the real one.** `update`'s fake HTTP answered
  `commits/tags/v0.1.0` because the test wrote it, while GitHub refuses that form with 422 for a tag. Each kind of ref
  (a tag, a branch, a commit) can take a different path form, so call the real API once per form before pinning it,
  and pin the exact URL in a test (`refs/tags/` and `refs/heads/` in `update.rs`, #295).

## Tooling and process

- **Gate commit and push on the checks.** Chain them with `&&`, never `;`, or a failing test still gets committed and
  pushed (PR #9, `00fdbc3`).
- **Install scripts: check what the build will actually use.** PR #45's first draft took `command -v cc` as a working
  toolchain (gcc without libc6-dev can't link), resolved a relative `--dir` after changing into the source tree, and
  looked for the binary in `CARGO_HOME` while Cargo's `install.root` can send it elsewhere. Test the capability (link
  a program), make paths absolute before any `cd`, pin outputs (`--root`), and validate an option only where it's used.
  The second round found more of the same class: MSVC without a Windows SDK can't link, a packaged rustup can keep
  `cargo` off PATH, and a bad `-Source` was only caught after a multi-GB install. Check every component the build
  needs, validate all input before any system-wide change, and pass user paths to PowerShell with `-LiteralPath`
  (`[` and `]` are wildcards to `-Path`). And don't trust whichever `cargo` is first on PATH: a system one ignores
  `rust-toolchain.toml`. Nor rustup's own pick: `RUSTUP_TOOLCHAIN` and `rustup override` beat the file, and `RUSTC`
  swaps the compiler. Read the channel from the file and build with `rustup run <channel>`. Every inherited path
  (`CARGO_HOME`, `RUSTUP_HOME`) needs making absolute, like `--dir`. And "installed" isn't "usable": probe HTTPS
  (curl can lack a CA bundle) and link a program on macOS too (stale Command Line Tools after an OS upgrade).
  Sweep all of a script's inputs, including its environment, in one pass; this took four review rounds piecemeal.
- **A bare ref can be a tag, a branch and a commit prefix.** A bare `commits/<name>` lookup leaves the
  choice to GitHub, so the install scripts could build a branch's commit for a name the user meant as a tag. Look a bare name up as
  `refs/tags/` and `refs/heads/` and refuse when both exist. Fall through to the next form only on HTTP 404 or 422
  ("no such ref"): a 500 or a rate limit that fell through could build a different ref than the one asked for.
  Test with a fake API, in both `install.sh` and `install.ps1` (#296).
- **`pkill -f <pattern>` matches the shell running it** when the pattern is in its own command line. Save the PID
  when starting a background process and kill that.
- **clap skips `requires` when the required argument conflicts with one that's present.** `--baud` once required
  `--serial`, but with `--tcp` given (same group as `--serial`) clap accepted it silently. Add `conflicts_with` too,
  and test every combination. (`--baud` has since dropped the `requires`: without `--serial`, the adapter found
  automatically takes it.) `--listen-only` and `--bitrate` (which require `--gsusb`) did the same with `--tcp`
  until they got `conflicts_with_all` too (#246). They now require the group `can` (`--gsusb` or `--socketcan`). A new
  adapter flag goes into every other flag's conflict list too: `--baud` still allowed `--socketcan` until a test
  of every combination said so (#108).
- **Keep commit subjects under 72 characters.** Check before committing: once a commit is pushed, fixing its subject
  means rewriting shared history.
- **Run clippy before committing.** Pedantic lints that caught us: `manual_is_multiple_of`, `assert!(x.is_empty())`,
  `cloned_ref_to_slice_refs`, and `format!` collected into a `String` (use `write!`).
- **PR gate and blockers.** `scripts/pr-gate.sh` only knows about blockers through GitHub's "blocked by" links, not
  `status:blocked` labels or comments. When you mark an issue blocked, add the link too, or a PR fixing it passes
  while its blocker is still open; when a plan drops a blocker, remove its link, or every PR fixing the issue fails.
  The gate's drift list catches both.
- **An issue number alone doesn't name an issue.** Links, references and API results can point into another
  repository, where `#42` is a different issue. Compare the repository too before treating two issues as the same
  (PR #176, Codex: a claude-ship blocker numbered like a fixed OBDCracker issue was exempted).
- **Codex threads re-anchor.** After a push, old resolved threads show up again at new line numbers. Pick new
  findings by comment ID or unresolved state, not by commit.
- **A required check must always report.** Branch protection waits for the literal check names, so a job-level `if:`
  or a dynamic matrix that drops a leg leaves the PR waiting forever. To skip work, keep the matrix and run the
  steps conditionally (`ci.yml`, #207).
- **A skipped required check passes.** A job whose `needs` job failed is skipped, not failed, and branch protection
  counts a skipped required check as passing. A job that decides whether to skip must run on `!cancelled()` and skip
  only when the deciding job's `result` is `success`, so a failed decider runs everything (`ci.yml`, #222).
- **A CI skip list must include every file the build pulls in.** `include_str!` and `#[doc = include_str!]` read files
  outside `crates/` (`README.md` and `docs/library.md` become `obdcracker` doctests), so a path regex that skips
  "docs" lets a doc edit break the doctests unseen. When a skip list changes, grep the crates for `include_str!`,
  `include_bytes!` and `include!` and check each target is on it. Tool configs (`clippy.toml`, `rustfmt.toml`) change the checks' results, so they count
  too (`ci.yml`, #222).
- **`git diff --name-only` C-quotes a name with non-ASCII or special characters.** `"crates/x/\303\251.txt"` has a
  leading `"` and a trailing `"`, so an anchored filter (`^crates/`, `\.rs$`) misses it and a CI skip goes green
  falsely. Read names with `-z` and match with `grep -z`. `core.quotepath=off` isn't enough: it still quotes tabs,
  newlines, quotes and backslashes (`ci.yml`, #237). Scripts count too: `scripts/pr-gate.sh` matched quoted names
  against issue bodies until #250. A name can also hold a newline, so don't turn the NUL list into newlines before
  matching or counting: a `docs/a\nb.md` becomes two files (#250).
- **`git diff --name-only` hides a rename's source.** Moving `README.md` to `docs/x.md` lists only the destination, so a
  path filter sees a docs file while the build lost an input. Pass `--no-renames` wherever changed paths decide what
  runs (`ci.yml`, #222).
- **`grep -q` in a `pipefail` pipeline can fail on a match.** `grep -q` exits at the first hit, `echo` then dies of
  SIGPIPE, and `set -o pipefail` reports the pipeline failed, so a large list reads as "no match". Feed it with a
  here-string (`grep -Eq ... <<< "$files"`) instead (`ci.yml`, #222).
