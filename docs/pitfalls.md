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
- **Respect the wire format's limits.** A count stored in a `u8` (mode 03, mode 09) or a `u16` (UDS DTC count) caps
  the list. Reject the input; don't saturate with `unwrap_or(MAX)`, which makes two replies contradict each other.
- **Standard data has a format whether or not a profile lists it.** F190 must be a VIN, and
  F187/F188/F189/F191/F197/F19E must be text (ISO 14229-1). Skipping validation because there's no `DidDef` let
  `hex = "FF"` pass as a VIN, and letting a `DidDef` replace the check let `F190 text = "abc"` through. A profile
  can't declare a standard DID in another format either (`standard_decode`). The rule cuts both ways: a standard
  DID with *no* fixed format (F18B's BCD date) must take the profile's format, and every reader of a text DID must
  apply the same check as the others. Scan forced F18B to text and read F190 with the plain text decoder, so a
  printable date showed as a string and `62 F1 90 61 62 63` as the VIN `abc` (#50, #51). Keep the list in one place
  (`uds::did::is_text`, `obd::check_vin`).
- **Cross-check related sources.** Fixture vs profile: every DID is standard or in the profile, values match the
  profile's `decode`, and OBD-II data only sits on OBD-II ID pairs (0x7E0..=0x7E7 → +8).
- **Check data against the real replies, not against another hand-made file.** The instruments' F19E got the
  reply's length (24, with `62 F1 9E`) instead of the data's (21), in both the profile and the fixture. The cross-check
  between them passed, because both were wrong the same way, and the car's correct reply then read as malformed
  (#62). Keep the car's replies as test data (`crates/obdcracker-profile/tests/data/a7-did-replies.txt`) and
  check every value derived from them against it.
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
- **Quote for a shell with an allowlist, not a denylist.** The sweep's resume command refused Windows words with
  `$ % ! "` and double-quoted the rest, but PowerShell also reads typographic quotes (`“`, `’`) as quotes, so a
  crafted path could still end the quoting. Write a word only if every character is known plain; otherwise print
  no command at all (PR #76).
- **Don't over-restrict.** Know the protocol before rejecting something: Toyota body modules legitimately share
  CAN ID 0x750 with different extended-address bytes.

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
  transport that never stops sending proves it (PR #9: an ECU repeating its VIN reply hung `exchange` forever).
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
  failure was logged twice (#83). Track whether anything happened since.
- **"Busy, repeat request" (NRC 0x21) isn't an answer.** Recording it as the DID's value and moving on misses the
  DID and keeps a busy module busy. Stop or wait, then ask again.
- **A refusal doesn't say which request it refuses.** UDS `7F 22 31` names the service, not the DID, so after a read
  times out its late refusal can arrive as the next read's answer. Asking again doesn't fix it: the retry takes the
  first answer, and the duplicate's answer is left queued for the read after. Once replies may be out of step, they
  stay so for the rest of the connection, even past answers that plainly match: stop at the next one that can't be
  matched, and resume on a fresh connection from there.
- **Match a reply to its request by what it echoes**, not only the service ID: the PID (mode 09), a requested PID
  (mode 01), a requested DID (0x22) or the subfunction. A late reply to an earlier request has the same SID
  (`response::answers`).
- **A deadline on the far side of the bus needs a margin for the trip, and the earliest safe time.** The guard
  checked S3 against its own clock, so a `3E 00` sent just in time could reach the module after its session
  lapsed. The module answered it in the default session anyway, so nothing showed. The next fix timed S3 from
  the answer's arrival, but an ELM can take 18 s to print a long answer the module sent at once. When you can't
  see when the other side acted, take the earliest moment it could have (the request), and stop trusting the
  deadline early enough for the next message to get there. Pick the failure that costs least: a needless `10 03`,
  not a read sent into the default session (#68, three Codex rounds).
- **Use the limits the other side declares.** A module's `50 03` gives its own P2 and P2*; ignoring them timed
  out a module that said it needs 100 ms. Extend the caller's timing by the excess over the standard defaults,
  so an adapter's allowance stays on top (#68, Codex).
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
  (`elm::codec::LineSplitter`), not at each place that prints it (M3 branch, security review).
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
- **Don't ask for an answer that looks like a failure.** `ATI` answers with the same banner a reset prints, so a
  reset during `info` looked like an answer. Take such values once, when they can't be confused (the reset banner),
  and treat them as failures everywhere else (M3 branch, Codex).
- **A truncated answer must not pass as a complete one.** Accepting any well-formed subset of `AT PPS` let a cut-off
  summary skip the parameters that mattered. Require every entry you check (M3 branch, Codex).
- **Output the driver could never have caused is evidence its assumptions broke.** `STOPPED` when the driver never
  interrupts, or a frame from an ID the receive filter excludes, means something else wrote to the adapter or it lost
  a setting. Stop, don't ignore it as noise (M3 branch, Codex).
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
- **Don't confuse a transport limit with a protocol limit.** 4095 bytes is ISO-TP's short first-frame length, not a
  UDS maximum; the 32-bit escape carries more.

## Links and adapters

- **An audit log that sees only what the code reads misses the evidence.** The ELM driver dropped reply lines nobody
  read before the next request, and adapter commands never reached the log, so a late reply or a changed setting left
  no trace. Log what the adapter did, not just what the caller used.
- **An adapter's learned timeout can hide a slow module.** The ELM327's adaptive timing (`AT AT1`) shortens its wait
  to fit the modules that answered fast, so a module that wakes slowly reads as absent. Before acting on "nothing is
  there", as discovery's wide pass does, look again with the adapter's longest wait.
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

## Docs vs code

- **After every fix, re-read the doc comments on what changed** ("returns every reply", "capped at", "fixture
  order") and the PR description. Fixes silently make them false.

## Tests

- **A test that never ends gets the container OOM-killed** (1 GB cap) rather than failing cleanly. Run termination
  tests under `timeout`, and treat `SIGKILL` as "it hangs".
- **`timeout` around `scripts/cargo.sh` stops only the Docker client.** The container goes on running the hung test.
  Kill it with `docker kill` (find it with `docker ps --filter ancestor=rust:1-slim`).
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
- **No dev-dependency cycles across the `Transport` trait.** `obdcracker-transport` tests can't use `obdcracker-sim`:
  a cycle builds two copies of the trait. Put integration tests in the downstream crate.

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
- **`pkill -f <pattern>` matches the shell running it** when the pattern is in its own command line. Save the PID
  when starting a background process and kill that.
- **clap skips `requires` when the required argument conflicts with one that's present.** `--baud` requires
  `--serial`, but with `--tcp` given (same group as `--serial`) clap accepted it silently. Add `conflicts_with` too,
  and test every combination.
- **Keep commit subjects under 72 characters.** Check before committing: once a commit is pushed, fixing its subject
  means rewriting shared history.
- **Run clippy before committing.** Pedantic lints that caught us: `manual_is_multiple_of`, `assert!(x.is_empty())`,
  `cloned_ref_to_slice_refs`, and `format!` collected into a `String` (use `write!`).
- **PR gate and milestones.** Any open issue tagged with the PR's milestone blocks it, whatever the area. Fold that
  milestone's issues into the PR, or land them first.
- **Codex threads re-anchor.** After a push, old resolved threads show up again at new line numbers. Pick new
  findings by comment ID or unresolved state, not by commit.
