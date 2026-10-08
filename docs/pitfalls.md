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
- **Validate against the real decoder.** Data the tool will decode must pass the decoder that reads it: VIN characters,
  mode 01 PID widths, text DIDs. Round-trip through `obdcracker-core` rather than re-implementing the rule.
- **Respect the wire format's limits.** A count stored in a `u8` (mode 03, mode 09) or a `u16` (UDS DTC count) caps
  the list. Reject the input; don't saturate with `unwrap_or(MAX)`, which makes two replies contradict each other.
- **Standard data has a format whether or not a profile lists it.** F190 must be a VIN, and
  F187/F188/F189/F191/F197/F19E must be text (ISO 14229-1). Skipping validation because there's no `DidDef` let
  `hex = "FF"` pass as a VIN, and letting a `DidDef` replace the check let `F190 text = "abc"` through. A profile
  can't declare a standard DID in another format either (`standard_decode`).
- **Cross-check related sources.** Fixture vs profile: every DID is standard or in the profile, values match the
  profile's `decode`, and OBD-II data only sits on OBD-II ID pairs (0x7E0..=0x7E7 → +8).
- **Public fields bypass the parser.** Anything with `pub` fields can be built or edited by hand, so consumers must
  re-validate (`Profile::validate`), or the type must make invalid values impossible.
- **Empty, blank and padding-only values** are input too: names, text DIDs, CALIDs. `"   "` is not empty but
  decodes as `""`, and so does `hex = "20 20"` for a text DID. Codes that are padding or wildcards aren't codes:
  P0000 in mode 03, and 0x000000 and 0xFFFFFF ("all groups") in UDS.
- **Names are keys.** If lookups are exact, reject names with surrounding spaces rather than trimming them in one
  place only, and treat names that differ only in case as duplicates.
- **Don't over-restrict.** Know the protocol before rejecting something: Toyota body modules legitimately share
  CAN ID 0x750 with different extended-address bytes.

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
- **Deadlines must shrink back** once the reason to extend them is gone (P2 again after the pending ECU answers).
- **Match a reply to its request by what it echoes**, not only the service ID: the PID (mode 09), a requested PID
  (mode 01), a requested DID (0x22) or the subfunction. A late reply to an earlier request has the same SID
  (`response::answers`).
- **The suppress-positive-response bit (bit 7) is not echoed.** It applies to every UDS service with a subfunction,
  0x19 included. A request with the bit set gets no positive reply, so only a refusal answers it; masking the bit
  off instead lets a late positive reply to an earlier, unsuppressed request through. A refusal is still sent when
  the bit is set, and **after response-pending (0x78) the final positive reply is sent even with the bit set**
  (ISO 14229-1), so it answers the request then (`response::answers_after_pending`). Check claims about the
  standard against a source before writing them down; this entry first said 0x19 had no such bit, then missed the
  0x78 exception (PR #9, PR #11).
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
- **Datasheet examples aren't byte-exact.** Real ELM327s print a space after every byte, the last one included; the
  datasheet's typeset examples don't show it. Test parsers against an implementation you didn't write
  (ELM327-emulator), not only against fakes built from the same reading of the datasheet (M3 branch, #13).
- **Don't confuse a transport limit with a protocol limit.** 4095 bytes is ISO-TP's short first-frame length, not a
  UDS maximum; the 32-bit escape carries more.

## Links and adapters

- **Every read and write on a link needs a bound, not just the bus waits.** A peer that stops reading blocks a write
  forever once buffers fill (set a write timeout), and some calls ignore that timeout altogether: serial2's `flush`
  waits for the OS queue to drain with no limit. Check each I/O call's docs for what its timeout covers (M3 branch,
  Codex).
- **Bound what you collect, not just each piece.** Each line was capped at `MAX_LINE`, but a command's answer
  collected lines until its deadline, so an adapter streaming `A\r` could exhaust memory in two seconds. Cap the count
  too, and check every loop that accumulates (M3 branch, Codex).
- **Timeouts must cover the link, not only the bus.** At 9600 baud a 4095-byte reply takes about 18 s just to print,
  so a P2 sized for the ECU timed out mid-reply. When one timer gets the allowance, give it to every timer that can
  wait for the same data: P2, P2* and the wait for a request to finish were fixed in three rounds instead of one
  (M3 branch, Codex).
- **Don't hand back stale data to make a log complete.** Replies drained before the next request aren't returned:
  queueing them would let a late reply to a repeated request pass for a fresh one. Document what the audit log
  records instead (M3 branch, Codex).
- **Pin external test tools exactly, and check the pin installs from scratch.** PyPI's ELM327-emulator 4.0.0 sdist
  reports `4.0.0.post57`, which uv refuses; it only worked locally from a cached build. CI installs a pinned git
  commit (M3 branch).
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
