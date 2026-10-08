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
- **Cross-check related sources.** Fixture vs profile: every DID is standard or in the profile, values match the
  profile's `decode`, and OBD-II data only sits on OBD-II ID pairs (0x7E0..=0x7E7 → +8).
- **Public fields bypass the parser.** Anything with `pub` fields can be built or edited by hand, so consumers must
  re-validate (`Profile::validate`), or the type must make invalid values impossible.
- **Empty and blank names** are input too.
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
- **Keep timers per source.** Each pending ECU gets its own P2*. One global "latest deadline" lets a late ECU in.
- **Deadlines must shrink back** once the reason to extend them is gone (P2 again after the pending ECU answers).
- **Match a reply to its request by what it echoes**, not only the service ID: the PID (mode 09), a requested PID
  (mode 01), a requested DID (0x22) or the subfunction. A late reply to an earlier request has the same SID
  (`response::answers`).
- **The suppress-positive-response bit (bit 7) is not echoed** for 0x10 and 0x3E. 0x19 has no such bit, so compare its
  subfunction exactly.
- **Don't confuse a transport limit with a protocol limit.** 4095 bytes is ISO-TP's short first-frame length, not a
  UDS maximum; the 32-bit escape carries more.

## Docs vs code

- **After every fix, re-read the doc comments on what changed** ("returns every reply", "capped at", "fixture
  order") and the PR description. Fixes silently make them false.

## Tests

- **A test that never ends gets the container OOM-killed** (1 GB cap) rather than failing cleanly. Run termination
  tests under `timeout`, and treat `SIGKILL` as "it hangs".
- **Termination needs an adversarial transport**: one that repeats forever, sends pending forever, or sleeps through
  each wait. `Mock` returns `Timeout` as soon as it's empty, so it can't show a hang.
- **No dev-dependency cycles across the `Transport` trait.** `obdcracker-transport` tests can't use `obdcracker-sim`:
  a cycle builds two copies of the trait. Put integration tests in the downstream crate.

## Tooling and process

- **Run clippy before committing.** Pedantic lints that caught us: `manual_is_multiple_of`, `assert!(x.is_empty())`,
  `cloned_ref_to_slice_refs`, and `format!` collected into a `String` (use `write!`).
- **PR gate and milestones.** Any open issue tagged with the PR's milestone blocks it, whatever the area. Fold that
  milestone's issues into the PR, or land them first.
- **Codex threads re-anchor.** After a push, old resolved threads show up again at new line numbers. Pick new
  findings by comment ID or unresolved state, not by commit.
