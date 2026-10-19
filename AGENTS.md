# AGENTS.md

Instructions for AI agents (Codex, Claude) working on OBDCracker, a Rust tool that talks to a car's OBD2
diagnostic bus. Contributor standards are in [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## Code Review Rules

Codex's PR review and the pre-push review gate both follow this section. Rate every finding on this scale:

- **P0**: anything that could send an unapproved request to a car, or a change that breaks the main path
  for everyone. Never merge.
- **P1**: wrong behaviour on a real path, a hole in the safety model, ECU data that can be misparsed, or a
  doc that would lead a user to do something unsafe to a car.
- **P2**: an edge case that breaks (0, max, max+1, empty, trailing bytes, error paths), a doc or comment
  promise the code doesn't keep, a test that can pass while the code is wrong, or CI/script behaviour that
  differs from its description.
- **P3**: a minor issue a strict reviewer might still flag.

How each finding is handled (fixed, deferred to an issue, or decided by the maintainer) depends on its
priority and on which review found it: see `docs/CONTRIBUTING.md` › Handling review findings.

Every finding needs a concrete failure scenario (input or state → wrong result). Don't flag style, naming,
or anything CI already checks (rustfmt, clippy, tests, cargo-deny).

### Project invariants

- Nothing sent may brick the car. Every request goes through `obdcracker-safety`: `Policy::approve` →
  `Approved`, which can't be built anywhere else. Transports take only `&Approved`. No send path may skip
  it, and there is no raw-frame escape hatch.
- A new service goes into `classify` in `crates/obdcracker-safety/src/lib.rs` and into the independent
  coverage for its tier in `crates/obdcracker-safety/tests/policy.rs`: the `READ_SERVICES` or
  `FLASH_SERVICES` list, or the clear-DTC/coding table in `locks_clear_dtc_and_coding_in_read_only`. Only
  T0 Read is unlocked; T3 Flash is banned.
- Vehicle profiles can only narrow the policy, never widen it.
- `obdcracker-core` stays `no_std` and IO-free.
- All public items have docs (`missing_docs`); the facade doctest must keep working.
- The audit log logs requests before sending.
- ECU replies are untrusted input: every length, count and echoed ID is checked exactly.
- No emissions-control delete/defeat features; no tune files, maps or dumps in the repo.
- Commit subjects and PR titles: one-line Conventional Commits, lower-case imperative, under 72 chars, no
  scope, no body or trailers.

### Known pitfalls

Classes of bug past reviews caught here are in [`docs/pitfalls.md`](docs/pitfalls.md); check every change
against them.
