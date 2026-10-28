# Contributing

## How we work

- **Library first.** OBDCracker is a library that other projects import through the `obdcracker` crate. The CLI is
  one consumer of it. Anything an importer would need (backends, the audit log, dry runs, decoders) goes in the
  library crates, not in the CLI. Keep the `obdcracker` crate's doc example compiling, since it's the "how to use it"
  guide.
- **Test first, in this order:** golden-frame unit tests (from the standard or a captured frame), then property tests
  of the parsers, then the simulator (`obdcracker-sim`), then a `--dry-run` on a car, then a live session with the
  audit log on. Write the failing test before the code.
- **ECU replies are untrusted input.** Every parser returns an error on bad bytes and never panics. A property test
  that feeds it arbitrary bytes shows this.
- **Changes land through pull requests.** Nobody pushes to `main` directly. Work on a branch, open a PR, and merge only
  once CI is green, including the Windows and macOS builds (a PR that touches no Rust, Cargo, toolchain, deny or
  install-script file skips the macOS work and still reports those checks). PRs are squash-merged, the only merge method the repo
  allows, so each PR becomes one commit on `main`.
- **Comments are for what the code can't say.** Reference material goes in `docs/`, not in code files. See
  [Comments](#comments).

## Comments

- **Plain `//` comments:** only for a reason that isn't obvious from the code, a safety reason (why a request,
  command or byte is or isn't sent), a spec or datasheet citation a value depends on, or code in another file that
  must change with this. Never restate what the next line does.
- **`///` on public items:** the contract: what it does, what it returns or refuses, its errors, limits and units.
  Background, adapter quirks and derivations go in a page under `docs/`, linked with a `See docs/<page>.md` line.
- **`//!` module docs:** a few lines on what the module is for, and a link to its page under `docs/`.
- **Tests:** the test name says what is checked, and helper and fixture names say what the setup is. Comment only a
  reason that isn't obvious, or which third-party test a case comes from.
- **Said twice:** a note repeated at several call sites becomes one helper or constant, commented once.

If what you'd write doesn't fit an existing page in `docs/`, start a new one and add it to
[`docs/README.md`](README.md).

## Found a problem? File an issue and keep going

When you find a problem outside the task you're working on (a bug, out-of-date docs, a design gap, a flaky test), file
it as a GitHub issue right away, then carry on with your task. Search the open issues first so you don't file a
duplicate. Include:

- what's wrong and where (`file:line`)
- how to reproduce it, or why it matters
- what you expected and what actually happens
- a suggested fix
- the feature it belongs to, if you know

Label it `bug`, `documentation` or `enhancement`, and tag what it impacts:

- **Every area it affects:** `area:core`, `area:safety`, `area:transport`, `area:sim`, `area:profile`, `area:cli`, `area:facade`
  (the `obdcracker` crate), `area:docs` (any `*.md` or `docs/`), `area:ci` (workflows, `scripts/`, Cargo and tool
  config).
- **Its milestone** (a GitHub milestone, not a label): the feature it belongs to, such as `M7 · TP2.0 & scan-tool
  reads`. Milestones are numbered in the order they'll be worked on. If you're not sure where it falls, leave it
  without a milestone; the maintainer sorts those.
- **Its status:** `status:ready` if it can be picked up now, `status:blocked` if it waits on something else
  (another issue, a car session, hardware or a decision), or `status:queued` if it waits only for an earlier
  milestone to close. Milestones are worked in order, so an issue in a later milestone than the earliest open one
  is queued unless the maintainer has pulled it forward. See [Blocked issues](#blocked-issues).

Only fix it in the same change if it blocks your task, and then reference it in the commit (`fixes #N`).

### Blocked issues

What blocks an issue is recorded twice: the `status:blocked` label, and a GitHub "blocked by" link to each blocking
issue. `scripts/pr-gate.sh` reads only the links, so keep both in step whenever the issue list changes:

- **Filing a blocked issue, or marking one blocked:** add `status:blocked`, comment naming what blocks it, and link
  each blocking issue, from the issue's sidebar or with
  `gh api -X POST repos/DaSonOfPoseidon/OBDCracker/issues/<blocked>/dependencies/blocked_by -F issue_id=<id>`
  (the blocker's id is `gh api repos/DaSonOfPoseidon/OBDCracker/issues/<blocker> --jq .id`).
- **Blocked by something that isn't an issue yet:** if it's work someone will do, such as a car session, file it as
  an issue (like #169) and link that. A pure outside wait (hardware arriving, the maintainer's decision) stays
  unlinked, and the gate lists it until it's resolved.
- **No longer blocked, but the blocker is still open** (a plan changed, or the issue was re-scoped): remove the
  link (`gh api -X DELETE repos/DaSonOfPoseidon/OBDCracker/issues/<blocked>/dependencies/blocked_by/<id>`), say why
  in a comment, and move the issue to `status:ready` if nothing else blocks it. A stale link fails every PR that
  fixes the issue.
- **Closing an issue:** list what it blocked
  (`gh api repos/DaSonOfPoseidon/OBDCracker/issues/<n>/dependencies/blocking --jq '.[].number'`) and move each
  to `status:ready` unless it has another open blocker. A link to a closed issue stays but no longer blocks.
- **Closing a milestone:** move the next milestone's `status:queued` issues to `status:ready`, or to
  `status:blocked` if an open blocker is linked. `status:queued` needs no links, and `scripts/pr-gate.sh` doesn't
  check it.
- **Reviewing the issue list:** run `scripts/pr-gate.sh`. Its last list shows open issues whose label and links
  disagree: `status:blocked` with no open blocker linked, or an open blocker linked without `status:blocked`. Fix
  each one on the issue.

## Before opening a pull request

An issue the PR fixes (`fixes #N` in a commit subject) mustn't be blocked by an open issue (GitHub's "blocked by"
link) that the PR doesn't fix too, whatever the blocker's labels. A blocker in another repository always counts,
since this PR can't close it. Run:

```sh
scripts/pr-gate.sh M2   # the PR's milestone; leave it out to use the branch's open PR's, if any
```

It fails on any such blocker: fix it in the same PR, or land it first. It also lists, without failing, the open
issues not marked `status:blocked` that cite a file the PR changes and are in the PR's milestone or an earlier one
(any milestone when the PR has none; issues without a milestone aren't listed). Fold those in when they're small and
related; keep the PR to one feature. Give the PR the milestone of the feature it's part of. Last, it lists
open issues whose `status:blocked` label and "blocked by" links disagree (see [Blocked issues](#blocked-issues)).
If either list can't be fetched, the script warns on stderr and still reports the blockers.

## Reviews

Codex reviews a pull request only when asked, with an `@codex review` comment, and each review costs time
and usage. Both Codex and the maintainer's pre-push review use the rules and P0–P3 scale in
[`AGENTS.md`](../AGENTS.md); how each finding is handled is under
[Handling review findings](#handling-review-findings). So review your own change just as hard before asking,
and push fixes in batches rather than one at a time. Read
[`docs/pitfalls.md`](pitfalls.md) before making a change: it lists the classes of bug reviews have
caught here. Add a new entry when a review finds a new class. Check each change against:

- **Untrusted input:** every length, count and echoed ID is checked exactly. Reject trailing bytes,
  zero counts, empty or padding-only values, and anything the standard doesn't allow.
- **Docs vs code:** every promise in a doc comment holds on every path, including errors and edge
  values such as 0, the maximum and one past it.
- **Conversions:** nothing rounds the unsafe way or loses a remainder before rounding.
- **State:** after any error, nothing stale can complete or leak into the next operation.
- **Scripts and CI:** every path, rename, word boundary and concurrent run behaves as described.
  Lint workflow changes with actionlint (see Checks); GitHub silently refuses an invalid workflow.
- **Your own fixes:** re-read the new code for the same problems; it's where new findings hide.

### Handling review findings

Every finding gets one outcome, and its thread is resolved once it has one:

- **Fix:** with a test first, in its own commit. Reply on the thread with the commit.
- **Doesn't apply:** reply explaining why, with evidence.
- **Defer:** file an issue in the milestone of the feature it belongs to, or with none if that isn't clear. Reply
  with the link.
- **Out of scope:** a real problem outside the PR becomes a tagged issue, as in
  [Found a problem?](#found-a-problem-file-an-issue-and-keep-going). Reply with the link.

Which outcome a valid finding in the PR's scope gets depends on its priority and on which review found it:

| Finding | Reviews 1–2 | Review 3, and any later review |
|---|---|---|
| P0 or P1 | Fix | The maintainer picks fix or defer (a P0 is always fixed) |
| P2 | Fix | Defer |
| P3 | Defer | Defer |

Push all the fixes at once, then ask for the next review with `@codex review`. There's no review after the
third unless the maintainer asks for one, which they do when they have a P0 or P1 fixed in the PR, since
`codex-review` needs a review of the new head.

A PR is ready for approval when Codex has reviewed its head commit, every Codex thread is resolved, CI is green on
the head commit, and `scripts/pr-gate.sh` passes. Branch protection enforces the Codex part with the
`codex-review` status (the `DaSonOfPoseidon/claude-ship@v1` action, run by `.github/workflows/codex-review.yml`):
it passes only once Codex has completed a review of the head commit, finishing after that commit was pushed, and
no Codex thread is unresolved. Resolving a thread doesn't trigger workflows, so after resolving, re-run the check
with `gh workflow run codex-review.yml -f pr=<pr>`, then see the result with `gh pr checks <pr>`.

## Commits

- **One logical step per commit.** A new test and the code that makes it pass go together; an unrelated cleanup goes
  in its own commit. Keep commits small enough to review in one sitting.
- **Every commit passes the checks below**, so any commit can be checked out, bisected or reverted on its own.
- **Subject:** one line in [Conventional Commits](https://www.conventionalcommits.org/) form, `type: summary`.
  - Types: `feat` (new capability), `fix` (bug fix), `test` (tests only), `refactor` (no behaviour change), `docs`,
    `ci`, `chore` (tooling, dependencies, housekeeping).
  - The summary is imperative and lower case, with no trailing period, and says what the commit does, not how:
    `feat: decode OBD-II mode 09 CVN`, not `feat: Added CVN parsing.`
  - Keep it under 72 characters. No scope in parentheses.
- **No body and no trailers.** If a change needs explaining, put the explanation in code comments, docs or the issue.
  Don't add `Co-Authored-By`, `Signed-off-by` or tool/session trailers.
- **Reference issues** at the end of the subject: `fix: escape the link name in audit log lines (fixes #2)`.
- **The PR title is the commit on `main`.** A squash merge uses the PR title as its subject and leaves the body empty,
  so the title follows the same rules: `feat: add ISO-TP, OBD-II and UDS codecs (M1)`. Put closing keywords
  (`Fixes #1`) in the PR description too. GitHub closes those issues when the PR merges.
- **Never commit** car dumps, tune files, maps or unreviewed audit logs (`.gitignore` covers the usual names), or
  secrets of any kind.

## Checks

```sh
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features
cargo build -p obdcracker-core --target thumbv7em-none-eabihf  # obdcracker-core must stay no_std
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.7  # when workflows change
```

New capabilities are written test-first. See the [safety model](safety.md) before adding anything that sends a request.
