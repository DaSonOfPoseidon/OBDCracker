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
  once CI is green, including the Windows and macOS builds. PRs are squash-merged, the only merge method the repo
  allows, so each PR becomes one commit on `main`.

## Found a problem? File an issue and keep going

When you find a problem outside the task you're working on (a bug, out-of-date docs, a design gap, a flaky test), file
it as a GitHub issue right away, then carry on with your task. Search the open issues first so you don't file a
duplicate. Include:

- what's wrong and where (`file:line`)
- how to reproduce it, or why it matters
- what you expected and what actually happens
- a suggested fix
- the milestone it blocks, if any

Label it `bug`, `documentation` or `enhancement`, and tag what it impacts:

- **Every area it affects:** `area:core`, `area:safety`, `area:transport`, `area:sim`, `area:cli`, `area:facade`
  (the `obdcracker` crate), `area:docs` (any `*.md` or `docs/`), `area:ci` (workflows, `scripts/`, Cargo and tool
  config).
- **The milestone it blocks,** if any: `milestone:M1` to `milestone:M7`.

Only fix it in the same change if it blocks your task, and then reference it in the commit (`fixes #N`).

## Before opening a pull request

No open issue may block it. An issue blocks a PR when either:

- it's tagged with an area the PR touches, and its milestone is the PR's milestone, an earlier one, or none; or
- it's tagged with the PR's milestone, whatever its area.

Issues for later milestones wait until then. Run:

```sh
scripts/pr-gate.sh M2   # the PR's milestone; leave it out if none
```

It works out the areas from the files changed since `origin/main`, lists the blocking issues, and fails if there are
any. Fix or close them first. An issue a commit on the branch fixes (`fixes #N` in the subject) doesn't count, since it
closes when the PR merges.

## Reviews

Codex reviews every push to a pull request, and each review costs time and usage. So review your
own change just as hard before pushing, and push fixes in batches rather than one at a time. Check
each change against:

- **Untrusted input:** every length, count and echoed ID is checked exactly. Reject trailing bytes,
  zero counts, empty or padding-only values, and anything the standard doesn't allow.
- **Docs vs code:** every promise in a doc comment holds on every path, including errors and edge
  values such as 0, the maximum and one past it.
- **Conversions:** nothing rounds the unsafe way or loses a remainder before rounding.
- **State:** after any error, nothing stale can complete or leak into the next operation.
- **Scripts and CI:** every path, rename, word boundary and concurrent run behaves as described.
  Lint workflow changes with actionlint (see Checks); GitHub silently refuses an invalid workflow.
- **Your own fixes:** re-read the new code for the same problems; it's where new findings hide.

Before a PR can be approved:

- Answer every finding. Either fix it (with a test first, in its own commit) and reply on the thread with the commit,
  or reply explaining why it doesn't apply. A real problem outside the PR's scope becomes a tagged issue instead.
- Push, then wait for Codex to review the new head commit. Repeat until a review of the head commit has no new
  findings.
- CI must be green on the head commit, and `scripts/pr-gate.sh` must still pass.

Branch protection enforces the Codex part with the `codex-review` status
(`scripts/codex-status.sh`, run by `.github/workflows/codex-review.yml`). It passes only once Codex
has completed a review of the head commit, finishing after that commit was pushed, and every Codex
thread is resolved. So resolve each
thread once its finding is fixed, or answered with why it doesn't apply. Resolving doesn't
trigger workflows, so then re-run the check with `gh workflow run codex-review.yml -f pr=<pr>`.
Check it locally with `DRY_RUN=1 scripts/codex-status.sh <pr>`.

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

New capabilities are written test-first. See the safety model in `README.md` before adding anything that sends a request.
