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
  once CI is green, including the Windows and macOS builds.

## Found a problem? File an issue and keep going

When you find a problem outside the task you're working on (a bug, out-of-date docs, a design gap, a flaky test), file
it as a GitHub issue right away, then carry on with your task. Search the open issues first so you don't file a
duplicate. Include:

- what's wrong and where (`file:line`)
- how to reproduce it, or why it matters
- what you expected and what actually happens
- a suggested fix
- the milestone it blocks, if any

Label it `bug`, `documentation` or `enhancement`. Only fix it in the same change if it blocks your task, and then
reference it in the commit (`fixes #N`).

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
- **Never commit** car dumps, tune files, maps or unreviewed audit logs (`.gitignore` covers the usual names), or
  secrets of any kind.

## Checks

```sh
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features
```

New capabilities are written test-first. See the safety model in `README.md` before adding anything that sends a request.
