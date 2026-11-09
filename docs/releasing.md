# Releasing

A release is a GitHub release for a tag `vX.Y.Z`. It holds the source and generated notes, no binaries: users build
it with the [install script](install.md) (`--ref vX.Y.Z`), and `obdcracker --version` then shows the tag's commit.

1. **Bump the version in a PR.** Change `version` under `[workspace.package]` in `Cargo.toml` to `X.Y.Z`, and let
   Cargo update `Cargo.lock` to match (`scripts/cargo.sh build`), since the installers build with `--locked`. Merge
   the PR once CI is green.
2. **Tag the commit the PR became on `main`.** `<sha>` is that commit (`origin/main` if nothing has merged since):

   ```sh
   git fetch origin main
   git tag vX.Y.Z <sha>
   git push origin vX.Y.Z
   ```

3. **Check the run.** Pushing the tag starts the `Release` workflow (`.github/workflows/release.yml`), which publishes
   the release with `gh release create --generate-notes`. See it with `gh run list --workflow release.yml`.

The workflow fails, and publishes nothing, unless

- the tag is exactly `v` plus the workspace version in `Cargo.toml` at the tagged commit, and the version is plain
  `X.Y.Z` (no pre-release suffix), and
- the tagged commit is on `main`.

If it fails, delete the tag (`git push origin :refs/tags/vX.Y.Z`, then `git tag -d vX.Y.Z`), fix the cause and tag
again. A release that was already published is edited or deleted on GitHub (`gh release delete vX.Y.Z --cleanup-tag`).
