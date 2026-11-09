// Shared by build.rs and tests/build_commit.rs, which includes it by path: a build script has no
// tests of its own.

/// What `--version` shows when the build wasn't told its commit.
pub const UNKNOWN: &str = "unknown";

/// The commit to record: `raw` when it is exactly 40 lowercase hex characters, else [`UNKNOWN`].
/// Anything looser (a `-dirty` suffix, a short or upper-case SHA) would put a string in
/// `--version` that no `git` command can resolve.
pub fn build_commit(raw: Option<&str>) -> &str {
    match raw {
        Some(sha)
            if sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            sha
        }
        _ => UNKNOWN,
    }
}
