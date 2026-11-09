//! The rule `build.rs` applies to `OBDCRACKER_COMMIT`, which decides what `--version` says.

#[path = "../build/commit.rs"]
mod commit;

use commit::{UNKNOWN, build_commit};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn keeps_exactly_forty_lowercase_hex_characters() {
    assert_eq!(build_commit(Some(SHA)), SHA);
    assert_eq!(build_commit(Some(&"0".repeat(40))), "0".repeat(40));
}

#[test]
fn unset_or_empty_is_unknown() {
    assert_eq!(build_commit(None), UNKNOWN);
    assert_eq!(build_commit(Some("")), UNKNOWN);
}

#[test]
fn a_wrong_length_is_unknown() {
    assert_eq!(build_commit(Some(&SHA[..39])), UNKNOWN);
    assert_eq!(build_commit(Some(&format!("{SHA}0"))), UNKNOWN);
    // A SHA-256 object name is not what the installers resolve
    assert_eq!(build_commit(Some(&SHA.repeat(2)[..64])), UNKNOWN);
}

#[test]
fn uppercase_hex_is_unknown() {
    assert_eq!(build_commit(Some(&SHA.to_uppercase())), UNKNOWN);
    assert_eq!(
        build_commit(Some("0123456789abcdef0123456789abcdef0123456A")),
        UNKNOWN
    );
}

#[test]
fn anything_else_around_the_sha_is_unknown() {
    for bad in [
        format!("{SHA}-dirty"),
        format!("{SHA}\n"),
        format!(" {SHA}"),
        format!("{}g", &SHA[..39]),
        format!("{}+", &SHA[..39]),
        // 40 bytes, but not 40 characters of hex
        format!("{}é", &SHA[..38]),
        "main".to_owned(),
    ] {
        assert_eq!(build_commit(Some(&bad)), UNKNOWN, "{bad:?}");
    }
}
