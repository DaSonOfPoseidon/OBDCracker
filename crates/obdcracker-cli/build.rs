//! Records the commit a build came from, for `--version`.

#[path = "build/commit.rs"]
mod commit;

fn main() {
    // The installers pass the commit in. Never ask git: a build from crates.io has no repository.
    println!("cargo:rerun-if-env-changed=OBDCRACKER_COMMIT");
    let raw = std::env::var("OBDCRACKER_COMMIT").ok();
    println!(
        "cargo:rustc-env=OBDCRACKER_BUILD_COMMIT={}",
        commit::build_commit(raw.as_deref())
    );
}
