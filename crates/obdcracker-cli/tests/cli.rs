//! The `obdcracker` binary end to end: dry runs, the audit log, and refusing live runs.

use std::path::PathBuf;
use std::process::{Command, Output};

fn obdcracker(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .args(args)
        .output()
        .unwrap()
}

fn temp_log(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("obdcracker-{}-{name}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn dry_run_prints_the_frame_and_audits_it() {
    let log = temp_log("vin");
    let out = obdcracker(&["--dry-run", "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("7DF 02 09 02"));

    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains(r#""dir":"tx","id":"7DF","payload":"09 02","link":"dry-run""#),
        "{}",
        lines[0]
    );
}

#[test]
fn audit_log_is_appended_not_replaced() {
    let log = temp_log("append");
    for _ in 0..2 {
        obdcracker(&["--dry-run", "--audit-log", log.to_str().unwrap(), "vin"]);
    }
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
}

#[test]
fn refuses_to_run_without_dry_run_until_a_backend_exists() {
    let log = temp_log("live");
    let out = obdcracker(&["--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--dry-run"));
    assert!(!log.exists());
}
