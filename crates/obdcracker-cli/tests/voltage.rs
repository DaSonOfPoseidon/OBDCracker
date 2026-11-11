//! The battery-voltage guard end to end: a reading before every command that talks to the car, a
//! refusal of long commands when it is too low, and a stop partway through when it drops.

#[path = "../../obdcracker-transport/tests/support/fake_elm.rs"]
mod fake_elm;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use fake_elm::FakeElm;

fn obdcracker(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .env("OBDCRACKER_TEST_PORTS", "")
        .args(args)
        .output()
        .unwrap()
}

fn temp_log(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "obdcracker-voltage-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// The sim's engine, swept over `range`, with the audit log at `log`.
fn sweep(log: &Path, sim: &[&str], flags: &[&str], range: &str) -> Output {
    let mut args = vec!["--sim", "a7", "--audit-log", log.to_str().unwrap()];
    args.extend(sim);
    args.extend(flags);
    args.extend(["sweep", "--module", "engine", "--range", range]);
    obdcracker(&args)
}

fn requests(log: &Path) -> usize {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|line| line.contains(r#""dir":"tx""#))
        .count()
}

#[test]
fn a_healthy_battery_is_logged_and_says_nothing() {
    let log = temp_log("healthy");
    let out = obdcracker(&["--sim", "a7", "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("voltage"), "{}", stderr(&out));
    let audit = std::fs::read_to_string(&log).unwrap();
    let first = audit.lines().next().unwrap();
    assert!(
        first.contains(r#""dir":"voltage","millivolts":12600"#),
        "{audit}"
    );
}

#[test]
fn a_low_battery_warns_and_the_command_goes_on() {
    let log = temp_log("low");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--sim-voltage",
        "12.0",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("warning: the supply voltage is 12 V, below 12.2 V"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("WAU2MBFC"), "{}", stdout(&out));
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(audit.contains(r#""millivolts":12000"#), "{audit}");
}

#[test]
fn exactly_12_2_volts_is_fine_and_exactly_11_8_is_only_a_warning() {
    let out = obdcracker(&["--sim", "a7", "--sim-voltage", "12.2", "vin"]);
    assert!(out.status.success());
    assert!(!stderr(&out).contains("voltage"), "{}", stderr(&out));
    let log = temp_log("eleven-eight");
    let out = sweep(&log, &["--sim-voltage", "11.8"], &[], "0600-0700");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("below 12.2 V"), "{}", stderr(&out));
    assert_eq!(requests(&log), 257);
}

#[test]
fn a_short_command_only_warns_below_11_8_volts() {
    let log = temp_log("short");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--sim-voltage",
        "11.5",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("below 11.8 V; this command is short"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_long_sweep_is_refused_below_11_8_volts_with_nothing_sent() {
    let log = temp_log("refused");
    let out = sweep(&log, &["--sim-voltage", "11.799"], &[], "0600-0700");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("refused: the supply voltage is 11.799 V, below 11.8 V"),
        "{err}"
    );
    assert!(err.contains("a sweep of 257 DIDs"), "{err}");
    assert!(err.contains("--force-low-voltage"), "{err}");
    assert_eq!(requests(&log), 0);
    // The reading that refused it is on record.
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(audit.contains(r#""millivolts":11799"#), "{audit}");
}

#[test]
fn a_sweep_of_exactly_256_dids_is_not_long() {
    let log = temp_log("exactly-256");
    let out = sweep(&log, &["--sim-voltage", "11.5"], &[], "0600-06FF");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(requests(&log), 256);
}

#[test]
fn forcing_goes_on_with_a_warning_and_never_stops_partway() {
    let log = temp_log("forced");
    let out = sweep(
        &log,
        &["--sim-voltage", "11.5"],
        &["--force-low-voltage"],
        "0600-0700",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("going on because of --force-low-voltage"),
        "{}",
        stderr(&out)
    );
    assert_eq!(requests(&log), 257);

    // A drop mid-run doesn't stop it either, and the voltage is still on record.
    let log = temp_log("forced-drop");
    let out = sweep(
        &log,
        &["--sim-voltage-drop", "60:11.0"],
        &["--force-low-voltage"],
        "0600-0700",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(requests(&log), 257);
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(audit.contains(r#""dir":"voltage""#), "{audit}");
}

#[test]
fn a_battery_that_drops_stops_a_long_sweep_at_the_next_check_and_says_where_to_go_on() {
    let log = temp_log("drop");
    let out = sweep(&log, &["--sim-voltage-drop", "60:11.0"], &[], "0600-0700");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    // Checked every 50 requests: at 50 it was 12.6 V, at 100 it is 11 V.
    assert!(
        err.contains("stopped at 0664: the supply voltage fell to 11 V after 100 requests"),
        "{err}"
    );
    assert!(
        err.contains("to go on:") && err.contains("0664-0700"),
        "{err}"
    );
    assert_eq!(requests(&log), 100);
    assert!(stdout(&out).contains("sweep: "), "{}", stdout(&out));
}

#[test]
fn a_battery_that_drops_stops_wide_discovery_after_what_it_found() {
    let log = temp_log("wide");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--sim-voltage-drop",
        "20:11.0",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
        "--wide",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("stopped: the supply voltage fell to 11 V after 50 requests"),
        "{}",
        stderr(&out)
    );
    assert_eq!(requests(&log), 50);
}

#[test]
fn wide_discovery_is_refused_when_the_battery_is_too_low() {
    let log = temp_log("wide-refused");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--sim-voltage",
        "11.5",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
        "--wide",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("scan --discover --wide"),
        "{}",
        stderr(&out)
    );
    assert_eq!(requests(&log), 0);
    // Plain discovery is shorter, and only warns.
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--sim-voltage",
        "11.5",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_dry_run_reads_no_voltage() {
    let log = temp_log("dry");
    let out = obdcracker(&["--dry-run", "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("voltage"), "{}", stderr(&out));
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(!audit.contains("voltage"), "{audit}");
}

// A fake ELM327 served over TCP.
fn wifi(mut elm: FakeElm) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut buf = [0; 256];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => elm.write(&buf[..n]),
                Err(_) => {}
            }
            let out = elm.read(usize::MAX);
            if !out.is_empty() && stream.write_all(&out).is_err() {
                return;
            }
        }
    });
    addr
}

fn adapter_reading(lines: &[&str]) -> SocketAddr {
    let mut elm = FakeElm::new(Box::new(|header, request| match (header, request) {
        (0x7DF, [0x01, 0x00]) => vec![(0x7E8, vec![0x41, 0x00, 0x00, 0x00, 0x00, 0x00])],
        (0x7E0, [0x09, 0x02]) => vec![(0x7E8, b"\x49\x02\x01WAUZZZ4G1EN000000".to_vec())],
        _ => Vec::new(),
    }));
    elm.voltage = lines.iter().map(|&line| line.to_owned()).collect();
    wifi(elm)
}

#[test]
fn an_elm_adapter_is_asked_with_atrv_and_the_log_has_the_command_and_the_reading() {
    let log = temp_log("elm");
    let addr = adapter_reading(&["12.4V"]).to_string();
    let out = obdcracker(&["--tcp", &addr, "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let audit = std::fs::read_to_string(&log).unwrap();
    let command = audit
        .lines()
        .position(|l| l.contains(r#""cmd":"ATRV","answer":"12.4V""#))
        .unwrap_or_else(|| panic!("{audit}"));
    let reading = audit
        .lines()
        .position(|l| l.contains(r#""dir":"voltage","millivolts":12400"#))
        .unwrap_or_else(|| panic!("{audit}"));
    // Both before the first request.
    let first_request = audit
        .lines()
        .position(|l| l.contains(r#""dir":"tx""#))
        .unwrap();
    assert!(command < reading && reading < first_request, "{audit}");
}

#[test]
fn an_elm_adapter_at_a_low_voltage_refuses_a_long_sweep_before_sending_any_request() {
    let log = temp_log("elm-low");
    let addr = adapter_reading(&["11.2V"]).to_string();
    let out = obdcracker(&[
        "--tcp",
        &addr,
        "--profile",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "sweep",
        "--module",
        "engine",
        "--range",
        "0600-0700",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("refused: the supply voltage is 11.2 V"),
        "{}",
        stderr(&out)
    );
    assert_eq!(requests(&log), 0);
}

#[test]
fn an_adapter_that_doesnt_report_a_voltage_gets_a_note_and_the_command_goes_on() {
    let log = temp_log("elm-unknown");
    let addr = adapter_reading(&["?"]).to_string();
    let out = obdcracker(&["--tcp", &addr, "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("this adapter doesn't report its supply voltage"),
        "{}",
        stderr(&out)
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(
        audit.contains(r#""dir":"voltage","millivolts":null"#),
        "{audit}"
    );
}

#[test]
fn the_adapter_command_still_only_shows_the_voltage() {
    let addr = adapter_reading(&["12.4V"]).to_string();
    let out = obdcracker(&["--tcp", &addr, "adapter"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("voltage: 12.4V"), "{}", stdout(&out));
}
