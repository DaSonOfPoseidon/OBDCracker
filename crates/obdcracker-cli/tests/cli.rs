//! The `obdcracker` binary end to end: dry runs, the simulated car, an ELM adapter over TCP, and
//! the audit log.

#[path = "../../obdcracker-transport/tests/support/fake_elm.rs"]
mod fake_elm;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use fake_elm::FakeElm;

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
fn refuses_to_run_without_an_adapter() {
    let log = temp_log("live");
    let out = obdcracker(&["--audit-log", log.to_str().unwrap(), "vin"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    for flag in ["--serial", "--tcp", "--dry-run", "--sim"] {
        assert!(stderr.contains(flag), "{stderr}");
    }
    assert!(!log.exists());
}

#[test]
fn sim_vin_prints_every_ecu_and_audits_each_frame() {
    let log = temp_log("sim");
    let out = obdcracker(&["--sim", "a7", "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "7E8 WAUZZZ4G1EN000000\n7E9 WAUZZZ4G1EN000000\n"
    );

    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 3, "{audit}");
    assert!(lines[0].contains(r#""dir":"tx","id":"7DF","payload":"09 02","link":"sim""#));
    assert!(lines[1].contains(r#""dir":"rx","id":"7E8""#));
    assert!(lines[2].contains(r#""dir":"rx","id":"7E9""#));
}

#[test]
fn unknown_sim_profile_is_refused() {
    let log = temp_log("sim-unknown");
    let out = obdcracker(&[
        "--sim",
        "delorean",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("a7"));
    assert!(!log.exists());
}

#[test]
fn sim_and_dry_run_are_exclusive() {
    let out = obdcracker(&["--sim", "a7", "--dry-run", "vin"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot be used with"));
}

#[test]
fn adapter_choices_are_exclusive() {
    for args in [
        &["--serial", "/dev/null", "--tcp", "127.0.0.1:1", "vin"][..],
        &["--serial", "/dev/null", "--sim", "a7", "vin"],
        &["--serial", "/dev/null", "--dry-run", "vin"],
        &["--tcp", "127.0.0.1:1", "--sim", "a7", "vin"],
        &["--tcp", "127.0.0.1:1", "--dry-run", "vin"],
    ] {
        let out = obdcracker(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
            "{args:?}"
        );
    }
}

#[test]
fn baud_needs_a_serial_port() {
    let out = obdcracker(&["--baud", "38400", "vin"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--serial"));
    for other in [
        &["--tcp", "127.0.0.1:1"][..],
        &["--sim", "a7"],
        &["--dry-run"],
    ] {
        let out = obdcracker(&[other, &["--baud", "38400", "vin"]].concat());
        assert!(!out.status.success(), "{other:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
            "{other:?}"
        );
    }
}

#[test]
fn ports_lists_serial_ports_without_an_adapter() {
    let out = obdcracker(&["ports"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_missing_serial_port_is_an_error() {
    let log = temp_log("serial-missing");
    let out = obdcracker(&[
        "--serial",
        "/dev/obdcracker-no-such-port",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("obdcracker-no-such-port"));
    assert!(!log.exists());
}

// A fake ELM327 on the A7's engine and transmission, served over TCP like a Wi-Fi adapter.
fn wifi_adapter() -> SocketAddr {
    const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut elm = FakeElm::new(Box::new(|header, request| {
            if header == 0x7DF && request == [0x09, 0x02] {
                vec![(0x7E8, VIN.to_vec()), (0x7E9, VIN.to_vec())]
            } else {
                Vec::new()
            }
        }));
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

#[test]
fn tcp_vin_reads_through_an_elm_adapter_and_warns_about_wireless() {
    let log = temp_log("tcp");
    let addr = wifi_adapter().to_string();
    let out = obdcracker(&["--tcp", &addr, "--audit-log", log.to_str().unwrap(), "vin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "7E8 WAUZZZ4G1EN000000\n7E9 WAUZZZ4G1EN000000\n"
    );
    assert!(
        stderr.contains("battery") && stderr.contains("in range"),
        "{stderr}"
    );

    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 3, "{audit}");
    assert!(lines[0].contains(r#""dir":"tx","id":"7DF","payload":"09 02","link":"tcp""#));
    assert!(lines[1].contains(r#""dir":"rx","id":"7E8""#) && lines[1].contains(r#""link":"tcp""#));
}

#[test]
fn adapter_prints_what_the_adapter_is_and_sends_nothing_on_the_bus() {
    let log = temp_log("tcp-adapter");
    let addr = wifi_adapter().to_string();
    let out = obdcracker(&[
        "--tcp",
        &addr,
        "--audit-log",
        log.to_str().unwrap(),
        "adapter",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(fake_elm::BANNER) && stdout.contains("12.6V"),
        "{stdout}"
    );
    assert!(!log.exists());
}

#[test]
fn adapter_needs_a_real_adapter() {
    let out = obdcracker(&["--sim", "a7", "adapter"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--serial"));
}
