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
    wifi_adapter_answering(|header, request| {
        if header == 0x7DF && request == [0x09, 0x02] {
            vec![(0x7E8, VIN.to_vec()), (0x7E9, VIN.to_vec())]
        } else {
            Vec::new()
        }
    })
}

// A fake ELM327 served over TCP, whose bus answers each request with `answer`.
fn wifi_adapter_answering(
    answer: impl FnMut(u32, &[u8]) -> Vec<(u32, Vec<u8>)> + Send + 'static,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut elm = FakeElm::new(Box::new(answer));
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

const FINGERPRINT_FRAMES: [&str; 12] = [
    "7DF 02 09 04",
    "7DF 02 09 06",
    "7E0 03 22 F1 87",
    "7E0 03 22 F1 88",
    "7E0 03 22 F1 89",
    "7E0 03 22 F1 91",
    "7E0 03 22 F1 9E",
    "7E1 03 22 F1 87",
    "7E1 03 22 F1 88",
    "7E1 03 22 F1 89",
    "7E1 03 22 F1 91",
    "7E1 03 22 F1 9E",
];

#[test]
fn dry_run_fingerprint_lists_every_frame_in_order() {
    for profile in [None, Some("a7")] {
        let log = temp_log("fingerprint-dry");
        let mut args = vec!["--dry-run", "--audit-log", log.to_str().unwrap()];
        args.extend(profile.map(|p| ["--profile", p]).into_iter().flatten());
        args.push("fingerprint");
        let out = obdcracker(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut expected = FINGERPRINT_FRAMES.join("\n");
        expected.push_str("\ndry run: nothing was sent\n");
        assert_eq!(stdout, expected, "{profile:?}");
        let audit = std::fs::read_to_string(&log).unwrap();
        assert_eq!(audit.lines().count(), 12, "{audit}");
        assert!(
            audit.lines().all(|line| line.contains(r#""dir":"tx""#)),
            "{audit}"
        );
    }
}

#[test]
fn sim_fingerprint_shows_values_and_refusals() {
    let log = temp_log("fingerprint-sim");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "fingerprint",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in [
        "7E8 CALID 4G0401N 0016BVAB, (empty), 0000000000000000, NOX00907807 0015, PMS00906261 4010",
        "7E8 CVN   9BF7470D, 00000000, 00000000, 38D3FF82, 0E1FC39E",
        "7E9 CALID 4G0158Q 100821  ",
        "7E8 engine F187 4G0907401A",
        "7E8 engine F19E EV_ECM30TDI0114G0907401A",
        "7E9 transmission F189 1100",
        "7E9 transmission F19E (service 0x22 refused: request out of range (0x31))",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "{line:?} missing from:\n{stdout}"
        );
    }
}

#[test]
fn unknown_profile_is_refused() {
    let out = obdcracker(&["--dry-run", "--profile", "delorean", "fingerprint"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("a7"));
}

#[test]
fn tcp_fingerprint_reads_a_multi_frame_part_number() {
    let addr = wifi_adapter_answering(|header, request| match (header, request) {
        (0x7DF, [0x09, 0x04]) => {
            let mut reply = b"\x49\x04\x014G0907401A  0010".to_vec();
            reply.resize(19, 0);
            vec![(0x7E8, reply)]
        }
        (0x7E0, [0x22, 0xF1, 0x87]) => vec![(0x7E8, b"\x62\xF1\x874G0907401A ".to_vec())],
        _ => Vec::new(),
    });
    let log = temp_log("fingerprint-tcp");
    let out = obdcracker(&[
        "--tcp",
        &addr.to_string(),
        "--audit-log",
        log.to_str().unwrap(),
        "fingerprint",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("7E8 CALID 4G0907401A  0010\n7E8 CVN   (no reply)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("7E8 engine F187 4G0907401A\n"), "{stdout}");
    assert!(
        stdout.contains("7E9 transmission F187 (no reply)\n"),
        "{stdout}"
    );
}

#[test]
fn fingerprint_fails_when_nothing_answers() {
    let addr = wifi_adapter_answering(|_, _| Vec::new());
    let log = temp_log("fingerprint-silent");
    let out = obdcracker(&[
        "--tcp",
        &addr.to_string(),
        "--audit-log",
        log.to_str().unwrap(),
        "fingerprint",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nothing answered"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
