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

// No serial ports are found unless a test lists some, so a test never reaches a real adapter.
fn obdcracker(args: &[&str]) -> Output {
    obdcracker_with_ports("", args)
}

fn obdcracker_with_ports(ports: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .env("OBDCRACKER_TEST_PORTS", ports)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn version_names_the_build_commit() {
    let out = obdcracker(&["--version"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text.strip_suffix('\n').unwrap();
    let rest = line.strip_prefix("obdcracker ").unwrap();
    let (version, commit) = rest.split_once(" (commit ").unwrap();
    let commit = commit.strip_suffix(')').unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    let numbers: Vec<&str> = version.split('.').collect();
    assert!(numbers.len() == 3 && numbers.iter().all(|n| n.parse::<u32>().is_ok()));
    assert!(
        commit == "unknown"
            || (commit.len() == 40
                && commit
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))),
        "{commit}"
    );
    // What the environment holds when it runs is not what the binary was built with
    let out = Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .env("OBDCRACKER_COMMIT", "f".repeat(40))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap(), text);
}

// Port names the host OS's adapter rule keeps.
fn usb_ports(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|n| {
            if cfg!(windows) {
                format!("COM{n}")
            } else if cfg!(target_os = "macos") {
                format!("/dev/cu.usbserial-{n}")
            } else {
                format!("/dev/ttyUSB{n}")
            }
        })
        .collect()
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
    for flag in [
        "--serial",
        "--tcp",
        "--gsusb",
        "--socketcan",
        "--dry-run",
        "--sim",
    ] {
        assert!(stderr.contains(flag), "{stderr}");
    }
    assert!(!log.exists());
}

#[test]
fn sim_vin_prints_each_answer_and_audits_each_frame() {
    // Only the A7's engine answers mode 09 PID 02; its transmission stays silent (#46).
    let log = temp_log("sim");
    let out = obdcracker(&["--sim", "a7", "--audit-log", log.to_str().unwrap(), "vin"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "7E8 WAU2MBFC6EN093415\n"
    );

    let audit = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = audit.lines().collect();
    assert_eq!(lines.len(), 2, "{audit}");
    assert!(lines[0].contains(r#""dir":"tx","id":"7DF","payload":"09 02","link":"sim""#));
    assert!(lines[1].contains(r#""dir":"rx","id":"7E8""#));
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
fn gsusb_options_need_gsusb_and_exclude_the_other_adapters() {
    for args in [
        &["--listen-only", "vin"][..],
        &["--bitrate", "500000", "vin"],
        &["--gsusb", "--tcp", "127.0.0.1:1", "vin"],
        &["--gsusb", "--sim", "a7", "vin"],
        &["--gsusb", "--dry-run", "vin"],
        &["--gsusb", "--baud", "38400", "vin"],
        &["--gsusb", "--bitrate", "125000", "vin"],
    ] {
        let out = obdcracker(args);
        assert!(!out.status.success(), "{args:?}");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn a_gsusb_bitrate_that_contradicts_the_profile_is_refused_before_any_usb() {
    let log = temp_log("gsusb-bitrate");
    let out = obdcracker(&[
        "--gsusb",
        "--profile",
        "a7",
        "--bitrate",
        "250000",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("contradicts"));
    assert!(!log.exists());
}

#[test]
fn adapter_is_for_elm_adapters_only() {
    for args in [
        &["--gsusb", "adapter"][..],
        &["--socketcan", "can0", "adapter"],
    ] {
        let out = obdcracker(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        // Elsewhere than Linux, --socketcan is refused before the command is looked at.
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("ELM327")
                || (args[0] == "--socketcan" && !cfg!(target_os = "linux")),
            "{args:?}"
        );
    }
}

#[test]
fn socketcan_options_need_an_interface_and_exclude_the_other_adapters() {
    for args in [
        &["--socketcan", "can0", "--tcp", "127.0.0.1:1", "vin"][..],
        &["--socketcan", "can0", "--gsusb", "vin"],
        &["--socketcan", "can0", "--sim", "a7", "vin"],
        &["--socketcan", "can0", "--dry-run", "vin"],
        &["--socketcan", "can0", "--baud", "38400", "vin"],
        &["--socketcan", "can0", "--bitrate", "125000", "vin"],
    ] {
        let out = obdcracker(args);
        assert!(!out.status.success(), "{args:?}");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

// With nothing after it, --socketcan has no interface. clap must name the missing value, not just
// exit 2: `--socketcan vin` takes `vin` as the interface and fails on the subcommand instead.
#[test]
fn socketcan_with_no_interface_names_the_missing_value() {
    let out = obdcracker(&["--socketcan"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("a value is required for '--socketcan <IFACE>'"),
        "{stderr}"
    );
}

// Elsewhere than Linux the option is refused before the bitrate is looked at.
#[cfg(target_os = "linux")]
#[test]
fn a_socketcan_bitrate_that_contradicts_the_profile_is_refused_before_the_interface_is_read() {
    let log = temp_log("socketcan-bitrate");
    let out = obdcracker(&[
        "--socketcan",
        "can0",
        "--profile",
        "a7",
        "--bitrate",
        "250000",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("contradicts"));
    assert!(!log.exists());
}

// Whatever interfaces the machine running the test has, one that does not exist opens nothing: the
// run stops before anything is sent.
#[cfg(target_os = "linux")]
#[test]
fn a_socketcan_interface_that_does_not_exist_stops_before_anything_is_sent() {
    let log = temp_log("socketcan-missing");
    let out = obdcracker(&[
        "--socketcan",
        "nosuchcan9",
        "--audit-log",
        log.to_str().unwrap(),
        "vin",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("using"), "{stderr}");
    assert!(stderr.contains("nosuchcan9"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_socketcan_interface_name_that_could_leave_its_directory_is_refused() {
    let log = temp_log("socketcan-path");
    for name in ["../../etc", "can0/..", "a:b", ".."] {
        let out = obdcracker(&[
            "--socketcan",
            name,
            "--audit-log",
            log.to_str().unwrap(),
            "vin",
        ]);
        assert_eq!(out.status.code(), Some(1), "{name}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("isn't a network interface name"),
            "{name}: {stderr}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn socketcan_says_it_is_for_linux_elsewhere() {
    let out = obdcracker(&["--socketcan", "can0", "vin"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Linux"));
}

// Whatever USB is plugged into the machine running the test, a serial number that no device has
// opens nothing: the run stops before anything is written to a device.
#[test]
fn a_gsusb_serial_that_matches_no_device_stops_before_anything_is_sent() {
    let out = obdcracker(&["--gsusb=no-such-serial-0", "--listen-only", "vin"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("using a gs_usb adapter"), "{stderr}");
    assert!(
        stderr.contains("gs_usb adapter") || stderr.contains("USB devices"),
        "{stderr}"
    );
}

#[test]
fn baud_alone_looks_for_the_adapter() {
    let out = obdcracker(&["--baud", "38400", "vin"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no adapter found"));
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

// Each of these stops before `update` looks anything up, so no test reaches GitHub.
#[test]
fn update_refuses_the_flags_that_pick_an_adapter_or_an_audit_log() {
    let log = temp_log("update-flags");
    for flags in [
        &["--serial", "/dev/obdcracker-no-such-port"][..],
        &["--tcp", "127.0.0.1:1"],
        &["--sim", "a7"],
        &["--profile", "a7"],
        &["--audit-log", log.to_str().unwrap()],
        &["--gsusb", "--listen-only"],
    ] {
        let out = obdcracker(&[flags, &["update"]].concat());
        assert_eq!(out.status.code(), Some(2), "{flags:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("`update` uses no adapter"),
            "{flags:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{flags:?}");
    }
    assert!(!log.exists());
}

#[test]
fn update_refuses_a_version_together_with_main_and_a_bad_version() {
    let out = obdcracker(&["update", "0.2.0", "--main"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot be used with"));
    let out = obdcracker(&["update", "latest"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("isn't a release version"));
}

#[test]
fn update_help_names_its_options() {
    let out = obdcracker(&["update", "--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for word in ["[VERSION]", "--main", "--allow-downgrade"] {
        assert!(text.contains(word), "{word}: {text}");
    }
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
    wifi_adapter_with_vins(|_| VIN.to_vec())
}

const VIN: &[u8] = b"\x49\x02\x01WAUZZZ4G1EN000000";

// A plain ELM327 is paced, so `vin` asks `01 00` first, then each ECU by its own request ID. ECU
// `n` (0 or 1) answers on 0x7E8 + n with `vin(n)`.
fn wifi_adapter_with_vins(vin: impl Fn(u32) -> Vec<u8> + Send + 'static) -> SocketAddr {
    wifi_adapter_answering(move |header, request| match (header, request) {
        (0x7DF, [0x01, 0x00]) => (0x7E8..=0x7E9)
            .map(|id| (id, vec![0x41, 0x00, 0x00, 0x00, 0x00, 0x00]))
            .collect(),
        (0x7E0..=0x7E1, [0x09, 0x02]) => vec![(header + 8, vin(header - 0x7E0))],
        _ => Vec::new(),
    })
}

// A fake ELM327 served over TCP, whose bus answers each request with `answer`.
fn wifi_adapter_answering(
    answer: impl FnMut(u32, &[u8]) -> Vec<(u32, Vec<u8>)> + Send + 'static,
) -> SocketAddr {
    wifi_elm(FakeElm::new(Box::new(answer)))
}

// `elm` served over TCP, as set up by the test.
fn wifi_elm(mut elm: FakeElm) -> SocketAddr {
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
    // The adapter's setup is logged too, before the request.
    let setup = audit
        .lines()
        .take_while(|l| l.contains(r#""dir":"cmd""#))
        .count();
    assert!(
        audit.lines().next().unwrap().contains(r#""cmd":"ATZ""#),
        "{audit}"
    );
    let lines: Vec<_> = audit
        .lines()
        .skip(setup)
        .filter(|l| !l.contains(r#""dir":"cmd""#))
        .collect();
    // `01 00` names the ECUs, then each is asked by its own request ID (#242).
    let shape: Vec<_> = lines
        .iter()
        .map(|l| {
            let dir = if l.contains(r#""dir":"tx""#) {
                "tx"
            } else {
                "rx"
            };
            let id = l
                .split(r#""id":""#)
                .nth(1)
                .and_then(|r| r.get(..3))
                .unwrap();
            format!("{dir} {id}")
        })
        .collect();
    assert_eq!(
        shape,
        [
            "tx 7DF", "rx 7E8", "rx 7E9", "tx 7E0", "rx 7E8", "tx 7E1", "rx 7E9"
        ],
        "{audit}"
    );
    assert!(lines[0].contains(r#""payload":"01 00","link":"tcp""#));
    assert!(lines[3].contains(r#""payload":"09 02","link":"tcp""#));
    assert!(lines[5].contains(r#""payload":"09 02","link":"tcp""#));
}

fn vin_over_tcp(vin: impl Fn(u32) -> Vec<u8> + Send + 'static) -> (Output, String) {
    let addr = wifi_adapter_with_vins(vin).to_string();
    let out = obdcracker(&["--tcp", &addr, "vin"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stderr)
}

#[test]
fn a_refusal_beside_a_good_vin_still_succeeds() {
    // An ECU with no VIN refuses a request of its own, where it stays silent for a broadcast.
    let (out, stderr) = vin_over_tcp(|n| {
        if n == 0 {
            VIN.to_vec()
        } else {
            vec![0x7F, 0x09, 0x31]
        }
    });
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "7E8 WAUZZZ4G1EN000000\n"
    );
    assert!(stderr.contains("7E9 service 0x09 refused"), "{stderr}");
}

#[test]
fn only_refusals_fail() {
    let (out, stderr) = vin_over_tcp(|_| vec![0x7F, 0x09, 0x31]);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(stderr.contains("7E8 service 0x09 refused"), "{stderr}");
}

#[test]
fn a_malformed_vin_beside_a_good_one_still_fails() {
    let (out, stderr) = vin_over_tcp(|n| {
        if n == 0 {
            VIN.to_vec()
        } else {
            b"\x49\x02\x01WAUZZZ4G1EN00000!".to_vec()
        }
    });
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "7E8 WAUZZZ4G1EN000000\n"
    );
    assert!(stderr.contains("7E9 reply is malformed"), "{stderr}");
}

#[test]
fn a_refusal_and_a_malformed_vin_fail_together() {
    let (out, stderr) = vin_over_tcp(|n| {
        if n == 0 {
            vec![0x7F, 0x09, 0x31]
        } else {
            b"\x49\x02\x01WAUZZZ4G1EN00000!".to_vec()
        }
    });
    assert_eq!(out.status.code(), Some(1), "{stderr}");
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

#[test]
fn adapter_without_a_flag_and_no_port_found_says_so() {
    let out = obdcracker(&["adapter"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no adapter found"));
}

#[test]
fn many_adapters_found_are_listed_and_none_is_used() {
    let log = temp_log("many");
    let ports = usb_ports(&["98", "99"]);
    let out = obdcracker_with_ports(
        &ports.join(";"),
        &["--audit-log", log.to_str().unwrap(), "vin"],
    );
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("found 2 adapters"), "{stderr}");
    for port in &ports {
        assert!(stderr.contains(port.as_str()), "{stderr}");
    }
    assert!(stderr.contains("--serial"), "{stderr}");
    assert!(!log.exists());
}

#[test]
fn the_one_adapter_found_is_opened_as_if_given_with_serial() {
    let log = temp_log("one");
    let ports = usb_ports(&["98"]);
    let out = obdcracker_with_ports(&ports[0], &["--audit-log", log.to_str().unwrap(), "vin"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let using = format!("using the adapter on {}", ports[0]);
    let cant_open = format!("can't open {}", ports[0]);
    let (a, b) = (stderr.find(&using), stderr.find(&cant_open));
    assert!(a.is_some() && b.is_some() && a < b, "{stderr}");
    assert!(!log.exists());
}

#[test]
#[cfg(not(windows))]
fn a_port_that_cannot_be_an_adapter_is_not_used() {
    let out = obdcracker_with_ports("/dev/ttyS0;/dev/cu.debug-console", &["vin"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no adapter found"));
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
        "7E8 engine F187 4G0907401N",
        "7E8 engine F188 (service 0x22 refused: request out of range (0x31))",
        "7E8 engine F19E EV_ECM30TDI0114G0907401N",
        "7E9 transmission F188 (service 0x22 refused: request out of range (0x31))",
        "7E9 transmission F189 1008",
        "7E9 transmission F191 0BK927156AM",
        "7E9 transmission F19E EV_TCMAL551211",
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

#[test]
fn sim_scan_reads_obd_data_and_every_profile_module() {
    let log = temp_log("scan");
    let out = obdcracker(&["--sim", "a7", "--audit-log", log.to_str().unwrap(), "scan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // What the car printed in #49, apart from mode 09 PID 0B, which the sim can't send.
    for line in [
        "7E8 PID 05 63 °C",
        "7E8 PID 0C 0 rpm",
        "7E8 PID 42 12 V",
        "7E8 PID 8F [03 00 FF FF 00 00 00]",
        "7E8 PID 10 2.36 g/s",
        "7E8 PID 30 237",
        "7E8 PID 3E 31 °C",
        "7E8 PID 5D 0 °",
        "7E8 PID 61 -9 %",
        "7E8 PID 63 580 Nm",
        "7E8 mode 09 PIDs 02, 04, 06, 0A",
        "7E8 ECU name ECM-EngineControl",
        "7E8 stored DTCs (none)",
        "7E9 PID 42 11.961 V",
        "7E9 ECU name TCM-TransmisCtrl",
        "7E9 stored DTCs (none)",
        "7E8 engine F197 3.0TDI FSA",
        "7E8 engine F1AA J623",
        "7E8 engine DTC count (service 0x19 refused: subfunction not supported (0x12))",
        // Every A7 DTC is untested, not a fault (#49, #52).
        "7E8 engine DTCs (no faults)",
        "7E9 transmission F191 0BK927156AM",
        "77A gateway F18B [00 00 00]",
        "77A gateway F190 (service 0x22 refused: request out of range (0x31))",
        "77A gateway F197 J533--Gateway",
        "77A gateway DTCs (no faults)",
        "77E instruments DTCs (no faults)",
        "77E instruments F18B [13 11 19]",
        "77E instruments F197 TDieUsaAccNv",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "{line:?} missing from:\n{stdout}"
        );
    }

    // Read services only, never a session change; 0600 reads in the default session, as on the car.
    let audit = std::fs::read_to_string(&log).unwrap();
    for line in audit.lines().filter(|l| l.contains(r#""dir":"tx""#)) {
        assert!(
            [
                r#""payload":"01 "#,
                r#""payload":"03""#,
                r#""payload":"09 "#,
                r#""payload":"22 "#,
                r#""payload":"19 "#
            ]
            .iter()
            .any(|prefix| line.contains(prefix)),
            "{line}"
        );
    }
    assert!(
        stdout
            .lines()
            .any(|l| l == "7E8 engine 0600 [1A 2A 40 12 05 66 01 05 00 00]"),
        "{stdout}"
    );
}

#[test]
fn dry_run_scan_sends_nothing() {
    let log = temp_log("scan-dry");
    let out = obdcracker(&["--dry-run", "--audit-log", log.to_str().unwrap(), "scan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry run: nothing was sent"), "{stdout}");
    // The PID reads depend on the car's answers, so the preview says they're missing.
    assert!(
        stdout.contains("a live scan also sends") && stdout.contains("01 <PID>"),
        "{stdout}"
    );
}

#[test]
fn sim_scan_discover_finds_the_modules_that_answer_then_scans_them() {
    let log = temp_log("discover");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The simulated A7 has the 22 modules discovery found on the car in #54, all in the profile.
    for line in [
        "77A found at 710 (profile: gateway), F187 4G0907468AD",
        "77E found at 714 (profile: instruments), F187 4G8920984A",
        "785 found at 71B (profile: head-up display), F187 4G8919604K",
        "7D3 found at 769 (profile: top view), F187 4H0907428B",
        "discovery: 22 of 106 request IDs answered",
        "77A gateway F197 J533--Gateway",
        // As the car sent them in #54, now that #62 and #63 are fixed.
        "77E instruments F19E EV_RBD4K",
        "785 head-up display F19E EV_HUDContiC7",
        "78D rear lid F190 (not set)",
        "791 night vision DTC 001017 failed, confirmed (status 09)",
        "78B sensor cluster DTC format 01, the module counts 0 for mask AF",
        // The car's quirks, as #54's car3.txt shows them.
        "77F airbag DTC count (reply is malformed: 59 01 00 00)",
        "791 night vision F190 (service 0x22 refused: conditions not correct (0x22))",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "{line:?} missing from:\n{stdout}"
        );
    }
    // One 22 F1 87 to each request ID 0x700..=0x769, in order, before the scan; never to a reply
    // ID.
    let audit = std::fs::read_to_string(&log).unwrap();
    let sent: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx""#))
        .collect();
    for (line, id) in sent.iter().zip(0x700..=0x769) {
        assert!(
            line.contains(&format!(r#""id":"{id:03X}","payload":"22 F1 87""#)),
            "{line}"
        );
    }
    for line in &sent {
        let id = line.split(r#""id":""#).nth(1).unwrap();
        let id = u32::from_str_radix(&id[..3], 16).unwrap();
        assert!(
            !(0x76A..=0x7D3).contains(&id) && !(0x7E8..=0x7EF).contains(&id),
            "{line}"
        );
    }
}

#[test]
fn sim_scan_discover_asks_listed_ids_again_patiently() {
    let log = temp_log("discover-patient");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
        "--patient-ids",
        "71D,755,710",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The gateway (710) answered the first pass, so only the other two are asked again.
    assert!(
        stdout.contains("patient recheck, waiting up to 5.0 s each: 0 of 2 request IDs answered"),
        "{stdout}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    let reads_of = |id: &str| {
        audit
            .lines()
            .filter(|l| l.contains(&format!(r#""dir":"tx","id":"{id}","payload":"22 F1 87""#)))
            .count()
    };
    assert_eq!(reads_of("71D"), 2, "{audit}");
    assert_eq!(reads_of("755"), 2, "{audit}");
    // Only the first pass's: it answered, so it isn't asked again (the scan batches its reads).
    assert_eq!(reads_of("710"), 1, "{audit}");
}

#[test]
fn sim_scan_discover_wide_doesnt_ask_a_patient_id_twice() {
    let log = temp_log("discover-patient-wide");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
        "--wide",
        "--patient-ids",
        "71D",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 71D answers on 787, a wide-pass request ID, so the recheck would otherwise ask it too.
    assert!(
        stdout.contains("recheck, waiting up to 5.0 s each: 0 of 20 request IDs answered"),
        "{stdout}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    let asked = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx","id":"71D","payload":"22 F1 87""#))
        .count();
    assert_eq!(asked, 2, "{audit}");
}

#[test]
fn scan_refuses_patient_ids_outside_the_discovery_range_or_malformed() {
    for ids in [
        "7E0", "6FF", "76A", "71", "071D", "+1D", "71G", "71D,71D", "71d,71D", "",
    ] {
        let out = obdcracker(&[
            "--dry-run",
            "--profile",
            "a7",
            "scan",
            "--discover",
            "--patient-ids",
            ids,
        ]);
        assert_eq!(out.status.code(), Some(2), "{ids:?}: {out:?}");
        assert!(out.stdout.is_empty(), "nothing sent: {out:?}");
    }
    let out = obdcracker(&[
        "--dry-run",
        "--profile",
        "a7",
        "scan",
        "--patient-ids",
        "71D",
    ]);
    assert_eq!(out.status.code(), Some(2), "needs --discover: {out:?}");
}

#[test]
fn sim_scan_discover_wide_looks_past_the_discovery_range_without_sending_on_a_reply_id() {
    let log = temp_log("discover-wide");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover",
        "--wide",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("discovery: 22 of 106 request IDs answered"),
        "{stdout}"
    );
    // The silent first-pass IDs whose reply IDs the wide pass sends on are asked again first,
    // waiting as long as the transport allows: the sim waits whatever it's asked to (#87).
    assert!(
        stdout.contains("recheck, waiting up to 5.0 s each: 0 of 21 request IDs answered"),
        "{stdout}"
    );
    // The simulated A7 has nothing past 0x769. The wide pass is as patient, for a module such
    // as the MMI that may answer slowly through the gateway.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("wide discovery, waiting up to 5.0 s each: 0 of ")),
        "{stdout}"
    );
    assert!(
        stdout.contains("77A gateway F197 J533--Gateway"),
        "{stdout}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    // The recheck and wide passes: the reads of F187 right after the first pass's 106, before
    // the scan.
    let after: Vec<u32> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx""#))
        .skip(0x6A)
        .take_while(|l| l.contains(r#""payload":"22 F1 87""#))
        .map(|l| {
            let id = l.split(r#""id":""#).nth(1).unwrap();
            u32::from_str_radix(&id[..3], 16).unwrap()
        })
        .collect();
    let (recheck, wide) = after.split_at(after.iter().take_while(|id| **id <= 0x769).count());
    // Each recheck is for a reply ID the wide pass then sends on, and the wide pass sends on
    // no other first-pass reply ID that nothing answered on.
    let mut replies: Vec<u32> = recheck.iter().map(|id| id + 0x6A).collect();
    replies.sort_unstable();
    let mut first_pass_replies: Vec<u32> = wide.iter().copied().filter(|id| *id <= 0x7D3).collect();
    first_pass_replies.sort_unstable();
    assert_eq!(replies, first_pass_replies, "{recheck:X?} then {wide:X?}");
    assert_eq!(recheck.len(), 21, "{recheck:X?}");
    assert_eq!(wide.first(), Some(&0x76A), "{wide:X?}");
    // Up to 0x795, with the MMI's MQB ID among them.
    assert!(wide.contains(&0x773), "{wide:X?}");
    assert!(wide.iter().all(|id| *id <= 0x795), "{wide:X?}");
    // Never on the reply ID of a module that answered (as every module in the profile did), nor
    // on one whose reply would be an OBD-II ID.
    let profile = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../obdcracker-profile/profiles/audi-a7-c7.toml"
    ))
    .unwrap();
    for reply in profile
        .lines()
        .filter_map(|l| l.strip_prefix("response_id = 0x"))
        .map(|id| u32::from_str_radix(id, 16).unwrap())
    {
        assert!(!wide.contains(&reply), "{reply:03X}");
    }
    assert!(
        wide.iter()
            .all(|id| !(0x7DF..=0x7EF).contains(&(id + 0x6A))),
        "{wide:X?}"
    );
}

#[test]
fn scan_wide_needs_discover() {
    let out = obdcracker(&["--dry-run", "--profile", "a7", "scan", "--wide"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--discover"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn scan_discover_needs_a_profile_with_a_discovery_range() {
    let out = obdcracker(&["--dry-run", "scan", "--discover"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--discover needs a profile"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = obdcracker(&["--dry-run", "--profile", "a7", "scan", "--discover"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry run: nothing was sent"), "{stdout}");
}

#[test]
fn scan_extended_switches_only_the_modules_with_extended_dids() {
    // In the A7 profile only the head-up display has DIDs that need the extended session (0100
    // and 0102, #86), so --extended sends 10 03 to it alone, and a plain scan says it didn't read them.
    let log = temp_log("scan-extended");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--extended",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("extended diagnostic session (10 03)"),
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in [
        "785 head-up display 0100 [00]",
        "785 head-up display 0102 [00]",
    ] {
        assert!(stdout.lines().any(|l| l == line), "{line}: {stdout}");
    }
    let audit = std::fs::read_to_string(&log).unwrap();
    let switches: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""payload":"10 03""#))
        .collect();
    assert_eq!(switches.len(), 1, "{audit}");
    assert!(switches[0].contains(r#""id":"71B""#), "{audit}");

    let out = obdcracker(&["--sim", "a7", "scan"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout
            .lines()
            .any(|l| l == "785 head-up display 0100 (not read: needs the extended session)"),
        "{stdout}"
    );
}

#[test]
fn dry_run_scan_extended_lists_the_session_reads() {
    let out = obdcracker(&["--dry-run", "scan", "--extended"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("with --extended, a live scan also reads"),
        "{stdout}"
    );
}

#[test]
fn sim_patient_sweep_says_how_long_it_may_take() {
    let out = obdcracker(&[
        "--sim",
        "a7",
        "sweep",
        "--module",
        "gateway",
        "--range",
        "00BE-00BF",
        "--extended",
        "--patient",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sweep: 2 reads of gateway (710), up to 1 min"),
        "{stderr}"
    );
}

#[test]
fn sim_sweep_lists_the_dids_a_module_has() {
    let log = temp_log("sweep");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "sweep",
        "--module",
        "head-up display",
        "--range",
        "F180-F18F",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 4G8919604K and a space, as the car sent it in #54.
    assert!(
        stdout
            .lines()
            .any(|l| l == "785 head-up display F187 [34 47 38 39 31 39 36 30 34 4B 20]"),
        "{stdout}"
    );
    assert!(!stdout.contains("F180"), "{stdout}");
    let listed = stdout
        .lines()
        .filter(|l| l.starts_with("785 head-up display "))
        .count();
    assert!(
        stdout.contains(&format!("sweep: {listed} DIDs answered\n")),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sweep: 16 reads of head-up display (71B)"),
        "{stderr}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    let sent: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx""#))
        .collect();
    assert_eq!(sent.len(), 16);
    assert!(sent.iter().all(|l| l.contains(r#""id":"71B""#)), "{sent:?}");
}

#[test]
fn dry_run_sweep_says_what_a_live_one_reads() {
    let out = obdcracker(&[
        "--dry-run",
        "--profile",
        "a7",
        "sweep",
        "--module",
        "engine",
        "--range",
        "0600-06FF",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("7E0 03 22 06 00"), "{stdout}");
    assert!(
        stdout.contains("a live sweep reads every DID from 22 0600 to 22 06FF"),
        "{stdout}"
    );
}

#[test]
fn sweep_refuses_bad_ranges_modules_and_a_missing_profile() {
    for args in [
        &[
            "--dry-run",
            "--profile",
            "a7",
            "sweep",
            "--module",
            "engine",
            "--range",
            "06FF-0600",
        ][..],
        &[
            "--dry-run",
            "--profile",
            "a7",
            "sweep",
            "--module",
            "engine",
            "--range",
            "+600-0700",
        ],
        &[
            "--dry-run",
            "--profile",
            "a7",
            "sweep",
            "--module",
            "engine",
            "--range",
            "0600",
        ],
        &[
            "--dry-run",
            "--profile",
            "a7",
            "sweep",
            "--module",
            "engine",
            "--range",
            "10000-10001",
        ],
        &[
            "--dry-run",
            "--profile",
            "a7",
            "sweep",
            "--module",
            "radio",
            "--range",
            "0600-0601",
        ],
        &[
            "--dry-run",
            "sweep",
            "--module",
            "engine",
            "--range",
            "0600-0601",
        ],
    ] {
        let out = obdcracker(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stdout).is_empty(), "{args:?}");
    }
}

#[test]
fn sim_dtc_reads_snapshots_then_extended_data() {
    // The A7's modules were only ever asked 19 02, so the sim's gateway refuses 19 04 and 06 as
    // not supported, and the refusal of the first doesn't stop the second.
    let log = temp_log("dtc");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "dtc",
        "--module",
        "gateway",
        "--code",
        "0016A0",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for what in ["snapshots", "extended data"] {
        let line = format!(
            "77A gateway DTC 0016A0 {what} (service 0x19 refused: subfunction not supported (0x12))"
        );
        assert!(stdout.lines().any(|l| l == line), "{line:?} in:\n{stdout}");
    }
    let audit = std::fs::read_to_string(&log).unwrap();
    let sent: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx""#))
        .collect();
    assert_eq!(sent.len(), 2, "{audit}");
    assert!(sent[0].contains(r#""id":"710","payload":"19 04 00 16 A0 FF""#));
    assert!(sent[1].contains(r#""id":"710","payload":"19 06 00 16 A0 FF""#));
}

#[test]
fn dry_run_dtc_says_what_a_live_one_reads() {
    let out = obdcracker(&[
        "--dry-run",
        "--profile",
        "a7",
        "dtc",
        "--module",
        "gateway",
        "--code",
        "0016a0",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("710 06 19 04 00 16 A0 FF"), "{stdout}");
    assert!(
        stdout.contains(
            "a live read also sends 19 06 00 16 A0 FF once 19 04 00 16 A0 FF is answered"
        ),
        "{stdout}"
    );
}

#[test]
fn dry_run_dtc_reads_one_record_by_its_number() {
    let out = obdcracker(&[
        "--dry-run",
        "--profile",
        "a7",
        "dtc",
        "--module",
        "gateway",
        "--code",
        "0016A0",
        "--record",
        "01",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("710 06 19 04 00 16 A0 01"), "{stdout}");
    assert!(
        stdout.contains(
            "a live read also sends 19 06 00 16 A0 01 once 19 04 00 16 A0 01 is answered"
        ),
        "{stdout}"
    );
}

#[test]
fn dtc_refuses_a_bad_record_number() {
    for record in ["1", "001", "+1", "0G", "", "FE", "fe"] {
        let out = obdcracker(&[
            "--dry-run",
            "--profile",
            "a7",
            "dtc",
            "--module",
            "gateway",
            "--code",
            "0016A0",
            "--record",
            record,
        ]);
        assert_eq!(out.status.code(), Some(2), "{record:?}: {out:?}");
        assert!(out.stdout.is_empty(), "nothing sent: {out:?}");
    }
}

#[test]
fn dtc_refuses_bad_codes_modules_and_a_missing_profile() {
    let dtc = |profile: Option<&str>, module: &str, code: &str| {
        let mut args = vec!["--dry-run"];
        if let Some(profile) = profile {
            args.extend(["--profile", profile]);
        }
        args.extend(["dtc", "--module", module, "--code", code]);
        obdcracker(&args)
    };
    for out in [
        dtc(Some("a7"), "gateway", "16A0"),
        dtc(Some("a7"), "gateway", "0016A00"),
        dtc(Some("a7"), "gateway", "+016A0"),
        dtc(Some("a7"), "gateway", "0016AG"),
        dtc(Some("a7"), "gateway", "000000"),
        dtc(Some("a7"), "gateway", "FFFFFF"),
        dtc(Some("a7"), "gateway", "ffffff"),
        dtc(Some("a7"), "nowhere", "0016A0"),
        dtc(None, "gateway", "0016A0"),
    ] {
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(out.stdout.is_empty(), "nothing sent: {out:?}");
    }
}

#[test]
fn sim_scan_discover_29bit_tries_each_vag_29_bit_id_and_goes_back_to_11_bit() {
    // The sim's A7 has no module on 29-bit IDs (none is known yet), so nothing answers there,
    // and the scan's 11-bit reads still do.
    let log = temp_log("scan-29bit");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover-29bit",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("29-bit discovery: 0 of 256 request IDs answered"),
        "{stdout}"
    );
    assert!(
        stdout.contains("77A gateway F197 J533--Gateway"),
        "{stdout}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    let sent: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx""#))
        .collect();
    for (line, id) in sent.iter().zip(0x17FC_0000u32..=0x17FC_00FF) {
        assert!(
            line.contains(&format!(r#""id":"{id:08X}","payload":"22 F1 87""#)),
            "{line}"
        );
    }
    assert!(
        !audit.contains(r#""id":"17FE"#),
        "nothing sent on a reply ID"
    );
}

#[test]
fn dry_run_scan_discover_29bit_lists_the_29_bit_reads() {
    let out = obdcracker(&["--dry-run", "--profile", "a7", "scan", "--discover-29bit"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("17FC0000 03 22 F1 87"), "{stdout}");
    assert!(stdout.contains("17FC00FF 03 22 F1 87"), "{stdout}");
}

#[test]
fn scan_discover_29bit_needs_a_profile() {
    let out = obdcracker(&["--dry-run", "scan", "--discover-29bit"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "", "nothing sent");
}

#[test]
fn sim_scan_discover_tp20_sets_up_a_channel_to_each_profile_address_after_the_scan() {
    // The sim's A7 has no TP2.0 module (none is confirmed yet), so no address answers.
    let log = temp_log("scan-tp20");
    let out = obdcracker(&[
        "--sim",
        "a7",
        "--audit-log",
        log.to_str().unwrap(),
        "scan",
        "--discover-tp20",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TP2.0 discovery: 0 of 29 addresses answered"),
        "{stdout}"
    );
    let scanned = stdout.find("77A gateway F197 J533--Gateway").unwrap();
    assert!(
        scanned < stdout.find("TP2.0 discovery").unwrap(),
        "{stdout}"
    );
    let audit = std::fs::read_to_string(&log).unwrap();
    let setups: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""dir":"tx","id":"200""#))
        .collect();
    assert_eq!(setups.len(), 29, "{audit}");
    assert!(
        setups[10].contains(r#""payload":"5F C0 00 10 00 03 01""#),
        "{}",
        setups[10]
    );
}

#[test]
fn dry_run_scan_discover_tp20_lists_the_channel_setups() {
    let out = obdcracker(&["--dry-run", "--profile", "a7", "scan", "--discover-tp20"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("200 05 C0 00 10 00 03 01"), "{stdout}");
    assert!(stdout.contains("200 72 C0 00 10 00 03 01"), "{stdout}");
    assert!(stdout.contains("200 7F C0 00 10 00 03 01"), "{stdout}");
    assert!(stdout.contains("A8 (disconnect)"), "{stdout}");
    assert!(stdout.contains("22 F1 87 and 22 F1 9E"), "{stdout}");
    // Nothing was sent, so nothing could answer.
    assert!(!stdout.contains("addresses answered"), "{stdout}");
    assert!(
        stdout.contains("TP2.0 discovery: dry run, no channel setup was sent"),
        "{stdout}"
    );
}

#[test]
fn scan_discover_tp20_needs_a_profile() {
    let out = obdcracker(&["--dry-run", "scan", "--discover-tp20"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "", "nothing sent");
}

#[test]
fn sim_scan_compares_the_gateways_list_with_the_modules_that_answered() {
    let log = temp_log("scan-gateway-list");
    let out = obdcracker(&["--sim", "a7", "--audit-log", log.to_str().unwrap(), "scan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let summary = stdout
        .lines()
        .find(|l| l.starts_with("gateway lists "))
        .unwrap_or_else(|| panic!("no gateway list in:\n{stdout}"));
    // The profile's VAG addresses 01, 02, 19, 82, 17, 03, 13, 8B, 3B, 44 and 8E answer; the
    // gateway lists 17 and 03 twice, so each counts for both of its slots.
    assert_eq!(
        summary,
        "gateway lists 73 installed modules: 13 found, 60 not in profile"
    );
    // The A7 profile has no module for 22 (request 0x71D) or 34 (request 0x755).
    for line in [
        "  22 not in profile (request 0x71D)",
        "  34 not in profile (request 0x755)",
    ] {
        assert!(stdout.lines().any(|l| l == line), "{line:?} in:\n{stdout}");
    }
    // The modules the profile gives an address no longer show up as not in profile.
    for address in ["03", "13", "3B", "44", "8B", "8E"] {
        let prefix = format!("  {address} not in profile");
        assert!(
            !stdout.lines().any(|l| l.starts_with(&prefix)),
            "{prefix:?} in:\n{stdout}"
        );
    }
    // Two extra reads of the gateway, and nothing but reads.
    let audit = std::fs::read_to_string(&log).unwrap();
    for did in ["22 2A 2A", "22 2A 2C"] {
        let sent = format!(r#""dir":"tx","id":"710","payload":"{did}""#);
        assert_eq!(audit.matches(&sent).count(), 1, "{did}");
    }
}

#[test]
fn dry_run_scan_with_a_profile_names_the_gateway_list_reads() {
    let out = obdcracker(&["--dry-run", "--profile", "a7", "scan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a live scan also reads the gateway's installed-module list"),
        "{stdout}"
    );
    assert!(!stdout.contains("gateway lists "), "{stdout}");
}

#[test]
fn sim_scan_with_tp20_discovery_calls_the_listed_addresses_it_tried_silent() {
    let out = obdcracker(&["--sim", "a7", "scan", "--discover-tp20"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The A7 profile tries TP2.0 setups to 29 addresses, and the gateway lists every one.
    assert!(
        stdout
            .lines()
            .any(|l| l
                == "gateway lists 73 installed modules: 13 found, 29 silent, 31 not in profile"),
        "{stdout}"
    );
    assert!(stdout.lines().any(|l| l == "  05 silent"), "{stdout}");
}

// ---- read-dids and --elm-segmenting ---------------------------------------------------------

mod read_dids {
    use super::*;
    use fake_elm::Module;

    // The A7 profile's transmission: F187 and F191 are 11 bytes, F189 4 and F190 17; F188 isn't
    // listed.
    const KNOWN: &str = "F187,F189,F190,F191";
    const FOUR: [u8; 9] = [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90, 0xF1, 0x91];

    fn data(fill: u8, len: usize) -> Vec<u8> {
        vec![fill; len]
    }

    // What the transmission answers `22 F187 F189 F190 F191` with.
    fn four_dids_reply() -> Vec<u8> {
        let mut reply = vec![0x62];
        for (did, len) in [(0xF187u16, 11), (0xF189, 4), (0xF190, 17), (0xF191, 11)] {
            reply.extend(did.to_be_bytes());
            reply.extend(data(0x41, len));
        }
        reply
    }

    // `elm` with a transmission at 7E1/7E9 that answers a read of F187 (what the command sends
    // first) and `request` with `answer`.
    fn with_transmission(request: Vec<u8>, answer: Vec<u8>) -> FakeElm {
        let responder = move |header: u32, sent: &[u8]| match (header, sent) {
            (0x7E1, [0x22, 0xF1, 0x87]) => {
                let mut reply = vec![0x62, 0xF1, 0x87];
                reply.extend(data(0x41, 11));
                vec![(0x7E9, reply)]
            }
            (0x7E1, sent) if sent == request => vec![(0x7E9, answer.clone())],
            _ => Vec::new(),
        };
        FakeElm::new(Box::new(responder)).with_module(Module::new(0x7E1, 0x7E9))
    }

    fn adapter(stn: bool, answer: Vec<u8>) -> SocketAddr {
        let mut elm = with_transmission(FOUR.to_vec(), answer);
        if stn {
            elm.sti = Some("STN1155 v5.6.19".into());
        }
        wifi_elm(elm)
    }

    fn read_dids(addr: SocketAddr, log: &std::path::Path, extra: &[&str], dids: &str) -> Output {
        let addr = addr.to_string();
        let mut args = vec!["--tcp", &addr, "--profile", "a7"];
        args.extend(extra);
        args.extend(["--audit-log", log.to_str().unwrap()]);
        args.extend(["read-dids", "--module", "transmission", "--did", dids]);
        obdcracker(&args)
    }

    // `dir` and the command, payload or setting name of each line of the audit log.
    fn audit_story(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let dir = v["dir"].as_str().unwrap();
                let rest = ["cmd", "payload", "name"]
                    .iter()
                    .find_map(|key| v[key].as_str())
                    .unwrap_or("");
                format!("{dir} {rest}")
            })
            .collect()
    }

    fn position(story: &[String], line: &str) -> usize {
        story
            .iter()
            .position(|s| s == line)
            .unwrap_or_else(|| panic!("{line} not in {story:?}"))
    }

    fn hex(byte: &str, len: usize) -> String {
        vec![byte; len].join(" ")
    }

    #[test]
    fn a_plain_elm327_sends_the_request_in_frames_after_a_one_did_read() {
        let log = temp_log("read-dids-plain");
        let out = read_dids(adapter(false, four_dids_reply()), &log, &[], KNOWN);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout,
            format!(
                "7E9 transmission F187 [{}]\n7E9 transmission F189 [{}]\n\
                 7E9 transmission F190 [{}]\n7E9 transmission F191 [{}]\n",
                hex("41", 11),
                hex("41", 4),
                hex("41", 17),
                hex("41", 11)
            )
        );
        let story = audit_story(&log);
        // The first request shows the adapter echoes as it reads, which a request in frames needs.
        let warm_up = position(&story, "tx 22 F1 87");
        let request = position(&story, "tx 22 F1 87 F1 89 F1 90 F1 91");
        assert!(warm_up < request, "{story:?}");
        assert_eq!(story.iter().filter(|s| s.starts_with("tx ")).count(), 2);
        let first_frame = position(&story, "tx_frame 10 09 22 F1 87 F1 89 F1");
        let last_frame = position(&story, "tx_frame 21 90 F1 91 00 00 00 00");
        assert!(
            request < first_frame && first_frame < last_frame,
            "{story:?}"
        );
        assert!(story.contains(&"cmd ATCAF0".to_owned()), "{story:?}");
        // Nothing was set: the default is the driver's own.
        assert!(!story.iter().any(|s| s.starts_with("setting")), "{story:?}");
    }

    #[test]
    fn an_stn_sends_it_as_stpx_unless_told_to_use_caf0() {
        let log = temp_log("read-dids-stn");
        let out = read_dids(adapter(true, four_dids_reply()), &log, &[], KNOWN);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let story = audit_story(&log);
        assert!(story.contains(&"tx 22 F1 87 F1 89 F1 90 F1 91".to_owned()));
        assert!(
            !story.iter().any(|s| s.starts_with("tx_frame")),
            "{story:?}"
        );
        assert!(!story.contains(&"cmd ATCAF0".to_owned()), "{story:?}");
        assert!(!story.iter().any(|s| s.starts_with("setting")), "{story:?}");

        for method in ["stpx", "caf0"] {
            let log = temp_log(&format!("read-dids-stn-{method}"));
            let out = read_dids(
                adapter(true, four_dids_reply()),
                &log,
                &["--elm-segmenting", method],
                KNOWN,
            );
            assert!(
                out.status.success(),
                "{method}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let story = audit_story(&log);
            let setting = position(&story, "setting segment-on-stn");
            // Before the first request, whichever it is.
            let first = story.iter().position(|s| s.starts_with("tx ")).unwrap();
            assert!(setting < first, "{method}: {story:?}");
            let framed = story.iter().any(|s| s.starts_with("tx_frame 10 09"));
            assert_eq!(framed, method == "caf0", "{method}: {story:?}");
        }
    }

    #[test]
    fn the_log_records_how_it_was_set() {
        for (method, value) in [("caf0", "on"), ("stpx", "off")] {
            let log = temp_log("read-dids-setting-value");
            let out = read_dids(
                adapter(true, four_dids_reply()),
                &log,
                &["--elm-segmenting", method],
                KNOWN,
            );
            assert!(out.status.success());
            let audit = std::fs::read_to_string(&log).unwrap();
            let line = format!(r#""dir":"setting","name":"segment-on-stn","value":"{value}""#);
            assert!(
                audit.lines().any(|l| l.contains(&line)),
                "{method}: {audit}"
            );
        }
    }

    #[test]
    fn a_reply_that_doesnt_fit_is_reported_and_fails() {
        // F189 is missing from the answer, as a module may leave out a DID it doesn't have.
        let mut missing = vec![0x62, 0xF1, 0x87];
        missing.extend(data(0x41, 11));
        missing.extend([0xF1, 0x90]);
        missing.extend(data(0x41, 17));
        missing.extend([0xF1, 0x91]);
        missing.extend(data(0x41, 11));
        // Bytes after the last DID.
        let mut extra = four_dids_reply();
        extra.push(0x00);
        for (what, reply) in [("a missing DID", missing), ("extra bytes", extra)] {
            let log = temp_log("read-dids-misfit");
            let out = read_dids(adapter(false, reply), &log, &[], KNOWN);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(out.status.code(), Some(1), "{what}: {stdout}");
            assert!(
                stdout.starts_with(
                    "7E9 transmission F187 F189 F190 F191 (reply is malformed: 62 F1 87"
                ),
                "{what}: {stdout}"
            );
            // Nothing of it is shown as a value.
            assert!(!stdout.contains("F187 ["), "{what}: {stdout}");
        }
    }

    #[test]
    fn a_did_without_a_profile_length_leaves_the_rest_unsplit() {
        // F188 isn't in the profile: F187 splits, and the rest is shown as the module sent it.
        let mut reply = vec![0x62, 0xF1, 0x87];
        reply.extend(data(0x41, 11));
        reply.extend([0xF1, 0x88, 0x01, 0x02]);
        reply.extend([0xF1, 0x89]);
        reply.extend(data(0x42, 4));
        reply.extend([0xF1, 0x91]);
        reply.extend(data(0x43, 11));
        let request = vec![0x22, 0xF1, 0x87, 0xF1, 0x88, 0xF1, 0x89, 0xF1, 0x91];
        let addr = wifi_elm(with_transmission(request, reply));
        let log = temp_log("read-dids-unsplit");
        let out = read_dids(addr, &log, &[], "F187,F188,F189,F191");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{stdout}");
        assert_eq!(
            lines[0],
            format!("7E9 transmission F187 [{}]", hex("41", 11))
        );
        assert!(
            lines[1].starts_with("7E9 transmission F188 F189 F191 not split"),
            "{stdout}"
        );
        let rest = format!(
            "[F1 88 01 02 F1 89 {} F1 91 {}]",
            hex("42", 4),
            hex("43", 11)
        );
        assert!(lines[1].ends_with(&rest), "{stdout}");
    }

    #[test]
    fn a_refusal_is_shown_by_name_and_fails() {
        let elm = FakeElm::new(Box::new(|header, request| match (header, request) {
            (0x7E1, [0x22, 0xF1, 0x87]) => vec![(0x7E9, vec![0x7F, 0x22, 0x31])],
            _ => Vec::new(),
        }))
        .with_module(Module::new(0x7E1, 0x7E9));
        let log = temp_log("read-dids-refused");
        let out = read_dids(wifi_elm(elm), &log, &[], "F187");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{stdout}");
        assert_eq!(
            stdout,
            "7E9 transmission F187 (service 0x22 refused: request out of range (0x31))\n"
        );
    }

    #[test]
    fn a_read_of_up_to_three_dids_is_one_request_with_no_warm_up() {
        let log = temp_log("read-dids-one");
        let out = read_dids(adapter(false, four_dids_reply()), &log, &[], "F187");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let story = audit_story(&log);
        assert_eq!(story.iter().filter(|s| s.starts_with("tx ")).count(), 1);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("7E9 transmission F187 [{}]\n", hex("41", 11))
        );
    }

    #[test]
    fn a_list_that_cant_be_read_sends_no_warm_up_either() {
        let dids = |count: u16| {
            (0..count)
                .map(|n| format!("F1{n:02X}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        for (what, list, says) in [
            ("22 DIDs", dids(22), "too many"),
            ("a repeat", "F187,F189,F190,F191,F187".to_owned(), "twice"),
        ] {
            let log = temp_log("read-dids-bad-list");
            let out = read_dids(adapter(false, four_dids_reply()), &log, &[], &list);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{what}: {stderr}");
            assert!(stderr.contains(says), "{what}: {stderr}");
            let story = audit_story(&log);
            assert!(
                !story.iter().any(|s| s.starts_with("tx")),
                "{what}: {story:?}"
            );
        }
    }

    // A transmission that answers the request of four DIDs, and the one-DID read before it with
    // `warm_up` (nothing, if that's empty).
    fn answering_the_warm_up_with(warm_up: Vec<u8>) -> SocketAddr {
        let reply = four_dids_reply();
        wifi_elm(
            FakeElm::new(Box::new(move |header, request| match (header, request) {
                (0x7E1, [0x22, 0xF1, 0x87]) if !warm_up.is_empty() => {
                    vec![(0x7E9, warm_up.clone())]
                }
                (0x7E1, request) if request == FOUR => vec![(0x7E9, reply.clone())],
                _ => Vec::new(),
            }))
            .with_module(Module::new(0x7E1, 0x7E9)),
        )
    }

    #[test]
    fn a_warm_up_nobody_answers_stops_before_the_long_request() {
        // Its late answer could be taken for the long request's.
        let log = temp_log("read-dids-silent-warm-up");
        let out = read_dids(answering_the_warm_up_with(Vec::new()), &log, &[], KNOWN);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("wasn't sent"), "{stderr}");
        assert_eq!(out.stdout.len(), 0);
        let story = audit_story(&log);
        assert_eq!(story.iter().filter(|s| s.starts_with("tx ")).count(), 1);
        assert!(
            !story.iter().any(|s| s.starts_with("tx_frame")),
            "{story:?}"
        );
    }

    #[test]
    fn a_refused_warm_up_is_an_answer_and_the_request_goes_on() {
        let log = temp_log("read-dids-refused-warm-up");
        let out = read_dids(
            answering_the_warm_up_with(vec![0x7F, 0x22, 0x31]),
            &log,
            &[],
            KNOWN,
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        let story = audit_story(&log);
        assert_eq!(story.iter().filter(|s| s.starts_with("tx ")).count(), 2);
        assert!(
            story.iter().any(|s| s.starts_with("tx_frame 10 09")),
            "{story:?}"
        );
    }

    #[test]
    fn the_dry_run_prints_the_frames_and_sends_nothing() {
        let out = obdcracker(&[
            "--dry-run",
            "--profile",
            "a7",
            "read-dids",
            "--module",
            "transmission",
            "--did",
            KNOWN,
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The request once, as two frames: there is no warm-up read.
        assert_eq!(
            stdout.lines().filter(|l| l.starts_with("7E1 ")).count(),
            2,
            "{stdout}"
        );
        assert!(stdout.contains("7E1 10 09 22 F1 87 F1 89 F1"), "{stdout}");
        assert!(stdout.contains("dry run: nothing was sent"), "{stdout}");
    }

    #[test]
    fn the_simulated_car_answers_a_multi_did_read() {
        let log = temp_log("read-dids-sim");
        let out = obdcracker(&[
            "--sim",
            "a7",
            "--audit-log",
            log.to_str().unwrap(),
            "read-dids",
            "--module",
            "transmission",
            "--did",
            "F187,F189,F191",
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let ids: Vec<&str> = stdout
            .lines()
            .map(|l| l.split_whitespace().nth(2).unwrap())
            .collect();
        assert_eq!(ids, ["F187", "F189", "F191"], "{stdout}");
    }

    #[test]
    fn what_cant_be_read_is_refused_before_anything_is_sent() {
        let dids = |count: u16| {
            (0..count)
                .map(|n| format!("F1{n:02X}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let many = dids(22);
        for (list, module, says) in [
            ("", "transmission", "isn't a DID"),
            ("F187,", "transmission", "isn't a DID"),
            ("F18", "transmission", "\"F18\" isn't a DID"),
            ("F18G", "transmission", "\"F18G\" isn't a DID"),
            ("+187", "transmission", "\"+187\" isn't a DID"),
            ("F0187", "transmission", "isn't a DID"),
            ("F187,F189,F187", "transmission", "F187 is named twice"),
            (&many, "transmission", "22 DIDs in one request is too many"),
            ("F187", "boot", "has no module named \"boot\""),
        ] {
            let out = obdcracker(&[
                "--dry-run",
                "--profile",
                "a7",
                "read-dids",
                "--module",
                module,
                "--did",
                list,
            ]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{list:?}: {stderr}");
            assert!(stderr.contains(says), "{list:?}: {stderr}");
            assert!(out.stdout.is_empty(), "{list:?}");
        }
        // The most.
        let out = obdcracker(&[
            "--dry-run",
            "--profile",
            "a7",
            "read-dids",
            "--module",
            "transmission",
            "--did",
            &dids(21),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // No --did, and no profile.
        let out = obdcracker(&[
            "--dry-run",
            "--profile",
            "a7",
            "read-dids",
            "--module",
            "engine",
        ]);
        assert_eq!(out.status.code(), Some(2));
        let out = obdcracker(&[
            "--dry-run",
            "read-dids",
            "--module",
            "engine",
            "--did",
            "F187",
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("needs a profile"));
    }

    #[test]
    fn the_segmenting_flag_is_for_elm_adapters_only() {
        let combos: [&[&str]; 6] = [
            &["--gsusb"],
            &["--socketcan", "can0"],
            &["--sim", "a7"],
            &["--dry-run"],
            &["--gsusb", "--listen-only"],
            &["--socketcan", "can0", "--bitrate", "500000"],
        ];
        for adapter in combos {
            let mut args = vec!["--elm-segmenting", "caf0"];
            args.extend(adapter);
            args.push("vin");
            let out = obdcracker(&args);
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        // Only the two methods.
        let out = obdcracker(&["--elm-segmenting", "caf1", "--tcp", "127.0.0.1:1", "vin"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("stpx"));
    }

    #[test]
    fn the_flag_doesnt_apply_to_commands_that_send_nothing_through_it() {
        // `adapter` sends no request, and `update` uses no adapter.
        let addr = wifi_adapter().to_string();
        let out = obdcracker(&["--tcp", &addr, "--elm-segmenting", "caf0", "adapter"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("--elm-segmenting doesn't apply"));
        let out = obdcracker(&["--elm-segmenting", "caf0", "update"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("--elm-segmenting"));
    }
}
