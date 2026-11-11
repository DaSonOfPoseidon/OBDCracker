//! `obdcracker diff OLD NEW` end to end: documents written by the simulated car's `--json` output,
//! edited, and compared. It opens no adapter and writes no audit log.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const VIN: &str = "WAU2MBFC6EN093415";

// A directory of this test's own, which is also where `diff` runs: it writes nothing there.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("obdcracker-diff-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn document(&self, name: &str, document: &Value) -> PathBuf {
        self.file(name, serde_json::to_string(document).unwrap())
    }

    // `diff` with these words before the command, run in the scratch directory.
    fn diff(&self, flags: &[&str], old: &Path, new: &Path) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_obdcracker"))
            .env("OBDCRACKER_TEST_PORTS", "")
            .current_dir(&self.0)
            .args(flags)
            .arg("diff")
            .arg(old)
            .arg(new)
            .output()
            .unwrap();
        let files: Vec<_> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            !files.iter().any(|f| f.to_string_lossy().contains("audit")),
            "{files:?}"
        );
        out
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn lines(out: &Output) -> Vec<String> {
    stdout(out).lines().map(str::to_owned).collect()
}

// The `--json` document the simulated A7 prints for a command.
fn sim(args: &[&str]) -> Value {
    let log =
        std::env::temp_dir().join(format!("obdcracker-diff-sim-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&log);
    let mut all = vec![
        "--sim",
        "a7",
        "--json",
        "--audit-log",
        log.to_str().unwrap(),
    ];
    all.extend(args);
    let out = Command::new(env!("CARGO_BIN_EXE_obdcracker"))
        .env("OBDCRACKER_TEST_PORTS", "")
        .args(&all)
        .output()
        .unwrap();
    // A sweep stopped by the voltage guard exits 1 and still prints its document
    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "{args:?}: {}",
        stderr(&out)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

// The DID's entry in a module's list.
fn did_entry<'a>(module: &'a mut Value, did: &str) -> &'a mut Value {
    module["dids"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["did"] == did)
        .unwrap()
}

fn module<'a>(result: &'a mut Value, name: &str) -> &'a mut Value {
    result["modules"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|module| module["name"] == name)
        .unwrap()
}

// ---- what it reports --------------------------------------------------------------------------

#[test]
fn identical_documents_have_no_changes_and_the_same_file_twice_is_fine() {
    let scratch = Scratch::new("identical");
    let document = sim(&["fingerprint"]);
    let (old, new) = (
        scratch.document("old.json", &document),
        scratch.document("new.json", &document),
    );
    for (old, new) in [(&old, &new), (&old, &old)] {
        let out = scratch.diff(&[], old, new);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(stdout(&out), "no changes\n");
        assert_eq!(stderr(&out), "");
    }
}

#[test]
fn a_tune_shows_as_changed_calibration_ids_cvns_and_part_numbers() {
    let scratch = Scratch::new("tune");
    let old = sim(&["fingerprint"]);
    let mut new = old.clone();
    new["result"]["ecus"][0]["calids"]["value"][0] = json!("4G0401N 0016BVAC");
    new["result"]["ecus"][0]["cvns"]["value"][0] = json!("38D3FF82");
    let was = old["result"]["modules"][1]["dids"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["did"] == "F189")
        .unwrap()["value"]["Text"]
        .as_str()
        .unwrap()
        .to_owned();
    *did_entry(&mut new["result"]["modules"][1], "F189") =
        json!({"did": "F189", "value": {"Text": "0006"}});
    let out = scratch.diff(
        &[],
        &scratch.document("old.json", &old),
        &scratch.document("new.json", &new),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        lines(&out),
        [
            "7E8 CALID 1: 4G0401N 0016BVAB → 4G0401N 0016BVAC".to_owned(),
            "7E8 CVN 1: 9BF7470D → 38D3FF82".to_owned(),
            format!("transmission F189 {was} → 0006"),
        ]
    );
}

#[test]
fn modules_that_appear_or_disappear_are_one_line_each() {
    let scratch = Scratch::new("modules");
    let old = sim(&["fingerprint"]);
    let mut new = old.clone();
    let modules = new["result"]["modules"].as_array_mut().unwrap();
    let removed = modules.remove(0);
    modules.push(json!({"name": "5F mmi", "response_id": "77F", "dids": []}));
    let out = scratch.diff(
        &[],
        &scratch.document("old.json", &old),
        &scratch.document("new.json", &new),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        lines(&out),
        // In name order: "5F mmi" sorts before the profile's lower-case names
        [
            "module added: 5F mmi (0x77F)".to_owned(),
            format!(
                "module removed: {} (0x{})",
                removed["name"].as_str().unwrap(),
                removed["response_id"].as_str().unwrap()
            ),
        ]
    );
}

#[test]
fn a_scan_reports_dtcs_and_answers_but_not_live_values_and_never_an_unchanged_vin() {
    let scratch = Scratch::new("scan");
    let old = sim(&["scan"]);
    assert!(
        old.to_string().contains(VIN),
        "the scan should read the VIN"
    );
    let mut new = old.clone();
    // A live value moving is not a change
    new["result"]["ecus"][0]["pids"]["value"][0]["value"] =
        json!({"Quantity": {"value": 99.0, "unit": "Celsius"}});
    new["result"]["ecus"][0]["stored_dtcs"] = json!({"value": ["P0401"]});
    let gateway = module(&mut new["result"], "gateway");
    gateway["dtcs"] = json!({"value": [{"dtc": "0016A0", "status": "08"}]});
    let (old_path, new_path) = (
        scratch.document("old.json", &old),
        scratch.document("new.json", &new),
    );
    let out = scratch.diff(&[], &old_path, &new_path);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        lines(&out),
        ["7E8 DTC new: P0401", "gateway DTC new: 0016A0 (confirmed)"]
    );
    assert!(!stdout(&out).contains(VIN));

    // The VIN is shown once it is the thing that changed
    let mut revised = new.clone();
    did_entry(module(&mut revised["result"], "engine"), "F190")["value"] =
        json!({"Text": "WAU2MBFC6EN099999"});
    let out = scratch.diff(&[], &old_path, &scratch.document("revised.json", &revised));
    let text = stdout(&out);
    assert!(
        text.contains(&format!("engine F190 {VIN} → WAU2MBFC6EN099999")),
        "{text}"
    );

    // A module that went silent
    let mut silent = old.clone();
    module(&mut silent["result"], "gateway")["answered"] = json!(false);
    let out = scratch.diff(&[], &old_path, &scratch.document("silent.json", &silent));
    assert_eq!(lines(&out), ["gateway answered → didn't answer"]);
}

#[test]
fn a_vin_is_shown_only_when_it_changed() {
    let scratch = Scratch::new("vin");
    let old = sim(&["vin"]);
    assert_eq!(old["result"][0]["vin"], VIN);
    let old_path = scratch.document("old.json", &old);
    let out = scratch.diff(&[], &old_path, &old_path);
    assert_eq!(stdout(&out), "no changes\n");

    let mut new = old.clone();
    new["result"][0]["vin"] = json!("WBA3A5C51CF256651");
    let out = scratch.diff(&[], &old_path, &scratch.document("new.json", &new));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(lines(&out), [format!("7E8 VIN {VIN} → WBA3A5C51CF256651")]);

    // An ECU that only one document has isn't shown with its VIN
    let mut none = old.clone();
    none["result"] = json!([]);
    let none_path = scratch.document("none.json", &none);
    for (old, new, line) in [
        (&none_path, &old_path, "7E8 ECU added"),
        (&old_path, &none_path, "7E8 ECU removed"),
    ] {
        let out = scratch.diff(&[], old, new);
        assert_eq!(lines(&out), [line]);
        assert!(!stdout(&out).contains(VIN));
    }
}

#[test]
fn a_sweep_compares_what_was_found() {
    let scratch = Scratch::new("sweep");
    let old = sim(&[
        "sweep",
        "--module",
        "head-up display",
        "--range",
        "F180-F18F",
    ]);
    let mut new = old.clone();
    let found = new["result"]["sweep"]["found"].as_array_mut().unwrap();
    let entry = found.iter_mut().find(|e| e["did"] == "F187").unwrap();
    let was = entry["value"].as_str().unwrap().to_owned();
    entry["value"] = json!("00");
    let out = scratch.diff(
        &[],
        &scratch.document("old.json", &old),
        &scratch.document("new.json", &new),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        lines(&out),
        [format!("head-up display F187 [{was}] → [00]")]
    );
}

#[test]
fn sweeps_are_compared_over_the_range_both_read_all_of() {
    let scratch = Scratch::new("sweep-range");
    let whole = sim(&["sweep", "--module", "engine", "--range", "0600-0700"]);
    let stopped = sim(&[
        "--sim-voltage-drop",
        "60:11.0",
        "sweep",
        "--module",
        "engine",
        "--range",
        "0600-0700",
    ]);
    let stop = stopped["result"]["sweep"]["stop"]["at"].as_str().unwrap();
    assert_eq!(stop, "0664");
    let out = scratch.diff(
        &[],
        &scratch.document("whole.json", &whole),
        &scratch.document("stopped.json", &stopped),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "no changes\n");
    assert!(
        stderr(&out).contains("note: compared the DIDs 0600-0663"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn sweeps_that_cant_be_compared_are_an_error() {
    let scratch = Scratch::new("sweep-error");
    let first = sim(&[
        "sweep",
        "--module",
        "head-up display",
        "--range",
        "F180-F18F",
    ]);
    let other_range = sim(&[
        "sweep",
        "--module",
        "head-up display",
        "--range",
        "0600-0610",
    ]);
    let other_module = sim(&["sweep", "--module", "engine", "--range", "F180-F18F"]);
    let first_path = scratch.document("first.json", &first);
    for (name, other, message) in [
        ("range", &other_range, "no DID in common"),
        ("module", &other_module, "different modules"),
    ] {
        let out = scratch.diff(&[], &first_path, &scratch.document(name, other));
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert_eq!(stdout(&out), "");
        assert!(stderr(&out).contains(message), "{name}: {}", stderr(&out));
    }
}

#[test]
fn a_multi_did_read_compares_its_split_dids() {
    let scratch = Scratch::new("read-dids");
    let old = sim(&[
        "read-dids",
        "--module",
        "transmission",
        "--did",
        "F189,F191",
    ]);
    let mut new = old.clone();
    new["result"]["read"]["value"]["split"][0]["data"] = json!("30 30 30 36");
    let old_path = scratch.document("old.json", &old);
    let out = scratch.diff(&[], &old_path, &scratch.document("new.json", &new));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let line = &lines(&out)[0];
    assert!(
        line.starts_with("transmission F189 [") && line.ends_with("] → [30 30 30 36]"),
        "{line}"
    );

    let other_dids = sim(&["read-dids", "--module", "transmission", "--did", "F189"]);
    let other_module = sim(&["read-dids", "--module", "engine", "--did", "F189,F191"]);
    for (name, other, message) in [
        ("dids", &other_dids, "different DIDs"),
        ("module", &other_module, "different modules"),
    ] {
        let out = scratch.diff(&[], &old_path, &scratch.document(name, other));
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(stderr(&out).contains(message), "{name}: {}", stderr(&out));
    }
}

// ---- --json -----------------------------------------------------------------------------------

#[test]
fn json_prints_the_changes_in_the_usual_envelope() {
    let scratch = Scratch::new("json");
    let old = sim(&["fingerprint"]);
    let mut new = old.clone();
    new["result"]["ecus"][0]["cvns"]["value"][0] = json!("38D3FF82");
    let (old_path, new_path) = (
        scratch.document("old.json", &old),
        scratch.document("new.json", &new),
    );
    let out = scratch.diff(&["--json"], &old_path, &new_path);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "{text}");
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        document,
        json!({
            "schema": 1,
            "command": "diff",
            "obdcracker": env!("CARGO_PKG_VERSION"),
            "result": {
                "compared": "fingerprint",
                "changes": [{
                    "change": "CvnChanged",
                    "source": "7E8",
                    "slot": 1,
                    "old": "9BF7470D",
                    "new": "38D3FF82",
                }],
            },
        })
    );

    let out = scratch.diff(&["--json"], &old_path, &old_path);
    assert_eq!(out.status.code(), Some(0));
    let document: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(document["result"]["changes"], json!([]));

    // Its own output isn't one of the documents it reads
    let own = scratch.file("own.json", text);
    let out = scratch.diff(&[], &own, &own);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not `diff`"), "{}", stderr(&out));
}

// ---- what it refuses ----------------------------------------------------------------------------

#[test]
fn flags_that_pick_an_adapter_or_a_log_are_refused() {
    let scratch = Scratch::new("flags");
    let document = scratch.document("doc.json", &sim(&["vin"]));
    let cases: [&[&str]; 11] = [
        &["--sim", "a7"],
        &["--serial", "COM3"],
        &["--tcp", "127.0.0.1:1"],
        &["--gsusb"],
        &["--socketcan", "can0"],
        &["--profile", "a7"],
        &["--baud", "9600"],
        &["--dry-run"],
        &["--audit-log", "x.jsonl"],
        &["--force-low-voltage"],
        &["--sim-voltage", "11.5"],
    ];
    for flags in cases {
        let out = scratch.diff(flags, &document, &document);
        assert_eq!(out.status.code(), Some(2), "{flags:?}");
        assert_eq!(stdout(&out), "", "{flags:?}");
        assert!(
            stderr(&out).contains(flags[0]),
            "{flags:?}: {}",
            stderr(&out)
        );
    }
}

fn refused(scratch: &Scratch, old: &Path, new: &Path, message: &str) {
    let out = scratch.diff(&[], old, new);
    assert_eq!(out.status.code(), Some(2), "{message}: {}", stderr(&out));
    assert_eq!(stdout(&out), "", "{message}");
    assert!(
        stderr(&out).contains(message),
        "wanted {message:?} in {}",
        stderr(&out)
    );
}

#[test]
fn a_file_that_cant_be_read_names_itself() {
    let scratch = Scratch::new("unreadable");
    let good = scratch.document("good.json", &sim(&["vin"]));
    let missing = scratch.0.join("missing.json");
    refused(&scratch, &missing, &good, "missing.json");
    refused(&scratch, &good, &missing, "missing.json");
    refused(&scratch, &good, &scratch.0, "obdcracker-diff-");
    refused(
        &scratch,
        &good,
        &scratch.file("bad.json", [0xFF, 0xFE, 0x7B]),
        "bad.json",
    );
    refused(
        &scratch,
        &good,
        &scratch.file("empty.json", ""),
        "empty.json",
    );
    refused(
        &scratch,
        &scratch.file("text.json", "not json"),
        &good,
        "text.json",
    );
    refused(
        &scratch,
        &good,
        &scratch.file("cut.json", r#"{"schema": 1, "com"#),
        "cut.json",
    );
    let envelope = |tail: &str| {
        format!(r#"{{"schema":1,"command":"vin","obdcracker":"0","result":[]}}{tail}"#)
    };
    refused(
        &scratch,
        &good,
        &scratch.file("tail.json", envelope(" x")),
        "tail.json",
    );
    // Whitespace after the document is fine
    let padded = scratch.file("padded.json", envelope("\n\n"));
    let out = scratch.diff(&[], &padded, &padded);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn a_schema_this_build_doesnt_read_is_refused() {
    let scratch = Scratch::new("schema");
    let good = sim(&["vin"]);
    let good_path = scratch.document("good.json", &good);
    for schema in [json!(0), json!(2), json!(u32::MAX), json!(-1), json!("1")] {
        let mut bad = good.clone();
        bad["schema"] = schema.clone();
        let path = scratch.document("bad.json", &bad);
        refused(&scratch, &path, &good_path, "bad.json");
        refused(&scratch, &good_path, &path, "bad.json");
    }
    let mut bad = good.clone();
    bad["schema"] = json!(2);
    refused(
        &scratch,
        &scratch.document("v2.json", &bad),
        &good_path,
        "isn't one this build reads",
    );
}

#[test]
fn documents_of_different_or_unsupported_commands_are_refused() {
    let scratch = Scratch::new("commands");
    let vin = scratch.document("vin.json", &sim(&["vin"]));
    let fingerprint = scratch.document("fingerprint.json", &sim(&["fingerprint"]));
    refused(
        &scratch,
        &vin,
        &fingerprint,
        "diff compares two documents of one command",
    );
    for command in ["adapter", "ports", "dtc", "diff", "nope", ""] {
        let mut document = sim(&["vin"]);
        document["command"] = json!(command);
        let path = scratch.document("other.json", &document);
        refused(
            &scratch,
            &path,
            &path,
            "fingerprint, scan, sweep, vin and read-dids",
        );
    }
}

#[test]
fn a_result_that_isnt_the_commands_is_refused_and_unknown_entries_are_ignored() {
    let scratch = Scratch::new("shape");
    let scan = sim(&["scan"]);
    let mut wrong = sim(&["fingerprint"]);
    wrong["result"] = scan["result"].clone();
    // A scan's result under another command still lacks nothing a fingerprint needs, so break it
    wrong["result"]["ecus"] = json!("7E8");
    let wrong_path = scratch.document("wrong.json", &wrong);
    refused(&scratch, &wrong_path, &wrong_path, "wrong.json");

    let mut extra = sim(&["vin"]);
    extra["added later"] = json!([1]);
    extra["result"][0]["too"] = json!(null);
    let extra_path = scratch.document("extra.json", &extra);
    let out = scratch.diff(&[], &extra_path, &extra_path);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // The same key twice is two things said, not one
    let twice = scratch.file(
        "twice.json",
        r#"{"schema":1,"command":"vin","obdcracker":"0","result":[{"source":"7E8","vin":"A","vin":"B"}]}"#,
    );
    refused(&scratch, &twice, &twice, "duplicate field");
}

#[test]
fn text_from_a_document_never_reaches_the_terminal_as_control_characters() {
    let scratch = Scratch::new("terminal");
    let mut document = sim(&["vin"]);
    document["command"] = json!("\u{1b}[31mred\u{7}");
    let path = scratch.document("esc.json", &document);
    let out = scratch.diff(&[], &path, &path);
    assert_eq!(out.status.code(), Some(2));
    let text = stderr(&out);
    assert!(text.contains("red"), "{text}");
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "{text:?}"
    );

    let old = sim(&["fingerprint"]);
    let mut new = old.clone();
    new["result"]["ecus"][0]["calids"]["value"][0] = json!("\u{1b}]0;pwned\u{7}");
    let out = scratch.diff(
        &[],
        &scratch.document("old.json", &old),
        &scratch.document("new.json", &new),
    );
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "{text:?}"
    );
}
