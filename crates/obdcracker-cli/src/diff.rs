//! `obdcracker diff OLD NEW`: what changed between two `--json` documents of one command
//! (`docs/usage.md#diff`). It opens no adapter and writes no audit log, and reads nothing but the
//! two files, which are untrusted input: parsed exactly, size-bounded, and their text made
//! printable before it reaches a terminal.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::ops::RangeInclusive;
use std::path::Path;
use std::process::ExitCode;

use obdcracker_transport::diff::{self, Change, DuplicateError, Input, ModuleId};
use obdcracker_transport::fingerprint::Fingerprint;
use obdcracker_transport::scan::Scan;
use serde::de::{DeserializeOwned, IgnoredAny};

use crate::Cli;
use crate::json::{self, DiffReport, Envelope, ReadDidsReport, SweepReport, VinReading};

const SUPPORTED: &str = "fingerprint, scan, sweep, vin and read-dids";

// A `sweep` of every DID is about 6 MB; nothing `--json` prints comes near this.
const MAX_DOCUMENT: u64 = 64 << 20;

// What comparing two documents found: the command they were of, the changes from the first to
// the second, and notes on what was compared when that isn't everything.
struct Comparison {
    command: &'static str,
    changes: Vec<Change>,
    notes: Vec<String>,
}

impl Comparison {
    fn new(command: &'static str, changes: Vec<Change>) -> Self {
        Self {
            command,
            changes,
            notes: Vec::new(),
        }
    }
}

// The refusal for a flag `diff` has no use for, if one was given: a car's adapter, profile or log,
// or `--dry-run`, which would suggest something is sent.
fn ignored_flag(cli: &Cli, audit_log_given: bool) -> Option<&'static str> {
    crate::flag_adapter_free_ignores(cli, audit_log_given)
        .or_else(|| cli.dry_run.then_some("--dry-run"))
}

pub(crate) fn run(cli: &Cli, audit_log_given: bool, old: &Path, new: &Path) -> ExitCode {
    if let Some(flag) = ignored_flag(cli, audit_log_given) {
        eprintln!("`diff` uses no adapter or audit log, so {flag} doesn't apply");
        return ExitCode::from(2);
    }
    let found = match compare(old, new) {
        Ok(found) => found,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    for note in &found.notes {
        eprintln!("note: {note}");
    }
    if cli.json {
        let report = DiffReport {
            compared: found.command,
            changes: &found.changes,
        };
        if !json::print("diff", &report) {
            return ExitCode::from(2);
        }
    } else if found.changes.is_empty() {
        println!("no changes");
    } else {
        for change in &found.changes {
            println!("{change}");
        }
    }
    // As diff(1): 1 is "they differ", so a script can tell it from a failure (2).
    ExitCode::from(u8::from(!found.changes.is_empty()))
}

// Text from a document that is going to a terminal: printable ASCII only, anything else as `\u{..}`.
fn printable(text: &str) -> String {
    text.chars()
        .fold(String::with_capacity(text.len()), |mut out, c| {
            if (' '..='~').contains(&c) {
                out.push(c);
            } else {
                let _ = write!(out, "{}", c.escape_unicode());
            }
            out
        })
}

fn read_text(path: &Path, limit: u64) -> Result<String, String> {
    let name = path.display();
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(limit.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|e| format!("{name}: {e}"))?;
    if u64::try_from(bytes.len()).is_ok_and(|len| len > limit) {
        return Err(format!(
            "{name}: over {} MiB, too large to be a document",
            limit >> 20
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("{name}: isn't UTF-8 text"))
}

// One document: where it came from, for messages, and its text.
struct Document<'a> {
    path: &'a Path,
    text: String,
}

impl Document<'_> {
    fn error(&self, what: &str) -> String {
        format!("{}: {}", self.path.display(), printable(what))
    }

    // The command it says it is of, once its envelope (schema and all) has been read.
    fn command(&self) -> Result<String, String> {
        serde_json::from_str::<Envelope<IgnoredAny>>(&self.text)
            .map(|envelope| envelope.command)
            .map_err(|e| self.error(&e.to_string()))
    }

    // Its result, read exactly as the command's type says: a field twice, or the wrong shape, is
    // an error.
    fn result<T: DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_str::<Envelope<T>>(&self.text)
            .map(|envelope| envelope.result)
            .map_err(|e| self.error(&e.to_string()))
    }
}

// The error for a document that lists something twice, naming the file that does.
fn duplicate(paths: [&Path; 2], error: &DuplicateError) -> String {
    let path = match error.input {
        Input::Old => paths[0],
        Input::New => paths[1],
    };
    format!(
        "{}: lists {} twice, so which entry counts isn't known",
        path.display(),
        printable(&error.entry)
    )
}

fn compare(old: &Path, new: &Path) -> Result<Comparison, String> {
    compare_limited(old, new, MAX_DOCUMENT)
}

fn compare_limited(old: &Path, new: &Path, limit: u64) -> Result<Comparison, String> {
    let old = Document {
        path: old,
        text: read_text(old, limit)?,
    };
    let new = Document {
        path: new,
        text: read_text(new, limit)?,
    };
    let paths = [old.path, new.path];
    let (old_command, new_command) = (old.command()?, new.command()?);
    for (document, command) in [(&old, &old_command), (&new, &new_command)] {
        if !matches!(
            command.as_str(),
            "fingerprint" | "scan" | "sweep" | "vin" | "read-dids"
        ) {
            return Err(document.error(&format!(
                "diff reads documents of {SUPPORTED}, not `{command}`"
            )));
        }
    }
    if old_command != new_command {
        return Err(format!(
            "{} is a `{old_command}` document and {} is a `{new_command}` one: diff compares two \
             documents of one command",
            old.path.display(),
            new.path.display()
        ));
    }
    match old_command.as_str() {
        "fingerprint" => {
            diff::diff_fingerprint(&old.result::<Fingerprint>()?, &new.result::<Fingerprint>()?)
                .map(|changes| Comparison::new("fingerprint", changes))
                .map_err(|e| duplicate(paths, &e))
        }
        "scan" => diff::diff_scan(&old.result::<Scan>()?, &new.result::<Scan>()?)
            .map(|changes| Comparison::new("scan", changes))
            .map_err(|e| duplicate(paths, &e)),
        "vin" => {
            let vins = |document: &Document<'_>| -> Result<Vec<(u32, String)>, String> {
                let readings = document.result::<Vec<VinReading>>()?;
                Ok(readings.into_iter().map(|r| (r.source, r.vin)).collect())
            };
            diff::diff_vins(&vins(&old)?, &vins(&new)?)
                .map(|changes| Comparison::new("vin", changes))
                .map_err(|e| duplicate(paths, &e))
        }
        "sweep" => compare_sweeps(paths, &old.result()?, &new.result()?),
        // `compare_limited` refused every other command above.
        _ => compare_reads(paths, &old.result()?, &new.result()?),
    }
}

// The DIDs a sweep read all of: its range, up to where it stopped. A DID past the stop wasn't read,
// so its absence says nothing.
fn covered(report: &SweepReport) -> Option<RangeInclusive<u16>> {
    let end = match &report.sweep.stop {
        Some(stop) => stop.at.checked_sub(1)?.min(report.last),
        None => report.last,
    };
    (report.first <= end).then_some(report.first..=end)
}

fn dids(range: &RangeInclusive<u16>) -> String {
    format!("{:04X}-{:04X}", range.start(), range.end())
}

fn compare_sweeps(
    paths: [&Path; 2],
    old: &SweepReport,
    new: &SweepReport,
) -> Result<Comparison, String> {
    if old.module != new.module {
        return Err(format!(
            "the sweeps are of different modules: {} and {}",
            printable(&ModuleId::from(&old.module).to_string()),
            printable(&ModuleId::from(&new.module).to_string())
        ));
    }
    let (Some(old_read), Some(new_read)) = (covered(old), covered(new)) else {
        return Err(
            "a sweep read no DID before it stopped, so there is nothing to compare".to_owned(),
        );
    };
    let range = *old_read.start().max(new_read.start())..=*old_read.end().min(new_read.end());
    if range.is_empty() {
        return Err(format!(
            "the sweeps have no DID in common: the old one read {} and the new one {}",
            dids(&old_read),
            dids(&new_read)
        ));
    }
    let changes = diff::diff_sweep(&old.module, &old.sweep, &new.sweep, range.clone())
        .map_err(|e| duplicate(paths, &e))?;
    let mut found = Comparison::new("sweep", changes);
    let (old_asked, new_asked) = (old.first..=old.last, new.first..=new.last);
    if range != old_asked || range != new_asked {
        found.notes.push(format!(
            "compared the DIDs {}, the range both sweeps read (the old one asked for {} and read {}, \
             the new one asked for {} and read {})",
            dids(&range),
            dids(&old_asked),
            dids(&old_read),
            dids(&new_asked),
            dids(&new_read)
        ));
    }
    Ok(found)
}

fn compare_reads(
    paths: [&Path; 2],
    old: &ReadDidsReport,
    new: &ReadDidsReport,
) -> Result<Comparison, String> {
    if old.module != new.module {
        return Err(format!(
            "the reads are of different modules: {} and {}",
            printable(&ModuleId::from(&old.module).to_string()),
            printable(&ModuleId::from(&new.module).to_string())
        ));
    }
    if old.dids != new.dids {
        let list = |dids: &[u16]| {
            dids.iter()
                .map(|did| format!("{did:04X}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        return Err(format!(
            "the reads asked for different DIDs: {} and {}",
            list(&old.dids),
            list(&new.dids)
        ));
    }
    diff::diff_dids_data(&old.module, &old.read, &new.read)
        .map(|changes| Comparison::new("read-dids", changes))
        .map_err(|e| duplicate(paths, &e))
}

#[cfg(test)]
mod tests {
    use obdcracker_transport::fingerprint::{ReadError, UdsModule};
    use obdcracker_transport::sweep::{Stop, Sweep, Why};

    use super::*;

    fn report(first: u16, last: u16, stop: Option<u16>) -> SweepReport {
        SweepReport {
            module: UdsModule::obd_engine(),
            first,
            last,
            sweep: Sweep {
                found: Vec::new(),
                stop: stop.map(|at| Stop {
                    at,
                    why: Why::Module(ReadError::NoReply),
                }),
                still_extended: None,
                out_of_step: false,
            },
        }
    }

    #[test]
    fn a_sweep_covers_its_range_up_to_where_it_stopped() {
        assert_eq!(covered(&report(0x600, 0x6FF, None)), Some(0x600..=0x6FF));
        assert_eq!(
            covered(&report(0x600, 0x6FF, Some(0x664))),
            Some(0x600..=0x663)
        );
        // Stopped at the first DID, or at DID 0: nothing was read
        assert_eq!(covered(&report(0x600, 0x6FF, Some(0x600))), None);
        assert_eq!(covered(&report(0, 0xFF, Some(0))), None);
        // A stop past the range (a hand-edited document) doesn't widen it
        assert_eq!(
            covered(&report(0x600, 0x6FF, Some(0x900))),
            Some(0x600..=0x6FF)
        );
        // The first DID alone, and the last DID of all
        assert_eq!(covered(&report(0x600, 0x600, None)), Some(0x600..=0x600));
        assert_eq!(
            covered(&report(0xFFFF, 0xFFFF, None)),
            Some(0xFFFF..=0xFFFF)
        );
        assert_eq!(
            covered(&report(0xFF00, 0xFFFF, Some(0xFFFF))),
            Some(0xFF00..=0xFFFE)
        );
        // A range turned around (hand-edited) reads nothing
        assert_eq!(covered(&report(0x700, 0x600, None)), None);
    }

    #[test]
    fn sweeps_are_compared_where_their_ranges_overlap() {
        let found = |old: &SweepReport, new: &SweepReport| {
            compare_sweeps([Path::new("old"), Path::new("new")], old, new)
                .map(|found| (found.changes, found.notes))
        };
        let (changes, notes) =
            found(&report(0x600, 0x6FF, None), &report(0x600, 0x6FF, None)).unwrap();
        assert!(changes.is_empty() && notes.is_empty());
        let (_, notes) = found(&report(0x600, 0x6FF, None), &report(0x680, 0x7FF, None)).unwrap();
        assert_eq!(
            notes,
            [
                "compared the DIDs 0680-06FF, the range both sweeps read (the old one asked for 0600-06FF and read 0600-06FF, the new one asked for 0680-07FF and read 0680-07FF)"
            ]
        );
        // Both stopped at the same DID: what they have in common is still less than they asked for
        let (_, notes) = found(
            &report(0x600, 0x700, Some(0x664)),
            &report(0x600, 0x700, Some(0x664)),
        )
        .unwrap();
        assert_eq!(
            notes,
            [
                "compared the DIDs 0600-0663, the range both sweeps read (the old one asked for 0600-0700 and read 0600-0663, the new one asked for 0600-0700 and read 0600-0663)"
            ]
        );
        // Stopped past the range, or at its last DID's successor: nothing left out
        let (_, notes) = found(
            &report(0x600, 0x700, Some(0x900)),
            &report(0x600, 0x700, None),
        )
        .unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        // Sharing exactly one DID is enough, and none is an error
        assert!(found(&report(0x600, 0x6FF, None), &report(0x6FF, 0x7FF, None)).is_ok());
        let error = found(&report(0x600, 0x6FF, None), &report(0x700, 0x7FF, None)).unwrap_err();
        assert!(error.contains("no DID in common"), "{error}");
        let error = found(
            &report(0x600, 0x6FF, Some(0x600)),
            &report(0x600, 0x6FF, None),
        )
        .unwrap_err();
        assert!(error.contains("read no DID"), "{error}");
    }

    #[test]
    fn diff_takes_two_paths_and_refuses_every_flag_that_picks_an_adapter_or_dry_run() {
        use clap::Parser;

        let parse = |words: &[&str]| {
            Cli::try_parse_from([&["obdcracker"], words, &["diff", "a", "b"]].concat())
        };
        let cli = parse(&[]).unwrap();
        let crate::Command::Diff { old, new } = &cli.command else {
            panic!("not diff");
        };
        assert_eq!((old.to_str(), new.to_str()), (Some("a"), Some("b")));
        assert_eq!(ignored_flag(&cli, false), None);
        assert_eq!(ignored_flag(&cli, true), Some("--audit-log"));
        for flag in [
            &["--dry-run"][..],
            &["--sim", "a7"],
            &["--serial", "COM3"],
            &["--tcp", "127.0.0.1:1"],
            &["--profile", "a7"],
            &["--force-low-voltage"],
        ] {
            let cli = parse(flag).unwrap();
            assert_eq!(ignored_flag(&cli, false), Some(flag[0]), "{flag:?}");
        }
        assert!(Cli::try_parse_from(["obdcracker", "diff", "a"]).is_err());
        assert!(Cli::try_parse_from(["obdcracker", "diff", "a", "b", "c"]).is_err());
    }

    #[test]
    fn text_is_made_printable() {
        assert_eq!(printable("plain 4G0 {x}"), "plain 4G0 {x}");
        assert_eq!(
            printable("\u{1b}[31m\u{202E}é\n"),
            "\\u{1b}[31m\\u{202e}\\u{e9}\\u{a}"
        );
    }

    #[test]
    fn a_file_over_the_limit_is_refused_and_one_at_it_is_read() {
        let path =
            std::env::temp_dir().join(format!("obdcracker-diff-limit-{}", std::process::id()));
        std::fs::write(&path, "0123456789").unwrap();
        assert_eq!(read_text(&path, 10).unwrap(), "0123456789");
        let error = read_text(&path, 9).unwrap_err();
        assert!(error.contains("too large"), "{error}");
        // A limit that isn't a whole number of MiB still reads what is under it
        assert!(read_text(&path, u64::MAX).is_ok());
        std::fs::remove_file(&path).unwrap();
        assert!(
            read_text(&path, 10)
                .unwrap_err()
                .contains("obdcracker-diff-limit")
        );
    }
}
