//! The `live` command: poll mode 01 PIDs and profile DIDs again and again, show each sample and
//! append it to a CSV file (`docs/usage.md#live`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use obdcracker_core::obd;
use obdcracker_core::uds;
use obdcracker_profile::{Decode, Profile};
use obdcracker_safety::{Policy, SupplyVoltage, VoltageCheck, VoltageThresholds};
use obdcracker_transport::fingerprint::ReadError;
use obdcracker_transport::live::{DidPoll, DidSample, LONGEST_INTERVAL, PollError, Poller, Sample};
use obdcracker_transport::read_dids::DidsData;
use obdcracker_transport::scan::PidValue;
use obdcracker_transport::voltage::VoltageWatch;
use obdcracker_transport::{Timing, Transport, hex};

use crate::{Cli, Command, SINGLE_FRAME_DIDS};

// The shortest interval: a poll of a few PIDs takes tens of milliseconds on an ELM327, and a
// shorter one only keeps the bus and the audit log busy.
const MIN_INTERVAL: Duration = Duration::from_millis(50);

// The first line of the CSV file. A file that already holds data must start with it, or its rows
// are another format.
const CSV_HEADER: &str = "elapsed_ms,ecu,pid_or_did,value,unit";

// Two PIDs is `01 0C 0D`: one hex digit pair each.
pub(crate) fn parse_pid(text: &str) -> Result<u8, String> {
    if text.len() == 2 && crate::is_hex(text) {
        u8::from_str_radix(text, 16).map_err(|e| e.to_string())
    } else {
        Err(format!(
            "{text:?} isn't a PID: give two hex digits, such as 0C"
        ))
    }
}

// `module:DID`. A module's name may hold spaces ("head-up display") but a colon ends the name.
pub(crate) fn parse_module_did(text: &str) -> Result<(String, u16), String> {
    let (module, did) = text.rsplit_once(':').ok_or_else(|| {
        format!(
            "{text:?} isn't MODULE:DID: give the module's name and a DID, such as transmission:F187"
        )
    })?;
    if module.is_empty() {
        return Err(format!("{text:?} has no module name before the colon"));
    }
    Ok((module.to_owned(), crate::parse_did(did)?))
}

// A whole number and a unit: `250ms`, `60s`, `2m`, `1h`. A bare number could be either.
pub(crate) fn parse_span(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let wrong = || {
        format!(
            "{text:?} isn't a time: give a whole number and a unit, such as 250ms, 60s, 2m or 1h"
        )
    };
    let number: u64 = number.parse().map_err(|_| wrong())?;
    let seconds = |factor: u64| {
        number
            .checked_mul(factor)
            .map(Duration::from_secs)
            .ok_or_else(|| format!("{text:?} is too long"))
    };
    match unit {
        "ms" => Ok(Duration::from_millis(number)),
        "s" => seconds(1),
        "m" => seconds(60),
        "h" => seconds(3600),
        _ => Err(wrong()),
    }
}

pub(crate) fn parse_interval(text: &str) -> Result<Duration, String> {
    let interval = parse_span(text)?;
    if interval < MIN_INTERVAL {
        return Err(format!(
            "an interval of {text} is below {} ms, which a poll can't keep up with",
            MIN_INTERVAL.as_millis()
        ));
    }
    if interval > LONGEST_INTERVAL {
        return Err(format!(
            "an interval of {text} is over {} s: poll less often by running the command again",
            LONGEST_INTERVAL.as_secs()
        ));
    }
    Ok(interval)
}

pub(crate) fn parse_duration(text: &str) -> Result<Duration, String> {
    let duration = parse_span(text)?;
    if duration.is_zero() {
        return Err(format!(
            "a duration of {text} polls for no time: leave --duration out to go on until Ctrl-C"
        ));
    }
    Ok(duration)
}

// One value of a sample, as the table shows it and as the CSV holds it.
struct Line {
    text: String,
    // Nothing for a line that isn't one value: a failure, a DID the reply left out.
    csv: Option<CsvRow>,
}

struct CsvRow {
    ecu: u32,
    // The PID as two hex digits, or the DID as four.
    key: String,
    value: CsvValue,
    unit: String,
}

enum CsvValue {
    Number(f32),
    Text(String),
}

impl CsvRow {
    // A number is written as it is, since nothing in it needs quoting. Everything else is quoted
    // with its quotes doubled, so a comma or a quote in a value can't change the columns.
    fn line(&self, elapsed_ms: u128) -> String {
        let value = match &self.value {
            CsvValue::Number(value) if value.is_finite() => value.to_string(),
            CsvValue::Number(value) => quoted(&value.to_string()),
            CsvValue::Text(text) => quoted(text),
        };
        format!(
            "{elapsed_ms},{},{},{value},{}\n",
            quoted(&format!("{:03X}", self.ecu)),
            quoted(&self.key),
            quoted(&self.unit)
        )
    }
}

fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\"\""))
}

// An answer that couldn't be read says so, not what it might have been.
fn failure(error: &ReadError) -> String {
    match error {
        ReadError::Undecodable { .. } => format!("malformed ({error})"),
        _ => format!("({error})"),
    }
}

// Each ECU's value for each PID. A PID an ECU doesn't list, or that no ECU lists, has no line: the
// first is every sample's silence, and the second is said once at the start.
fn pid_lines(sample: &Sample) -> Vec<Line> {
    let mut lines = Vec::new();
    for (&ecu, readings) in &sample.pids {
        for (pid, reading) in readings {
            if sample.unsupported_pids.contains(pid) {
                continue;
            }
            let key = format!("{pid:02X}");
            lines.push(match reading {
                Ok(PidValue::Quantity { value, unit }) => Line {
                    // A count has no unit, so no trailing space either.
                    text: format!("{ecu:03X} {key} {value} {unit}")
                        .trim_end()
                        .to_owned(),
                    csv: Some(CsvRow {
                        ecu,
                        key,
                        value: CsvValue::Number(*value),
                        unit: unit.to_string(),
                    }),
                },
                Ok(PidValue::Raw(bytes)) => {
                    let shown = format!("[{}]", hex(bytes));
                    Line {
                        text: format!("{ecu:03X} {key} {shown}"),
                        csv: Some(CsvRow {
                            ecu,
                            key,
                            value: CsvValue::Text(shown),
                            unit: String::new(),
                        }),
                    }
                }
                Err(ReadError::NoReply) => continue,
                Err(e) => Line {
                    text: format!("{ecu:03X} {key} {}", failure(e)),
                    csv: None,
                },
            });
        }
    }
    lines
}

// The DIDs the profile or the standard makes text, by module name.
type TextDids = BTreeMap<String, BTreeSet<u16>>;

// A DID's data for the table and the CSV: text where the DID is text and the data is printable
// text, in quotes with its quotes and backslashes escaped, else the bytes in brackets. Text with
// no delimiter of its own could read as the bytes `[FF]` (or as `(not set)`), and two different
// values must never print the same.
fn shown(did: u16, data: &[u8], texts: &BTreeSet<u16>) -> String {
    let text = if did == uds::did::VIN {
        if obd::is_vin_placeholder(data) {
            return "(not set)".to_owned();
        }
        obd::check_vin(data).ok()
    } else if texts.contains(&did) || uds::did::is_text(did) {
        uds::decode_text(data).ok().filter(|text| !text.is_empty())
    } else {
        None
    };
    text.map_or_else(|| format!("[{}]", hex(data)), |text| format!("{text:?}"))
}

fn did_list(dids: &[u16]) -> String {
    dids.iter()
        .map(|did| format!("{did:04X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// One module's answer, each DID in the order asked, then what the reply left out or couldn't split.
fn did_lines(sample: &DidSample, asked: &[(u16, Option<usize>)], texts: &TextDids) -> Vec<Line> {
    let (id, name) = (sample.module.response_id, &sample.module.name);
    let ids: Vec<u16> = asked.iter().map(|&(did, _)| did).collect();
    let found: &DidsData = match &sample.result {
        Ok(found) => found,
        Err(e) => {
            return vec![Line {
                text: format!("{id:03X} {name} {} {}", did_list(&ids), failure(e)),
                csv: None,
            }];
        }
    };
    let no_texts = BTreeSet::new();
    let texts = texts.get(name).unwrap_or(&no_texts);
    let mut lines = Vec::new();
    let mut unsplit = Vec::new();
    for &did in &ids {
        if let Some((_, data)) = found.split.iter().find(|(split, _)| *split == did) {
            let shown = shown(did, data, texts);
            lines.push(Line {
                text: format!("{id:03X} {name} {did:04X} {shown}"),
                csv: Some(CsvRow {
                    ecu: id,
                    key: format!("{did:04X}"),
                    value: CsvValue::Text(shown),
                    unit: String::new(),
                }),
            });
        } else if found.left_out.contains(&did) {
            lines.push(Line {
                text: format!("{id:03X} {name} {did:04X} (not in the reply)"),
                csv: None,
            });
        } else {
            unsplit.push(did);
        }
    }
    if !found.unsplit.is_empty() {
        lines.push(Line {
            text: format!(
                "{id:03X} {name} {} not split, as the profile gives no length for the first [{}]",
                did_list(&unsplit),
                hex(&found.unsplit)
            ),
            csv: None,
        });
    }
    lines
}

// What the sample shows: its PIDs, then each module's DIDs.
fn sample_lines(sample: &Sample, polls: &[DidPoll], texts: &TextDids) -> Vec<Line> {
    let mut lines = pid_lines(sample);
    for (answer, poll) in sample.dids.iter().zip(polls) {
        lines.extend(did_lines(answer, &poll.dids, texts));
    }
    lines
}

// The table on standard output. On a terminal it is drawn again in place; otherwise each sample is
// one line, `1250 ms | 7E8 0C 812.5 rpm | 7E8 0D 0 km/h`, so a pipe or a file can be read with a
// tool that works line by line.
struct Screen {
    redraw: bool,
    // The lines the last draw wrote.
    drawn: usize,
}

impl Screen {
    // A terminal reads cursor movements. Windows' console reads them only where it has been told
    // to, which this program doesn't do, so it gets lines too.
    fn for_stdout() -> Self {
        let redraw = io::stdout().is_terminal()
            && !cfg!(windows)
            && std::env::var_os("TERM").is_some_and(|term| term != "dumb");
        Self { redraw, drawn: 0 }
    }

    fn show(
        &mut self,
        out: &mut impl Write,
        number: u64,
        elapsed_ms: u128,
        lines: &[Line],
    ) -> io::Result<()> {
        if self.redraw {
            if self.drawn > 0 {
                // Up to the table's first line, then clear from there to the end of the screen.
                write!(out, "\x1b[{}A\r\x1b[J", self.drawn)?;
            }
            writeln!(out, "sample {number} at {elapsed_ms} ms")?;
            for line in lines {
                writeln!(out, "{}", line.text)?;
            }
            self.drawn = lines.len() + 1;
        } else {
            write!(out, "{elapsed_ms} ms")?;
            for line in lines {
                write!(out, " | {}", line.text)?;
            }
            writeln!(out)?;
        }
        out.flush()
    }

    // A line on standard error must not land inside the table, so the next draw starts below it.
    fn note(&mut self, text: &str) {
        eprintln!("{text}");
        self.drawn = 0;
    }
}

// The CSV file the samples are appended to. It is written a sample at a time, straight to the file,
// so what a Ctrl-C leaves is whole samples.
struct CsvFile {
    file: File,
}

impl CsvFile {
    // A new or empty file gets the header. One that already holds rows must be a live CSV, and ends
    // its last row, so the new rows start on a line of their own.
    fn open(path: &Path) -> Result<Self, String> {
        let wrong = |e: io::Error| format!("can't open {}: {e}", path.display());
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(wrong)?;
        let length = file.metadata().map_err(wrong)?.len();
        if length == 0 {
            file.write_all(format!("{CSV_HEADER}\n").as_bytes())
                .map_err(wrong)?;
            return Ok(Self { file });
        }
        let mut first = String::new();
        io::BufReader::new(Read::by_ref(&mut file).take(1024))
            .read_line(&mut first)
            .map_err(wrong)?;
        if first.trim_end() != CSV_HEADER {
            return Err(format!(
                "{} isn't a live CSV: its first line isn't {CSV_HEADER}. Give a new file, or remove it",
                path.display()
            ));
        }
        file.seek(SeekFrom::End(-1)).map_err(wrong)?;
        let mut last = [0];
        file.read_exact(&mut last).map_err(wrong)?;
        if last != *b"\n" {
            file.write_all(b"\n").map_err(wrong)?;
        }
        Ok(Self { file })
    }

    fn write(&mut self, elapsed_ms: u128, lines: &[Line]) -> io::Result<()> {
        let rows: String = (lines.iter())
            .filter_map(|line| line.csv.as_ref())
            .map(|row| row.line(elapsed_ms))
            .collect();
        self.file.write_all(rows.as_bytes())
    }
}

// The DIDs of the profile's module that the profile says are text.
fn text_dids(profile: Option<&Profile>, module: &str) -> BTreeSet<u16> {
    profile
        .and_then(|profile| profile.module(module))
        .map(|module| {
            module
                .dids
                .iter()
                .filter(|did| did.decode == Decode::Text)
                .map(|did| did.id)
                .collect()
        })
        .unwrap_or_default()
}

// What the poll's modules and DIDs are, from `--did`: one `DidPoll` for each module in the order
// the first `--did` for it names it, its DIDs in the order given.
fn did_polls(cli: &Cli, wanted: &[(String, u16)]) -> Result<(Vec<DidPoll>, TextDids), String> {
    let mut names: Vec<&str> = Vec::new();
    for (name, _) in wanted {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    let profile = crate::profile_of(cli);
    let mut polls = Vec::new();
    let mut texts = TextDids::new();
    for name in names {
        let (module, _) = crate::profile_module(cli, name, "live")?;
        let lengths = crate::module_did_lengths(cli, name);
        let dids = wanted
            .iter()
            .filter(|(wanted_name, _)| wanted_name == name)
            .map(|&(_, did)| {
                let length = lengths
                    .iter()
                    .find(|&&(known, _)| known == did)
                    .map(|&(_, length)| length);
                (did, length)
            })
            .collect();
        texts.insert(module.name.clone(), text_dids(profile.as_ref(), name));
        polls.push(DidPoll { module, dids });
    }
    Ok((polls, texts))
}

// What `Poller::new` refused is the command line's fault, except a refusal by the policy.
fn refused(e: &PollError) -> ExitCode {
    eprintln!("{e}");
    match e {
        PollError::Rejected(_) | PollError::Transport(_) => ExitCode::FAILURE,
        _ => ExitCode::from(2),
    }
}

// What the first poll tells that isn't a value: the PIDs no ECU lists, and the ECUs whose lists
// couldn't be read. Said when it first shows, since the first poll that finds an ECU may not be
// the first one.
#[derive(Default)]
struct Told {
    unsupported: Vec<u8>,
    bitmap_errors: BTreeMap<u32, ReadError>,
}

impl Told {
    fn notes(&mut self, sample: &Sample, screen: &mut Screen) {
        if sample.unsupported_pids != self.unsupported {
            let pids: Vec<String> = (sample.unsupported_pids.iter())
                .map(|pid| format!("{pid:02X}"))
                .collect();
            screen.note(&format!(
                "note: no ECU lists PID{} {}: {} not polled",
                if pids.len() == 1 { "" } else { "s" },
                pids.join(", "),
                if pids.len() == 1 { "it is" } else { "they are" }
            ));
            self.unsupported.clone_from(&sample.unsupported_pids);
        }
        for (ecu, e) in &sample.bitmap_errors {
            if self.bitmap_errors.get(ecu) != Some(e) {
                screen.note(&format!(
                    "warning: {ecu:03X}'s list of supported PIDs couldn't be read in full ({e}), so \
                     the PIDs it didn't list aren't polled from it"
                ));
            }
        }
        self.bitmap_errors.clone_from(&sample.bitmap_errors);
    }
}

// A run that is long (`crate::long_command`) reads the battery again after this many polls, or this
// long, whichever comes first: the polls alone would be hours apart at a long interval.
const POLLS_BETWEEN_VOLTAGE_CHECKS: u32 = 50;
const LONGEST_BETWEEN_VOLTAGE_CHECKS: Duration = Duration::from_secs(30);

// Reads the supply voltage again now and then during a long run, as the sweep does.
struct SupplyWatch {
    watch: VoltageWatch,
    // The longest between two readings.
    longest: Duration,
    polls: u32,
    last: Instant,
}

impl SupplyWatch {
    fn new(watch: VoltageWatch) -> Self {
        Self {
            watch,
            longest: LONGEST_BETWEEN_VOLTAGE_CHECKS,
            polls: 0,
            last: Instant::now(),
        }
    }

    fn polled(&mut self) {
        self.polls += 1;
    }

    // When a reading is due at the latest, so that a long wait for the next poll can be cut short.
    fn deadline(&self) -> Instant {
        self.last + self.longest
    }

    // The voltage if a reading is due and it is too low. One that is unknown, or couldn't be read,
    // doesn't stop the run: an adapter that can't measure it would never finish one.
    fn too_low<T: Transport>(&mut self, transport: &mut T) -> Option<SupplyVoltage> {
        if self.polls < POLLS_BETWEEN_VOLTAGE_CHECKS && self.last.elapsed() < self.longest {
            return None;
        }
        self.polls = 0;
        self.last = Instant::now();
        let supply = transport.supply_voltage().ok()?;
        (self.watch.thresholds.check(supply) == VoltageCheck::TooLow).then_some(supply)
    }
}

// Waits until `due`, reading the voltage when `supply` says one is due, also in the middle of a long
// wait, and before the poll that follows it. The voltage if it was too low, which ends the wait.
fn wait_until<T: Transport>(
    transport: &mut T,
    due: Instant,
    supply: &mut Option<SupplyWatch>,
) -> Option<SupplyVoltage> {
    if let Some(watch) = supply {
        watch.polled();
    }
    loop {
        if let Some(low) = supply.as_mut().and_then(|watch| watch.too_low(transport)) {
            return Some(low);
        }
        let now = Instant::now();
        if now >= due {
            return None;
        }
        let wake = supply
            .as_ref()
            .map_or(due, |watch| due.min(watch.deadline()));
        std::thread::sleep(wake.saturating_duration_since(now));
    }
}

const OUT_OF_STEP: &str = "stopped: a request went unanswered, so a late reply could be taken for \
     a later poll's value, and no value after it can be trusted. Check the ignition and the \
     adapter, then run the command again; the rows already written are kept";

// Polls until `--duration` is over or Ctrl-C ends the process, which keeps what the CSV already
// holds. The audit log gets every request, however long that runs.
pub(crate) fn run<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    elm: bool,
) -> ExitCode {
    let Command::Live {
        pid,
        did,
        interval,
        duration,
        csv,
    } = &cli.command
    else {
        unreachable!()
    };
    if cli.json {
        eprintln!("`live` prints text and CSV, so --json doesn't apply");
        return ExitCode::from(2);
    }
    if cli.dry_run && csv.is_some() {
        eprintln!("a dry run sends nothing, so there is nothing to write to --csv");
        return ExitCode::from(2);
    }
    let policy = match crate::policy(cli) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let (polls, texts) = match did_polls(cli, did) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut poller = match Poller::new(&policy, pid, polls.clone()) {
        Ok(poller) => poller,
        Err(e) => return refused(&e),
    };
    if let Err(code) = crate::vin_cmd::check_profile(cli, transport, timing) {
        return code;
    }
    let mut csv = match csv.as_deref().map(CsvFile::open).transpose() {
        Ok(csv) => csv,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if cli.dry_run {
        return dry_run(transport, timing, &mut poller);
    }
    if let Err(code) = warm_up(elm, transport, timing, &policy, pid, &polls, cli) {
        return code;
    }
    let plan = Plan {
        polls: &polls,
        texts: &texts,
        interval: *interval,
        duration: *duration,
        watch: crate::voltage_watch(cli),
    };
    poll_until_done(transport, timing, &mut poller, &plan, csv.as_mut())
}

// A poll with only DIDs sends nothing before its first `22` request, and an ELM327 sends one over
// 7 bytes in segments only once an earlier request has shown that it echoes each character. So the
// first module with a request that long is read for its first DID alone, as `read-dids` does. A
// poll with PIDs sends the bitmaps first.
fn warm_up<T: Transport>(
    elm: bool,
    transport: &mut T,
    timing: Timing,
    policy: &Policy,
    pids: &[u8],
    polls: &[DidPoll],
    cli: &Cli,
) -> Result<(), ExitCode> {
    if !elm || !pids.is_empty() {
        return Ok(());
    }
    let Some(poll) = polls
        .iter()
        .find(|poll| poll.dids.len() > SINGLE_FRAME_DIDS)
    else {
        return Ok(());
    };
    let lengths = crate::module_did_lengths(cli, &poll.module.name);
    let length_of = |did: u16| {
        lengths
            .iter()
            .find(|&&(known, _)| known == did)
            .map(|&(_, length)| length)
    };
    let dids: Vec<u16> = poll.dids.iter().map(|&(did, _)| did).collect();
    crate::elm_warm_up(transport, policy, &poll.module, &dids, length_of, timing)
}

// One poll through the dry run's transport, which prints the frames it is given and answers
// nothing, then the PID requests a live poll sends once the bitmaps are read.
fn dry_run<T: Transport>(transport: &mut T, timing: Timing, poller: &mut Poller) -> ExitCode {
    if let Err(e) = poller.poll(transport, timing) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    for request in poller.pid_requests() {
        if let Err(e) = transport.send(request) {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    }
    println!("dry run: nothing was sent");
    println!(
        "a live poll sends the bitmap request (01 00, and 01 20, 01 40, ... while an ECU says the \
         next is supported) once, then on every poll each PID request above to the ECUs that list \
         one of its PIDs (PIDs no ECU lists are left out), then each module's DID request"
    );
    println!(
        "it goes on until --duration is over or Ctrl-C, one poll every --interval or as soon as a \
         slower poll is over"
    );
    ExitCode::SUCCESS
}

// What a run polls and shows, and when it ends.
struct Plan<'a> {
    polls: &'a [DidPoll],
    texts: &'a TextDids,
    interval: Duration,
    duration: Option<Duration>,
    // Only a long run is watched.
    watch: Option<VoltageWatch>,
}

fn poll_until_done<T: Transport>(
    transport: &mut T,
    timing: Timing,
    poller: &mut Poller,
    plan: &Plan,
    mut csv: Option<&mut CsvFile>,
) -> ExitCode {
    let Plan {
        polls,
        texts,
        interval,
        duration,
        watch,
    } = *plan;
    let mut supply = watch.map(SupplyWatch::new);
    let started = Instant::now();
    // A duration too long for the clock never ends.
    let end = duration.and_then(|duration| started.checked_add(duration));
    let mut screen = Screen::for_stdout();
    let mut told = Told::default();
    let mut samples = 0_u64;
    let mut stdout = io::stdout().lock();
    loop {
        let sample = match poller.poll(transport, timing) {
            Ok(sample) => sample,
            Err(e @ PollError::NothingSupported(_)) => {
                eprintln!("{e}, so there is nothing to poll");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        told.notes(&sample, &mut screen);
        if sample.out_of_step {
            eprintln!("{OUT_OF_STEP}");
            return ExitCode::FAILURE;
        }
        samples += 1;
        let elapsed = sample
            .started
            .saturating_duration_since(started)
            .as_millis();
        let lines = sample_lines(&sample, polls, texts);
        if let Err(e) = screen.show(&mut stdout, samples, elapsed, &lines) {
            // A pipe closed by the reader is how `| head` ends it.
            if e.kind() != io::ErrorKind::BrokenPipe {
                eprintln!("can't write the table: {e}");
            }
            return ExitCode::FAILURE;
        }
        if let Some(file) = csv.as_deref_mut()
            && let Err(e) = file.write(elapsed, &lines)
        {
            eprintln!("can't write the CSV file: {e}");
            return ExitCode::FAILURE;
        }
        let now = Instant::now();
        let due = obdcracker_transport::live::next_due(sample.started, interval, now);
        if end.is_some_and(|end| due >= end) {
            eprintln!("done: {samples} samples");
            return ExitCode::SUCCESS;
        }
        if let Some(low) = wait_until(transport, due, &mut supply) {
            eprintln!(
                "stopped: the supply voltage fell to {low}, below {}: with the engine off, going on \
                 can flatten the battery. The rows already written are kept. Charge it or run the \
                 engine and run the command again, or give --force-low-voltage to go on without \
                 this check",
                SupplyVoltage::Known {
                    millivolts: VoltageThresholds::DEFAULT.refuse_mv
                }
            );
            return ExitCode::FAILURE;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obdcracker_transport::fingerprint::UdsModule;

    // A simulated car whose battery is `millivolts`.
    fn car(millivolts: u32) -> obdcracker_sim::SimBus {
        let mut car = obdcracker_sim::SimBus::builtin("a7").unwrap();
        car.set_supply_voltage(SupplyVoltage::Known { millivolts });
        car
    }

    fn watch(longest: Duration) -> SupplyWatch {
        let mut watch = SupplyWatch::new(VoltageWatch::default());
        watch.longest = longest;
        watch
    }

    #[test]
    fn a_long_wait_is_cut_short_to_read_the_battery() {
        // The next poll is an hour away; the reading is due in 20 ms, and the battery is low.
        let mut supply = Some(watch(Duration::from_millis(20)));
        let started = Instant::now();
        let low = wait_until(
            &mut car(11_000),
            started + Duration::from_secs(3600),
            &mut supply,
        );
        assert_eq!(low, Some(SupplyVoltage::Known { millivolts: 11_000 }));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_wait_with_a_good_battery_lasts_until_the_poll_is_due() {
        let mut supply = Some(watch(Duration::from_millis(10)));
        let due = Instant::now() + Duration::from_millis(100);
        assert_eq!(wait_until(&mut car(12_600), due, &mut supply), None);
        assert!(Instant::now() >= due);
        // Without a watch it is only a wait.
        let due = Instant::now() + Duration::from_millis(30);
        assert_eq!(wait_until(&mut car(11_000), due, &mut None), None);
        assert!(Instant::now() >= due);
    }

    #[test]
    fn a_reading_is_also_due_after_fifty_polls_and_an_unknown_voltage_never_stops() {
        let mut supply = Some(watch(Duration::from_secs(3600)));
        let mut low = car(11_000);
        // 49 waits that are already over read nothing; the 50th does.
        for _ in 0..49 {
            assert_eq!(wait_until(&mut low, Instant::now(), &mut supply), None);
        }
        assert_eq!(
            wait_until(&mut low, Instant::now(), &mut supply),
            Some(SupplyVoltage::Known { millivolts: 11_000 })
        );
        let mut unknown = car(11_000);
        unknown.set_supply_voltage(SupplyVoltage::Unknown);
        let mut supply = Some(watch(Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(wait_until(&mut unknown, Instant::now(), &mut supply), None);
    }

    #[test]
    fn a_pid_is_two_hex_digits() {
        assert_eq!(parse_pid("0C"), Ok(0x0C));
        assert_eq!(parse_pid("0c"), Ok(0x0C));
        assert_eq!(parse_pid("FF"), Ok(0xFF));
        // Neither a sign nor a missing or extra digit gets in: `from_str_radix` takes "+C".
        for bad in ["", "C", "+C", "-1", "0G", "100", " 0C", "0C "] {
            assert!(parse_pid(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_did_names_its_module_and_has_four_hex_digits() {
        assert_eq!(
            parse_module_did("transmission:F187"),
            Ok(("transmission".to_owned(), 0xF187))
        );
        assert_eq!(
            parse_module_did("head-up display:0600"),
            Ok(("head-up display".to_owned(), 0x0600))
        );
        for bad in [
            "F187",
            ":F187",
            "engine:",
            "engine:F18",
            "engine:+187",
            "engine:F1870",
        ] {
            assert!(parse_module_did(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_time_is_a_whole_number_and_a_unit() {
        assert_eq!(parse_span("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_span("60s"), Ok(Duration::from_secs(60)));
        assert_eq!(parse_span("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_span("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_span("0s"), Ok(Duration::ZERO));
        // No unit, no number, a fraction, a sign, or a unit this doesn't know; and a number too
        // big for seconds.
        for bad in [
            "",
            "250",
            "ms",
            "1.5s",
            "+5s",
            "-5s",
            "5 s",
            "5S",
            "5d",
            " 5s",
            "99999999999999999999s",
            "18446744073709551615h",
        ] {
            assert!(parse_span(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_interval_has_a_floor_and_a_ceiling_and_the_duration_isnt_zero() {
        assert_eq!(parse_interval("50ms"), Ok(Duration::from_millis(50)));
        assert!(parse_interval("49ms").is_err());
        assert!(parse_interval("0ms").is_err());
        assert_eq!(parse_interval("1h"), Ok(LONGEST_INTERVAL));
        assert!(parse_interval("3601s").is_err());
        assert_eq!(parse_duration("1ms"), Ok(Duration::from_millis(1)));
        assert!(parse_duration("0ms").is_err());
        assert!(parse_duration("0h").is_err());
    }

    fn row(value: CsvValue, key: &str, unit: &str) -> String {
        CsvRow {
            ecu: 0x7E8,
            key: key.to_owned(),
            value,
            unit: unit.to_owned(),
        }
        .line(1250)
    }

    #[test]
    fn a_number_is_written_bare_and_anything_else_is_quoted_with_its_quotes_doubled() {
        assert_eq!(
            row(CsvValue::Number(812.5), "0C", "rpm"),
            "1250,\"7E8\",\"0C\",812.5,\"rpm\"\n"
        );
        assert_eq!(
            row(CsvValue::Number(-40.0), "05", "°C"),
            "1250,\"7E8\",\"05\",-40,\"°C\"\n"
        );
        assert_eq!(
            row(CsvValue::Number(7.0), "0D", ""),
            "1250,\"7E8\",\"0D\",7,\"\"\n"
        );
        assert_eq!(
            row(CsvValue::Text("a,b \"c\"".to_owned()), "F187", ""),
            "1250,\"7E8\",\"F187\",\"a,b \"\"c\"\"\",\"\"\n"
        );
        // A line break in a quoted field stays in it.
        assert_eq!(
            row(CsvValue::Text("a\nb".to_owned()), "F187", ""),
            "1250,\"7E8\",\"F187\",\"a\nb\",\"\"\n"
        );
        // JSON-style infinities aren't numbers.
        assert_eq!(
            row(CsvValue::Number(f32::INFINITY), "0C", "rpm"),
            "1250,\"7E8\",\"0C\",\"inf\",\"rpm\"\n"
        );
    }

    fn line(text: &str) -> Line {
        Line {
            text: text.to_owned(),
            csv: None,
        }
    }

    #[test]
    fn off_a_terminal_each_sample_is_one_line() {
        let mut screen = Screen {
            redraw: false,
            drawn: 0,
        };
        let mut out = Vec::new();
        let lines = [line("7E8 0C 812.5 rpm"), line("7E8 0D 0 km/h")];
        screen.show(&mut out, 1, 0, &lines).unwrap();
        screen.show(&mut out, 2, 250, &lines[..1]).unwrap();
        screen.show(&mut out, 3, 500, &[]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0 ms | 7E8 0C 812.5 rpm | 7E8 0D 0 km/h\n250 ms | 7E8 0C 812.5 rpm\n500 ms\n"
        );
    }

    #[test]
    fn on_a_terminal_the_table_is_drawn_again_over_itself() {
        let mut screen = Screen {
            redraw: true,
            drawn: 0,
        };
        let mut out = Vec::new();
        screen
            .show(&mut out, 1, 0, &[line("a"), line("b")])
            .unwrap();
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "sample 1 at 0 ms\na\nb\n"
        );
        out.clear();
        // Up three lines (the heading and two), clear, then the new table, which is shorter.
        screen.show(&mut out, 2, 250, &[line("c")]).unwrap();
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "\x1b[3A\r\x1b[Jsample 2 at 250 ms\nc\n"
        );
        out.clear();
        screen.show(&mut out, 3, 500, &[line("d")]).unwrap();
        assert!(
            String::from_utf8(out.clone())
                .unwrap()
                .starts_with("\x1b[2A")
        );
        // Something printed on standard error between draws starts the next one below it.
        screen.drawn = 0;
        out.clear();
        screen.show(&mut out, 4, 750, &[line("e")]).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "sample 4 at 750 ms\ne\n");
    }

    #[test]
    fn a_did_is_text_only_where_it_is_text_and_printable() {
        let texts = BTreeSet::from([0xF1A3]);
        // The standard makes F187 text, whatever the profile says.
        assert_eq!(
            shown(0xF187, b"4G0927158Q ", &BTreeSet::new()),
            "\"4G0927158Q\""
        );
        assert_eq!(shown(0xF1A3, b"X14", &texts), "\"X14\"");
        // Binary data, an empty (all padding) value, and a DID the profile doesn't call text.
        assert_eq!(shown(0xF187, &[0x00, 0xFF], &texts), "[00 FF]");
        assert_eq!(shown(0xF187, b"   ", &texts), "[20 20 20]");
        assert_eq!(shown(0x0600, b"abc", &texts), "[61 62 63]");
        // The VIN is a VIN, the placeholder, or bytes: not any printable text.
        assert_eq!(
            shown(0xF190, b"WAU2MBFC6EN093415", &texts),
            "\"WAU2MBFC6EN093415\""
        );
        assert_eq!(shown(0xF190, b"-----------------", &texts), "(not set)");
        assert_eq!(shown(0xF190, b"abc", &texts), "[61 62 63]");
    }

    #[test]
    fn text_that_looks_like_bytes_or_a_placeholder_prints_differently_from_them() {
        let texts = BTreeSet::from([0xF188]);
        // The text `[FF]` and the byte FF, the text `(not set)` and a VIN that is none.
        assert_eq!(shown(0xF188, b"[FF]", &texts), "\"[FF]\"");
        assert_eq!(shown(0xF188, &[0xFF], &texts), "[FF]");
        assert_eq!(shown(0xF188, b"(not set)", &texts), "\"(not set)\"");
        assert_eq!(shown(0xF190, b"-----------------", &texts), "(not set)");
        // A quote and a backslash are escaped, so the text can't end its own quotes early.
        assert_eq!(shown(0xF188, b"a\"b\\", &texts), "\"a\\\"b\\\\\"");
    }

    #[test]
    fn a_module_that_failed_is_one_line_and_no_csv_row() {
        let sample = DidSample {
            module: UdsModule {
                name: "transmission".to_owned(),
                request_id: 0x7E1,
                response_id: 0x7E9,
            },
            result: Err(ReadError::Undecodable {
                error: obdcracker_core::response::Error::Malformed,
                reply: vec![0x62, 0xF1],
            }),
        };
        let lines = did_lines(
            &sample,
            &[(0xF187, None), (0xF189, Some(4))],
            &TextDids::new(),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].csv.is_none());
        assert!(
            lines[0]
                .text
                .starts_with("7E9 transmission F187 F189 malformed ("),
            "{}",
            lines[0].text
        );
    }
}
