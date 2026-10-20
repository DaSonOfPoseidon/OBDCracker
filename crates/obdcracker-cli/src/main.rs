//! The `obdcracker` command-line tool.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use obdcracker_core::obd;
use obdcracker_core::response::{Error as ReplyError, Nrc};
use obdcracker_core::uds::DiagnosticSession;
use obdcracker_profile::{Decode, DidSession, Profile, Protocol};
use obdcracker_safety::{ModuleIds, Policy, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::discover;
use obdcracker_transport::elm::Elm;
use obdcracker_transport::fingerprint::{self, DidValue, Fingerprint, ReadError, UdsModule};
use obdcracker_transport::link::{Link, SerialLink, TcpLink};
use obdcracker_transport::scan::{
    self, DidFormat, ExtraDid, PidValue, Scan, ScanModule, ScanOptions,
};
use obdcracker_transport::sweep::{self, SweepOptions};
use obdcracker_transport::{
    Audited, DryRun, Expect, S3, Timing, Transport, exchange, hex, log_failure,
};

// OBDLink USB adapters' rate.
const DEFAULT_BAUD: u32 = 115_200;
// How long to wait for a Wi-Fi adapter to accept the connection.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Talk to a car's diagnostic bus through an OBD2 adapter"
)]
struct Cli {
    /// Use an ELM327/STN adapter on this serial port (e.g. /dev/ttyUSB0, COM3)
    #[arg(long, value_name = "PORT", group = "adapter")]
    serial: Option<PathBuf>,

    /// The serial port's baud rate [default: 115200, for `OBDLink` adapters; ELM327 clones use
    /// 38400, 9600, 230400 or 500000]
    #[arg(long, requires = "serial", conflicts_with_all = ["tcp", "dry_run", "sim"])]
    baud: Option<u32>,

    /// Use a Wi-Fi ELM327/STN adapter at this address (e.g. 192.168.0.10:35000)
    #[arg(long, value_name = "HOST:PORT", group = "adapter")]
    tcp: Option<String>,

    /// Print the frames that would be sent without opening any adapter
    #[arg(long, group = "adapter")]
    dry_run: bool,

    /// Talk to a simulated car with this vehicle profile instead of an adapter
    #[arg(long, value_name = "PROFILE", group = "adapter",
          value_parser = PossibleValuesParser::new(Profile::BUILTIN))]
    sim: Option<String>,

    /// The vehicle profile that gives module addresses [default: the --sim profile, else the
    /// OBD-II engine and transmission IDs]
    #[arg(long, value_name = "PROFILE",
          value_parser = PossibleValuesParser::new(Profile::BUILTIN))]
    profile: Option<String>,

    /// Append every request and reply to this JSON Lines file
    #[arg(long, default_value = "obdcracker.audit.jsonl")]
    audit_log: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read the VIN from every emissions ECU (OBD-II mode 09 PID 02)
    Vin,
    /// Identify the engine and transmission software: calibration IDs and CVNs (mode 09 PIDs 04
    /// and 06), then part numbers and versions (UDS 0x22 F187, F188, F189, F191, F19E)
    Fingerprint,
    /// Read everything the default diagnostic session allows: every supported mode 01 PID, mode
    /// 09 PIDs 00 and 0A and mode 03 DTCs from each emissions ECU, then each profile module's
    /// identification and profile DIDs and its DTCs that are failed, pending, confirmed or failed
    /// since the last clear (UDS 0x22 and 0x19)
    Scan {
        /// First look for modules the profile doesn't list: read the part number (UDS 0x22 F187)
        /// from each request ID in the profile's discovery range (on the A7, 0x700 to 0x769),
        /// then scan those that answer too
        #[arg(long)]
        discover: bool,
        /// Also read the DIDs the profile says need the extended diagnostic session: each module
        /// that has any is switched to it (UDS 0x10 03) after its other reads, kept there with
        /// a tester-present request (0x3E 00), and switched back (0x10 01)
        #[arg(long)]
        extended: bool,
        /// With --discover, then look further: each request ID after the discovery range (on the
        /// A7, 0x76A to 0x795) that no module found or listed answers on, such as the MMI's.
        /// These are the first range's reply IDs, so a module that stayed silent there may own one
        #[arg(long, requires = "discover")]
        wide: bool,
    },
    /// Look for the DIDs a module has: read each DID in a range (UDS 0x22), one request each, and
    /// list those it answers. Reads only. Needs a profile (--profile or --sim) that lists the
    /// module
    Sweep {
        /// The module's name in the profile, such as "head-up display"
        #[arg(long)]
        module: String,
        /// The DIDs to read, as hex: FIRST-LAST, such as 0600-06FF. A whole range is 65536 reads
        #[arg(long, value_parser = parse_did_range)]
        range: (u16, u16),
        /// Read in the extended diagnostic session: switch the module to it first (UDS 0x10 03),
        /// keep it there with a tester-present request (0x3E 00), and switch it back (0x10 01)
        #[arg(long)]
        extended: bool,
    },
    /// List this computer's serial ports
    Ports,
    /// Show what the adapter is and the voltage it sees; sends nothing on the bus
    Adapter,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Ports = cli.command {
        return ports();
    }
    if let Some(port) = &cli.serial {
        match SerialLink::open(port, cli.baud.unwrap_or(DEFAULT_BAUD)) {
            Ok(link) => adapter(&cli, link),
            Err(e) => {
                eprintln!("can't open {}: {e}", port.display());
                ExitCode::FAILURE
            }
        }
    } else if let Some(addr) = &cli.tcp {
        eprintln!(
            "warning: a Wi-Fi adapter left plugged in drains the battery, and anyone in range can \
             connect to it. Unplug it when you're done."
        );
        match TcpLink::connect(addr.as_str(), TCP_CONNECT_TIMEOUT) {
            Ok(link) => adapter(&cli, link),
            Err(e) => {
                eprintln!("can't connect to {addr}: {e}");
                ExitCode::FAILURE
            }
        }
    } else if let Command::Adapter = cli.command {
        eprintln!("`adapter` needs a real adapter: use --serial <PORT> or --tcp <HOST:PORT>");
        ExitCode::from(2)
    } else if let Some(profile) = &cli.sim {
        match SimBus::builtin(profile) {
            Ok(car) => run(&cli, car, "sim", Timing::default()),
            Err(e) => {
                eprintln!("can't build the simulated car: {e}");
                ExitCode::FAILURE
            }
        }
    } else if cli.dry_run {
        run(
            &cli,
            DryRun::new(std::io::stdout()),
            "dry-run",
            Timing::default(),
        )
    } else {
        eprintln!(
            "no adapter given; use --serial <PORT> or --tcp <HOST:PORT>, or try --dry-run or \
             --sim <PROFILE>"
        );
        ExitCode::from(2)
    }
}

fn ports() -> ExitCode {
    match SerialLink::available_ports() {
        Ok(ports) => {
            for port in ports {
                println!("{}", port.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("can't list serial ports: {e}");
            ExitCode::FAILURE
        }
    }
}

fn adapter<L: Link>(cli: &Cli, link: L) -> ExitCode {
    let kind = link.kind();
    let mut elm = match Elm::connect_reporting(link) {
        Ok(elm) => elm,
        Err(failed) => {
            // What the adapter was sent and said before it failed is evidence too.
            if let Err(e) = log_failure(
                &cli.audit_log,
                kind.name(),
                failed.events,
                "connect",
                &failed.error,
            ) {
                eprintln!("can't write audit log {}: {e}", cli.audit_log.display());
            }
            eprintln!("{}", failed.error);
            return ExitCode::FAILURE;
        }
    };
    if let Command::Adapter = cli.command {
        return match elm.info() {
            Ok(info) => {
                println!("adapter: {}", info.id);
                if let Some(stn) = info.stn {
                    println!("STN chip: {stn}");
                }
                println!("voltage: {}", info.voltage.as_deref().unwrap_or("unknown"));
                println!("link: {}", kind.name());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    run(cli, elm, kind.name(), Elm::<L>::timing())
}

fn run<T: Transport>(cli: &Cli, transport: T, link: &str, timing: Timing) -> ExitCode {
    let mut transport = match Audited::open(&cli.audit_log, transport, link) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("can't open audit log {}: {e}", cli.audit_log.display());
            return ExitCode::FAILURE;
        }
    };
    if let Command::Fingerprint = cli.command {
        return run_fingerprint(cli, &mut transport, timing);
    }
    if let Command::Scan {
        discover,
        wide,
        extended,
    } = cli.command
    {
        return run_scan(cli, &mut transport, timing, discover, wide, extended);
    }
    if let Command::Sweep {
        module,
        range,
        extended,
    } = &cli.command
    {
        return run_sweep(cli, &mut transport, timing, module, *range, *extended);
    }
    let (target, payload, expect) = match cli.command {
        Command::Vin => (
            Target::ObdFunctional,
            obd::vehicle_info(0x02),
            Expect::ObdEcus,
        ),
        // Handled before any transport is opened, or above.
        Command::Ports
        | Command::Adapter
        | Command::Fingerprint
        | Command::Scan { .. }
        | Command::Sweep { .. } => {
            unreachable!()
        }
    };
    let request = match Policy::read_only().approve(target, &payload) {
        Ok(request) => request,
        Err(rejection) => {
            eprintln!("safety policy {rejection}");
            return ExitCode::FAILURE;
        }
    };
    let replies = match exchange(&mut transport, &request, expect, timing) {
        Ok(replies) => replies,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if replies.is_empty() {
        if cli.dry_run {
            println!("dry run: nothing was sent");
            return ExitCode::SUCCESS;
        }
        eprintln!("no ECU answered");
        return ExitCode::FAILURE;
    }
    // Each ECU's reply is decoded on its own, so one bad reply doesn't hide the others.
    let mut status = ExitCode::SUCCESS;
    for reply in replies {
        match obd::decode_vin(&reply.payload) {
            Ok(vin) => println!("{:03X} {vin}", reply.source),
            Err(e) => {
                eprintln!("{:03X} {e}: {}", reply.source, hex(&reply.payload));
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

// The read-only policy, narrowed to the profile's modules when there is one, so requests go only
// to its request IDs and the adapter shows only each module's own replies.
fn policy(cli: &Cli) -> Result<Policy, String> {
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Ok(Policy::read_only());
    };
    let profile = Profile::builtin(name).map_err(|e| format!("profile {name}: {e}"))?;
    profile
        .narrow(Policy::read_only())
        .map_err(|e| format!("profile {name}: {e}"))
}

// The engine and transmission modules from the profile, or their OBD-II IDs without one.
fn fingerprint_modules(cli: &Cli) -> Result<Vec<UdsModule>, String> {
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Ok(vec![UdsModule::obd_engine(), UdsModule::obd_transmission()]);
    };
    let profile = Profile::builtin(name).map_err(|e| format!("profile {name}: {e}"))?;
    ["engine", "transmission"]
        .into_iter()
        .map(|wanted| {
            let module = profile
                .module(wanted)
                .ok_or_else(|| format!("profile {name} has no {wanted} module"))?;
            // Extended addressing and other protocols need support the transports don't have yet.
            if module.protocol != Protocol::Uds || module.extended_address.is_some() {
                return Err(format!(
                    "profile {name}'s {wanted} module isn't plain UDS, which fingerprint needs"
                ));
            }
            Ok(UdsModule {
                name: module.name.clone(),
                request_id: module.request_id,
                response_id: module.response_id,
            })
        })
        .collect()
}

fn run_fingerprint<T: Transport>(cli: &Cli, transport: &mut T, timing: Timing) -> ExitCode {
    let (modules, policy) = match fingerprint_modules(cli).and_then(|m| Ok((m, policy(cli)?))) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match fingerprint::fingerprint(transport, &policy, &modules, timing) {
        Ok(_) if cli.dry_run => {
            println!("dry run: nothing was sent");
            ExitCode::SUCCESS
        }
        Ok(found) => {
            print_fingerprint(&found);
            if found.anything_answered() {
                ExitCode::SUCCESS
            } else {
                eprintln!("nothing answered: check the ignition and the adapter's connection");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn print_fingerprint(found: &Fingerprint) {
    if found.ecus.is_empty() {
        println!("no ECU answered mode 09 PIDs 04 and 06");
    }
    for ecu in &found.ecus {
        match &ecu.calids {
            Ok(calids) => {
                let calids: Vec<_> = calids
                    .iter()
                    .map(|calid| calid.as_deref().unwrap_or("(empty)"))
                    .collect();
                println!("{:03X} CALID {}", ecu.source, calids.join(", "));
            }
            Err(e) => println!("{:03X} CALID ({e})", ecu.source),
        }
        match &ecu.cvns {
            Ok(cvns) => {
                let cvns: Vec<_> = cvns.iter().map(ToString::to_string).collect();
                println!("{:03X} CVN   {}", ecu.source, cvns.join(", "));
            }
            Err(e) => println!("{:03X} CVN   ({e})", ecu.source),
        }
    }
    for module in &found.modules {
        print_dids(module.response_id, &module.name, &module.dids);
    }
}

// `FIRST-LAST`, each up to four hex digits, FIRST no later than LAST.
fn parse_did_range(text: &str) -> Result<(u16, u16), String> {
    let did = |part: &str| {
        // Only hex digits: from_str_radix also takes a leading `+`.
        if (1..=4).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_hexdigit()) {
            u16::from_str_radix(part, 16).map_err(|e| e.to_string())
        } else {
            Err(format!("{part:?} isn't a DID: up to four hex digits"))
        }
    };
    let (first, last) = text
        .split_once('-')
        .ok_or_else(|| format!("{text:?} isn't a range: give FIRST-LAST, such as 0600-06FF"))?;
    let (first, last) = (did(first)?, did(last)?);
    if first > last {
        return Err(format!(
            "the range starts at {first:04X}, after its end {last:04X}"
        ));
    }
    Ok((first, last))
}

// Reads each DID in the range from one profile module and lists those it has.
fn run_sweep<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    name: &str,
    (first, last): (u16, u16),
    extended: bool,
) -> ExitCode {
    let usage = |e: String| {
        eprintln!("{e}");
        ExitCode::from(2)
    };
    let Some(profile_name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return usage("sweep needs a profile that lists the module (--profile or --sim)".into());
    };
    let profile = match Profile::builtin(profile_name) {
        Ok(profile) => profile,
        Err(e) => return usage(format!("profile {profile_name}: {e}")),
    };
    let Some(module) = profile.module(name) else {
        return usage(format!(
            "profile {profile_name} has no module named {name:?}"
        ));
    };
    if module.protocol != Protocol::Uds || module.extended_address.is_some() {
        return usage(format!("{name} isn't plain UDS, which sweep needs"));
    }
    let module = UdsModule {
        name: module.name.clone(),
        request_id: module.request_id,
        response_id: module.response_id,
    };
    let policy = match policy(cli) {
        Ok(policy) => policy,
        Err(e) => return usage(e),
    };
    let count = u32::from(last) - u32::from(first) + 1;
    // About what an ELM adapter takes per refused read.
    eprintln!(
        "sweep: {count} reads of {} ({:03X}), about {} min",
        module.name,
        module.request_id,
        (count * 50).div_ceil(60_000)
    );
    let mut options = SweepOptions::default();
    if extended {
        options.extended = Some(S3::default());
    }
    let progress = |did: u16| {
        if did & 0xFF == 0xFF && did != last {
            eprintln!("sweep: read up to {did:04X}");
        }
    };
    let found = match sweep::sweep_dids_reporting(
        transport,
        &policy,
        &module,
        first..=last,
        timing,
        &options,
        progress,
    ) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if cli.dry_run {
        println!("dry run: nothing was sent");
        // Nothing answers a dry run, so the sweep stopped after a few reads.
        println!(
            "a live sweep reads every DID from 22 {first:04X} to 22 {last:04X}, one request each, \
             and stops early if the module stops answering"
        );
        return ExitCode::SUCCESS;
    }
    print_sweep(&module, &found, last)
}

// Lists what a sweep found, and how to resume one that stopped.
fn print_sweep(module: &UdsModule, found: &sweep::Sweep, last: u16) -> ExitCode {
    for (did, value) in &found.found {
        match value {
            Ok(data) => println!(
                "{:03X} {} {did:04X} [{}]",
                module.response_id,
                module.name,
                hex(data)
            ),
            Err(e) => println!("{:03X} {} {did:04X} ({e})", module.response_id, module.name),
        }
    }
    let unanswered = found.found.len() - found.answered();
    println!(
        "sweep: {} DIDs answered{}",
        found.answered(),
        if unanswered > 0 {
            format!(", {unanswered} unanswered (worth reading again)")
        } else {
            String::new()
        }
    );
    if let Some(e) = &found.still_extended {
        eprintln!(
            "warning: {} may still be in the extended session ({e}); it returns to the default \
             session by itself within about 5 s",
            module.name
        );
    }
    match &found.stop {
        None => {
            if found.out_of_step {
                eprintln!(
                    "note: some reads went unanswered, so a late answer may still arrive; connect \
                     again before reading from {} again",
                    module.name
                );
            }
            ExitCode::SUCCESS
        }
        Some(stop) => {
            eprintln!("stopped at {:04X}: {}", stop.at, stop.why);
            // A module that refused `22` or the session refuses it again; the rest may pass.
            let busy = matches!(
                &stop.why,
                sweep::Why::Module(ReadError::Reply(ReplyError::Negative(refusal)))
                    if [Nrc::BusyRepeatRequest, Nrc::GeneralReject].contains(&refusal.nrc)
            );
            if busy
                || matches!(
                    stop.why,
                    sweep::Why::Module(ReadError::NoReply | ReadError::StillPending)
                        | sweep::Why::Unmatched(_)
                        | sweep::Why::Adapter(_)
                )
            {
                // An argument that isn't UTF-8 can't be printed as it was given.
                let ran: Option<Vec<String>> = std::env::args_os()
                    .map(|arg| arg.into_string().ok())
                    .collect();
                match ran.and_then(|ran| resume_command(ran, stop.at, last, cfg!(windows))) {
                    Some(command) => eprintln!("to go on: {command}"),
                    None => eprintln!(
                        "to go on: run the same command with --range {:04X}-{last:04X}",
                        stop.at
                    ),
                }
            }
            ExitCode::FAILURE
        }
    }
}

fn print_dids(id: u32, name: &str, dids: &[(u16, Result<DidValue, ReadError>)]) {
    for (did, value) in dids {
        match value {
            Ok(DidValue::Text(text)) => println!("{id:03X} {name} {did:04X} {text}"),
            // Bracketed, so binary data can't pass for text that looks like hex.
            Ok(bytes @ DidValue::Bytes(_)) => println!("{id:03X} {name} {did:04X} [{bytes}]"),
            Ok(DidValue::NotSet) => println!("{id:03X} {name} {did:04X} (not set)"),
            Err(e) => println!("{id:03X} {name} {did:04X} ({e})"),
        }
    }
}

// Every plain-UDS module in the profile with its profile DIDs, or the OBD-II engine and
// transmission without a profile.
fn scan_modules(cli: &Cli) -> Result<Vec<ScanModule>, String> {
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Ok([UdsModule::obd_engine(), UdsModule::obd_transmission()]
            .into_iter()
            .map(|module| ScanModule {
                module,
                extra_dids: Vec::new(),
            })
            .collect());
    };
    let profile = Profile::builtin(name).map_err(|e| format!("profile {name}: {e}"))?;
    let mut modules = Vec::with_capacity(profile.modules.len());
    for module in &profile.modules {
        // Extended addressing and other protocols need support the transports don't have yet.
        if module.protocol != Protocol::Uds || module.extended_address.is_some() {
            eprintln!(
                "skipping {}: it isn't plain UDS, which scan needs",
                module.name
            );
            continue;
        }
        modules.push(ScanModule {
            module: UdsModule {
                name: module.name.clone(),
                request_id: module.request_id,
                response_id: module.response_id,
            },
            extra_dids: module
                .dids
                .iter()
                .map(|did| ExtraDid {
                    id: did.id,
                    format: match did.decode {
                        Decode::Text => DidFormat::Text,
                        Decode::Hex => DidFormat::Hex,
                    },
                    length: did.length,
                    session: match did.session {
                        DidSession::Default => DiagnosticSession::Default,
                        DidSession::Extended => DiagnosticSession::Extended,
                    },
                })
                .collect(),
        });
    }
    Ok(modules)
}

fn run_scan<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    discover: bool,
    wide: bool,
    extended: bool,
) -> ExitCode {
    let (mut modules, mut policy) = match scan_modules(cli).and_then(|m| Ok((m, policy(cli)?))) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if discover {
        match discover_modules(cli, transport, timing, wide) {
            Ok((found, discovery_policy)) => {
                modules.extend(found);
                policy = discovery_policy;
            }
            Err(code) => return code,
        }
    }
    let mut options = ScanOptions::default();
    if extended {
        eprintln!(
            "note: --extended switches each module with extended-session DIDs to the extended \
             diagnostic session (10 03) and back (10 01); it only reads"
        );
        options.extended = Some(S3::default());
    }
    match scan::scan_with(transport, &policy, &modules, timing, &options) {
        Ok(_) if cli.dry_run => {
            println!("dry run: nothing was sent");
            // Nothing answers a dry run, so the reads that depend on the answers aren't shown.
            println!(
                "a live scan also sends, to 7DF: 01 20, 01 40, ... up to 01 E0 while an ECU says \
                 the next bitmap is supported, then 01 <PID> for each PID an ECU says it supports \
                 (mode 01 reads only)"
            );
            if extended {
                // `10 03` gets no answer here, so the reads it would allow aren't shown.
                println!(
                    "with --extended, a live scan also reads each extended-session DID (22 <DID>) \
                     between a module's 10 03 and 10 01, with 3E 00 before a read once 2 s have \
                     passed since the module last accepted one"
                );
            }
            ExitCode::SUCCESS
        }
        Ok(found) => {
            print_scan(&found);
            if found.anything_answered() {
                ExitCode::SUCCESS
            } else {
                eprintln!("nothing answered: check the ignition and the adapter's connection");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

// The command that ran, with its `--range` starting at `from`, for a shell to run again: a
// Windows one if `windows`. None if a word can't be written so every such shell reads it as is.
fn resume_command(
    ran: impl IntoIterator<Item = String>,
    from: u16,
    last: u16,
    windows: bool,
) -> Option<String> {
    let range = format!("{from:04X}-{last:04X}");
    let mut ran = ran.into_iter();
    // The program as installed, not however this run reached it.
    ran.next();
    let mut words = vec!["obdcracker".to_owned()];
    let mut range_next = false;
    for word in ran {
        words.push(if range_next {
            range.clone()
        } else if word.starts_with("--range=") {
            format!("--range={range}")
        } else {
            word.clone()
        });
        range_next = word == "--range";
    }
    Some(
        words
            .iter()
            .map(|word| shell_word(word, windows))
            .collect::<Option<Vec<_>>>()?
            .join(" "),
    )
}

// `word` as one shell word: as is if no shell treats any of it specially, in double quotes if it
// only has spaces too (POSIX shells, PowerShell and cmd all read those), else quoted for the
// platform's shell. On Windows a backslash is an ordinary character (`\\.\COM10`), and cmd
// groups words only with double quotes; but inside them PowerShell still expands `$` and `` ` ``
// (and reads typographic quotes as quotes), cmd `%` (and `!` with delayed expansion), so any
// other word gives None rather than trusting a list of what's special.
fn shell_word(word: &str, windows: bool) -> Option<String> {
    // PowerShell reads a leading `@` as splatting or an array.
    if windows && word.starts_with('@') {
        return None;
    }
    let plain =
        |c: char| c.is_ascii_alphanumeric() || "-_./=:,+@".contains(c) || (windows && c == '\\');
    Some(if !word.is_empty() && word.chars().all(plain) {
        word.to_owned()
    } else if word.chars().all(|c| plain(c) || c == ' ') {
        format!("\"{word}\"")
    } else if windows {
        return None;
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    })
}

// Looks for modules in the profile's discovery range, and with `wide` its wide range too, and
// prints each that answers. Returns those the profile doesn't list, to scan with the rest, and the
// policy that allows them.
fn discover_modules<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    wide: bool,
) -> Result<(Vec<ScanModule>, Policy), ExitCode> {
    let usage = |e: String| {
        eprintln!("{e}");
        ExitCode::from(2)
    };
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Err(usage(
            "--discover needs a profile with a discovery range (--profile or --sim)".to_owned(),
        ));
    };
    let profile = Profile::builtin(name).map_err(|e| usage(format!("profile {name}: {e}")))?;
    let candidates = profile.candidates();
    if candidates.is_empty() {
        return Err(usage(format!(
            "--discover needs a profile with a discovery range, and {name} has none"
        )));
    }
    if wide && profile.wide_candidates(&[]).is_empty() {
        return Err(usage(format!(
            "--wide needs a profile with a wide discovery range, and {name} has none"
        )));
    }
    let policy = profile
        .narrow_for_discovery(Policy::read_only())
        .map_err(|e| usage(format!("profile {name}: {e}")))?;
    let mut found = discover_pass(
        transport,
        &policy,
        &candidates,
        timing,
        &profile,
        "discovery",
        None,
    )?;
    if wide {
        // Before sending on a first-pass reply ID, look again, more patiently, for a module
        // that may own it but was slow to answer. The first pass waited the adapter's usual
        // timeout; only a longer one can catch it (#87).
        let known: Vec<ModuleIds> = found.iter().map(module_ids).collect();
        let recheck = profile.recheck_candidates(&known);
        if !recheck.is_empty() {
            let again = discover_pass(
                transport,
                &policy,
                &recheck,
                timing,
                &profile,
                "recheck",
                Some(discover::PATIENT_WAIT),
            )?;
            found.extend(again);
        }
    }
    if !wide {
        return Ok((unlisted(&profile, &found), policy));
    }
    // The wide range's request IDs are the first pass's reply IDs: skip those a module found
    // there answers on.
    let mut known: Vec<ModuleIds> = found.iter().map(module_ids).collect();
    let wide_candidates = profile.wide_candidates(&known);
    let narrow = |extra: &[ModuleIds]| {
        profile
            .narrow_with(Policy::read_only(), extra)
            .map_err(|e| {
                eprintln!("profile {name}: {e}");
                ExitCode::FAILURE
            })
    };
    let wide_policy = narrow(&[known.as_slice(), &wide_candidates].concat())?;
    // Patient too: modules out here, such as the MMI, may answer slowly through the gateway.
    let more = discover_pass(
        transport,
        &wide_policy,
        &wide_candidates,
        timing,
        &profile,
        "wide discovery",
        Some(discover::PATIENT_WAIT),
    )?;
    known.extend(more.iter().map(module_ids));
    found.extend(more);
    Ok((unlisted(&profile, &found), narrow(&known)?))
}

fn module_ids(found: &discover::Found) -> ModuleIds {
    ModuleIds {
        request: found.request_id,
        reply: found.response_id,
    }
}

// One discovery pass over `candidates`, printing each module that answers. A `patient` pass
// asks the adapter to wait up to that long for each reply, and says how long it really waited.
fn discover_pass<T: Transport>(
    transport: &mut T,
    policy: &Policy,
    candidates: &[ModuleIds],
    timing: Timing,
    profile: &Profile,
    pass: &str,
    patient: Option<Duration>,
) -> Result<Vec<discover::Found>, ExitCode> {
    let failed = |e: fingerprint::FingerprintError| {
        eprintln!("{e}");
        ExitCode::FAILURE
    };
    let (found, pass) = match patient {
        Some(wait) => {
            let (found, waited) =
                discover::discover_patiently(transport, policy, candidates, timing, wait)
                    .map_err(failed)?;
            let most = if waited < wait {
                ", the most this adapter can"
            } else {
                ""
            };
            let secs = waited.as_secs_f64();
            (
                found,
                format!("{pass}, waiting up to {secs:.1} s each{most}"),
            )
        }
        None => (
            discover::discover(transport, policy, candidates, timing).map_err(failed)?,
            pass.to_owned(),
        ),
    };
    for module in &found {
        let listed = profile
            .modules
            .iter()
            .find(|listed| listed.request_id == module.request_id);
        let known = listed.map_or_else(
            || " (not in profile)".to_owned(),
            |listed| format!(" (profile: {})", listed.name),
        );
        let part = match &module.part_number {
            Ok(DidValue::Text(text)) => text.clone(),
            Ok(bytes @ DidValue::Bytes(_)) => format!("[{bytes}]"),
            Ok(DidValue::NotSet) => "(not set)".to_owned(),
            Err(e) => format!("({e})"),
        };
        println!(
            "{:03X} found at {:03X}{known}, F187 {part}",
            module.response_id, module.request_id
        );
    }
    println!(
        "{pass}: {} of {} request IDs answered",
        found.len(),
        candidates.len()
    );
    Ok(found)
}

// The modules found that the profile doesn't list, to scan.
fn unlisted(profile: &Profile, found: &[discover::Found]) -> Vec<ScanModule> {
    found
        .iter()
        .filter(|module| {
            !profile
                .modules
                .iter()
                .any(|listed| listed.request_id == module.request_id)
        })
        .map(|module| ScanModule {
            module: UdsModule {
                name: format!("module-{:03X}", module.request_id),
                request_id: module.request_id,
                response_id: module.response_id,
            },
            extra_dids: Vec::new(),
        })
        .collect()
}

fn print_scan(found: &Scan) {
    if found.ecus.is_empty() {
        println!("no ECU answered OBD-II modes 01, 03 and 09");
    }
    for ecu in &found.ecus {
        let id = ecu.source;
        match &ecu.pids {
            Ok(pids) => {
                for (pid, value) in pids {
                    match value {
                        Ok(PidValue::Quantity { value, unit }) => {
                            // A count has no unit, so no trailing space either.
                            println!(
                                "{}",
                                format!("{id:03X} PID {pid:02X} {value} {unit}").trim_end()
                            );
                        }
                        Ok(PidValue::Raw(bytes)) => {
                            println!("{id:03X} PID {pid:02X} [{}]", hex(bytes));
                        }
                        Err(e) => println!("{id:03X} PID {pid:02X} ({e})"),
                    }
                }
            }
            Err(e) => println!("{id:03X} PIDs ({e})"),
        }
        if let Some((page, e)) = &ecu.pids_cut_short {
            println!("{id:03X} PIDs from {page:02X} on not read ({e})");
        }
        match &ecu.supported_info {
            Ok(pids) => {
                let pids: Vec<_> = pids.iter().map(|pid| format!("{pid:02X}")).collect();
                println!("{id:03X} mode 09 PIDs {}", pids.join(", "));
            }
            Err(e) => println!("{id:03X} mode 09 PIDs ({e})"),
        }
        match &ecu.ecu_name {
            Ok(name) => println!("{id:03X} ECU name {name}"),
            Err(e) => println!("{id:03X} ECU name ({e})"),
        }
        match &ecu.stored_dtcs {
            Ok(dtcs) if dtcs.is_empty() => println!("{id:03X} stored DTCs (none)"),
            Ok(dtcs) => {
                let dtcs: Vec<_> = dtcs.iter().map(ToString::to_string).collect();
                println!("{id:03X} stored DTCs {}", dtcs.join(", "));
            }
            Err(e) => println!("{id:03X} stored DTCs ({e})"),
        }
    }
    for module in &found.modules {
        let (id, name) = (module.response_id, &module.name);
        print_dids(id, name, &module.dids);
        let format = match &module.dtc_count {
            Ok(count) => {
                // The module's own count, which may ignore the mask; the list below is filtered.
                println!(
                    "{id:03X} {name} DTC format {:02X}, the module counts {} for mask {:02X}",
                    count.format.code(),
                    count.count,
                    obdcracker_transport::scan::FAULT_MASK
                );
                Some(count.format)
            }
            Err(e) => {
                println!("{id:03X} {name} DTC count ({e})");
                None
            }
        };
        match &module.dtcs {
            Ok(dtcs) if dtcs.is_empty() => println!("{id:03X} {name} DTCs (no faults)"),
            Ok(dtcs) => {
                for record in dtcs {
                    // The J2012 form only when the module said its DTCs are in that format.
                    let code = format
                        .and_then(|format| record.dtc.j2012(format))
                        .map_or_else(|| record.dtc.to_string(), |dtc| dtc.to_string());
                    println!(
                        "{id:03X} {name} DTC {code} {} (status {:02X})",
                        record.status, record.status.0
                    );
                }
            }
            Err(e) => println!("{id:03X} {name} DTCs ({e})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resume_command;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|&w| w.to_owned()).collect()
    }

    #[test]
    fn the_resume_command_is_the_one_that_ran_from_where_it_stopped() {
        let ran = args(&[
            "/usr/local/bin/obdcracker",
            "--serial",
            "/dev/ttyUSB0",
            "--profile",
            "a7",
            "--audit-log",
            "car4-hud.jsonl",
            "sweep",
            "--module",
            "head-up display",
            "--range",
            "0000-0FFF",
            "--extended",
        ]);
        assert_eq!(
            resume_command(ran, 0x0123, 0x0FFF, false).unwrap(),
            "obdcracker --serial /dev/ttyUSB0 --profile a7 --audit-log car4-hud.jsonl sweep \
             --module \"head-up display\" --range 0123-0FFF --extended"
        );
        let ran = args(&[
            "obdcracker",
            "--sim",
            "a7",
            "sweep",
            "--range=0-ff",
            "--module",
            "x",
        ]);
        assert_eq!(
            resume_command(ran, 0x0080, 0x00FF, false).unwrap(),
            "obdcracker --sim a7 sweep --range=0080-00FF --module x"
        );
        // A word a shell would expand is quoted so it isn't.
        let ran = args(&["obdcracker", "--tcp", "a$b", "sweep", "--range", "0-1"]);
        assert_eq!(
            resume_command(ran.clone(), 1, 1, false).unwrap(),
            "obdcracker --tcp 'a$b' sweep --range 0001-0001"
        );
        // Windows shells expand `$` (PowerShell), `%` and, with delayed expansion, `!` (cmd)
        // even in double quotes.
        assert_eq!(resume_command(ran, 1, 1, true), None);
        // PowerShell also reads typographic quotes as quotes, so only known-plain words are
        // written, whatever else a shell might treat specially.
        for word in [
            "%run%.jsonl",
            r"C:\logs\!CAR!\audit.jsonl",
            "car\u{201C} 4.jsonl",
            "car\u{2019}s log.jsonl",
            "a^b c",
            "(car).jsonl",
            // PowerShell reads a leading `@` as splatting or an array.
            "@args",
            "caf\u{E9}.jsonl",
        ] {
            let ran = args(&["obdcracker", "--audit-log", word, "sweep", "--range", "0-1"]);
            assert_eq!(resume_command(ran, 1, 1, true), None, "{word}");
        }
        // cmd.exe groups only with double quotes, and a backslash is part of a path there.
        let ran = args(&[
            r"C:\tools\obdcracker.exe",
            "--serial",
            r"\\.\COM10",
            "--audit-log",
            r"C:\car 4\hud.jsonl",
            "sweep",
            "--module",
            "head-up display",
            "--range",
            "0000-0FFF",
        ]);
        assert_eq!(
            resume_command(ran, 0x0123, 0x0FFF, true).unwrap(),
            r#"obdcracker --serial \\.\COM10 --audit-log "C:\car 4\hud.jsonl" sweep --module "head-up display" --range 0123-0FFF"#
        );
    }
}
