//! The `obdcracker` command-line tool.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use obdcracker_core::obd;
use obdcracker_core::response::{self, Error as ReplyError, Nrc};
use obdcracker_core::uds::{DiagnosticSession, UdsDtc};
use obdcracker_profile::{Decode, DidSession, Profile, Protocol};
use obdcracker_safety::{ModuleIds, Policy, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::discover;
use obdcracker_transport::dtc::{self, RecordData};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::fingerprint::{self, DidValue, Fingerprint, ReadError, UdsModule};
use obdcracker_transport::gateway::{self, Compared, GatewayTables, ListedAs, Tried};
use obdcracker_transport::link::{self, FindAdapterError, Link, SerialLink, TcpLink};
use obdcracker_transport::scan::{
    self, DidFormat, ExtraDid, PidValue, Scan, ScanModule, ScanOptions,
};
use obdcracker_transport::sweep::{self, SweepOptions};
use obdcracker_transport::tp20::{self, Answer, ChannelSession, Disconnect};
use obdcracker_transport::{
    Audited, DryRun, Expect, S3, Timing, Transport, exchange, hex, log_failure,
};

const DEFAULT_BAUD: u32 = 115_200;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Talk to a car's diagnostic bus through an OBD2 adapter"
)]
struct Cli {
    /// Use an ELM327/STN adapter on this serial port (e.g. /dev/ttyUSB0, COM3); found
    /// automatically when only one USB adapter is plugged in
    #[arg(long, value_name = "PORT", group = "adapter")]
    serial: Option<PathBuf>,

    /// The serial port's baud rate [default: 115200, for `OBDLink` adapters; ELM327 clones use
    /// 38400, 9600, 230400 or 500000]
    #[arg(long, conflicts_with_all = ["tcp", "dry_run", "sim"])]
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
        /// With --discover, then ask these request IDs again, waiting up to 5 s each (about 1 s on
        /// a plain ELM327), unless they answered the first pass: for modules that answer slowly,
        /// such as those the A7 gateway's tables list at 71D and 755. Three hex digits each,
        /// comma-separated, all in the profile's discovery range
        #[arg(long, requires = "discover", value_delimiter = ',', value_parser = parse_request_id)]
        patient_ids: Vec<u32>,
        /// Also look on 29-bit CAN IDs: read the part number (UDS 0x22 F187) from each request ID
        /// in the profile's 29-bit discovery range (on the A7, VAG's 0x17FC0000 to 0x17FC00FF,
        /// answered on 0x17FE00xx), then scan those that answer too. The adapter switches to
        /// 29-bit CAN for them and back
        #[arg(long)]
        discover_29bit: bool,
        /// After the scan, look for VW TP2.0 modules: send a channel setup to each address in the
        /// profile's TP2.0 list (on the A7, the modules silent on ISO-TP and others the gateway
        /// lists), show the channel each one gives, and close it again (A8). Then read each
        /// module's identification (KWP2000 1A 9B) on a channel of its own, closed the same way.
        /// Needs an adapter that echoes each character as it reads it, such as an `OBDLink` EX
        #[arg(long)]
        discover_tp20: bool,
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
        /// Wait up to 5 s for each reply (about 1 s on a plain ELM327), for a module that
        /// answers slowly, so its late answer isn't taken for the next read's. Each read then
        /// takes up to that long, so give it a narrow range
        #[arg(long)]
        patient: bool,
    },
    /// Read one DTC's snapshot records and extended data records from a module (UDS 0x19 04
    /// and 06). Reads only. Needs a profile (--profile or --sim) that lists the module
    Dtc {
        /// The module's name in the profile, such as "gateway"
        #[arg(long)]
        module: String,
        /// The DTC, as six hex digits, as scan lists it, such as 0016A0
        #[arg(long, value_parser = parse_dtc)]
        code: UdsDtc,
        /// The record number to read of each, as two hex digits, such as 01; FF is every record.
        /// FE isn't taken: it would mean one record to the snapshot read and every OBD record to
        /// the extended data read
        #[arg(long, value_parser = parse_record, default_value = "FF")]
        record: u8,
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
        open_serial(&cli, port)
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
    } else if (cli.sim.is_some() || cli.dry_run) && matches!(cli.command, Command::Adapter) {
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
        match find_adapter() {
            Ok(port) => {
                eprintln!("using the adapter on {}", port.display());
                open_serial(&cli, &port)
            }
            Err(FindAdapterError::NotFound) => {
                eprintln!(
                    "no adapter found; plug one in, or use --serial <PORT> or --tcp <HOST:PORT>, \
                     or try --dry-run or --sim <PROFILE>"
                );
                ExitCode::from(2)
            }
            Err(e @ FindAdapterError::Many(_)) => {
                eprintln!("{e}; pick one with --serial <PORT>");
                ExitCode::from(2)
            }
            Err(e) => {
                eprintln!("{e}; use --serial <PORT>");
                ExitCode::from(2)
            }
        }
    }
}

fn open_serial(cli: &Cli, port: &Path) -> ExitCode {
    match SerialLink::open(port, cli.baud.unwrap_or(DEFAULT_BAUD)) {
        Ok(link) => adapter(cli, link),
        Err(e) => {
            eprintln!("can't open {}: {e}", port.display());
            ExitCode::FAILURE
        }
    }
}

// Debug builds let a test list the ports (paths separated by `;`, empty for none) so that it
// never auto-picks a real adapter plugged into the machine running it.
#[cfg(debug_assertions)]
fn find_adapter() -> Result<PathBuf, FindAdapterError> {
    match std::env::var_os("OBDCRACKER_TEST_PORTS") {
        Some(ports) => {
            let ports = ports.to_string_lossy();
            link::find_adapter_in(
                ports
                    .split(';')
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
                    .collect(),
            )
        }
        None => link::find_adapter(),
    }
}

#[cfg(not(debug_assertions))]
fn find_adapter() -> Result<PathBuf, FindAdapterError> {
    link::find_adapter()
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
        ref patient_ids,
        extended,
        discover_29bit,
        discover_tp20,
    } = cli.command
    {
        let passes = Discovery {
            discover,
            wide,
            discover_29bit,
            discover_tp20,
        };
        return run_scan(cli, &mut transport, timing, passes, patient_ids, extended);
    }
    if let Command::Sweep {
        module,
        range,
        extended,
        patient,
    } = &cli.command
    {
        let mut options = SweepOptions::default();
        options.extended = extended.then(S3::default);
        options.patient = patient.then_some(discover::PATIENT_WAIT);
        return run_sweep(cli, &mut transport, timing, module, *range, &options);
    }
    if let Command::Dtc {
        module,
        code,
        record,
    } = &cli.command
    {
        return run_dtc(cli, &mut transport, timing, module, *code, *record);
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
        | Command::Sweep { .. }
        | Command::Dtc { .. } => {
            unreachable!()
        }
    };
    let request =
        match Policy::read_only().approve(obdcracker_safety::Protocol::Uds, target, &payload) {
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

// `from_str_radix` also takes a leading `+`, so check every character first.
fn is_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_did_range(text: &str) -> Result<(u16, u16), String> {
    let did = |part: &str| {
        if (1..=4).contains(&part.len()) && is_hex(part) {
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

fn profile_module(cli: &Cli, name: &str, command: &str) -> Result<(UdsModule, Policy), String> {
    let Some(profile_name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Err(format!(
            "{command} needs a profile that lists the module (--profile or --sim)"
        ));
    };
    let profile =
        Profile::builtin(profile_name).map_err(|e| format!("profile {profile_name}: {e}"))?;
    let module = profile
        .module(name)
        .ok_or_else(|| format!("profile {profile_name} has no module named {name:?}"))?;
    if module.protocol != Protocol::Uds || module.extended_address.is_some() {
        return Err(format!("{name} isn't plain UDS, which {command} needs"));
    }
    let module = UdsModule {
        name: module.name.clone(),
        request_id: module.request_id,
        response_id: module.response_id,
    };
    Ok((module, policy(cli)?))
}

// Exactly two hex digits. `from_str_radix` alone would also take `+1`. FE means every OBD record
// only to the extended data read; to the snapshot read it's one record, so the two would differ.
fn parse_record(text: &str) -> Result<u8, String> {
    if text.len() != 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{text:?} isn't a record number: give two hex digits, such as 01"
        ));
    }
    match u8::from_str_radix(text, 16).map_err(|e| e.to_string())? {
        0xFE => {
            Err("FE means every OBD record only for extended data; give FF for every record".into())
        }
        record => Ok(record),
    }
}

// Exactly three hex digits. `from_str_radix` alone would also take `+1D`.
fn parse_request_id(text: &str) -> Result<u32, String> {
    if text.len() == 3 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(text, 16).map_err(|e| e.to_string())
    } else {
        Err(format!(
            "{text:?} isn't a request ID: give three hex digits, such as 71D"
        ))
    }
}

// Six hex digits, and not 000000 (no code) or FFFFFF (every group).
fn parse_dtc(text: &str) -> Result<UdsDtc, String> {
    if text.len() != 6 || !is_hex(text) {
        return Err(format!(
            "{text:?} isn't a DTC: give six hex digits, such as 0016A0"
        ));
    }
    match u32::from_str_radix(text, 16).map_err(|e| e.to_string())? {
        0 | 0xFF_FFFF => Err(format!(
            "{text} isn't one DTC: 000000 is no code and FFFFFF means every group"
        )),
        code => Ok(UdsDtc::new(code)),
    }
}

fn run_dtc<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    name: &str,
    code: UdsDtc,
    record: u8,
) -> ExitCode {
    let (module, policy) = match profile_module(cli, name, "dtc") {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let found = match dtc::read_dtc_detail(transport, &policy, &module, code, record, timing) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if cli.dry_run {
        println!("dry run: nothing was sent");
        // Nothing answers a dry run, so the second read was left out.
        println!(
            "a live read also sends 19 06 {code} {record:02X} once 19 04 {code} {record:02X} is \
             answered",
            code = hex(&code.code().to_be_bytes()[1..])
        );
        return ExitCode::SUCCESS;
    }
    let line = |what: &str, value: &Result<RecordData, ReadError>| {
        let (id, name) = (module.response_id, &module.name);
        match value {
            Ok(data) if data.records.is_empty() => println!(
                "{id:03X} {name} DTC {code} {what}: none (status {:02X}, {})",
                data.status.0, data.status
            ),
            Ok(data) => println!(
                "{id:03X} {name} DTC {code} {what}: [{}] (status {:02X}, {})",
                hex(&data.records),
                data.status.0,
                data.status
            ),
            Err(e) => println!("{id:03X} {name} DTC {code} {what} ({e})"),
        }
    };
    line("snapshots", &found.snapshots);
    match &found.extended_data {
        Some(value) => line("extended data", value),
        None => println!(
            "{:03X} {} DTC {code} extended data not read: the snapshot read {}",
            module.response_id,
            module.name,
            if found.out_of_step {
                "went unanswered"
            } else {
                "found the module busy"
            }
        ),
    }
    if found.out_of_step {
        eprintln!("{}", dtc_out_of_step_note(&module.name));
    }
    if found.answered() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "{} answered nothing: check the ignition, the adapter's connection and the profile",
            module.name
        );
        ExitCode::FAILURE
    }
}

fn run_sweep<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    name: &str,
    (first, last): (u16, u16),
    options: &SweepOptions,
) -> ExitCode {
    let (module, policy) = match profile_module(cli, name, "sweep") {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let count = u32::from(last) - u32::from(first) + 1;
    let (most, each) = match options.patient {
        Some(wait) => ("up to", u32::try_from(wait.as_millis()).unwrap_or(u32::MAX)),
        None => ("about", 50),
    };
    eprintln!(
        "sweep: {count} reads of {} ({:03X}), {most} {} min",
        module.name,
        module.request_id,
        count.saturating_mul(each).div_ceil(60_000)
    );
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
        options,
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
    if found.out_of_step {
        eprintln!("{}", sweep_out_of_step_note(&module.name));
    }
    match &found.stop {
        None => ExitCode::SUCCESS,
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

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
struct Discovery {
    discover: bool,
    wide: bool,
    discover_29bit: bool,
    discover_tp20: bool,
}

fn run_scan<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    passes: Discovery,
    patient_ids: &[u32],
    extended: bool,
) -> ExitCode {
    let (mut modules, mut policy) = match scan_modules(cli).and_then(|m| Ok((m, policy(cli)?))) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let tp20_addresses = if passes.discover_tp20 {
        match tp20_addresses(cli) {
            Ok(addresses) => Some(addresses),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    if passes.discover {
        match discover_modules(cli, transport, timing, passes.wide, patient_ids) {
            Ok((found, discovery_policy)) => {
                modules.extend(found);
                policy = discovery_policy;
            }
            Err(code) => return code,
        }
    }
    if passes.discover_29bit {
        match discover_29_bit_modules(cli, transport, timing, &modules) {
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
    // A TP2.0 pass goes after the scan, whose ISO-TP requests show whether the adapter echoes
    // each character as it reads it, which the ELM driver's raw mode needs.
    let mut scanned = None;
    let mut answered = match scan::scan_with(transport, &policy, &modules, timing, &options) {
        Ok(_) if cli.dry_run => {
            println!("dry run: nothing was sent");
            // Nothing answers a dry run, so the reads that depend on the answers aren't shown.
            println!(
                "a live scan also sends, to 7DF: 01 20, 01 40, ... up to 01 E0 while an ECU says \
                 the next bitmap is supported, then 01 <PID> for each PID an ECU says it supports \
                 (mode 01 reads only)"
            );
            print_gateway_list_preview(cli);
            if extended {
                // `10 03` gets no answer here, so the reads it would allow aren't shown.
                println!(
                    "with --extended, a live scan also reads each extended-session DID (22 <DID>) \
                     between a module's 10 03 and 10 01, with 3E 00 before a read once 2 s have \
                     passed since the module last accepted one"
                );
            }
            true
        }
        Ok(found) => {
            print_scan(&found);
            let answered = found.anything_answered();
            scanned = Some(found);
            answered
        }
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // A module that's silent on ISO-TP may still answer on TP2.0.
    let mut tp20_tries = Vec::new();
    if let Some(addresses) = tp20_addresses {
        match discover_tp20_modules(transport, &policy, &addresses, timing, cli.dry_run) {
            Ok(found) => {
                answered |= !found.is_empty();
                tp20_tries = tp20_outcomes(&addresses, &found);
            }
            Err(code) => return code,
        }
        if cli.dry_run {
            println!(
                "a live TP2.0 pass also sends, on each channel a module gives: A8 (disconnect); \
                 then it opens the channel again to read the module's identification: A0 \
                 (parameters), 1A 9B in one data frame, an ACK of each frame that asks, and A8"
            );
        }
    }
    if let (Some(profile), Some(scanned)) = (profile_of(cli), &scanned) {
        show_gateway_list(&profile, transport, &policy, scanned, tp20_tries, timing);
    }
    if answered {
        ExitCode::SUCCESS
    } else {
        eprintln!("nothing answered: check the ignition and the adapter's connection");
        ExitCode::FAILURE
    }
}

// What a TP2.0 pass did at each address it tried.
fn tp20_outcomes(tried: &[u8], answered: &[u8]) -> Vec<(u8, Tried)> {
    tried
        .iter()
        .map(|&address| {
            let outcome = if answered.contains(&address) {
                Tried::Answered
            } else {
                Tried::Silent
            };
            (address, outcome)
        })
        .collect()
}

fn print_gateway_list_preview(cli: &Cli) {
    let Some(profile) = profile_of(cli) else {
        return;
    };
    let Some((module, list)) = profile.gateway_list_module() else {
        return;
    };
    let dids = std::iter::once(list.addresses).chain(list.request_ids);
    let dids: Vec<_> = dids
        .map(|did| format!("22 {:02X} {:02X}", did >> 8, did & 0xFF))
        .collect();
    println!(
        "a live scan also reads the gateway's installed-module list, to {:03X}: {}",
        module.request_id,
        dids.join(", ")
    );
}

fn profile_of(cli: &Cli) -> Option<Profile> {
    let name = cli.profile.as_ref().or(cli.sim.as_ref())?;
    Profile::builtin(name).ok()
}

// Reads the gateway's list of installed modules, if the profile has one and the gateway answered
// the scan, and compares it with what answered. Any failure is a warning: the scan's result
// stands. `tp20_tries` is what the TP2.0 pass found at each address it tried.
fn show_gateway_list<T: Transport>(
    profile: &Profile,
    transport: &mut T,
    policy: &Policy,
    scanned: &Scan,
    tp20_tries: Vec<(u8, Tried)>,
    timing: Timing,
) {
    let Some((module, list)) = profile.gateway_list_module() else {
        return;
    };
    if !scanned
        .modules
        .iter()
        .any(|m| m.name == module.name && m.answered)
    {
        return;
    }
    let gateway_module = UdsModule {
        name: module.name.clone(),
        request_id: module.request_id,
        response_id: module.response_id,
    };
    let tables = GatewayTables {
        addresses: list.addresses,
        request_ids: list.request_ids,
    };
    let read = match gateway::read_gateway_list(transport, policy, &gateway_module, tables, timing)
    {
        Ok(Ok(read)) => read,
        Ok(Err(e)) => {
            eprintln!("warning: the gateway's installed-module list wasn't read ({e})");
            return;
        }
        Err(e) => {
            eprintln!("warning: the gateway's installed-module list wasn't read ({e})");
            return;
        }
    };
    if let Err(e) = &read.request_ids {
        eprintln!("warning: the gateway's request ID table wasn't read ({e})");
    }
    // What the scan did with each profile module, then what the TP2.0 pass did at each address.
    let mut tries: Vec<(u8, Tried)> = profile
        .modules
        .iter()
        .filter_map(|m| {
            let tried = match scanned.modules.iter().find(|s| s.name == m.name) {
                Some(s) if s.answered => Tried::Answered,
                Some(_) => Tried::Silent,
                None => Tried::NotTried,
            };
            Some((m.vag_address?, tried))
        })
        .collect();
    tries.extend(tp20_tries);
    for line in gateway_list_lines(&gateway::compare(&read.installed, &tries)) {
        println!("{line}");
    }
}

// Most addresses a summary line names for one status; more are left to the lines below it.
const SUMMARY_ADDRESSES: usize = 8;

// The summary line, then one line for each listed module that wasn't found.
fn gateway_list_lines(compared: &[Compared]) -> Vec<String> {
    let of = |status: ListedAs| compared.iter().filter(move |c| c.status == status);
    let address = |c: &Compared| format!("{:02X}", c.installed.address);
    let mut parts = Vec::new();
    let found = of(ListedAs::Found).count();
    if found > 0 {
        parts.push(format!("{found} found"));
    }
    for (status, name) in [
        (ListedAs::Silent, "silent"),
        (ListedAs::NotTried, "not tried"),
        (ListedAs::NotInProfile, "not in profile"),
    ] {
        let listed: Vec<String> = of(status)
            .map(|c| match (status, c.installed.request_id) {
                (ListedAs::NotInProfile, Some(id)) => format!("{} at 0x{id:03X}", address(c)),
                _ => address(c),
            })
            .collect();
        match listed.len() {
            0 => {}
            // The lines below name them all.
            n if n > SUMMARY_ADDRESSES => parts.push(format!("{n} {name}")),
            n => parts.push(format!("{n} {name} ({})", listed.join(", "))),
        }
    }
    let n = compared.len();
    let plural = if n == 1 { "" } else { "s" };
    let mut lines = vec![format!(
        "gateway lists {n} installed module{plural}: {}",
        parts.join(", ")
    )];
    for c in compared {
        let status = match c.status {
            ListedAs::Found => continue,
            ListedAs::Silent => "silent",
            ListedAs::NotTried => "not tried",
            ListedAs::NotInProfile => "not in profile",
        };
        let request = c
            .installed
            .request_id
            .map_or_else(String::new, |id| format!(" (request 0x{id:03X})"));
        lines.push(format!("  {} {status}{request}", address(c)));
    }
    lines
}

fn tp20_addresses(cli: &Cli) -> Result<Vec<u8>, String> {
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Err(
            "--discover-tp20 needs a profile with TP2.0 addresses (--profile or --sim)".to_owned(),
        );
    };
    let profile = Profile::builtin(name).map_err(|e| format!("profile {name}: {e}"))?;
    let addresses = profile.tp20_addresses();
    if addresses.is_empty() {
        return Err(format!(
            "--discover-tp20 needs a profile with TP2.0 addresses, and {name} has none"
        ));
    }
    Ok(addresses)
}

// Sends a TP2.0 channel setup to each address and closes each channel a module gives, printing
// what each module that answered did. Returns the addresses that did.
fn discover_tp20_modules<T: Transport>(
    transport: &mut T,
    policy: &Policy,
    addresses: &[u8],
    timing: Timing,
    dry_run: bool,
) -> Result<Vec<u8>, ExitCode> {
    let found = tp20::probe(transport, policy, addresses, timing).map_err(|e| {
        eprintln!("{e}");
        ExitCode::FAILURE
    })?;
    for module in &found {
        let answer = match &module.answer {
            Answer::Channel(channel) => format!(
                "gave channel {:03X} (it answers on {:03X})",
                channel.send_id, channel.receive_id
            ),
            Answer::Refused(op) => format!("refused a channel ({op:02X})"),
            Answer::Undecodable(bytes) => format!("sent an unreadable answer [{}]", hex(bytes)),
        };
        let disconnect = match &module.disconnect {
            None => String::new(),
            Some(Disconnect::Closed) => ", closed".to_owned(),
            Some(Disconnect::NoReply) => {
                ", no answer to A8 (the module closes an idle channel by itself)".to_owned()
            }
            Some(Disconnect::NotSent(rejection)) => {
                format!(", A8 not sent ({rejection}); the module closes an idle channel by itself")
            }
        };
        println!("TP2.0 {:02X} {answer}{disconnect}", module.address);
    }
    if dry_run {
        println!("TP2.0 discovery: dry run, no channel setup was sent");
    } else {
        println!(
            "TP2.0 discovery: {} of {} addresses answered",
            found.len(),
            addresses.len()
        );
    }
    if !dry_run {
        for module in &found {
            if matches!(module.answer, Answer::Channel(_)) {
                // The adapter's state is unknown after it fails, so nothing more is sent.
                let shown = tp20_identification(transport, policy, module.address, timing)
                    .map_err(|e| {
                        eprintln!("TP2.0 {:02X} identification: {e}", module.address);
                        ExitCode::FAILURE
                    })?;
                println!("TP2.0 {:02X} identification: {shown}", module.address);
            }
        }
    }
    Ok(found.iter().map(|module| module.address).collect())
}

// VAG's ECU identification (KWP2000 `ReadEcuIdentification`, option 0x9B).
const TP20_IDENTIFICATION: [u8; 2] = [0x1A, 0x9B];

// Reads a TP2.0 module's identification on a channel of its own, and says what came back. An
// adapter failure, opening, reading or closing, is the error.
fn tp20_identification<T: Transport>(
    transport: &mut T,
    policy: &Policy,
    address: u8,
    timing: Timing,
) -> Result<String, tp20::ChannelError> {
    let mut session = match ChannelSession::open(transport, policy, address, timing) {
        Ok(session) => session,
        Err(e @ tp20::ChannelError::Transport(_)) => return Err(e),
        Err(e) => return Ok(format!("no channel ({e})")),
    };
    let read = session.request(&TP20_IDENTIFICATION);
    let closed = session.close();
    if let Err(e @ tp20::ChannelError::Transport(_)) = read {
        return Err(e);
    }
    if let Err(e @ tp20::ChannelError::Transport(_)) = closed {
        return Err(e);
    }
    Ok(match read {
        Err(e) => format!("not read ({e})"),
        Ok(answer) => match response::positive(TP20_IDENTIFICATION[0], &answer) {
            Err(ReplyError::Negative(refusal)) => format!("refused ({})", refusal.nrc),
            Err(e) => format!("not read ({e}) [{}]", hex(&answer)),
            // The generic KWP2000 match leaves the record to the manufacturer; VAG's starts with
            // the option it answers.
            Ok([]) => format!("not read (no option) [{}]", hex(&answer)),
            Ok([option, ..]) if *option != TP20_IDENTIFICATION[1] => format!(
                "not read (option {option:02X}, not {:02X}) [{}]",
                TP20_IDENTIFICATION[1],
                hex(&answer)
            ),
            // The rest of its record is VAG's: shown as bytes, and as text where printable.
            Ok([_, rest @ ..]) => {
                let text: String = rest
                    .iter()
                    .map(|&b| {
                        if b == b' ' || b.is_ascii_graphic() {
                            char::from(b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!("[{}] \"{text}\"", hex(&answer))
            }
        },
    })
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

// Looks for modules in the profile's discovery range, then patiently at each of `patient_ids`
// that didn't answer, and with `wide` in its wide range too, and prints each that answers.
// Returns those the profile doesn't list, to scan with the rest, and the policy narrowed to the
// profile's modules and the ones found.
fn discover_modules<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    wide: bool,
    patient_ids: &[u32],
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
    let mut patient = patient_candidates(name, &candidates, patient_ids).map_err(usage)?;
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
    let known: Vec<ModuleIds> = found.iter().map(module_ids).collect();
    patient.retain(|candidate| !known.contains(candidate));
    if !patient.is_empty() {
        let again = discover_pass(
            transport,
            &policy,
            &patient,
            timing,
            &profile,
            "patient recheck",
            Some(discover::PATIENT_WAIT),
        )?;
        found.extend(again);
    }
    if wide {
        // Before sending on a first-pass reply ID, look again, more patiently, for a module
        // that may own it but was slow to answer. The first pass waited the adapter's usual
        // timeout; only a longer one can catch it (#87).
        let known: Vec<ModuleIds> = found.iter().map(module_ids).collect();
        let mut recheck = profile.recheck_candidates(&known);
        // Those --patient-ids named were asked just as patiently already.
        recheck.retain(|candidate| !patient.contains(candidate));
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
    let narrow = |extra: &[ModuleIds]| {
        profile
            .narrow_with(Policy::read_only(), extra)
            .map_err(|e| {
                eprintln!("profile {name}: {e}");
                ExitCode::FAILURE
            })
    };
    let mut known: Vec<ModuleIds> = found.iter().map(module_ids).collect();
    if !wide {
        return Ok((unlisted(&profile, &found), narrow(&known)?));
    }
    // The wide range's request IDs are the first pass's reply IDs: skip those a module found
    // there answers on.
    let wide_candidates = profile.wide_candidates(&known);
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

fn discover_29_bit_modules<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
    known: &[ScanModule],
) -> Result<(Vec<ScanModule>, Policy), ExitCode> {
    let usage = |e: String| {
        eprintln!("{e}");
        ExitCode::from(2)
    };
    let Some(name) = cli.profile.as_ref().or(cli.sim.as_ref()) else {
        return Err(usage(
            "--discover-29bit needs a profile with a 29-bit discovery range (--profile or --sim)"
                .to_owned(),
        ));
    };
    let profile = Profile::builtin(name).map_err(|e| usage(format!("profile {name}: {e}")))?;
    let candidates = profile.candidates_29bit();
    if candidates.is_empty() {
        return Err(usage(format!(
            "--discover-29bit needs a profile with a 29-bit discovery range, and {name} has none"
        )));
    }
    let narrow = |extra: &[ModuleIds]| {
        profile
            .narrow_with(Policy::read_only(), extra)
            .map_err(|e| {
                eprintln!("profile {name}: {e}");
                ExitCode::FAILURE
            })
    };
    let found = discover_pass(
        transport,
        &narrow(&candidates)?,
        &candidates,
        timing,
        &profile,
        "29-bit discovery",
        None,
    )?;
    let mut ids: Vec<ModuleIds> = known
        .iter()
        .map(|scanned| ModuleIds {
            request: scanned.module.request_id,
            reply: scanned.module.response_id,
        })
        .collect();
    ids.extend(found.iter().map(module_ids));
    Ok((unlisted(&profile, &found), narrow(&ids)?))
}

// The discovery candidate for each of `ids`, in order: each must be one, and listed once.
fn patient_candidates(
    name: &str,
    candidates: &[ModuleIds],
    ids: &[u32],
) -> Result<Vec<ModuleIds>, String> {
    let mut patient = Vec::new();
    for &id in ids {
        let Some(&candidate) = candidates.iter().find(|c| c.request == id) else {
            return Err(format!(
                "--patient-ids: {id:03X} isn't in {name}'s discovery range"
            ));
        };
        if patient.contains(&candidate) {
            return Err(format!("--patient-ids: {id:03X} is listed twice"));
        }
        patient.push(candidate);
    }
    Ok(patient)
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

fn dtc_out_of_step_note(module: &str) -> String {
    out_of_step_note("a read went unanswered", module)
}

// A sweep is also out of step when a `10 01` timed out and its retry was answered.
fn sweep_out_of_step_note(module: &str) -> String {
    out_of_step_note("a request timed out", module)
}

fn out_of_step_note(what: &str, module: &str) -> String {
    format!(
        "note: {what}, so a late answer may still arrive; connect again before \
         reading from {module} again"
    )
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;
    use std::time::Duration;

    use clap::Parser;
    use obdcracker_core::tp20::Channel;
    use obdcracker_safety::{Approved, Target};
    use obdcracker_sim::SimBus;
    use obdcracker_transport::gateway::{Compared, Installed, ListedAs};
    use obdcracker_transport::{Error, Response, Timing, Transport};

    use super::{
        Cli, Discovery, dtc_out_of_step_note, gateway_list_lines, resume_command, run_scan,
        sweep_out_of_step_note, tp20_identification,
    };

    fn compared(address: u8, request_id: Option<u16>, status: ListedAs) -> Compared {
        Compared {
            installed: Installed {
                slot: 0,
                address,
                request_id,
            },
            status,
        }
    }

    #[test]
    fn the_gateway_list_summary_counts_each_status_and_names_the_few_that_are_not_found() {
        let compared = [
            compared(0x01, None, ListedAs::Found),
            compared(0x13, Some(0x757), ListedAs::Silent),
            compared(0x1B, None, ListedAs::Silent),
            compared(0x05, None, ListedAs::NotTried),
            compared(0x22, Some(0x71D), ListedAs::NotInProfile),
        ];
        assert_eq!(
            gateway_list_lines(&compared),
            [
                "gateway lists 5 installed modules: 1 found, 2 silent (13, 1B), \
                 1 not tried (05), 1 not in profile (22 at 0x71D)",
                "  13 silent (request 0x757)",
                "  1B silent",
                "  05 not tried",
                "  22 not in profile (request 0x71D)",
            ]
        );
    }

    #[test]
    fn the_gateway_list_summary_handles_one_module_none_missing_and_many_missing() {
        assert_eq!(
            gateway_list_lines(&[compared(0x01, None, ListedAs::Found)]),
            ["gateway lists 1 installed module: 1 found"]
        );
        let many: Vec<_> = (1..=9)
            .map(|a| compared(a, None, ListedAs::Silent))
            .collect();
        let lines = gateway_list_lines(&many);
        assert_eq!(lines[0], "gateway lists 9 installed modules: 9 silent");
        assert_eq!(lines.len(), 10);
    }

    fn a7_with_tp20() -> SimBus {
        let mut bus = SimBus::builtin("a7").unwrap();
        bus.add_tp20(
            0x5F,
            Channel {
                send_id: 0x740,
                receive_id: 0x300,
            },
        )
        .unwrap();
        bus.add_tp20_answer(0x5F, &[0x1A, 0x9B], b"\x5A\x9B4G0907401")
            .unwrap();
        bus
    }

    fn scan(bus: &mut impl Transport, discover: bool) -> ExitCode {
        let cli = Cli::try_parse_from(["obdcracker", "--sim", "a7", "scan"]).unwrap();
        let passes = Discovery {
            discover,
            wide: false,
            discover_29bit: false,
            discover_tp20: true,
        };
        run_scan(&cli, bus, Timing::default(), passes, &[], false)
    }

    // On the module's channel: how many frames had this payload.
    fn on_channel(sent: &[Approved], payload: &[u8]) -> usize {
        sent.iter()
            .filter(|request| {
                request.target() == Target::Tp20Channel(0x740) && request.payload() == payload
            })
            .count()
    }

    fn disconnects(sent: &[Approved]) -> usize {
        on_channel(sent, &[0xA8])
    }

    #[test]
    fn a_tp20_identification_is_shown_as_bytes_and_text_and_a_refusal_as_one() {
        let policy = obdcracker_safety::Policy::read_only();
        let mut bus = a7_with_tp20();
        assert_eq!(
            tp20_identification(&mut bus, &policy, 0x5F, Timing::default()).unwrap(),
            "[5A 9B 34 47 30 39 30 37 34 30 31] \"4G0907401\""
        );
        // A module with no identification refuses the read.
        let mut bus = SimBus::builtin("a7").unwrap();
        bus.add_tp20(
            0x5F,
            Channel {
                send_id: 0x740,
                receive_id: 0x300,
            },
        )
        .unwrap();
        let shown = tp20_identification(&mut bus, &policy, 0x5F, Timing::default()).unwrap();
        assert!(shown.starts_with("refused ("), "{shown}");
    }

    #[test]
    fn a_tp20_record_without_the_9b_echo_isnt_shown_as_the_identification() {
        let policy = obdcracker_safety::Policy::read_only();
        for (record, shown) in [
            (
                &b"\x5A\x904G0907401"[..],
                "not read (option 90, not 9B) [5A 90 34 47 30 39 30 37 34 30 31]",
            ),
            (&b"\x5A"[..], "not read (no option) [5A]"),
        ] {
            let mut bus = SimBus::builtin("a7").unwrap();
            bus.add_tp20(
                0x5F,
                Channel {
                    send_id: 0x740,
                    receive_id: 0x300,
                },
            )
            .unwrap();
            bus.add_tp20_answer(0x5F, &[0x1A, 0x9B], record).unwrap();
            assert_eq!(
                tp20_identification(&mut bus, &policy, 0x5F, Timing::default()).unwrap(),
                shown
            );
        }
    }

    // Discovery works, then the adapter fails on the first frame on a channel.
    struct FailsOnChannels(SimBus);

    impl Transport for FailsOnChannels {
        fn send(&mut self, request: &Approved) -> Result<(), Error> {
            if request.target() == Target::Tp20Channel(0x740) && request.payload() != [0xA8] {
                return Err(Error::Adapter("the link went away".into()));
            }
            self.0.send(request)
        }

        fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
            self.0.recv(timeout)
        }
    }

    #[test]
    fn an_adapter_failure_while_reading_identifications_fails_the_scan() {
        let mut bus = FailsOnChannels(a7_with_tp20());
        assert_eq!(scan(&mut bus, false), ExitCode::FAILURE);
    }

    #[test]
    fn discovery_doesnt_keep_tp20_disconnects_off_channels_in_its_range() {
        // 0x740 is in the A7's discovery range, but no module answered there.
        let mut bus = a7_with_tp20();
        assert_eq!(scan(&mut bus, true), ExitCode::SUCCESS);
        // The probe's, and the identification read's.
        assert_eq!(disconnects(bus.sent()), 2);
    }

    // The ISO-TP modules are asleep; only TP2.0 answers.
    struct Tp20Only(SimBus);

    impl Transport for Tp20Only {
        fn send(&mut self, request: &Approved) -> Result<(), Error> {
            self.0.send(request)
        }

        fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
            loop {
                let reply = self.0.recv(timeout)?;
                if (0x200..=0x300).contains(&reply.source) {
                    return Ok(reply);
                }
            }
        }
    }

    #[test]
    fn tp20_discovery_runs_after_a_silent_iso_tp_scan() {
        let mut bus = Tp20Only(a7_with_tp20());
        assert_eq!(scan(&mut bus, false), ExitCode::SUCCESS);
        assert_eq!(disconnects(bus.0.sent()), 2);
        // Each channel a module gives is read for its identification.
        assert_eq!(on_channel(bus.0.sent(), &[0x10, 0x00, 0x02, 0x1A, 0x9B]), 1);
        // With nothing on TP2.0 either, nothing answered.
        let mut bus = Tp20Only(SimBus::builtin("a7").unwrap());
        assert_eq!(scan(&mut bus, false), ExitCode::FAILURE);
    }

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

    #[test]
    fn dtc_note_reads_as_one_sentence() {
        assert_eq!(
            dtc_out_of_step_note("gateway"),
            "note: a read went unanswered, so a late answer may still arrive; connect again \
             before reading from gateway again"
        );
    }

    #[test]
    fn sweep_note_says_a_request_timed_out() {
        assert_eq!(
            sweep_out_of_step_note("gateway"),
            "note: a request timed out, so a late answer may still arrive; connect again \
             before reading from gateway again"
        );
    }
}
