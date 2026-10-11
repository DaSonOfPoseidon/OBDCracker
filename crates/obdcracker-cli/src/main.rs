//! The `obdcracker` command-line tool.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use obdcracker_core::obd;
use obdcracker_profile::{Decode, Profile, Protocol};
use obdcracker_safety::{Policy, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::elm::Elm;
use obdcracker_transport::fingerprint::{self, DidValue, Fingerprint, ReadError, UdsModule};
use obdcracker_transport::link::{Link, SerialLink, TcpLink};
use obdcracker_transport::scan::{self, DidFormat, ExtraDid, PidValue, Scan, ScanModule};
use obdcracker_transport::{Audited, DryRun, Expect, Timing, Transport, exchange, hex};

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

    /// The serial port's baud rate [default: 115200, for `OBDLink` adapters; ELM327 clones often
    /// use 38400]
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
    /// identification and profile DIDs and its DTCs that are failed, pending or confirmed (UDS
    /// 0x22 and 0x19)
    Scan,
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
    let mut elm = match Elm::connect(link) {
        Ok(elm) => elm,
        Err(e) => {
            eprintln!("{e}");
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
    if let Command::Scan = cli.command {
        return run_scan(cli, &mut transport, timing);
    }
    let (target, payload, expect) = match cli.command {
        Command::Vin => (
            Target::ObdFunctional,
            obd::vehicle_info(0x02),
            Expect::ObdEcus,
        ),
        // Handled before any transport is opened, or above.
        Command::Ports | Command::Adapter | Command::Fingerprint | Command::Scan => {
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
    let modules = match fingerprint_modules(cli) {
        Ok(modules) => modules,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match fingerprint::fingerprint(transport, &Policy::read_only(), &modules, timing) {
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

fn print_dids(id: u32, name: &str, dids: &[(u16, Result<DidValue, ReadError>)]) {
    for (did, value) in dids {
        match value {
            Ok(DidValue::Text(text)) => println!("{id:03X} {name} {did:04X} {text}"),
            // Bracketed, so binary data can't pass for text that looks like hex.
            Ok(bytes @ DidValue::Bytes(_)) => println!("{id:03X} {name} {did:04X} [{bytes}]"),
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
                })
                .collect(),
        });
    }
    Ok(modules)
}

fn run_scan<T: Transport>(cli: &Cli, transport: &mut T, timing: Timing) -> ExitCode {
    let modules = match scan_modules(cli) {
        Ok(modules) => modules,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match scan::scan(transport, &Policy::read_only(), &modules, timing) {
        Ok(_) if cli.dry_run => {
            println!("dry run: nothing was sent");
            // Nothing answers a dry run, so the reads that depend on the answers aren't shown.
            println!(
                "a live scan also sends, to 7DF: 01 20, 01 40, ... up to 01 E0 while an ECU says \
                 the next bitmap is supported, then 01 <PID> for each PID an ECU says it supports \
                 (mode 01 reads only)"
            );
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
