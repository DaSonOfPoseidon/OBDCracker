//! The `obdcracker` command-line tool.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use obdcracker_core::obd;
use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::{Audited, DryRun, Expect, Timing, Transport, exchange, hex};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Talk to a car's diagnostic bus through an OBD2 adapter"
)]
struct Cli {
    /// Print the frames that would be sent without opening any adapter
    #[arg(long)]
    dry_run: bool,

    /// Talk to a simulated car with this vehicle profile instead of an adapter
    #[arg(long, value_name = "PROFILE", conflicts_with = "dry_run",
          value_parser = PossibleValuesParser::new(Profile::BUILTIN))]
    sim: Option<String>,

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(profile) = &cli.sim {
        match SimBus::builtin(profile) {
            Ok(car) => run(&cli, car, "sim"),
            Err(e) => {
                eprintln!("can't build the simulated car: {e}");
                ExitCode::FAILURE
            }
        }
    } else if cli.dry_run {
        run(&cli, DryRun::new(std::io::stdout()), "dry-run")
    } else {
        eprintln!("no adapter backend is available yet; run with --dry-run or --sim <PROFILE>");
        ExitCode::from(2)
    }
}

fn run<T: Transport>(cli: &Cli, transport: T, link: &str) -> ExitCode {
    let mut transport = match Audited::open(&cli.audit_log, transport, link) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("can't open audit log {}: {e}", cli.audit_log.display());
            return ExitCode::FAILURE;
        }
    };
    let (target, payload, expect) = match cli.command {
        Command::Vin => (
            Target::ObdFunctional,
            obd::vehicle_info(0x02),
            Expect::ObdEcus,
        ),
    };
    let request = match Policy::read_only().approve(target, &payload) {
        Ok(request) => request,
        Err(rejection) => {
            eprintln!("safety policy {rejection}");
            return ExitCode::FAILURE;
        }
    };
    let replies = match exchange(&mut transport, &request, expect, Timing::default()) {
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
