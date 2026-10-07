//! The `obdcracker` command-line tool.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use obdcracker_safety::{Policy, Target};
use obdcracker_transport::{Audited, DryRun, Error, Transport, hex};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Talk to a car's diagnostic bus through an OBD2 adapter"
)]
struct Cli {
    /// Print the frames that would be sent without opening any adapter
    #[arg(long)]
    dry_run: bool,

    /// Append every request and reply to this JSON Lines file
    #[arg(long, default_value = "obdcracker.audit.jsonl")]
    audit_log: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read the VIN (OBD-II mode 09 PID 02)
    Vin,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if !cli.dry_run {
        eprintln!("no adapter backend is available yet; run with --dry-run");
        return ExitCode::from(2);
    }
    let mut transport =
        match Audited::open(&cli.audit_log, DryRun::new(std::io::stdout()), "dry-run") {
            Ok(transport) => transport,
            Err(e) => {
                eprintln!("can't open audit log {}: {e}", cli.audit_log.display());
                return ExitCode::FAILURE;
            }
        };
    let (target, payload) = match cli.command {
        Command::Vin => (Target::ObdFunctional, [0x09, 0x02]),
    };
    let request = match Policy::read_only().approve(target, &payload) {
        Ok(request) => request,
        Err(rejection) => {
            eprintln!("refused by the safety policy: {rejection:?}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = transport.send(&request) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    match transport.recv(RESPONSE_TIMEOUT) {
        Ok(response) => println!("{:03X} {}", response.source, hex(&response.payload)),
        Err(Error::Timeout) if cli.dry_run => println!("dry run: nothing was sent"),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
