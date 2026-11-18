// `monitor`: listens to the bus through an ELM327/STN adapter and sends nothing. The adapter is
// told to stay off the bus (silent monitoring) before it listens, and every frame heard goes in
// the audit log (docs/elm327.md#listen-only-monitor).

use std::io::{self, Write};
use std::ops::ControlFlow;
use std::process::ExitCode;
use std::time::Duration;

use obdcracker_transport::elm::listen_commands;
use obdcracker_transport::{Audited, Error, Heard, Listen, ListenFilter, Transport, hex};

use crate::{Cli, Command};

// The longest `--duration`. A monitor holds the adapter and the car's bus awake and can't read the
// battery while it runs (any command stops it), so a longer one is several runs, each checked
// against the voltage first (`check_supply`), rather than one that nothing watches (#97).
const LONGEST: Duration = Duration::from_secs(300);
pub(crate) const DEFAULT_DURATION: &str = "30s";

pub(crate) fn parse_duration(text: &str) -> Result<Duration, String> {
    let duration = crate::live_cmd::parse_span(text)?;
    if duration.is_zero() {
        return Err(format!(
            "a duration of {text} listens for no time: give 1ms to {}s",
            LONGEST.as_secs()
        ));
    }
    if duration > LONGEST {
        return Err(format!(
            "a duration of {text} is over {} s: run the command again for longer, so the battery \
             voltage is checked before each run",
            LONGEST.as_secs()
        ));
    }
    Ok(duration)
}

// What `monitor` can't do with the options or the adapter given, before anything is opened, or
// the dry run's answer.
pub(crate) fn before_opening(cli: &Cli) -> Option<ExitCode> {
    let Command::Monitor { filter, .. } = &cli.command else {
        unreachable!()
    };
    if cli.json {
        eprintln!("`monitor` prints text, so --json doesn't apply");
        return Some(ExitCode::from(2));
    }
    if cli.gsusb.is_some() || cli.socketcan.is_some() {
        eprintln!(
            "`monitor` isn't supported yet with --gsusb or --socketcan (#42); use an ELM327/STN \
             adapter (--serial or --tcp)"
        );
        return Some(ExitCode::from(2));
    }
    if cli.sim.is_some() {
        eprintln!("`monitor` listens to a real bus, and --sim has none; use --serial or --tcp");
        return Some(ExitCode::from(2));
    }
    if cli.elm_segmenting.is_some() {
        eprintln!("`monitor` sends no request, so --elm-segmenting doesn't apply");
        return Some(ExitCode::from(2));
    }
    if cli.dry_run {
        dry_run(filter);
        return Some(ExitCode::SUCCESS);
    }
    None
}

fn dry_run(filter: &ListenFilter) {
    println!("dry run: nothing was sent");
    for (name, stn) in [("an STN (OBDLink)", true), ("any other ELM327", false)] {
        let commands = listen_commands(stn, filter);
        let stop = commands.iter().position(|c| c == "X").unwrap_or(0);
        println!(
            "{name}: {}, then X to stop the monitor, then {}",
            commands[..stop].join(", "),
            commands[stop + 1..].join(", ")
        );
    }
    println!(
        "these are commands to the adapter and none puts a frame on the bus. The monitor is silent \
         on the bus too: it acknowledges nothing, so it hears only what other nodes acknowledge"
    );
}

pub(crate) fn run<T: Transport + Listen>(cli: &Cli, transport: T, link: &str) -> ExitCode {
    let Command::Monitor { filter, duration } = &cli.command else {
        unreachable!()
    };
    let mut transport = match Audited::open(&cli.audit_log, transport, link) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("can't open audit log {}: {e}", cli.audit_log.display());
            return ExitCode::FAILURE;
        }
    };
    // A monitor lasts at most 5 minutes, so a low battery warns and doesn't refuse.
    if let Err(code) = crate::check_supply(cli, &mut transport) {
        return code;
    }
    eprintln!(
        "listening to {filter} for {}; nothing is sent on the bus. Each line is the milliseconds \
         since the start, the CAN ID and the data",
        describe(*duration)
    );
    let mut out = io::stdout().lock();
    let mut frames = 0_u64;
    let ended = transport.listen(filter, *duration, &mut |heard| {
        writeln!(out, "{}", line(heard))
            .and_then(|()| out.flush())
            .map_err(|e| Error::Adapter(format!("can't write the frame to stdout: {e}")))?;
        frames += 1;
        Ok(ControlFlow::Continue(()))
    });
    match ended {
        Ok(_) => {
            eprintln!("heard {frames} frame(s)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            eprintln!("heard {frames} frame(s) before it stopped");
            ExitCode::FAILURE
        }
    }
}

fn describe(duration: Duration) -> String {
    if duration.as_millis() < 1000 || duration.subsec_millis() != 0 {
        format!("{} ms", duration.as_millis())
    } else {
        format!("{} s", duration.as_secs())
    }
}

// `<ms since the start> <id> <bytes>`, the ID in the width it has.
fn line(heard: &Heard) -> String {
    let id = if heard.extended {
        format!("{:08X}", heard.id)
    } else {
        format!("{:03X}", heard.id)
    };
    format!("{:>8} {id} {}", heard.elapsed.as_millis(), hex(&heard.data))
}
