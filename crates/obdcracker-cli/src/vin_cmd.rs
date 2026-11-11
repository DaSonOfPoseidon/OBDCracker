//! What `vin` prints about a VIN, and the check of the car's VIN against `--profile` that runs
//! before a command that reads the car (`docs/usage.md#vin`).

use std::process::ExitCode;

use obdcracker_core::vin::{CheckStatus, Vin};
use obdcracker_profile::{Profile, builtins_matching};
use obdcracker_transport::fingerprint::{VinCheck, check_vin};
use obdcracker_transport::{Timing, Transport};
use serde::Serialize;

use crate::{Cli, Command};

// What a VIN says about itself and which profiles fit it. The VDS and the plant code are shown as
// written: what they mean is the manufacturer's.
pub(crate) struct Decoded<'a> {
    vin: Vin<'a>,
    builtins: Vec<&'static str>,
    // The `--profile`'s name and whether it fits: `None` when the profile has no `[vin]` table.
    profile: Option<(String, Option<bool>)>,
}

impl<'a> Decoded<'a> {
    pub(crate) fn new(vin: Vin<'a>, profile: Option<(&str, &Profile)>) -> Self {
        Self {
            vin,
            builtins: builtins_matching(&vin),
            profile: profile.map(|(name, profile)| {
                (
                    name.to_owned(),
                    profile.vin.is_some().then(|| profile.matches_vin(&vin)),
                )
            }),
        }
    }

    // The lines under the VIN, each already indented.
    pub(crate) fn lines(&self) -> Vec<String> {
        let vin = &self.vin;
        let digit = vin.check_digit();
        let note = match (digit.status(), digit.matches()) {
            (CheckStatus::Valid, _) => "correct".to_owned(),
            (CheckStatus::Invalid, _) => {
                format!("wrong: the rest of the VIN gives {}", digit.computed)
            }
            (CheckStatus::NotRequired, true) => {
                "correct; not required outside North America".to_owned()
            }
            (CheckStatus::NotRequired, false) => format!(
                "the rest of the VIN gives {}; not required outside North America",
                digit.computed
            ),
        };
        let years = vin.model_years();
        let year = match years.as_slice() {
            [] => format!("{} isn't a model year code", vin.year_code()),
            [first, second] => format!("{} = {first} or {second}", vin.year_code()),
            _ => unreachable!("a VIN has no candidate years or two"),
        };
        let mut lines = vec![
            format!("    manufacturer code: {}", vin.wmi()),
            format!("    descriptor section: {}", vin.vds()),
            format!("    check digit: {} ({note})", digit.found),
            format!("    model year: {year}"),
            format!("    plant code: {}", vin.plant()),
            format!("    serial: {}", vin.serial()),
        ];
        lines.push(if self.builtins.is_empty() {
            "    no builtin profile matches".to_owned()
        } else {
            format!("    matches profile: {}", self.builtins.join(", "))
        });
        match &self.profile {
            Some((name, Some(false))) => {
                lines.push(format!("    does not fit --profile {name}"));
            }
            Some((name, None)) => lines.push(format!(
                "    --profile {name} doesn't say which VINs it fits"
            )),
            _ => {}
        }
        lines
    }

    pub(crate) fn entry(&self, source: u32) -> VinEntry {
        let vin = &self.vin;
        let digit = vin.check_digit();
        VinEntry {
            source,
            vin: vin.as_str().to_owned(),
            wmi: vin.wmi().to_owned(),
            vds: vin.vds().to_owned(),
            check_digit: CheckDigitEntry {
                found: digit.found,
                computed: digit.computed,
                status: match digit.status() {
                    CheckStatus::Valid => "valid",
                    CheckStatus::Invalid => "invalid",
                    CheckStatus::NotRequired => "not-required",
                },
            },
            year_code: vin.year_code(),
            model_years: vin.model_years().as_slice().to_vec(),
            plant: vin.plant(),
            serial: vin.serial().to_owned(),
            builtin_profiles: self.builtins.clone(),
            profile: self.profile.as_ref().map(|(name, fits)| VinProfileEntry {
                name: name.clone(),
                fits: *fits,
            }),
        }
    }
}

// One entry of `vin`'s document (docs/json.md). Readers ignore every field but `source` and `vin`:
// the rest is worked out from the VIN.
#[derive(Debug, Serialize)]
pub(crate) struct VinEntry {
    #[serde(with = "obdcracker_transport::json::can_id")]
    source: u32,
    vin: String,
    wmi: String,
    vds: String,
    check_digit: CheckDigitEntry,
    year_code: char,
    model_years: Vec<u16>,
    plant: char,
    serial: String,
    builtin_profiles: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<VinProfileEntry>,
}

// The `--profile` and whether the VIN fits it: null when the profile doesn't say which VINs it fits.
#[derive(Debug, Serialize)]
struct VinProfileEntry {
    name: String,
    fits: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CheckDigitEntry {
    found: char,
    computed: char,
    status: &'static str,
}

// Whether the command reads the car, and so needs the car to be the one `--profile` is for.
fn reads_the_car(command: &Command) -> bool {
    matches!(
        command,
        Command::Fingerprint
            | Command::Scan { .. }
            | Command::Sweep { .. }
            | Command::Dtc { .. }
            | Command::ReadDids { .. }
    )
}

// Reads the car's VIN, as a command that reads the car does first when `--profile` is given, and
// compares it with the profile. An unknown VIN stops the command as a mismatch does, unless
// `--ignore-vin-mismatch` turns the stop into a warning. A dry run sends nothing and compares
// nothing, so it never stops.
pub(crate) fn check_profile<T: Transport>(
    cli: &Cli,
    transport: &mut T,
    timing: Timing,
) -> Result<(), ExitCode> {
    let Some(name) = cli.profile.as_ref().filter(|_| reads_the_car(&cli.command)) else {
        return Ok(());
    };
    let policy = match crate::policy(cli) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("{e}");
            return Err(ExitCode::from(2));
        }
    };
    let profile = match Profile::builtin(name) {
        Ok(profile) => profile,
        Err(e) => {
            eprintln!("profile {name}: {e}");
            return Err(ExitCode::from(2));
        }
    };
    let found = match check_vin(transport, &policy, timing, &profile) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("can't check the car's VIN against the {name} profile: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    if cli.dry_run {
        println!("dry run: the car's VIN wasn't compared with the {name} profile");
        return Ok(());
    }
    let problem = match &found {
        VinCheck::Match { .. } => return Ok(()),
        VinCheck::ProfileHasNoVin => {
            eprintln!(
                "note: the {name} profile doesn't say which VINs it fits, so the car's VIN isn't \
                 checked"
            );
            return Ok(());
        }
        VinCheck::Mismatch { vin } => format!(
            "the car's VIN is {vin}, which the {name} profile ({}) doesn't fit",
            profile.name
        ),
        VinCheck::NoVin => format!(
            "no ECU gave the car's VIN, so it can't be told whether the car is the one the {name} \
             profile ({}) is for",
            profile.name
        ),
        VinCheck::Conflicting { vins } => format!(
            "ECUs gave different VINs ({}), so it can't be told which car this is or whether it \
             is the one the {name} profile ({}) is for",
            vins.join(", "),
            profile.name
        ),
    };
    if cli.ignore_vin_mismatch {
        eprintln!("warning: {problem}; going on because of --ignore-vin-mismatch");
        Ok(())
    } else {
        eprintln!(
            "refused: {problem}. Use the profile that fits the car, or give --ignore-vin-mismatch \
             to go on anyway"
        );
        Err(ExitCode::FAILURE)
    }
}
