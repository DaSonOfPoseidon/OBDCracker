# OBDCracker

[![CI](https://github.com/DaSonOfPoseidon/OBDCracker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DaSonOfPoseidon/OBDCracker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.99](https://img.shields.io/badge/rust-1.99-orange.svg)](rust-toolchain.toml)

**Adapter-agnostic OBD2/UDS diagnostics in Rust, safe by construction.**

OBDCracker talks to a car's diagnostic bus through the OBD2 port using an off-the-shelf adapter. It works with any
adapter, any OS (macOS, Windows, Linux) and any manufacturer. OBD-II is the baseline every car shares, and
manufacturer diagnostics are added as vehicle profiles. The development testbed is a 2014 Audi A7 3.0 TDI (C7).

> [!NOTE]
> **Status: early.** The ELM327/STN driver works over USB serial and Wi-Fi (TCP), and has run three read-only sessions
> on the 2014 A7 over USB (OBDLink EX): fingerprinting, and a scan of the modules behind its gateway. Only read-only
> requests are allowed.

## Features

- **Safe by construction:** every request passes a tiered safety policy, and transports accept nothing else
- **Any adapter, any OS:** ELM327/STN over USB serial or Wi-Fi today; more backends planned
- **`fingerprint`:** calibration IDs, CVNs and part numbers of the engine and transmission, to see what a tune changed
- **`scan`:** live data, DTCs and identification from the profile's modules, plus any that `--discover` finds
- **`sweep`:** find the DIDs a module answers that no profile lists yet
- **`--dry-run` and `--sim`:** see the exact frames before sending, or run against a simulated car
- **Audit log** of every frame and adapter command in a real diagnostic session
- **A library first:** the CLI is one consumer of the importable `obdcracker` crate

## Quick start

```sh
# macOS and Linux
curl -fsSL https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.ps1 | iex
```

Then, with the adapter plugged into the car and the ignition on:

```sh
obdcracker adapter                            # check the adapter; sends nothing to the car
obdcracker fingerprint
obdcracker --profile a7 scan
```

With exactly one USB adapter plugged in the port is found for you; with none or several, give `--serial <PORT>`
(`obdcracker ports` lists them).

See [Install](docs/install.md) for notes for each OS, and [Using the CLI](docs/usage.md) for every command.

## Safety

**Nothing this tool sends may brick or damage a car.** Every request goes through `obdcracker-safety`, which returns an
`Approved` request that can't be created anywhere else; anything not on the allowlist is rejected. Each tier above
read-only needs a cargo feature, an explicit runtime unlock, passing preconditions, and a backup of what's on the
module.

| Tier | Allows | Status |
|---|---|---|
| T0 Read | OBD-II modes 01/03/09, UDS 0x22, 0x19, 0x3E, 0x10 (default/extended session) | allowed |
| T1 Clear DTCs | UDS 0x14, OBD-II mode 04 | planned |
| T2 Coding | UDS 0x2E, 0x27 | planned |
| T3 Flash | programming session, 0x31, 0x34/0x36/0x37, 0x11 | **hard-banned** |

Read the full [safety model](docs/safety.md), including its one known gap.

## Use as a library

```toml
[dependencies]
obdcracker = { git = "https://github.com/DaSonOfPoseidon/OBDCracker" }
```

```rust,no_run
use obdcracker::core::obd;
use obdcracker::safety::{Policy, Protocol, Target};
use obdcracker::transport::{DryRun, Transport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vin = Policy::read_only().approve(Protocol::Uds, Target::ObdFunctional, &obd::vehicle_info(0x02))?;
    DryRun::new(std::io::stdout()).send(&vin)?; // prints "7DF 02 09 02"
    Ok(())
}
```

The same policy applies to importers: there is no raw-frame escape hatch. See [Using it as a library](docs/library.md).

## Documentation

| | |
|---|---|
| [Install](docs/install.md) | One-command install on Windows, macOS and Linux |
| [Using the CLI](docs/usage.md) | `adapter`, `fingerprint`, `scan`, `sweep` and their options |
| [Library](docs/library.md) | Importing the `obdcracker` crate |
| [Safety model](docs/safety.md) | The policy, tiers, backups, dry runs and the audit log |
| [Adapters](docs/adapters.md) | Supported adapter drivers and links |
| [Protocols](docs/protocols.md) | Physical, transport and diagnostic protocol status |
| [Vehicle profiles](docs/profiles.md) | What a profile holds, and the profiles so far |
| [Development](docs/development.md) | Crate layout and checks |

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING](docs/CONTRIBUTING.md) and [pitfalls](docs/pitfalls.md) first.

## License

[MIT](LICENSE). Third-party test data is listed in [docs/third-party.md](docs/third-party.md).
