# OBDCracker

A laptop tool that talks to a car's diagnostic bus through the OBD2 port using an off-the-shelf adapter.
It works with any adapter, any OS (macOS, Windows, Linux) and any manufacturer. OBD-II is the baseline every car shares,
and manufacturer diagnostics are added as vehicle profiles. The development testbed is a 2014 Audi A7 3.0 TDI (C7).

> **Status:** early scaffolding. Nothing in this repo talks to a car yet.

## Safety model

The main rule: **nothing this tool sends may brick or damage a car.** That rule comes from how the code is built, not
from developers being careful:

- Every request goes through `obdcracker-safety`. Its `Policy` gives every OBD-II and UDS service a tier and returns an
  `Approved` request. That type can only be created inside `obdcracker-safety`, and every transport's `send` requires it.
- Anything not on the allowlist is rejected, unknown services included.
- The policy classifies each request by **protocol**, because service IDs mean different things in different protocols.
  In UDS `0x85` is ControlDTCSetting, but in KWP2000 `10 85` starts the programming (flashing) session. Every protocol
  has its own allowlist and banned list.
- A vehicle profile can only narrow what the policy allows, never widen it.
- Each tier above read-only needs a cargo feature, an explicit runtime unlock, and passing preconditions:

| Tier | Allows | Status |
|---|---|---|
| T0 Read | OBD-II modes 01/03/09, UDS 0x22, 0x19, 0x3E, 0x10 (default/extended session) | allowed |
| T1 Clear DTCs | UDS 0x14, OBD-II mode 04 | planned |
| T2 Coding | UDS 0x2E, 0x27 | planned; needs a backup of the current value |
| T3 Flash | programming session, 0x31, 0x34/0x36/0x37, 0x11 | **hard-banned** until a separate design doc exists; will need a full backup of the current image |

- **Back up before every change.** A write (T1 and up) can't be approved without a `Backup` of what is on the module
  right now: read from the same module, saved to disk and read back from disk. Every change is reversible from that
  backup, and each restore path is tested end to end against the simulator (back up → write → restore → read back
  equals the original) before it touches a car.
- `--dry-run` prints the exact frames a command would send without opening a device.
- `--sim a7` runs a command against a simulated A7 instead of a car, through the same policy and audit log.
- Every frame sent or received in a real session is appended to an audit log.

New capabilities are developed test-first: golden-frame unit tests, then property tests and fuzzing of response parsers,
then a simulated ECU (`obdcracker-sim`), then a dry run on the car, and only then a live session.

## Using it as a library

OBDCracker is meant to be imported. Add the `obdcracker` crate, which re-exports the others:

```toml
[dependencies]
obdcracker = { git = "https://github.com/DaSonOfPoseidon/OBDCracker" }
# obdcracker = { git = "...", features = ["sim"] }  # simulated ECUs for your own tests
```

```rust,no_run
use std::error::Error;
use std::time::Duration;

use obdcracker::core::obd;
use obdcracker::safety::{Policy, Target};
use obdcracker::transport::{Audited, DryRun, Transport};

fn main() -> Result<(), Box<dyn Error>> {
    let vin = Policy::read_only().approve(Target::ObdFunctional, &obd::vehicle_info(0x02))?;
    let adapter = DryRun::new(std::io::stdout());
    let mut adapter = Audited::open("session.audit.jsonl".as_ref(), adapter, "dry-run")?;
    adapter.send(&vin)?; // prints "7DF 02 09 02"
    if let Ok(reply) = adapter.recv(Duration::from_secs(1)) {
        println!("VIN {}", obd::decode_vin(&reply.payload)?);
    }
    Ok(())
}
```

The safety policy applies to importers too. Every transport takes only `Approved` requests, and there is no
raw-frame escape hatch, so no program built on these crates can send something the policy refuses. Higher tiers will be
unlocked by cargo features plus a runtime unlock, and flashing stays banned until its design doc exists. If you need raw
CAN for something else, use your own driver alongside this one.

The crates will be published to crates.io once the M1 codec API settles. Until then, depend on the git repo.

## Layout

| Crate | Role |
|---|---|
| `obdcracker` | Facade for importers: re-exports the crates below (`sim` behind a feature) |
| `obdcracker-core` | Pure `no_std` codecs: CAN, ISO-TP, VW TP2.0, OBD-II, UDS, KWP2000 |
| `obdcracker-safety` | Tiered policy and `Approved` |
| `obdcracker-transport` | `Transport` trait and adapter backends |
| `obdcracker-profile` | Vehicle profiles: module addresses, addressing, protocol and DIDs, as TOML data |
| `obdcracker-sim` | Simulated ECUs for tests: a profile plus a fixture of what each module answers (built in: `a7`) |
| `obdcracker-cli` | The `obdcracker` command-line tool |

## Adapters

An adapter backend has two parts: the **link** that carries bytes to the adapter, and the **driver** that speaks the
adapter's command set. The ELM driver takes any two-way byte stream, so serial, TCP and BLE share one tested driver.

| Driver | Hardware | Links | OS | Status |
|---|---|---|---|---|
| `mock` | none (tests) | — | all | done |
| `sim` | none: a simulated car from a vehicle profile and a fixture (`--sim a7`) | — | all | done |
| `elm` | ELM327 / STN (e.g. OBDLink EX, MX+, CX) | USB serial, Wi-Fi (TCP), Bluetooth LE, Bluetooth Classic | all | planned (USB serial first, then TCP) |
| `gsusb` | CANable / candleLight (USB-C) and an OBD2-to-DB9 cable | USB | all | planned, with listen-only mode |
| `socketcan` | any SocketCAN interface | kernel | Linux | planned |
| `j2534` | J2534 pass-thru (Tactrix OpenPort, Toyota Mini VCI, VAS 5054A clones) | vendor DLL | Windows | later |
| `dpdu` | ISO 22900 D-PDU API (what ODIS uses) | vendor DLL | Windows | maybe |

Leaving a wireless adapter plugged in drains the battery and lets anyone in range connect, so the CLI warns about it, and
the audit log records which link a session used.

## Protocols

| Layer | Protocol | Used by | Status |
|---|---|---|---|
| Physical | CAN 500 kbit/s (OBD pins 6/14), 11- and 29-bit IDs | every US car since 2008 | planned (11-bit first) |
| Physical | K-line (pin 7): ISO 9141-2, ISO 14230, VW KW1281 | pre-CAN cars, a few older modules | if a profile needs it |
| Physical | DoIP (ISO 13400, Ethernet on pins 3/11/12/13) | newer cars (around 2020+) | not yet; the transport trait leaves room |
| Physical | CAN FD | newer cars | not yet |
| Transport | ISO-TP (ISO 15765-2), normal and extended addressing | almost everyone; Toyota uses extended addressing | done (classic CAN, both addressing modes) |
| Transport | VW TP2.0 | older VAG module designs | after the A7 module scan |
| Diagnostic | OBD-II (SAE J1979) | every car | decoding done for mode 01 (supported PIDs, load, coolant, RPM, speed, intake temp, throttle, module voltage), mode 03 DTCs, mode 09 VIN, CALID, CVN and ECU name |
| Diagnostic | UDS (ISO 14229) | most modules from about 2010 | decoding done for 0x22 (single and multi-DID), 0x19 (0x01, 0x02, 0x0A) and negative response codes |
| Diagnostic | KWP2000 (ISO 14230-3) over CAN | VAG TP2.0 modules, Toyota enhanced diagnostics before about 2018 | planned, with its own allowlist |

The OBD port only reaches what the car's gateway passes on, which is the diagnostic bus. Internal buses (body CAN, FlexRay,
MOST, LIN) need a direct tap. If that is ever supported, it will run in listen-only mode, where the adapter can't transmit
or acknowledge frames.

## Vehicle profiles

A profile is data, not code: module addresses, addressing mode, protocol per module, the identifiers to read and how to
decode them. Without a profile the tool falls back to generic OBD-II. Profiles are TOML files in
`crates/obdcracker-profile/profiles/`; a profile has no field that names a service, so it can't widen the safety policy.

| Profile | Expected setup (confirmed by a read-only module scan before use) |
|---|---|
| 2014 Audi A7 3.0 TDI (C7) | CAN 500k behind the J533 gateway; mostly UDS on ISO-TP with 11-bit IDs, maybe some TP2.0/KWP2000 modules; engine 0x7E0/0x7E8 |
| 2014 Toyota Camry (XV50) | CAN 500k; OBD-II on 0x7DF/0x7E0+; enhanced diagnostics are KWP2000-style (e.g. 0x21 read by local ID) on ISO-TP; body modules sit behind 0x750 with an extended-address byte |

## Development

```sh
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features
cargo build -p obdcracker-core --target thumbv7em-none-eabihf  # obdcracker-core must stay no_std
```

You need either a local `rustup` (the version is pinned in `rust-toolchain.toml`) or Docker: `scripts/cargo.sh <args>` runs
cargo in a container.

## License

MIT
