# OBDCracker

A laptop tool that talks to a car's diagnostic bus through the OBD2 port using an off-the-shelf USB adapter.
It runs on macOS, Windows and Linux, and its development testbed is a 2014 Audi A7 3.0 TDI (C7).

> **Status:** early scaffolding. Nothing in this repo talks to a car yet.

## Safety model

The main rule: **nothing this tool sends may brick or damage a car.** That rule comes from how the code is built, not
from developers being careful:

- Every request goes through `obd-safety`. Its `Policy` gives every OBD-II and UDS service a tier and returns an
  `Approved` request. That type can only be created inside `obd-safety`, and every transport's `send` requires it.
- Anything not on the allowlist is rejected, unknown services included.
- Each tier above read-only needs a cargo feature, an explicit runtime unlock, and passing preconditions:

| Tier | Allows | Status |
|---|---|---|
| T0 Read | OBD-II modes 01/03/09, UDS 0x22, 0x19, 0x3E, 0x10 (default/extended session) | allowed |
| T1 Clear DTCs | UDS 0x14, OBD-II mode 04 | planned |
| T2 Coding | UDS 0x2E, 0x27, with a backup of the old value and a read-back to verify | planned |
| T3 Flash | programming session, 0x31, 0x34/0x36/0x37, 0x11 | **hard-banned** until a separate design doc exists |

- `--dry-run` prints the exact frames a command would send without opening a device.
- Every frame sent or received in a real session is appended to an audit log.

New capabilities are developed test-first: golden-frame unit tests, then property tests and fuzzing of response parsers,
then a simulated ECU (`obd-sim`), then a dry run on the car, and only then a live session.

## Layout

| Crate | Role |
|---|---|
| `obd-core` | Pure `no_std` codecs: CAN, ISO-TP, OBD-II, UDS |
| `obd-safety` | Tiered policy and `Approved` |
| `obd-transport` | `Transport` trait and adapter backends |
| `obd-sim` | Simulated ECUs for tests |
| `obdcracker` | CLI |

## Adapters

| Backend | Hardware | OS | Status |
|---|---|---|---|
| `mock` | none (tests) | all | in progress |
| `elm` | ELM327 / STN (e.g. OBDLink EX) over USB serial | all | planned |
| `gsusb` | CANable / candleLight (USB-C) and an OBD2-to-DB9 cable | all | planned |
| `socketcan` | any SocketCAN interface | Linux | planned |
| `j2534` | J2534 pass-thru devices | Windows | planned |

## Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

You need either a local `rustup` (the version is pinned in `rust-toolchain.toml`) or Docker: `scripts/cargo.sh <args>` runs
cargo in a container.

## License

MIT
