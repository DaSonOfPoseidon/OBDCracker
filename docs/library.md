# Using it as a library

OBDCracker is meant to be imported. Add the `obdcracker` crate, which re-exports the others:

```toml
[dependencies]
obdcracker = { git = "https://github.com/DaSonOfPoseidon/OBDCracker" }
# obdcracker = { git = "...", features = ["sim"] }  # simulated ECUs for your own tests
```

The crates will be published to crates.io once the M1 codec API settles. Until then, depend on the git repo.

## Example

```rust,no_run
use std::error::Error;
use std::time::Duration;

use obdcracker::core::obd;
use obdcracker::safety::{Policy, Protocol, Target};
use obdcracker::transport::{Audited, DryRun, Transport};

fn main() -> Result<(), Box<dyn Error>> {
    let vin = Policy::read_only().approve(Protocol::Uds, Target::ObdFunctional, &obd::vehicle_info(0x02))?;
    let adapter = DryRun::new(std::io::stdout());
    let mut adapter = Audited::open("session.audit.jsonl".as_ref(), adapter, "dry-run")?;
    adapter.send(&vin)?; // prints "7DF 02 09 02"
    if let Ok(reply) = adapter.recv(Duration::from_secs(1)) {
        println!("VIN {}", obd::decode_vin(&reply.payload)?);
    }
    Ok(())
}
```

## A `gs_usb` adapter

With the `gsusb` feature, `transport::gsusb::GsUsb` is a transport over a CANable or candleLight. It checks the bitrate
listening before it goes active, and has no way to write a frame of your own ([details](gsusb.md)).

```rust,no_run
# #[cfg(feature = "gsusb")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use obdcracker::core::obd;
use obdcracker::safety::Policy;
use obdcracker::transport::fingerprint::read_vin;
use obdcracker::transport::gsusb::{GsUsb, Options};
use obdcracker::transport::{Audited, Timing};

// The bitrate is the car's (a profile's `bitrate`); `Options::new` takes it as chosen by you.
let adapter = GsUsb::open(&Options::new(500_000))?;
let link = adapter.link_name();
let mut adapter = Audited::open("session.audit.jsonl".as_ref(), adapter, link)?;
for reply in read_vin(&mut adapter, &Policy::read_only(), Timing::default())? {
    println!("{:03X} {}", reply.source, obd::decode_vin(&reply.payload)?);
}
# Ok(())
# }
# #[cfg(not(feature = "gsusb"))]
# fn main() {}
```

## A SocketCAN interface

On Linux, with the `socketcan` feature, `transport::socketcan::SocketCan` is a transport over any CAN interface the
kernel has a driver for, and likewise has no way to write a frame of your own. It reads the interface (up, not faulted,
not in a mode that drops what is sent, the bitrate you ask for) and never sets its bitrate or mode
([details](socketcan.md)).

```rust,no_run
# #[cfg(all(feature = "socketcan", target_os = "linux"))]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use obdcracker::core::obd;
use obdcracker::safety::Policy;
use obdcracker::transport::fingerprint::read_vin;
use obdcracker::transport::socketcan::{Options, SocketCan};
use obdcracker::transport::{Audited, Timing};

// The interface must already be up at the car's bitrate; `bitrate` makes the check refuse another.
let mut options = Options::new("can0");
options.bitrate = Some(500_000);
let interface = SocketCan::open(&options).map_err(|failed| failed.error)?;
let link = interface.link_name();
let mut interface = Audited::open("session.audit.jsonl".as_ref(), interface, link)?;
for reply in read_vin(&mut interface, &Policy::read_only(), Timing::default())? {
    println!("{:03X} {}", reply.source, obd::decode_vin(&reply.payload)?);
}
# Ok(())
# }
# #[cfg(not(all(feature = "socketcan", target_os = "linux")))]
# fn main() {}
```

## The policy applies to you too

Every transport takes only `Approved` requests, and there is no raw-frame escape hatch, so no program built on these
crates can send something the policy refuses. Higher tiers will be unlocked by cargo features plus a runtime unlock,
and flashing stays banned until its design doc exists. If you need raw CAN for something else, use your own driver
alongside this one. See the [safety model](safety.md).

## Extended-session reads

Reads that need the extended diagnostic session go through `transport::ExtendedSession`; `scan::scan_with` uses it
for the DIDs a profile marks `session = "extended"`, and `sweep::sweep_dids` with `SweepOptions::extended`. It
enters the session (`10 03`), and its `keep_alive` sends TesterPresent (`3E 00`) between requests so the module
doesn't drop back after S3 (5 s). If the session has lapsed anyway, the guard enters it again before the next
request. Dropping the guard returns the module to the default session (`10 01`).

## The battery

`Transport::supply_voltage` returns the voltage the adapter sees on the OBD port: `Known` (an ELM327 or STN, the
simulator) or `Unknown` (every other backend, and an ELM327 that says `?`). `safety::VoltageThresholds::DEFAULT.check`
turns it into `Ok`, `Low`, `TooLow` or `Unknown`, and `Unknown` never satisfies a `safety::Precondition`. Pass
`transport::voltage::VoltageWatch::default()` in `SweepOptions::voltage_watch` or `DiscoverOptions::voltage_watch` and a
long run re-checks it every 50 requests and stops, keeping what it read, when it is too low. Nothing is checked unless
you ask: the CLI's guard (refusing a long command at the start) is yours to write. See [safety](safety.md#supply-voltage).

## JSON

With the `serde` feature, the results of `scan`, `fingerprint`, `sweep_dids`, `read_dtc_detail`, `read_dids` and
`Elm::info` implement `Serialize` and `Deserialize` in the forms the CLI's `--json` prints ([JSON output](json.md)): byte
strings as upper-case spaced hex, CAN IDs as 3 or 8 hex digits, DIDs and PIDs as hex, a result as `{"value": ...}` or
`{"error": ...}`. A value reads back exactly as it was written, and text that isn't one of the forms is an error.
`transport::json` has the `with` modules for a type of your own that holds such a field.

```toml
obdcracker = { git = "https://github.com/DaSonOfPoseidon/OBDCracker", features = ["serde"] }
```

```rust
# #[cfg(feature = "serde")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use obdcracker::transport::scan::Scan;

let scan: Scan = serde_json::from_str(r#"{"ecus": [], "modules": []}"#)?;
assert!(!scan.anything_answered());
assert_eq!(serde_json::to_string(&scan)?, r#"{"ecus":[],"modules":[]}"#);
# Ok(())
# }
# #[cfg(not(feature = "serde"))]
# fn main() {}
```

## Crates

See the [crate layout](development.md#crate-layout).
