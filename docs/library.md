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

## Crates

See the [crate layout](development.md#crate-layout).
