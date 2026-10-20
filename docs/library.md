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
