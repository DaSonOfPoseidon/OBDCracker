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

## VINs

`core::vin::decode` splits a VIN into its fields (`wmi`, `vds`, `check_char`, `year_code`, `plant`, `serial`), lists the
model years its position 10 can mean (`model_years`: two candidates 30 years apart, none for a code
that isn't a year) and computes the check digit (`check_digit`, with a status that is `NotRequired` outside North
America). It takes the VIN a decoder returned, or any text, and refuses what `obd::check_vin` refuses. A profile's `[vin]`
table says which cars it is for (`Profile::matches_vin`, and `profile::builtins_matching` for the builtin ones), and
`transport::fingerprint::check_vin` reads the car's VIN and compares it, as the CLI does before a session
([usage](usage.md#checking-the-car-against---profile)). Its `VinCheck` is `Match`, `Mismatch`, `NoVin`, `Conflicting` or
`ProfileHasNoVin`, and `VinCheck::passes` is true only for the first and the last: an unknown VIN doesn't pass.

```rust
use std::time::Duration;

use obdcracker::core::vin;
use obdcracker::profile::Profile;
use obdcracker::safety::Policy;
use obdcracker::transport::fingerprint::{VinCheck, check_vin};
use obdcracker::transport::{Mock, Response, Timing};

let vin = vin::decode("WAU2MBFC6EN093415").unwrap();
assert_eq!(vin.wmi(), "WAU");
assert_eq!(vin.model_years().as_slice(), [1984, 2014]);

let a7 = Profile::builtin("a7").unwrap();
assert!(a7.matches_vin(&vin));

// A car whose engine answers `09 02` with that VIN.
let mut car = Mock::default();
car.queue(Response::new(0x7E8, b"\x49\x02\x01WAU2MBFC6EN093415".to_vec()));
let timing = Timing { p2: Duration::from_millis(5), ..Timing::default() };
let checked = check_vin(&mut car, &Policy::read_only(), timing, &a7).unwrap();
assert_eq!(checked, VinCheck::Match { vin: "WAU2MBFC6EN093415".to_owned() });
assert!(checked.passes());
```

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
`{"error": ...}`. A value reads back exactly as it was written, and text that isn't one of the forms is an error (a `DtcFormat` or
`Nrc` holds its byte, and one built by hand as `Other` with a code that has a name reads back as the named variant,
as `From<u8>` makes it).
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

## Live data

`transport::live::Poller` reads a fixed list of mode 01 PIDs, and DIDs from profile modules, again and again. Each
`poll` returns one `Sample`: when it started and finished, each emissions ECU's decoded value for every PID (in the order
you gave them), and each module's answer to its `22` request. It never sleeps: you do, and `next_due` says until when.

```rust,no_run
use std::time::{Duration, Instant};

use obdcracker::safety::Policy;
use obdcracker::transport::live::{Poller, next_due};
use obdcracker::transport::{Timing, Transport};

fn watch(adapter: &mut impl Transport) -> Result<(), Box<dyn std::error::Error>> {
    // Engine speed, vehicle speed, coolant temperature and intake manifold pressure: one request a poll.
    let mut poller = Poller::new(&Policy::read_only(), &[0x0C, 0x0D, 0x05, 0x0B], Vec::new())?;
    let every = Duration::from_millis(500);
    loop {
        let sample = poller.poll(adapter, Timing::default())?;
        for (ecu, readings) in &sample.pids {
            for (pid, reading) in readings {
                println!("{ecu:03X} {pid:02X} {reading:?}");
            }
        }
        let due = next_due(sample.started, every, Instant::now());
        std::thread::sleep(due.saturating_duration_since(Instant::now()));
    }
}
```

- **Requests.** `Poller::new` approves every request, so a refusal is an error from `new` and nothing is sent. A
  supported-PID bitmap (0x00, 0x20, ...) or a PID named twice is refused. The first poll that finds an ECU reads every
  ECU's supported-PID bitmaps (`01 00`, `01 20`, ... as far as each chains them, as `scan` does), and a poll asks again
  until one answers. Then PIDs this crate decodes (`obd::is_known_pid`) go up to six to a request (SAE J1979), in the
  order given; any other PID is asked alone, since its length isn't known and its reply would swallow the PIDs after it.
  A PID no ECU lists is never sent: it is in `Sample::unsupported_pids`, and each ECU's entry for it is
  `ReadError::NoReply`. A list where no PID is listed, and no DID is polled, is `PollError::NothingSupported`. A
  request goes only to the ECUs that list one of its PIDs; where the adapter can't take eight ECUs' long replies at once,
  each of those is asked on its own request ID, as `fingerprint` does. An ECU that comes online after the bitmaps were
  read is missed until you build a new poller. An ECU whose first bitmap is refused or malformed is left out of the
  poll, and one whose chain breaks keeps the PIDs listed before the break: both are in `Sample::bitmap_errors`.
- **Replies are untrusted.** One ECU's reply must hold only PIDs that were asked for, each once, each with all its data,
  and nothing after. Anything else (an extra or repeated PID, a cut-off value, a byte left over) is
  `ReadError::Undecodable` for every PID of that request for that ECU, with the reply, and the other ECUs' values are
  unaffected. A PID the ECU leaves out of an otherwise good reply is `ReadError::NoReply`, which is how an ECU says it
  doesn't support it. An ECU that sent nothing has no entry.
- **DIDs.** Each `DidPoll` is one module and its DIDs (at most `read_dids::MAX_DIDS`, none twice), with the data length
  where the profile gives one. A module's DIDs are one `22` request, split as `read_dids` does, and come back as
  `DidsData`: bytes, which you show as text or hex as the profile says. A module is named once per poller. An ELM327
  sends a request over 7 bytes (4 or more DIDs) only once an earlier request has shown that it echoes each character,
  which a poll's PID request does; a poller of DIDs alone must send a shorter request first.
- **Late replies.** A request nobody answers may only be answered late, and a reply gives no sign of which poll it
  belongs to: the next poll's identical request takes it as a fresh value. So `Sample::out_of_step` is set, and stays
  set, once an ECU that lists a PID of a request doesn't answer it, a DID module gives no answer, the bitmaps get no
  answer or an announced next bitmap doesn't come, or the adapter fails mid-poll. No value after that is known to be
  fresh: reconnect and build a new `Poller` to clear it. An ECU that lists none of a request's PIDs is not sent it and
  owes no answer, so its silence is normal and sets nothing; neither does a PID left out of a reply that answered the
  rest.
- **Timing.** `next_due(started, interval, now)` is `started + interval`, or `now` if that has passed, so a poll that
  overran is followed by one at once and not by a backlog. An interval over an hour counts as an hour.

For tests, a simulated car can give a PID a value that changes on each request (`Ecu::set_pid_sequence`,
[fixtures](fixtures.md#ecuobd)).

## Comparing two reads

`transport::diff` says what changed between two results you already have, such as a car's fingerprint before and after a
tune. It sends nothing and needs no feature. `diff_fingerprint`, `diff_scan`, `diff_sweep`, `diff_dids_data` and
`diff_vins` each return the `Vec<Change>`, empty when nothing changed, or a `DuplicateError` when a result lists an ECU,
module, DID or DTC twice (a hand-edited document: which entry is the car's can't be told). `Change` is
`#[non_exhaustive]`, prints as the CLI's [`diff`](usage.md#diff) line, and with the `serde` feature serializes as the
document [`--json diff`](json.md#diff) prints.

```rust
use obdcracker::core::obd::Cvn;
use obdcracker::transport::diff::{DuplicateError, diff_fingerprint};
use obdcracker::transport::fingerprint::{Calibration, Fingerprint};

let engine = |calid: &str, cvn: [u8; 4]| Fingerprint {
    ecus: vec![Calibration {
        source: 0x7E8,
        calids: Ok(vec![Some(calid.to_owned())]),
        cvns: Ok(vec![Cvn(cvn)]),
    }],
    modules: Vec::new(),
};
let before = engine("4G0907589F", [0x9B, 0xF7, 0x47, 0x0D]);
let after = engine("4G0907589G", [0x38, 0xD3, 0xFF, 0x82]);

let changes = diff_fingerprint(&before, &after)?;
assert_eq!(changes.len(), 2);
assert_eq!(changes[0].to_string(), "7E8 CALID 1: \"4G0907589F\" → \"4G0907589G\"");
assert_eq!(changes[1].to_string(), "7E8 CVN 1: 9BF7470D → 38D3FF82");
assert!(diff_fingerprint(&before, &before)?.is_empty());
# Ok::<(), DuplicateError>(())
```

ECUs match by reply CAN ID and modules by name and reply CAN ID, and the changes come in a fixed order. A list that
couldn't be read on one side (a calibration list that failed, say) is one `Change::Unreadable`, not every entry added or
removed. Live PID values aren't compared. [`diff`](usage.md#diff) lists what is and the rest of the rules.

## Crates

See the [crate layout](development.md#crate-layout).
