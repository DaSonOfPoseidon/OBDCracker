# Using the CLI

Plug the adapter into the car and turn the ignition on. `vin`, `fingerprint`, `scan`, `sweep` and `dtc` send requests only
through the [safety policy](safety.md), and with a real adapter they append to an audit log. `ports` and `adapter`
send nothing to the car. `ports` writes no audit log; `adapter` writes one only if connecting to the adapter fails,
recording what it sent the adapter and heard back.

## Connecting

```sh
obdcracker ports                                   # list serial ports
obdcracker --serial /dev/ttyUSB0 adapter           # what the adapter is, and the battery voltage; sends nothing on the bus
obdcracker --serial /dev/ttyUSB0 vin               # 115200 baud by default; --baud 38400 for many clones
obdcracker --tcp 192.168.0.10:35000 vin            # a Wi-Fi adapter
```

On macOS use the `/dev/cu.*` port. Leaving a wireless adapter plugged in drains the battery and lets anyone in range
connect, so the CLI warns about it, and the audit log records which link a session used. See
[adapters](adapters.md) for what's supported.

Two options work with `vin`, `fingerprint`, `scan`, `sweep` and `dtc` (not `ports` or `adapter`):

- `--dry-run` prints the frames the command would send and opens no adapter.
- `--sim a7` runs it against a simulated A7.

## `fingerprint`

```sh
obdcracker --serial <PORT> fingerprint
```

Identifies the engine and transmission software: calibration IDs and CVNs (OBD-II mode 09), then part numbers and
versions (UDS `22 F187`, `F188`, `F189`, `F191`, `F19E`), one read at a time. A tune changes the CVNs, so a saved
fingerprint shows later what changed. Module addresses come from `--profile`, or the OBD-II engine and transmission IDs
without one.

## `scan`

```sh
obdcracker --dry-run --profile a7 scan # what scan would send; opens no adapter
obdcracker --serial <PORT> --profile a7 scan
```

Reads everything the default diagnostic session allows, without changing any module's session. From each emissions
ECU it reads every supported mode 01 PID, mode 09 PIDs 00 and 0A, and mode 03 stored DTCs. From each plain-UDS module
in the profile it reads the standard identification DIDs plus the profile's own DIDs, and its DTCs (`19 01 AF`,
`19 02 AF`). It lists only DTCs that are failed, pending, confirmed or failed since the last clear, not the module's
untested codes. DIDs whose length the profile gives are read three to a request; any a reply leaves out or doesn't fit
are read again one at a time, and must then be exactly that length.

### `--extended`

```sh
obdcracker --serial <PORT> --profile a7 scan --extended  # also read the profile's extended-session DIDs
```

Also reads the DIDs the profile marks `session = "extended"`. After a module's other reads it enters the extended
session (`10 03`), reads them (with `3E 00` before a read once 2 s have passed since the module last accepted one), and
returns it to the default session (`10 01`). A module with no such DIDs isn't switched, and without `--extended` those
DIDs show as not read. A module that refuses the session loses only those DIDs.

### `--discover`

```sh
obdcracker --serial <PORT> --profile a7 scan --discover  # also look for modules the profile doesn't list
```

First looks for modules the profile doesn't list. It reads the part number (`22 F1 87`) from each request ID in the
profile's discovery range, one at a time and through the policy narrowed to those IDs, then scans whatever answered
along with the profile's modules. On the A7 that's 0x700 to 0x769, replies at +0x6A: no ID it sends on is ever a reply
ID. A module whose request ID is past 0x769 isn't found by that pass.

### `--discover --wide`

```sh
obdcracker --serial <PORT> --profile a7 scan --discover --wide  # and past the discovery range
```

Then looks further, at 0x76A to 0x795 on the A7 (replies up to 0x7FF), where VW's MQB cars put the MMI (0x773). Those
request IDs are the first pass's reply IDs. It skips those a module it knows of (listed in the profile, or just found)
answers on, and any whose reply would be an OBD-II ID. A module that stayed silent in the first pass could still own
one, so before the wide pass it asks each of those first-pass IDs again, waiting up to 5 s for each, to find a module
that was only slow. The wide pass waits as long, for modules such as the MMI whose replies the gateway may route
slowly. An OBDLink (STN chip) can wait that long; a plain ELM327 waits about 1 s at most, and the output says so. One
that doesn't answer `22 F1 87` at all could still own one, so `--wide` is opt-in and may send a read on that module's
reply ID: a frame no module receives, since modules only send on theirs. A module that speaks only KWP2000/TP2.0, as
some older MMIs may, doesn't answer any pass.

## `sweep`

```sh
obdcracker --serial <PORT> --profile a7 sweep --module "head-up display" --range 0600-06FF  # DIDs it answers
```

Looks for the DIDs one profile module has that no profile lists yet, such as the head-up display's adaptation values.
It reads each DID in the range (`22 xxxx`), one request each, and lists those the module answers, skipping refusals as
out of range (NRC 0x31). It asks for an explicit range and prints how many reads that is first. It stops early, keeping
what it found, if the module goes quiet (3 reads in a row with no final answer), refuses `22` itself (such as "service
not supported in active session"), says it's busy, or the adapter fails, and prints the command to go on with when
that can help. `--extended` sweeps in the extended session, entered and left as `scan --extended` does, and warns if
the module may not have left it. A sweep that finishes with reads still unanswered notes that a late answer may yet
arrive, so connect again before reading from that module again.

## `dtc`

```sh
obdcracker --serial <PORT> --profile a7 dtc --module gateway --code 0016A0  # one DTC's stored detail
```

Reads one DTC from one profile module: every snapshot record (`19 04 <DTC> FF`), what the module stored when the fault
happened, then every extended data record (`19 06 <DTC> FF`), such as how often it happened. The code is the six hex
digits `scan` lists. Records print as hex, each a record number and its data: their lengths depend on the module's data
identifiers, so they aren't split up. A refusal of one read doesn't stop the other. If the snapshot read goes
unanswered, the extended data isn't asked, because a late refusal doesn't say which read it answers; nor if the module
says it's busy (NRC 0x21), since it's still on the first. The code can't be 000000 (no code) or FFFFFF (every group).
If the module answers nothing, the command fails.
