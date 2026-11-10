# Using the CLI

Plug the adapter into the car and turn the ignition on. `vin`, `fingerprint`, `scan`, `sweep`, `dtc` and `read-dids` send requests only
through the [safety policy](safety.md), and with a real adapter they append to an audit log. `ports`, `adapter`,
`update` and `diff` send nothing to the car. `ports`, `update` and `diff` write no audit log; `adapter` writes one only if connecting to
the adapter fails, recording what it sent the adapter and heard back.

## Connecting

```sh
obdcracker adapter                                 # the one USB serial port plugged in is found for you; what the adapter is and the battery voltage, sends nothing on the bus
obdcracker ports                                   # list serial ports
obdcracker vin                                     # 115200 baud by default; --baud 38400 for many clones
obdcracker --tcp 192.168.0.10:35000 vin            # a Wi-Fi adapter
```

`--serial` is optional when exactly one port whose name looks like a USB adapter is plugged in: the CLI says
`using the adapter on <port>` and carries on as if you had given it, `--baud` included. With none it stops and says
so, and with several it lists them and asks you to pick one with `--serial`; both exit with status 2 and write no
audit log. Only names that look like USB adapters count (Linux `ttyUSB*` and `ttyACM*`; macOS `cu.usbserial*`,
`cu.usbmodem*`, `cu.SLAB_USBtoUART*` and `cu.wchusbserial*`), so built-in and Bluetooth ports are never picked on Linux
or macOS. On Linux those names also match other USB serial devices (Arduinos, modems, printers, GPS receivers). A lone
one is picked and gets AT commands written to it, so pass `--serial` when one is plugged in. Windows can't tell USB
from built-in ports, so every COM port counts there, and a lone built-in COM port would be picked and the connection
would fail as "not an ELM"; give `--serial` on a PC with one. Other systems count every port too.
`--serial`, `--tcp`, `--gsusb`, `--socketcan`, `--sim` and `--dry-run` skip the search, and `ports` still lists
every port.

### Sending a long request on an STN (`--elm-segmenting`)

```sh
obdcracker --elm-segmenting caf0 --profile a7 read-dids --module transmission --did F187,F188,F189,F191
```

A request of 8 to 44 bytes (a `22` read of 4 or more DIDs) goes out as `STPX` on an STN chip such as an OBDLink, which
segments it itself, and as raw frames the driver writes with `AT CAF0` on a plain ELM327
([how](elm327.md#multi-frame-requests-on-a-plain-elm327)). `--elm-segmenting caf0` makes an STN take the second path
too, so it can be tried on the one adapter that has both ([design](design/elm-caf0-segmenting.md#13-forcing-it-on-an-stn-308)).
`--elm-segmenting stpx` is the default. Every check of that path applies, and a request of 1 to 7 bytes is one frame
either way. The audit log records the choice before the first request (`"dir":"setting"`, `"name":"segment-on-stn"`,
`"value":"on"` for `caf0`, `"off"` for an explicit `stpx`; nothing without the flag). The option is for ELM327/STN
adapters: it is refused with `--gsusb`, `--socketcan`, `--sim` and `--dry-run`, and by `adapter` and `update`, with
status 2.

### A CANable or candleLight (`--gsusb`)

```sh
obdcracker --gsusb --profile a7 vin                 # the one gs_usb adapter plugged in, at the profile's bitrate
obdcracker --gsusb=3A9F20 --bitrate 500000 vin      # one of several, picked by serial number
obdcracker --gsusb --listen-only --bitrate 500000 vin  # never transmits: every request fails
```

The adapter carries ISO-TP over USB with no ELM327 in between ([details](gsusb.md)). `--gsusb=SERIAL` needs the `=`,
or the serial would be taken for the command. With several adapters and no serial the CLI lists them and exits with
status 2 without writing to any. The bitrate (250000 or 500000) comes from `--bitrate` or the `--profile`; if both are
given they must agree. Before the adapter goes on the bus it listens at that bitrate: frames confirm it; error frames
refuse; silence goes active with a warning when the bitrate was given and is refused when it was only the default
(500000). `--listen-only` never goes on the bus at all. The audit log's link names the mode and bitrate
(`gsusb:active:500000`). `adapter` is for ELM327/STN adapters only. Setup per OS is in [install](install.md#gs_usb-adapters).

### A SocketCAN interface (`--socketcan`, Linux)

```sh
obdcracker --socketcan can0 --profile a7 vin                    # at the profile's bitrate, which can0 must already have
obdcracker --socketcan can0 --bitrate 500000 fingerprint
obdcracker --socketcan can0 --listen-only vin                   # never transmits: every request fails
```

Any interface the kernel has a driver for: a CANable on the kernel's `gs_usb` driver, PCAN-USB, Kvaser, a Pi CAN HAT, or
`vcan` for tests ([details and setup](socketcan.md)). Unlike `--gsusb`, the program never sets the interface's bitrate or
mode: bring it up yourself (`sudo ip link set can0 up type can bitrate 500000`). `--bitrate` (250000 or 500000) or the
`--profile` is the bitrate the car's bus runs at, and only checked against the interface's own: another bitrate is refused,
and an interface that reports none (`vcan`) gets a warning. Without either, nothing is checked. A down or faulted
interface, one in listen-only or loopback mode (for an active session), and one that isn't a CAN interface are refused,
with what was read in the audit log. `--listen-only` never writes a frame, but only an interface whose controller is in listen-only mode (`ip link set can0 type can listen-only on`, set up by you) also stays from acknowledging what it hears; otherwise the program says so. The audit log's link names the interface and the
mode (`socketcan:can0:active`). `adapter` is for ELM327/STN adapters only. On other systems than Linux the option is
refused.

On macOS use the `/dev/cu.*` port. Leaving a wireless adapter plugged in drains the battery and lets anyone in range
connect, so the CLI warns about it, and the audit log records which link a session used. See
[adapters](adapters.md) for what's supported.

Two options, each with its own list of commands:

- `--dry-run` works with `vin`, `fingerprint`, `scan`, `sweep`, `dtc`, `read-dids` and `update`. The car commands print the frames
  they would send and open no adapter; `update` makes the same lookups and prints the command it would run, and installs
  nothing. `adapter` and `diff` refuse it, and `ports` ignores it.
- `--sim a7` works with `vin`, `fingerprint`, `scan`, `sweep`, `dtc` and `read-dids`, and runs the command against a simulated A7.
  `adapter`, `update` and `diff` refuse it with status 2, and `ports` ignores it.

## Battery voltage

Before `vin`, `fingerprint`, `scan`, `sweep`, `dtc` and `read-dids` send anything, the CLI asks the adapter what voltage
it sees (`ATRV`) and writes the reading to the audit log (`"dir":"voltage"`; an ELM327 or STN also logs the `ATRV`
command and its answer). A dry run has no car and reads nothing; `adapter` just shows the voltage. With the engine
off:

| Voltage | What happens |
|---|---|
| 12.2 V or more | nothing is printed |
| under 12.2 V, at least 11.8 V | a warning |
| under 11.8 V | a long command is refused (status 1, nothing sent); a short one gets a warning |
| not reported (`gs_usb`, SocketCAN, a clone that prints `?`) | a note that the battery isn't checked; the command goes on |

A voltage equal to a threshold is on its good side: exactly 12.2 V prints nothing, and exactly 11.8 V is only a
warning. A **long command** is a `sweep` of more than 256 DIDs (exactly 256 is short) or `scan --discover --wide`.

While a long command runs, the voltage is read again every 50 requests, and a reading under 11.8 V stops it: `sweep`
and the discovery passes print what they found and exit with status 1, `sweep` also says where to go on from (and
leaves the extended session first, if it was in one). A reading that is unknown, or fails, doesn't stop it.

`--force-low-voltage` skips both the refusal and the stop. The voltage is still read, logged and warned about.
Some adapters without voltage sensing always print `0.0V`, which is read as a voltage of 0: use the flag with those.

To try this without a car, `--sim` takes `--sim-voltage 11.5` (the simulated battery, 12.6 V by default) and
`--sim-voltage-drop 60:11.0` (the battery drops to 11 V once 60 requests have been sent):

```sh
obdcracker --sim a7 --sim-voltage 11.5 sweep --module engine --range 0600-0700   # refused: 257 DIDs
obdcracker --sim a7 --sim-voltage-drop 60:11.0 sweep --module engine --range 0600-0700   # stops at the check after request 100
```

The thresholds and the rules behind them are in [safety](safety.md#supply-voltage).

## `vin`

```sh
obdcracker vin
```

Prints each ECU's VIN (OBD-II mode 09 PID 02) as a `<reply ID> <VIN>` line, with the VIN's fields indented under it:

```
7E8 WAU2MBFC6EN093415
    manufacturer code: WAU
    descriptor section: 2MBFC
    check digit: 6 (correct; not required outside North America)
    model year: E = 1984 or 2014
    plant code: N
    serial: 093415
    matches profile: a7
```

The fields are ISO 3779's: positions 1 to 3, 4 to 8, 9, 10, 11 and 12 to 17. The descriptor section and the plant code
are shown as written, because what they mean is the manufacturer's.

- **Model year.** Position 10's code repeats every 30 years, so two years are shown. Position 7 narrows them only for
  some North American vehicles (passenger cars and light trucks, 49 CFR 565.15), and a VIN doesn't say which class it
  is, so none is narrowed to one. A profile's `years` range fits if either is in it. `U`, `Z` and `0` aren't year codes.
- **Check digit.** The digit the other 16 characters make (weights and letter values from 49 CFR 565.15, 10 written as
  `X`) is shown beside the one written. North America requires it, so a wrong one there is called wrong; elsewhere a
  mismatch is only noted, since those VINs needn't have a correct one.
- **Profile.** `matches profile` lists the builtin profiles whose `[vin]` table ([profiles](profiles.md#vin)) fits the VIN,
  or says none does. With `--profile` that doesn't fit, a `does not fit --profile a7` line follows, and the command still
  exits 0: reading the VIN is its job.

It is one broadcast, except on an
adapter whose driver paces its replies (every plain ELM327, and an STN below 115200 baud): there it broadcasts mode 01
PID 00 to find the ECUs, then asks each in turn by its own request ID, so that several ECUs' long replies don't
overflow the adapter ([details](scanning.md#module-discovery)). `--dry-run` shows the one broadcast. With `--profile`,
the requests to each ECU go only to request IDs the profile lists; if it leaves one out, the VINs are read by a
`09 02` broadcast after the `01 00`. An ECU that has no VIN may refuse a request of its own: that is
printed to stderr but isn't a failure if another ECU gave a VIN. A malformed VIN, or no VIN at all, exits 1.

### Checking the car against `--profile`

With `--profile`, `fingerprint`, `scan`, `sweep`, `read-dids` and `dtc` first read the car's VIN (the same `09 02`
request as `vin`, after the battery check and after the command's own arguments have been checked) and compare it with
the profile's `[vin]` table. Only an explicit `--profile` is checked: `--sim` already is the car its profile describes,
and without a profile there is nothing to compare with. `vin` itself is not checked.

| What the car says | What happens |
|---|---|
| a VIN the profile fits, or ECUs that all give the same one | the command goes on |
| a VIN the profile doesn't fit | refused: the message names the VIN and the profile, nothing else is sent, exit 1 |
| no VIN: no ECU answered, or each refused or sent something that isn't a VIN | refused, the same |
| ECUs that give different VINs | refused, the same: it can't be told which car this is, even if each fits |
| a profile with no `[vin]` table | a note that the VIN isn't checked; the command goes on |

An unknown VIN stops the command just as a mismatch does. An ECU that refuses `09 02` or sends a malformed reply is left
out when another gives a VIN. `--ignore-vin-mismatch` (it needs `--profile`) turns each refusal into a warning and goes
on. A failure of the adapter or the policy while reading the VIN stops the command whatever the flag says.

`--dry-run` shows the planned request and says the comparison was skipped; it never stops a dry run:

```
$ obdcracker --dry-run --profile a7 fingerprint
7DF 02 09 02
dry run: the car's VIN wasn't compared with the a7 profile
...
```

## `fingerprint`

```sh
obdcracker fingerprint
```

Identifies the engine and transmission software: calibration IDs and CVNs (OBD-II mode 09), then part numbers and
versions (UDS `22 F187`, `F188`, `F189`, `F191`, `F19E`), one read at a time. A tune changes the CVNs, so a saved
fingerprint shows later what changed. Module addresses come from `--profile`, or the OBD-II engine and transmission IDs
without one. On an adapter whose driver paces its replies (every plain ELM327, and an STN below 115200 baud) the
calibration IDs and CVNs are asked of each emissions ECU in turn rather than by broadcast, after a mode 01 PID 00
broadcast that finds the ECUs, so that several ECUs' long replies don't overflow the adapter
([details](scanning.md#module-discovery)); `--dry-run` shows the broadcasts.

## `scan`

```sh
obdcracker --dry-run --profile a7 scan # what scan would send; opens no adapter
obdcracker --profile a7 scan
```

Reads everything the default diagnostic session allows, without changing any module's session. From each emissions
ECU it reads every supported mode 01 PID, mode 09 PIDs 00 and 0A, and mode 03 stored DTCs (on an adapter whose driver
paces its replies, PID 0A and mode 03 are asked of each ECU in turn rather than by broadcast;
[details](scanning.md#module-discovery)). From each plain-UDS module
in the profile it reads the standard identification DIDs plus the profile's own DIDs, and its DTCs (`19 01 AF`,
`19 02 AF`). It lists only DTCs that are failed, pending, confirmed or failed since the last clear, not the module's
untested codes. DIDs whose length the profile gives are read three to a request; any a reply leaves out or doesn't fit
are read again one at a time, and must then be exactly that length.

### Gateway list

If the profile has a `[gateway_list]` ([profiles](profiles.md#gateway-list)) and its gateway answered, scan ends by
reading the gateway's installed-module list and comparing it with the modules it tried:

```
gateway lists 73 installed modules: 20 found, 29 silent, 24 not in profile
  05 silent
  34 not in profile (request 0x755)
  22 not in profile (request 0x71D)
```

The summary counts each status and names the addresses when there are 8 or fewer of a status; each module that wasn't
found then gets a line, with its request CAN ID if the gateway gave one. An address the gateway lists twice shows
twice. The statuses:

- `found`: a profile module with that VAG address answered the scan, or a TP2.0 setup to it (`--discover-tp20`).
- `silent`: it was tried and nothing answered. A TP2.0 setup counts as a try only with `--discover-tp20`.
- `not tried`: a profile module has the address but scan skipped it, such as one that isn't plain UDS.
- `not in profile`: no profile module has that VAG address. That includes a module the profile lists without a
  `vag_address`.

If the list can't be read, scan prints a `warning:` and its result and exit status are unchanged. `--dry-run` says
which two reads a live scan adds.

### `--extended`

```sh
obdcracker --profile a7 scan --extended  # also read the profile's extended-session DIDs
```

Also reads the DIDs the profile marks `session = "extended"`. After a module's other reads it enters the extended
session (`10 03`), reads them (with `3E 00` before a read once 2 s have passed since the module last accepted one), and
returns it to the default session (`10 01`). A module with no such DIDs isn't switched, and without `--extended` those
DIDs show as not read. A module that refuses the session loses only those DIDs.

### `--discover`

```sh
obdcracker --profile a7 scan --discover  # also look for modules the profile doesn't list
```

First looks for modules the profile doesn't list. It reads the part number (`22 F1 87`) from each request ID in the
profile's discovery range, one at a time and through the policy narrowed to those IDs, then scans whatever answered
along with the profile's modules. On the A7 that's 0x700 to 0x769, replies at +0x6A: no ID it sends on is ever a reply
ID. A module whose request ID is past 0x769 isn't found by that pass.

### `--discover --patient-ids`

```sh
obdcracker --profile a7 scan --discover --patient-ids 71D,755  # and ask these again, patiently
```

After the first pass, asks each listed request ID that didn't answer again, waiting up to 5 s for each (about 1 s on
a plain ELM327), for a module that answers slowly. The A7 gateway's tables list 71D and 755 as request IDs (#169).
Each ID is three hex digits and must be in the profile's discovery range, listed once; anything else is refused before
anything is sent. With `--wide`, the recheck before the wide pass skips the IDs already asked here.

### `--discover --wide`

```sh
obdcracker --profile a7 scan --discover --wide  # and past the discovery range
```

Then looks further, at 0x76A to 0x795 on the A7 (replies up to 0x7FF), where VW's MQB cars put the MMI (0x773). Those
request IDs are the first pass's reply IDs. It skips those a module it knows of (listed in the profile, or just found)
answers on, and any whose reply would be an OBD-II ID. A module that stayed silent in the first pass could still own
one, so before the wide pass it asks each of those first-pass IDs again, waiting up to 5 s for each, to find a module
that was only slow. The wide pass waits as long, for modules such as the MMI whose replies the gateway may route
slowly. An OBDLink (STN chip) can wait that long; a plain ELM327 waits about 1 s at most, and the output says so. One
that doesn't answer `22 F1 87` at all could still own one, so `--wide` is opt-in and may send a read on that module's
reply ID: a frame no module receives, since modules only send on theirs. A module that speaks only KWP2000/TP2.0, as
some older MMIs may, doesn't answer any pass. `--wide` is a long command: it is refused on a low battery and stopped
if the battery drops ([Battery voltage](#battery-voltage)).

### `--discover-29bit`

```sh
obdcracker --profile a7 scan --discover-29bit  # look on 29-bit IDs too
```

Looks on 29-bit CAN IDs, as `--discover` does on 11-bit ones: the part number (`22 F1 87`) from each request ID in the
profile's 29-bit discovery range, then a scan of whatever answered. On the A7 that's VAG's 0x17FC0000 to 0x17FC00FF,
replies on 0x17FE00xx (256 reads, about 4 minutes on an ELM adapter). The adapter switches to 29-bit CAN for them and
back. It can run with `--discover` or alone. Whether the A7 has any module on these IDs is unknown (#89).

### `--discover-tp20`

```sh
obdcracker --profile a7 scan --discover-tp20  # then look for VW TP2.0 modules
```

After the scan, sends a VW TP2.0 channel setup (`<address> C0 00 10 00 03 01` on 0x200) to each address in the
profile's TP2.0 list. On the A7 these are the 13 modules that stayed silent on ISO-TP (#92), and the 16 other
addresses the gateway's `2A29` table marks like the passenger door's (52, #169). Some of those may be modules that
answer on ISO-TP; a setup to one is still a read. For each module that
answers, it shows the channel it gave, a refusal or the bytes it sent. It then closes each channel with `A8`. Then, for
each module that gave a channel, it opens one again, asks for VAG's diagnostic session (`10 89`, which the modules want
before they answer reads: car session 9's module 52 answered `1A 9B` with `7F 1A 11` without it), reads the module's
identification (KWP2000 `1A 9B`), showing the bytes and their printable text, and closes the channel, which ends the
session ([how](tp20.md#data-transfer)). A module that answers `1A 9B` with `7F 1A 11` (service not supported, whatever the
session) is asked on the same channel for its part number (`22 F1 87`) and its ODX name (`22 F1 9E`) instead, one request
each, since KWP2000's `22` takes one identifier. Each is a line of its own, `TP2.0 52 F187 "4G8959802B"`: the text if it's
printable (the padding a module adds is dropped), the bytes in brackets if not, `(empty)` for no value, `refused (...)` or
`not read (...)` otherwise, with the reply's bytes if it isn't `62` and the ID asked for. A read that fails closes the
channel, so the next is shown as not read without being sent. Any other refusal of `1A 9B` sends no `22`. The `1A 9B` line ends with the session the read ran in: `(session 89)` if the
module answered exactly `50 89`, else `(default session: ...)` with why (`10 89` refused with its code, not answered,
or answered with other bytes), and the read is still tried, on a new channel if the failed request closed the first. A record that doesn't start with
the `9B` it answers is shown as not read, with its bytes. An adapter failure on a channel ends the scan with an error.
The modules aren't scanned otherwise. A disconnect goes
only on a channel a module gave in answer to its setup, answered on 0x300 as the setup asked, and never on an ID
below 0x300, an ID a profile module uses, or the OBD-II IDs. If the policy refuses one, the output says so, and
the module closes the idle channel by itself. Over an ELM adapter it needs one that echoes each character as it reads it,
such as an OBDLink ([why](elm327.md#vw-tp20-channel-frames)); with `--gsusb` or `--socketcan` the frames go out as raw CAN
frames of their own length ([how](raw-can.md#vw-tp20)).

## `sweep`

```sh
obdcracker --profile a7 sweep --module "head-up display" --range 0600-06FF  # DIDs it answers
```

Looks for the DIDs one profile module has that no profile lists yet, such as the head-up display's adaptation values.
It reads each DID in the range (`22 xxxx`), one request each, and lists those the module answers, skipping refusals as
out of range (NRC 0x31). It asks for an explicit range and prints how many reads that is first. It stops early, keeping
what it found, if the module goes quiet (3 reads in a row with no final answer), refuses `22` itself (such as "service
not supported in active session"), says it's busy, or the adapter fails, and prints the command to go on with when
that can help. `--extended` sweeps in the extended session, entered and left as `scan --extended` does, and warns if
the module may not have left it. A sweep that finishes after a request went without a definite answer notes that a
late answer may yet arrive, so connect again before reading from that module again. A sweep of more than 256 DIDs is
a long command: it is refused on a low battery and stopped if the battery drops
([Battery voltage](#battery-voltage)).

`--patient` waits up to 5 s for each reply (about 1 s on a plain ELM327), for a module that answers slowly: the A7's
gateway refuses `22 00BE` after more than 1.1 s, so a usual sweep takes that refusal for the next read's answer and
stops there (#171). Each read then takes up to the full wait, so give it a narrow range, such as `--range 00BE-00BE`.

## `dtc`

```sh
obdcracker --profile a7 dtc --module gateway --code 0016A0  # one DTC's stored detail
```

Reads one DTC from one profile module: every snapshot record (`19 04 <DTC> FF`), what the module stored when the fault
happened, then every extended data record (`19 06 <DTC> FF`), such as how often it happened. The code is the six hex
digits `scan` lists. Records print as hex, each a record number and its data: their lengths depend on the module's data
identifiers, so they aren't split up. A snapshot reply whose first record is shorter than the identifiers its count
declares (each a 2-byte DID and data), or that declares none, is shown as undecodable, with its bytes. A refusal of
one read doesn't stop the other. If the snapshot read goes unanswered, the extended data isn't asked, because a late
refusal doesn't say which read it answers; nor if the module says it's busy (NRC 0x21), since it's still on the first.
The code can't be 000000 (no code) or FFFFFF (every group). If the module answers nothing, the command fails.

`--record 01` reads only that record of each instead (`19 04 <DTC> 01`, then `19 06 <DTC> 01`), as two hex digits;
the default is `FF`, every record. `FE` is refused: it means every OBD record only to the extended data read. It's
for a module that refuses `FF` but may answer a single record (#169). A reply for another record isn't taken as the
answer, since it may be a late answer to an earlier request.

## `read-dids`

```sh
obdcracker --profile a7 read-dids --module transmission --did F187,F188,F189,F191  # one request for four DIDs
```

Reads several DIDs from one profile module with a single request (`22` and each DID), such as the four identification
DIDs: 9 bytes, so it goes out in segments. The DIDs are four hex digits each, comma-separated, in the order the reply
must hold them: 1 to 21 (a request of at most 43 bytes, under the driver's 44), with no repeats. The policy approves the
request as it does any other, the profile can only narrow it, and nothing is sent if it refuses.

Through an ELM327 (`--serial` or `--tcp`), a read of 4 or more DIDs first sends a read of the first DID alone, since the
adapter sends a request over 7 bytes in segments only once an earlier request has shown that it echoes each character.
If the module doesn't answer that read, the long request isn't sent. Every other backend (`--gsusb`, `--socketcan`,
`--sim`) sends the one request. `--dry-run` has no backend, so it says both.

A module leaves out of its reply the DIDs it doesn't support (ISO 14229-1; it refuses with `7F 22 31` only when it has
none of them), so the reply may hold fewer DIDs than were asked for, still in the order asked. Each DID it left out is
printed as `<ID> <module> <DID> (not in the reply)`, and the read still succeeds.

The reply doesn't say where one DID's data ends, so it is split only as far as the profile gives lengths. Each DID
whose length the profile gives is printed as `<ID> <module> <DID> [bytes]`. From the first DID in the reply with no
length that isn't the last one asked for, the rest is printed whole, as `<ID> <module> <DIDs> not split, as the profile
gives no length for the first [bytes]`, from that DID's echo on (a DID with no length that is the last one asked for
takes the rest of the reply). The reply is checked exactly as far as it is split: each echo is one of the DIDs asked for
and comes in the order asked, with none repeated; each known length is held to; and nothing is left over once the last
DID is split. The length of a DID the reply leaves out doesn't matter. The bytes after the first DID with no length
aren't checked beyond that DID's echo and one data byte, so the DIDs after it aren't reported as left out: they are in the
`not split` line. A reply that fails any check (a DID out of order, a DID not asked for, bytes after the last one, or a
reply that leaves out every DID) is printed as `(reply is malformed: <bytes>)` and shows no values; a refusal is
printed by name, as `scan` does. The command exits 0 when the module gave a good reply, left-out DIDs included, 1 when
it didn't, refused or said nothing, and 2 for a bad command line (a DID that isn't four hex digits, a repeat, none or
more than 21, a module the profile doesn't have, no profile).

An ELM327 sends a request over 7 bytes in segments only on an adapter that has shown it echoes each character as it
reads it, and its first request shows that, so with 4 or more DIDs the command first reads the first DID alone (a single
frame to the same module, through the same policy) and then sends the whole read: the audit log has both. A list the
command would refuse is refused before that first read. If the first read gets no answer, the whole read isn't sent
(status 1), since the module's late answer could be taken for the whole read's; a refusal counts as an answer. `--dry-run`
prints the frames of the whole request only, and `--elm-segmenting caf0` chooses how an STN sends it
([above](#sending-a-long-request-on-an-stn---elm-segmenting)).

## `diff`

```sh
obdcracker --json fingerprint > before.json
# ... have the car tuned ...
obdcracker --json fingerprint > after.json
obdcracker diff before.json after.json
```

Compares two [`--json`](#json-output---json) documents of the same command and prints what changed from the first to the
second, one line per change, or `no changes`. It opens no adapter, needs no profile and writes no audit log, so every flag
that picks an adapter, a profile or the log (and `--dry-run`) is refused with status 2. It works on `fingerprint`, `scan`,
`sweep`, `vin` and `read-dids` documents; a document of another command (`dtc`, `adapter`, `ports`, or `diff`'s own output),
two documents of different commands, a file that can't be read, isn't UTF-8 or JSON, is over 64 MiB, has a schema this build
doesn't read, or a result that isn't its command's is an error that names the file (status 2, nothing on stdout).

```
7E8 CALID 1: "4G0907589F" → "4G0907589G"
7E8 CVN 1: 9BF7470D → 38D3FF82
transmission F189 "0005" → "0006"
module added: 5F mmi (0x77F)
engine DTC new: 0016A0 (confirmed)
```

A DID's, CALID's or ECU name's text is in double quotes (`\"` and `\\` for those characters), so it can't pass for bytes
(`[01]`) or a marker (`(absent)`, `(not set)`, `(empty)`, or why a read failed, such as `(no reply)`).

- **Exit status:** 0 when nothing changed, 1 when something did (as `diff(1)` does), 2 on an error.
- **What is compared:** each emissions ECU's calibration IDs and CVNs by slot (`fingerprint`), its supported mode 01 and
  mode 09 PIDs, name and stored DTCs (`scan`), the modules found, each module's DIDs (a DID's text, bytes, "not set", or
  why it wasn't read, and a DID only one document has), whether it answered, and its DTCs: new, cleared, or with a
  changed status (`scan`). Part and software numbers are DIDs, so they show here. The live values of mode 01 PIDs and a
  DTC count aren't compared, since they change on every run.
- **Matching:** ECUs by their reply CAN ID, and modules by name and reply CAN ID together, so a module that answers on
  another ID is one removed and one added. An ECU or module in only one document is one line; what it holds isn't listed.
- **A list that failed:** if a list (calibration IDs, DTCs, ...) couldn't be read in one document and was in the other, the
  line says it can't be compared (`engine DTCs can't be compared: old read, new no reply`) instead of listing every entry
  as new or cleared.
- **Order:** the same whatever order the documents list things in: ECUs by CAN ID, then modules by name and CAN ID, and within
  each by DID or DTC. A file that lists the same ECU, module, DID or DTC twice (a hand-edited one) is an error that names
  the file and the entry (status 2): which entry is the car's can't be told, so nothing is compared.
- **VINs:** a VIN is shown only when it changed (`vin`: `7E8 VIN <old> → <new>`; `scan`: the F190 line). An ECU that only one
  `vin` document has is `7E8 ECU added` or `removed`, without its VIN.
- **`sweep`:** both documents must be of the same module. A sweep that stopped early (the battery guard, a silent module)
  didn't read what is past its stop, so only the DIDs both sweeps read in full are compared; when that is less than the
  range either sweep asked for (two sweeps that stopped at the same DID included), a note on stderr gives it. Two sweeps
  with no DID in common are an error.
- **`read-dids`:** both documents must be of the same module and have asked for the same DIDs. The split DIDs' bytes are
  compared (a DID split in one and left out of the other is `(absent)` on the left-out side), and the bytes the profile
  gave no length for (`unsplit data`).
- **Text from the files** is shown as printable ASCII, anything else as `\u{...}`, so a document can't put an escape sequence
  on your terminal.
- **`--json diff`** prints the changes in the usual [envelope](json.md#diff), and the exit status above.

## JSON output (`--json`)

```sh
obdcracker --json scan > scan.json     # one JSON document on stdout, notes and warnings on stderr
obdcracker --sim a7 --json vin
```

`--json` goes before the command, like the other flags. It works with `vin`, `fingerprint`, `scan`, `sweep`,
`read-dids`, `dtc`, `adapter` and `ports`, and prints the changes [`diff`](#diff) finds. It is refused with `--dry-run`
and `update` (status 2). stdout holds only the document, and the exit status is the one the text output would give. The fields and their forms are in
[JSON output](json.md).

## `update`

```sh
obdcracker update                          # the highest release, if it is newer than this build
obdcracker update 0.2.0                    # that release (v0.2.0 works too)
obdcracker update --main                   # the newest commit on main
obdcracker --dry-run update                # look it up and say what would be installed; installs nothing
obdcracker update 0.1.0 --allow-downgrade  # replace this build with an older one
```

Looks a release (or `main`) up on GitHub, checks that it is newer than this build, and runs the
[install script](install.md) at that exact commit: `sh install.sh --ref <commit>` on macOS and Linux, and
`powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Ref <commit>` on Windows, each downloaded from
`raw.githubusercontent.com` at the same commit first. The script builds from source, so an update takes as long as a
first install. It needs `curl` (Windows 10 and later have `curl.exe`) or, on a system without it, `wget`.

- **Which release:** only published releases whose tag is exactly `v<major>.<minor>.<patch>` count (not drafts,
  pre-releases or other tags). Without a version it takes the highest version, not the newest.
- **Newer than this build:** this build's version and commit are in `obdcracker --version`. When the commit is
  known, GitHub compares it with the target's. The target is installed when it is ahead, and `update` says it is up
  to date when the commits are the same. A target that is behind, on a different line of history or not known to GitHub
  (a build from a local checkout) is refused.
- **Older versions:** a release with a lower version than this build is refused before any commit is compared.
  `--allow-downgrade` replaces the refusals above, and says which build it replaces with which (versions and short
  commits) before it installs. It doesn't change "up to date": the same commit is never reinstalled.
- **A build with no recorded commit** (`unknown` in `--version`: one made before `update` existed, or by a plain
  `cargo build`) can't be compared. It installs a release with a strictly higher version, and refuses `--main` and
  the same version unless `--allow-downgrade` is given. Running the [install script](install.md#updating) once
  replaces it with a build that records its commit.
- **`--dry-run`** goes before `update`, as for every command. It makes the same lookups and prints the command it
  would run, and downloads and installs nothing.
- **No adapter:** `update` opens no adapter and writes no audit log. `--serial`, `--tcp`, `--gsusb`, `--socketcan`,
  `--sim`, `--profile`, `--baud`, `--elm-segmenting`, `--listen-only`, `--bitrate`, `--sim-voltage`,
  `--sim-voltage-drop`, `--force-low-voltage`, `--ignore-vin-mismatch`, `--json` and `--audit-log` are refused with
  status 2.
- **Rate limit:** GitHub's API allows 60 requests an hour per address without signing in. `update` and
  `update <VERSION>` make one request per release page, one for the target's commit and, when the installed commit is
  known and differs from the target's, one comparison. `update --main` reads no release list, so it makes the commit
  lookup and that comparison only. The release list is read 100 releases at a time, and a page is read while the one
  before it was full: 99 releases take one page, and exactly 100 take two (the second empty). A list of exactly 1000
  releases takes eleven pages, and a longer one is refused after the eleventh. When the list has no
  release to install (none listed, or a named version missing) or the one it has is lower than this build's (without
  `--allow-downgrade`), `update` is refused before the commit is looked up. When GitHub refuses, `update` says so.
- **Exit status:** 0 when this build is up to date or was updated, 1 when the update was refused or failed (a
  script that failed with a code from 1 to 255 gives that code), 2 for a bad command line.
- **On Windows** the running `obdcracker.exe` can't be overwritten, so it is renamed to `obdcracker.old.exe` beside
  it and a copy of it takes its place while the script runs. The script then replaces the copy, and a failed or
  cancelled (Ctrl+C) update leaves a working `obdcracker.exe`. If the script removed the program and left none, the
  old one is renamed back. `obdcracker.old.exe` (and `obdcracker.copy.exe`, which only an interrupted update at the
  worst moment leaves) are removed by the next `update`, since Windows can't delete a program that is running.
