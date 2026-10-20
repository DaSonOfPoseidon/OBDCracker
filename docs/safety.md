# Safety model

The main rule: **nothing this tool sends may brick or damage a car.** That rule comes from how the code is built, not
from developers being careful.

## The policy

- Every request goes through `obdcracker-safety`. Its `Policy` gives every OBD-II and UDS service a tier and returns an
  `Approved` request. That type can only be created inside `obdcracker-safety`, and every transport's `send` requires it.
- Anything not on the allowlist is rejected, unknown services included.
- The policy classifies each request by **protocol** (`Protocol::Uds`, which includes the OBD-II modes, or
  `Protocol::Kwp2000`), because service IDs mean different things in different protocols. In UDS `0x85` is
  ControlDTCSetting, but in KWP2000 `10 85` starts the programming (flashing) session. Every protocol has its own
  allowlist and banned list. KWP2000 has no suppress-positive-response bit, so its parameters are read unmasked.
- A module doesn't know which protocol the tester meant, so **a read in one protocol is never a locked or banned
  request in the other**: KWP2000's reads (`17`, `18`, `1A`, `21`, `3E`) aren't UDS services, or are UDS reads, and
  UDS's aren't KWP2000 services. Tests check every form of read both ways.
- A [vehicle profile](profiles.md) can only narrow what the policy allows, never widen it.
- The policy applies to programs that [import the crates](library.md) too. There is no raw-frame escape hatch.

## Tiers

Each tier above read-only needs a cargo feature, an explicit runtime unlock, and passing preconditions.

| Tier | UDS and OBD-II | KWP2000 | Status |
|---|---|---|---|
| T0 Read | OBD-II modes 01/03/09, UDS 0x22, 0x19, 0x3E, 0x10 (default/extended session) | 0x1A, 0x21, 0x17, 0x18, 0x3E | allowed |
| T1 Clear DTCs | UDS 0x14, OBD-II mode 04 | 0x14 | planned |
| T2 Coding | UDS 0x2E, 0x27 | 0x2E, 0x3B, 0x27, 0x10 87 (adjustment session) | planned; needs a backup of the current value |
| T3 Flash | programming session, 0x31, 0x34/0x36/0x37, 0x11 | 0x10 85/86 (programming, development), 0x11, 0x31-0x3A, 0x3D | **hard-banned** until a separate design doc exists; will need a full backup of the current image |

Anything else is rejected, including KWP2000's IO control (0x30), memory reads (0x23) and every session other than the
banned and locked ones: ISO 14230-3 leaves what each value means to the manufacturer, so VAG's `10 89` will need a
rule of its own.

## Back up before every change

A write (T1 and up) can't be approved without a `Backup` of what is on the module right now: read from the same
module, saved to disk and read back from disk. Every change is reversible from that backup, and each restore path is
tested end to end against the simulator (back up → write → restore → read back equals the original) before it touches
a car.

## Seeing what will be sent

- `--dry-run` prints the exact frames a command would send without opening a device. Frames that depend on the
  car's answers (`scan`'s later PID bitmaps and PID reads) can't be known in advance; the dry run lists what they
  can be instead.
- `--sim a7` runs a command against a simulated A7 instead of a car, through the same policy and audit log.

## Audit log

Every frame sent or received in a real session is appended to an audit log, along with any adapter error (such as an
adapter mishearing a request it may already have sent), every command to the adapter (`"dir":"cmd"`, such as
`AT SH 7E0`, with its answer), every status line that ended a request instead of a reply (`"dir":"status"`, such as
`NO DATA`), and every reply line the adapter printed after nothing read it any more (`"dir":"unread"`, such as a late
reply). It holds only what the adapter hears through its receive filter, not the
whole bus. Requests are logged before they are sent, and the log records which link a session used.

## Known gap: ELM327/STN adapters that echo whole lines

Their serial line has no checksum. On an adapter that echoes each character as it reads it (the OBDLink EX does), the
driver checks a request's echo before sending its carriage return, so a misheard request never reaches the bus (#34).
One that echoes only whole lines sends a request before the driver can check it, so a single bit error can turn an
approved read into another request, a locked or banned one included (a reset, clearing DTCs, one write). It can't
complete a flash sequence, and the driver stops at the first mismatched echo. It's a rare, accepted risk, reasoned in
[`elm327.md`](elm327.md). Prefer a USB or Wi-Fi adapter over a direct serial cable.

## How new capabilities are built

Test-first: golden-frame unit tests, then property tests and fuzzing of response parsers, then a simulated ECU
(`obdcracker-sim`), then a dry run on the car, and only then a live session.
