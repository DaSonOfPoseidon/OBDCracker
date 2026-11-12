# Fixture files

A fixture is a TOML file that says what each simulated module answers. [`SimBus::new`](../crates/obdcracker-sim/src/lib.rs)
takes a [vehicle profile](profiles.md) (where each module sits) and a fixture (what it says). The built-in one is
[`a7.toml`](../crates/obdcracker-sim/fixtures/a7.toml). Every field is checked when the car is built, and an
unknown field is an error.

The other files in `crates/obdcracker-sim/fixtures/` aren't built into a car:

- [`standard-obd.toml`](../crates/obdcracker-sim/fixtures/standard-obd.toml) is in this format, but synthetic: OBD-II
  mode 01, 03 and 09 values worked out from the standard at the edges of what the decoders accept (every mode 01
  formula at both ends of its range, the first and last code of each DTC system, full-width and empty calibration
  IDs). It has no car behind it, and is used with a two-module profile in `tests/standard_obd.rs`. The 255-entry
  limits are built in that test, not listed in the file.
- [`obd-modes.toml`](../crates/obdcracker-sim/fixtures/obd-modes.toml) is in this format, but synthetic: what OBD-II
  modes 02, 06, 07 and 0A answer, worked out by hand in `tests/obd_modes.rs`. The A7's fixture has none of these keys,
  because the car's replies to them aren't known yet.
- `opendbc-vag.toml`, `opendbc-other-makes.toml` and `opendbc-toyota.toml` are real identification replies from
  [commaai/opendbc](third-party.md), written by `scripts/import-opendbc.sh` and read by `tests/opendbc.rs`. They
  hold replies, not a car: a reply may sit behind an extended-address byte, which the sim can't address yet (#112).

## Checks across the file

- A module named in `[[ecu]]` must be in the profile, listed once, speak UDS and use normal addressing (approved
  requests carry no extended-address byte yet).
- A `[[ecu.did]]` must be a standard identification DID (0xF180..=0xF19F) or listed for that module in the profile.
  A standard DID keeps its ISO 14229-1 format even when the profile lists it. A value that isn't refused must fit its
  format: F190 is a VIN (or a placeholder such as 17 dashes), a text DID isn't only padding. When the profile gives
  the DID a `length`, the value must have exactly that length, because a multi-DID read is split by it.
- A module with an `[ecu.obd]` table must sit on an OBD-II ID pair: request 0x7E0..=0x7E7, reply at request + 8.

## `[[ecu]]`

| Field | Meaning |
|---|---|
| `module` | The profile module's name. |
| `dtc_format` | The DTC format identifier (ISO 14229-1 D.4) sent in the count report (0x01). Default 0x01, ISO 14229-1's own format. Only allowed when `dtc_reports` includes 0x01. |
| `status_availability` | The status bits the module supports (ISO 14229-1 D.2). Default 0xFF, every bit. A DTC may not have a status bit outside it. |
| `dtc_reports` | The ReadDTCInformation sub-functions it answers, from 0x01, 0x02, 0x04, 0x06, 0x0A (count by status mask, DTCs by status mask, one DTC's snapshots and extended data with no records, supported DTCs). The others get NRC 0x12. Default all five. Not empty, no repeats. |
| `dtc_pending` | How many response-pending replies come before each positive DTC report. Default 0. |
| `dtc` | UDS DTCs (below). |
| `[ecu.obd]` | OBD-II data (below). |
| `[[ecu.did]]` | UDS data identifiers (below). |
| `[[ecu.raw]]` | Replies sent as the car sent them (below). |

### `dtc`

`{ code, status }` entries: a code of up to 3 bytes and its status byte. 0x000000 (no code) and 0xFFFFFF ("all
groups", ISO 14229-1) are refused, as are repeats and more than 65535 (the count reply has a 16-bit count).

### `[ecu.obd]`

| Field | Meaning |
|---|---|
| `vin` | Mode 09 PID 02: 17 characters that pass `obd::check_vin` (digits and upper case letters other than I, O and Q). |
| `calids` | Mode 09 PID 04: each up to 16 printable ASCII characters, 0x00-padded, not blank. `""` is an empty slot (all 0x00), which the A7's engine sends (#46). |
| `cvns` | Mode 09 PID 06: one per calibration ID, each 4 hex bytes. |
| `ecu_name` | Mode 09 PID 0A: `acronym` (up to 4 characters) and `name` (up to 15), printable and without blanks. |
| `dtcs` | Mode 03 codes such as `P0299`, up to 255. `P0000` is refused (it is the padding mode 03 replies use, SAE J1979), and so are repeats. |
| `pending_dtcs` | Mode 07 codes, as for `dtcs`. Absent: the module doesn't support the mode (a physical request gets NRC 0x11, a broadcast no answer). `[]` is a reply with a count of 0. |
| `permanent_dtcs` | Mode 0A codes, as for `pending_dtcs`. |
| `freeze_frame` | Mode 02 frame 0, a table (below). Absent: the mode isn't supported. |
| `monitor_ids` | Mode 06 monitor IDs: 2 hex digits each, such as `"21"`, without repeats. The bitmap IDs (0x00, 0x20, ...) are computed, so they are refused. Absent: the mode isn't supported. Only the bitmaps are answered; the test results behind an ID aren't. |
| `pids` | Mode 01 PIDs: 2 hex digits mapped to the data bytes as hex, such as `"0C" = "0C 80"`. Bitmap PIDs (0x00, 0x20, ...) are computed, so they are refused. For a PID the decoder knows, the data must be exactly one reading of it (SAE J1979); a PID it doesn't know takes any non-empty data. |

### `[ecu.obd.freeze_frame]`

| Field | Meaning |
|---|---|
| `cause` | The DTC that stored the frame (mode 02 PID 02), such as `P0299`. Absent: no DTC stored it, and the module answers P0000 (SAE J1979). |
| `pids` | The frame's PIDs, as the mode 01 `pids` table: 2 hex digits mapped to the data bytes as hex, bitmap PIDs refused, and each PID's data one reading of it. PID 02 is `cause`, so it is refused here, and a frame with `pids` needs a `cause`. |

An empty table (`freeze_frame = {}`) is a module that supports mode 02 and has no frame.

### `[[ecu.did]]`

| Field | Meaning |
|---|---|
| `id` | The 2-byte identifier. |
| `text` or `hex` or `nrc` | Exactly one of: printable, non-blank text; space-separated hex bytes such as `0C 80`; or an NRC to refuse with instead of answering. The NRC may not be 0x00 or 0x78 (response-pending isn't a refusal). |
| `session` | `default` (the default) or `extended`: the session the DID reads in. |
| `pending` | Response-pending replies before the answer or refusal. Default 0. |

### `[[ecu.raw]]`

A reply the car sent that the sim can't build, such as one too short to decode. It is sent as is to exactly this
request, after `pending` response-pending replies (default 0).

- `request` and `reply` are space-separated hex bytes.
- The reply must answer the request (`obdcracker_core::response::answers`, or `answers_after_pending` when `pending`
  is above 0, since the final reply comes even to a suppressed request).
- The request can't be session control (`10 ..`), which changes the module's state and a raw reply would skip.
- Two entries can't have the same request.
