# Fixture files

A fixture is a TOML file that says what each simulated module answers. [`SimBus::new`](../crates/obdcracker-sim/src/lib.rs)
takes a [vehicle profile](profiles.md) (where each module sits) and a fixture (what it says). The built-in one is
[`a7.toml`](../crates/obdcracker-sim/fixtures/a7.toml). Every field is checked when the car is built, and an
unknown field is an error.

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
| `pids` | Mode 01 PIDs: 2 hex digits mapped to the data bytes as hex, such as `"0C" = "0C 80"`. Bitmap PIDs (0x00, 0x20, ...) are computed, so they are refused. For a PID the decoder knows, the data must be exactly one reading of it (SAE J1979); a PID it doesn't know takes any non-empty data. |

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
