# Vehicle profiles

A profile is data, not code: module addresses, addressing mode, protocol per module, the identifiers to read and how to
decode them. Without a profile the tool falls back to generic OBD-II. Profiles are TOML files in
[`crates/obdcracker-profile/profiles/`](../crates/obdcracker-profile/profiles/); a profile has no field that names a
service, so it can't widen the [safety policy](safety.md). For outside sources to cross-check a profile against, and
which of them may be copied, see [third-party.md](third-party.md#reference-only).

| Profile | Expected setup (confirmed by a read-only module scan before use) |
|---|---|
| 2014 Audi A7 3.0 TDI (C7) | CAN 500k behind the J533 gateway; UDS on ISO-TP with 11-bit IDs: all 24 modules found so far answer UDS (#54), engine 0x7E0/0x7E8, head-up display 0x71B/0x785. A TP2.0/KWP2000-only module wouldn't show up in discovery, which only sends UDS. A 29-bit discovery range covers VAG's 0x17FC00xx IDs, untried on this car. A TP2.0 list names the 13 modules silent on ISO-TP (#92), untried too |
| 2014 Toyota Camry (XV50) | CAN 500k; OBD-II on 0x7DF/0x7E0+; enhanced diagnostics are KWP2000-style (e.g. 0x21 read by local ID) on ISO-TP; body modules sit behind 0x750 with an extended-address byte |

## File format

A profile is TOML. Unknown fields are errors. `Profile::from_toml` and `Profile::validate` check everything below.

### Top level

| Field | Meaning |
|---|---|
| `name` | What car it is, such as `2014 Audi A7 3.0 TDI (C7)`. |
| `bitrate` | The diagnostic CAN bus's bitrate in bit/s, 250000 or 500000. It is fixed per car, since a wrong bitrate can flood the bus with error frames. |
| `[[module]]` | The modules on the bus. |
| `[discovery]` | Where to look on 11-bit IDs for modules the profile doesn't list (optional). |
| `[discovery_29bit]` | Where to look on 29-bit IDs (optional). |
| `[discovery_tp20]` | The VAG addresses to try VW TP2.0 channel setups to (optional). Without it the narrowed policy allows no channel setup. |

Names (the profile's, modules' and DIDs') can't be empty or blank, and can't start or end with spaces, so a lookup by
the visible text finds them. Module names are unique ignoring case.

### `[[module]]`

| Field | Meaning |
|---|---|
| `name` | A short name, unique within the profile, such as `engine`. |
| `vag_address` | The VAG diagnostic address (`01` engine, `19` gateway), on VAG cars only. Unique. |
| `request_id`, `response_id` | The 11-bit CAN IDs requests go to and the module answers on. Both in 0x700..=0x7FF and not the OBD-II broadcast 0x7DF. A CAN ID may be shared only by modules that each have an `extended_address`, all different. |
| `protocol` | `uds` (ISO 14229 on ISO-TP), `kwp2000` (ISO 14230 on ISO-TP) or `tp20` (VW TP2.0 transport with KWP2000). Nothing reads a `kwp2000` or `tp20` module yet (#142 for TP2.0), and the simulator only simulates `uds` modules. |
| `extended_address` | The sub-address byte for ISO-TP extended addressing, if the module uses it. |
| `[[module.did]]` | The data identifiers the module can read beyond the standard ones. |

### `[[module.did]]`

| Field | Meaning |
|---|---|
| `id` | The 2-byte identifier. No repeats within a module. |
| `name` | What it holds, such as `VW coding`. |
| `decode` | `text` (printable ASCII) or `hex` (raw bytes as hex). The standard identification DIDs (0xF180..=0xF19F) with an ISO 14229-1 text format (the VIN, and the part, software, hardware, system and ODX names) must be `text`: `standard_decode` gives the format, and a DID with no fixed format takes the profile's. |
| `length` | The value's length in bytes, if the module always sends this many (not 0). It is fixed per ECU variant, not per DID, and lets several DIDs be read in one request, because a multi-DID reply doesn't say where each value ends. |
| `session` | `default` (the default) or `extended` (`10 03`): the session the module reads it in. |

### Discovery ranges

Discovery looks for modules the profile doesn't list. Every candidate must be a request and reply pair the safety
policy accepts (`Policy::narrowed_to`), and validation checks every ID in a range, then filters.

`[discovery]` is a range of request IDs, each answering on its request ID plus `reply_offset` (0x6A on VAG cars):

- `first_request_id` and `last_request_id`: the range, first no later than last and at most 0x7FF.
- No request ID in the range may be any module's or candidate's reply ID: a request sent there would look like that
  module's reply to everything listening. A candidate whose reply ID is a listed module's request ID is left out of
  `Profile::candidates`, by design: it is a module found past the range, then listed.
- `wide_last_request_id` (optional) ends a second, wider pass. It starts right after `last_request_id`, with the same
  reply offset, and must lie within the first pass's reply IDs (the only IDs the first pass can show no module answers
  on), up to 0x7FF. The wide pass skips any OBD-II ID (0x7DF..=0x7EF) and any ID a known module (listed, or found by
  the first pass) uses, except a candidate that is exactly a known module's request and reply pair. A module that
  exists and stayed silent in the first pass may still own one of its IDs, so the wide pass can send on that module's
  reply ID. It is opt-in: a stray read there is a frame no module receives, since modules
  only send on their reply IDs.
- Before the wide pass, `Profile::recheck_candidates` looks again, more patiently, at first-pass candidates that
  didn't answer and whose reply ID the wide pass would use. That finds a module that was only slow or asleep. One that
  doesn't answer `22 F187` at all stays unseen.

`[discovery_29bit]` is the same with `first_request_id`, `last_request_id` and `reply_offset` as 29-bit IDs (on VAG
cars, requests on 0x17FC00xx and replies on 0x17FE00xx: offset 0x20000). Every ID must be above 0x7FF, every candidate
a 29-bit pair the safety policy accepts, and the range at most 256 IDs (one byte of address, as VAG's scheme has).

`[discovery_tp20]` is `addresses`, the VAG addresses to try in order: at least one, none of them 0 (the tester's) or
`0xF0` to `0xFF` (broadcasts), none twice.

## Narrowing the policy

`Profile::narrow` narrows a safety policy to the car's modules. Physical requests may then only go to a module's
request ID, each approved request carries its module's reply ID, and TP2.0 channel setups may only go to the
`discovery_tp20` addresses. `narrow_for_discovery` also allows the 11-bit candidates (`Profile::candidates`). For 29-bit or wide discovery, pass
`candidates_29bit` or `wide_candidates` to `narrow_with` instead. A profile can only narrow the policy,
never widen it.
