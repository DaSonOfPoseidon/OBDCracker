# Vehicle profiles

A profile is data, not code: module addresses, addressing mode, protocol per module, the identifiers to read and how to
decode them. Without a profile the tool falls back to generic OBD-II. Profiles are TOML files in
[`crates/obdcracker-profile/profiles/`](../crates/obdcracker-profile/profiles/); a profile has no field that names a
service, so it can't widen the [safety policy](safety.md). For outside sources to cross-check a profile against, and
which of them may be copied, see [third-party.md](third-party.md#reference-only).

| Profile | Expected setup (confirmed by a read-only module scan before use) |
|---|---|
| 2014 Audi A7 3.0 TDI (C7) | CAN 500k behind the J533 gateway; UDS on ISO-TP with 11-bit IDs: all 24 modules found so far answer UDS (#54), engine 0x7E0/0x7E8, head-up display 0x71B/0x785. A TP2.0/KWP2000-only module wouldn't show up in discovery, which only sends UDS. A 29-bit discovery range covers VAG's 0x17FC00xx IDs, untried on this car. A TP2.0 list names the 13 modules silent on ISO-TP (#92); in session 6 one of them, the passenger door (52), opened a channel (#124). It also has the 16 other addresses the gateway's `2A29` table marks like 52, some possibly modules that answer on ISO-TP (#169) |
| 2014 Toyota Camry (XV50) | CAN 500k; OBD-II on 0x7DF/0x7E0+; enhanced diagnostics are KWP2000-style (e.g. 0x21 read by local ID) on ISO-TP; body modules sit behind 0x750 with an extended-address byte |

## File format

A profile is TOML. Unknown fields are errors. `Profile::from_toml` and `Profile::validate` check everything below.

### Top level

| Field | Meaning |
|---|---|
| `name` | What car it is, such as `2014 Audi A7 3.0 TDI (C7)`. |
| `bitrate` | The diagnostic CAN bus's bitrate in bit/s, 250000 or 500000. It is fixed per car, since a wrong bitrate can flood the bus with error frames. |
| `[[module]]` | The modules on the bus. |
| `[vin]` | The VINs the car may have, which a command checks the car against ([below](#vin)) (optional). |
| `[discovery]` | Where to look on 11-bit IDs for modules the profile doesn't list (optional). |
| `[discovery_29bit]` | Where to look on 29-bit IDs (optional). |
| `[discovery_tp20]` | The VAG addresses to try VW TP2.0 channel setups to (optional). Without it the narrowed policy allows no channel setup. |
| `[gateway_list]` | The DIDs of a VAG gateway's installed-module list, which `scan` reads and compares with what answered (optional). |

Names (the profile's, modules' and DIDs') can't be empty or blank, and can't start or end with spaces, so a lookup by
the visible text finds them. Module names are unique ignoring case.

### `[vin]`

Says which cars the profile is for. `fingerprint`, `scan`, `sweep`, `read-dids` and `dtc` read the car's VIN when `--profile`
is given and stop if the profile doesn't fit it ([usage](usage.md#checking-the-car-against---profile)); `vin` lists the
builtin profiles that fit. A profile with no `[vin]` table fits no VIN, and the check says so and goes on.

| Field | Meaning |
|---|---|
| `wmi` | The manufacturer codes (VIN positions 1 to 3) the car may have: at least one, each 3 VIN characters (digits and upper case letters except I, O and Q), none twice. Required. |
| `vds` | A pattern for the descriptor section (positions 4 to 8): 5 characters, each a VIN character or `?` for any one. Optional. |
| `years` | `[first, last]`: the model years, inclusive, `first` at most `last`, both within 1980 to 2039. A VIN fits if any year its position 10 can mean is in the range, so a VIN fits if either of its two candidate years is. A year code that isn't one (`U`, `Z`, `0`) fits no range. Optional. |

All the fields given must fit. Validation uses the same VIN character rule as the decoder (`obd::check_vin`), and
`years` takes exactly two numbers. The table only says which car the profile is for, so like the rest of the profile it
can't widen the safety policy.

The A7's table is `wmi = ["WAU"]` and `years = [2012, 2018]`. It has no `vds`: only the owner's one car's VIN was at hand, and
what the descriptor positions mean is Audi's, so a pattern would be a guess.

### `[[module]]`

| Field | Meaning |
|---|---|
| `name` | A short name, unique within the profile, such as `engine`. |
| `vag_address` | The VAG diagnostic address (`01` engine, `19` gateway), on VAG cars only. Unique. |
| `request_id`, `response_id` | The 11-bit CAN IDs requests go to and the module answers on. Both in 0x700..=0x7FF and not the OBD-II broadcast 0x7DF. A CAN ID may be shared only by modules that each have an `extended_address`, all different. |
| `protocol` | `uds` (ISO 14229 on ISO-TP), `kwp2000` (ISO 14230 on ISO-TP) or `tp20` (VW TP2.0 transport with KWP2000). Nothing reads a `kwp2000` module yet; a `tp20` module can be read through `tp20::ChannelSession` (#142), but scan doesn't read the profile's `tp20` modules yet (#170). The simulator only simulates `uds` modules from a fixture. |
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

## Gateway list

A VAG gateway keeps a list of the modules fitted to the car, as parallel tables with one slot per module, which `scan`
reads with `22` and compares with the modules it found (#172). The layout is VAG's, so it is profile data:

```toml
[gateway_list]
module = "gateway"      # a [[module]] name: plain UDS, no extended address
addresses = 0x2A2A      # DID of one VAG address per slot (00 = empty slot)
request_ids = 0x2A2C    # optional DID of two bytes of request CAN ID per slot (0000 = none)
```

`addresses` is required. The two DIDs must differ, and neither may be one of the module's own `[[module.did]]`
entries. On the A7 (#124) the gateway answers 80 slots: 73 addresses, with `03` and `17` listed twice, then
zero padding; the request ID table has 8 non-zero entries. A reply with another `request_ids` length than the
`addresses` table (two bytes per slot) is refused. A third table, `2A29`, is left out until its meaning is
confirmed: it looks like one byte per slot (`01` on the modules that answer on ISO-TP, `02` on those that don't) but that is a
guess.

On the A7 only six modules' addresses are confirmed by this list, each slot's request ID matching the module's (brakes
`03`, acc `13`, acc 2 `8B`, sensor cluster `3B`, steering `44`, image processing `8E`). The airbag `15`, climate `08`,
parking brake `53`, headlight range `55`, tire pressure `65`, camera `6C` and rear lid `6D` are each the module's own
claim: the list has the address but no request ID for its slot, so each was matched by the name the module gave at its
CAN ID (#231). Car session 12 (#334) checks them against each module's F197 and F19E, and they may be wrong. The head-up
display's `82` comes from an Audi bulletin.

## Narrowing the policy

`Profile::narrow` narrows a safety policy to the car's modules. Physical requests may then only go to a module's
request ID, each approved request carries its module's reply ID, and TP2.0 channel setups may only go to the
`discovery_tp20` addresses. `narrow_for_discovery` also allows the 11-bit candidates (`Profile::candidates`). For 29-bit or wide discovery, pass
`candidates_29bit` or `wide_candidates` to `narrow_with` instead. A profile can only narrow the policy,
never widen it.
