# Third-party test data

Test data from other projects, used to check our code against real-world data and implementations we didn't write. No
third-party code ships in the crates.

| Source | Commit | License | Used in |
|---|---|---|---|
| [pylessard/python-can-isotp](https://github.com/pylessard/python-can-isotp) | `5593c219f35e739554d743a98d3af68c9332da31` | MIT | `crates/obdcracker-core/tests/third_party.rs` (ISO-TP frames and reassembly) |
| [pylessard/python-udsoncan](https://github.com/pylessard/python-udsoncan) | `78e85f1b5dac968b6a2d478fce9c0cc5adba2b50` | MIT | `crates/obdcracker-core/tests/third_party.rs` (UDS 0x22, 0x19, negative responses); read, not copied, for how it refuses a 0x19 snapshot record that holds no identifiers (`udsoncan/services/ReadDTCInformation.py`, `interpret_response`, version 1.26.1) |
| [commaai/opendbc](https://github.com/commaai/opendbc) | `229dc7062d8986b4f954c7c97875b4ffd0044d12` | MIT | `crates/obdcracker-sim/fixtures/opendbc-vag.toml` (VW/Audi identification replies, from `scripts/import-opendbc.sh`); `crates/obdcracker-sim/fixtures/opendbc-other-makes.toml` (Hyundai, Ford and Honda identification replies, from `scripts/import-opendbc.sh --full`, tested in `crates/obdcracker-sim/tests/opendbc.rs`); `crates/obdcracker-sim/fixtures/opendbc-toyota.toml` (Toyota and Lexus identification replies, from `scripts/import-opendbc.sh --full`, tested in the same file); the VW UDS module addresses in `opendbc/car/volkswagen/fingerprints.py` and `values.py` (request IDs 0x712, 0x715, 0x74F, 0x757, replies at +0x6A), which the A7 profile's discovery range covers |

## Makes and addressing styles covered (#12)

The goal of #12 was test data for at least 5 makes and 3 addressing styles, built from real reply bytes. The five
makes are in the opendbc fixtures at the commit above, with these addressing styles:

| Make | Fixture | How the modules are addressed | What the reply is |
|---|---|---|---|
| VW/Audi | `opendbc-vag.toml` | 11-bit: engine and transmission on the OBD-II pairs 0x7E0 and 0x7E1; the other modules sit at +0x6A, which the A7 profile uses (opendbc's addresses, not in the fixture) | UDS multi-DID F187 and F189 |
| Hyundai | `opendbc-other-makes.toml` | 11-bit, reply at request + 8 (0x7C4, 0x7D0, 0x7D1, 0x7D4) | UDS F100 |
| Ford | `opendbc-other-makes.toml` | 11-bit, reply at request + 8 (0x706, 0x730, 0x760) | UDS F188 |
| Honda | `opendbc-other-makes.toml` | 29-bit `0x18DA<module>F1`, reply with the last two bytes swapped | UDS F181 |
| Toyota | `opendbc-toyota.toml` | 11-bit at request + 8 (0x700, 0x7E0, 0x7A1, 0x7B0, 0x791, 0x7D1), and ISO-TP extended addressing on 0x750 with a sub-address byte (0x0F radar, 0x6D camera) | mode 09 PID 04, UDS F181 and KWP2000 `1A 88 01` |

In the fixtures that is three styles: 11-bit with the reply at +8, 29-bit, and extended addressing (VW's +0x6A is a
fourth, in the A7 profile). What the tests check and what they don't:

- **The decoders** read every reply, and the expected texts are written by hand from the opendbc source
  (`tests/opendbc.rs`). That includes Toyota's three reply forms, which opendbc doesn't label: the importer works
  the form out from the key and the value's shape (see the fixture's header and
  [pitfalls](pitfalls.md#data-files-and-parsed-input-profiles-fixtures)), so a Toyota ECU that answers in a form
  its shape doesn't suggest would be mislabelled. A car session should confirm each form (#96).
- **Normal addressing** is also driven through `Target` and the policy for the 11-bit and 29-bit styles (Honda, Ford,
  and Toyota's 0x7E0 engine). The policy knows a reply ID only for 0x7E0..=0x7E7 and 29-bit IDs, so any other
  Toyota module needs a profile that lists it.
- **Extended addressing** (Toyota 0x750 + sub-address) is checked at the decoder level only. Sending to it needs
  ISO-TP extended addressing (#112).
- **KWP2000 `1A 88 01`**, which Toyota's ABS, EPS, DSU, radar and camera answer, isn't a request the policy
  approves: it allows `1A` with exactly one option byte. The replies decode, but nothing can ask for them yet (#280).
- **The cars** in the fixtures are the ones opendbc lists (the Camry is the 2018-20 XV70, not the 2014 XV50), so the
  identification values say what these modules look like, not what the testbed cars answer.
- **Synthetic data** for what identification replies don't cover (mode 01, 03 and 09 at the standard's edges) is
  [`standard-obd.toml`](../crates/obdcracker-sim/fixtures/standard-obd.toml), described in [fixtures](fixtures.md).
- **Not done here:** profile skeletons from opendbc (#95, draft a profile from a scan) and a contributor's export of
  a sanitised session (#101, replay an audit log).

## Reference only

The repo only takes data under MIT, Apache, BSD, CC0 or CC-BY ([Contributing](CONTRIBUTING.md#how-we-work)). These
sources aren't (CC BY-SA is share-alike, so it isn't CC-BY), so we read them while developing but never copy them into
the repo. The same goes for any GPL, non-commercial or unlicensed source:

| Source | License | Use |
|---|---|---|
| [OBDb](https://github.com/OBDb) | CC BY-SA 4.0 | Manufacturer DIDs, module addresses and signal scalings, one repo per model (`signalsets/v3/default.json`). A cross-check when writing a profile. Its entries are community-sourced, often for other model years, and many are still flagged for debugging (`dbg`), so a DID taken from it still goes through the sim, a dry run and a live read. An importer for files the user downloads is planned (#173). |

## pylessard/python-can-isotp and pylessard/python-udsoncan

Both are MIT licensed:

> MIT License
>
> Copyright (c) 2017 Pier-Yves Lessard
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
> documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
> rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
> persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
> Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
> COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## commaai/opendbc

> Copyright (c) 2020, Comma.ai, Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
