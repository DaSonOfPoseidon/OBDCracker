# JSON output

`--json` makes `vin`, `fingerprint`, `scan`, `sweep`, `read-dids`, `dtc`, `adapter` and `ports` print one JSON document
on stdout instead of text, and `diff` print the changes it finds between two of them. The data is the library's own result types ([`obdcracker-transport`](library.md#json),
`serde` feature), so a program importing the crates reads the same values.

```sh
obdcracker --sim a7 --json scan | jq '.result.modules[] | select(.name == "transmission")'
obdcracker --json fingerprint > fingerprint.json
```

- **One document, one line.** stdout holds the document and its newline, and nothing else. Notes and warnings (the
  battery voltage, the Wi-Fi adapter warning, `using the adapter on <port>`, a sweep's progress, `scan`'s discovery and
  TP2.0 lines and its gateway list) stay on stderr, so it is safe to pipe.
- **Exit status is the text mode's.** A command that reads something and then fails still prints its document, and
  exits 1 as before: `fingerprint` and `scan` with nothing answering print an empty result, `sweep` stopped early prints
  what it found with `stop` set, `read-dids` and `dtc` print the refusals, and `vin` where every reply was refused prints
  `[]`. Check the status as well as the document.
- **A fatal error prints no document.** An error before there is a result (a bad argument, an adapter that can't be
  opened or fails, nothing to read, `vin` with no ECU answering) prints its text on stderr, exits non-zero and writes
  nothing to stdout.
- **Not with `--dry-run` or `update`.** A dry run prints the frames it would send, and `update` prints text only. Both are
  refused with status 2.

## The envelope

```json
{"schema": 1, "command": "vin", "obdcracker": "0.1.0", "result": [{"source": "7E8", "vin": "WAU2MBFC6EN093415"}]}
```

| Field | Meaning |
|---|---|
| `schema` | The document format's version, a whole number from 1 |
| `command` | The command that printed it: `vin`, `fingerprint`, `scan`, `sweep`, `read-dids`, `dtc`, `adapter`, `ports` or `diff` |
| `obdcracker` | The version of the build that printed it |
| `result` | The command's result, below |

**The schema version** goes up on any change a reader of the version before could misread: a field removed or renamed,
a changed meaning or text form, a variant removed, or a variant added to an enum such as the errors (a reader of the
version before has no value for it). Adding a field to an object doesn't. A reader reads every version up to the one
it knows, refuses a higher one, and ignores object entries it doesn't know, a `value`/`error` object's included. Old
versions keep parsing: a change that would break them gets a new version, and the reader keeps the old form.

## Field forms

Each form has one spelling. A reader accepts exactly what a writer writes, so a malformed value is an error, never a
different value.

| What | Form | Example |
|---|---|---|
| Bytes | upper-case hex pairs, one space between, empty for none | `"1A 2A 40"`, `""` |
| CAN ID | 3 upper-case hex digits up to 7FF, or 8 from 00000800 to 1FFFFFFF (an ID is written in the first form if it fits) | `"7E8"`, `"17FE0010"` |
| DID | 4 upper-case hex digits | `"F187"` |
| PID, and a bare byte such as a status or an NRC | 2 upper-case hex digits | `"0C"`, `"31"` |
| OBD-II DTC | the J2012 text | `"P0401"` |
| UDS DTC | 6 upper-case hex digits, as `dtc` takes it | `"0016A0"` |
| DTC status | 2 hex digits, one flag per bit (ISO 14229-1 D.2) | `"2F"` |
| DTC format | 2 hex digits | `"00"` |
| CVN | 8 upper-case hex digits | `"9BF7470D"` |
| Text | a JSON string | `"4G0907401N"` |
| Unit | its variant's name | `"Celsius"`, `"Rpm"` |

A PID value is a finite number. The decoders never produce a NaN or an infinity, and a writer asked to write one
fails rather than write a `null` that can't be read back.

### A value or an error

A read that can fail is an object with `value` or `error`, one of them:

```json
{"value": ["P0401"]}
{"error": "NoReply"}
```

Where a list holds such results, each entry is an object with its key (`did` or `pid`) and `value` or `error`:

```json
[{"did": "F187", "value": {"Text": "4G0907401N"}}, {"did": "F188", "error": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}}]
```

An object with both, or neither, is refused.

### Errors

`error` is a `ReadError`, written as its variant:

| Value | Meaning |
|---|---|
| `"NoReply"` | nothing answered in time |
| `"StillPending"` | the module said it was busy but didn't answer in time |
| `{"Reply": <reply error>}` | the module refused, or the reply couldn't be used |
| `{"Undecodable": {"error": <reply error>, "reply": <bytes>}}` | the reply couldn't be decoded; the bytes are what was received |
| `"NeedsExtendedSession"` | only the extended session reads it, and `--extended` wasn't given; nothing was sent |
| `{"SessionRefused": {"error": <reply error>, "reply": <bytes>}}` | the module wouldn't enter or stay in the extended session |
| `{"CountMismatch": {"calids": 2, "cvns": 1}}` | the CVNs don't pair with the calibration IDs |

A reply error is `{"Negative": {"sid": "22", "nrc": "31"}}` (a refusal of service `22` with NRC `31`),
`{"WrongService": "7F"}`, `"TooShort"` or `"Malformed"`.

## Results

### `vin`

A list, one entry for each ECU whose reply was a VIN. An ECU that refused or sent something malformed is on stderr.

```json
[{
  "source": "7E8",
  "vin": "WAU2MBFC6EN093415",
  "wmi": "WAU",
  "vds": "2MBFC",
  "check_digit": {"found": "6", "computed": "6", "status": "not-required"},
  "year_code": "E",
  "model_years": [1984, 2014],
  "plant": "N",
  "serial": "093415",
  "builtin_profiles": ["a7"]
}]
```

`source` and `vin` are the entry's reading; the rest is worked out from the VIN ([`vin`](usage.md#vin) says how), so a
reader may recompute it, and [`diff`](usage.md#diff) ignores it. Documents from before these fields were added have only
`source` and `vin`, and read the same: adding fields to an object doesn't change the schema version.

| Field | Meaning |
|---|---|
| `wmi`, `vds`, `plant`, `serial` | VIN positions 1 to 3, 4 to 8, 11 and 12 to 17, as written. The meaning of `vds` and `plant` is the manufacturer's |
| `check_digit` | `found` is position 9; `computed` is the digit the rest of the VIN makes (`0` to `9` or `X`); `status` is `valid` or `invalid` where the manufacturer code is North American (first character 1 to 5), which requires the digit, and `not-required` elsewhere, whether it matches or not |
| `year_code` | Position 10, as written |
| `model_years` | The years the code can mean: two, 30 years apart (position 7 narrows them only for some North American vehicle classes, which a VIN does not name), and none for `U`, `Z` and `0`. Earliest first |
| `builtin_profiles` | The names of the builtin profiles whose `[vin]` table fits the VIN. Empty if none does |
| `profile` | Only with `--profile`: `{"name": "a7", "fits": true}`. `fits` is `false` when the profile's `[vin]` table doesn't fit the VIN, and `null` when the profile has no such table |

### `fingerprint`

```json
{
  "ecus": [{
    "source": "7E8",
    "calids": {"value": ["4G0401N 0016BVAB", null, "NOX00907807 0015"]},
    "cvns": {"value": ["9BF7470D", "00000000", "38D3FF82"]}
  }],
  "modules": [{
    "name": "transmission",
    "response_id": "7E9",
    "dids": [
      {"did": "F187", "value": {"Text": "4G0927158Q"}},
      {"did": "F188", "error": {"Reply": {"Negative": {"sid": "22", "nrc": "31"}}}}
    ]
  }]
}
```

`ecus` is each emissions ECU's mode 09 PID 04 and 06 answers. A `null` calibration ID is an empty slot (sent as only
0x00 padding) and keeps its place beside its CVN. `modules` is each module's identification DIDs. A DID's value is
`{"Text": "..."}`, `{"Bytes": "1A 2A"}` for data that isn't printable text, or `"NotSet"` for a placeholder that says
no value is stored (a VIN of 17 dashes).

### `scan`

```json
{
  "ecus": [{
    "source": "7E8",
    "pids": {"value": [
      {"pid": "05", "value": {"Quantity": {"value": 63.0, "unit": "Celsius"}}},
      {"pid": "8F", "value": {"Raw": "03 00 FF FF 00 00 00"}}
    ]},
    "pids_cut_short": null,
    "supported_info": {"value": ["02", "04", "06", "0A"]},
    "ecu_name": {"value": "ECM-EngineControl"},
    "stored_dtcs": {"value": ["P0401"]}
  }],
  "modules": [{
    "name": "transmission",
    "response_id": "7E9",
    "dids": [{"did": "F191", "value": {"Text": "0BK927156AM"}}],
    "dtc_count": {"value": {"availability": "FF", "format": "00", "count": 1}},
    "dtcs": {"value": [{"dtc": "040100", "status": "2F"}]},
    "answered": true
  }]
}
```

- `ecus[].pids` lists each mode 01 PID the ECU says it supports, other than the bitmap PIDs. A value is
  `{"Quantity": {"value": 63.0, "unit": "Celsius"}}`, scaled per SAE J1979, or `{"Raw": "<bytes>"}` for a PID that isn't
  decoded yet. `pids_cut_short` is `{"pid": "20", "error": ...}` when a later bitmap page was missing or garbled, and
  `null` otherwise.
- `supported_info` is the mode 09 PIDs the ECU supports.
- `modules[].dtcs` are the DTCs with a fault bit set, as the 6 hex digits of the UDS DTC. The `P0401-00` form the text
  output shows for a module whose `dtc_count.format` is `"00"` or `"04"` is the first two bytes as the J2012 code and
  the third as the failure type.
- `answered` is whether the module answered anything at all, a refusal included.
- **What isn't in it:** the discovery passes, the TP2.0 pass and the gateway's installed-module list are written to
  stderr. A module that `--discover` or `--discover-29bit` found and the profile doesn't list is in `modules`, named
  `module-<request ID>`.

### `sweep`

```json
{
  "module": {"name": "head-up display", "request_id": "71B", "response_id": "785"},
  "first": "F180",
  "last": "F18F",
  "sweep": {
    "found": [{"did": "F187", "value": "34 47 38 39 31 39 36 30 34 4B 20"}],
    "stop": null,
    "still_extended": null,
    "out_of_step": false
  }
}
```

`found` is each DID the module has, with its bytes, or why it refused it; a DID refused as out of range isn't listed.
`stop` is `null` when the sweep reached the end of the range. Otherwise it says where to go on and why:

```json
{"at": "0664", "why": {"LowVoltage": {"after": 100, "millivolts": 11000}}}
```

`why` is `{"Module": <error>}` (the module stopped answering or refused), `{"Unmatched": <error>}` (a reply may have
answered an earlier request), `{"LowVoltage": {...}}` (the battery guard), or `{"Adapter": <adapter error>}`, where an
adapter error is `"Timeout"`, `"StillPending"` or `{"Adapter": "<message>"}`. `still_extended` is why the module may
still be in the extended session, and `out_of_step` is whether a late answer may still arrive
([details](scanning.md#sweeps)).

### `read-dids`

```json
{
  "module": {"name": "transmission", "request_id": "7E1", "response_id": "7E9"},
  "dids": ["F189", "F191"],
  "read": {"value": {
    "split": [{"did": "F189", "data": "31 30 30 38"}, {"did": "F191", "data": "30 42 4B 39 32 37 31 35 36 41 4D"}],
    "unsplit": ""
  }}
}
```

`dids` is what was asked for, in order. `read` is `{"error": ...}` when the module refused. `split` is the DIDs whose
data could be told apart, and `unsplit` is the bytes from the first DID whose length the profile doesn't give, as the
module sent them, empty when every DID was split.

### `diff`

What [`obdcracker diff`](usage.md#diff) found between two documents of one command, not read back by it:

```json
{
  "compared": "fingerprint",
  "changes": [
    {"change": "CalidChanged", "source": "7E8", "slot": 1, "old": "4G0907589F", "new": "4G0907589G"},
    {"change": "DidChanged", "module": {"name": "transmission", "response_id": "7E9"}, "did": "F189",
     "old": {"value": {"Text": "0005"}}, "new": {"value": {"Text": "0006"}}}
  ]
}
```

`compared` is the command both documents were of, and `changes` is in the order the text output prints them (empty when
nothing changed). Each change is an object whose `change` is its kind, and the exit status is 0 with no changes, 1 with some
and 2 on an error, as for the text. Slots count from 1. A DID or other value that one side doesn't have is `null`; a value
that couldn't be read is `{"error": ...}`, as above.

| `change` | Other fields |
|---|---|
| `EcuAdded`, `EcuRemoved` | `source` |
| `CalidChanged` | `source`, `slot`, `old`, `new` (a calibration ID, or `null` for an empty slot) |
| `CalidAdded`, `CalidRemoved` | `source`, `slot`, `calid` (a slot only one side has) |
| `CvnChanged` | `source`, `slot`, `old`, `new` |
| `CvnAdded`, `CvnRemoved` | `source`, `slot`, `cvn` |
| `ObdPidAdded`, `ObdPidRemoved` | `source`, `pid` (a mode 01 PID the ECU supports) |
| `ObdInfoAdded`, `ObdInfoRemoved` | `source`, `pid` (a mode 09 PID) |
| `PidsCutShortChanged` | `source`, `old`, `new` (the bitmap PID the PID list was cut at, or `null`) |
| `EcuNameChanged` | `source`, `old`, `new` (each `{"value": ...}` or `{"error": ...}`) |
| `ObdDtcNew`, `ObdDtcCleared` | `source`, `dtc` |
| `VinChanged` | `source`, `old`, `new` |
| `ModuleAdded`, `ModuleRemoved` | `module` |
| `AnsweredChanged` | `module`, `old`, `new` (booleans) |
| `DidChanged` | `module`, `did`, `old`, `new` (each `null`, `{"value": ...}` or `{"error": ...}`) |
| `UnsplitChanged` | `module`, `old`, `new` (bytes) |
| `UdsDtcNew`, `UdsDtcCleared` | `module`, `dtc`, `status` |
| `UdsDtcStatusChanged` | `module`, `dtc`, `old`, `new` (statuses) |
| `Unreadable` | `scope`, `list`, `old`, `new`: a list that failed in one or both documents, with the errors differing |

`module` is `{"name": ..., "response_id": ...}`. `scope` is `{"kind": "Ecu", "source": ...}` or
`{"kind": "Module", "name": ..., "response_id": ...}`. `list` is `Calids`, `Cvns`, `ObdPids`, `ObdInfo`, `ObdDtcs`,
`UdsDtcs` or `Dids`, and `old` and `new` are each the error that list failed with, or `null` if it was read.
A kind added later raises the schema version, like any new variant.

### `dtc`

```json
{
  "module": {"name": "gateway", "request_id": "710", "response_id": "77A"},
  "dtc": "0016A0",
  "record": "FF",
  "detail": {
    "snapshots": {"value": {"status": "2F", "records": "01 01 F4 40 12"}},
    "extended_data": {"error": {"Reply": {"Negative": {"sid": "19", "nrc": "12"}}}},
    "out_of_step": false
  }
}
```

`extended_data` is `null` when it wasn't asked: the snapshot read went unanswered (`out_of_step` is then true) or found
the module busy. `records` is each record's number and data as the module sent them.

### `adapter`

```json
{"adapter": {"id": "ELM327 v1.4b", "stn": null, "voltage": "12.6V"}, "link": "tcp"}
```

`stn` is the `STI` answer of an STN chip, `null` for a plain ELM327. `voltage` is the adapter's own text for it
(`ATRV`), or `null`.

### `ports`

```json
{"ports": ["/dev/ttyUSB0"]}
```

## In a program

With the `serde` feature, the result types implement `Serialize` and `Deserialize` with the forms above. The `result`
of `fingerprint` is a `transport::fingerprint::Fingerprint` and that of `scan` a `transport::scan::Scan`. The others
wrap one: `sweep`'s `sweep` is a `transport::sweep::Sweep`, `read-dids`' `read` is a `Result<DidsData, ReadError>`
(`transport::read_dids`), `dtc`'s `detail` is a `transport::dtc::DtcDetail` and `adapter`'s `adapter` a
`transport::elm::AdapterInfo`. `diff`'s `changes` are `transport::diff::Change`s, which implement `Serialize` only.
`transport::json` has the `with` modules for a type of your own that holds a byte
string, a CAN ID, a DID or a result. See [using it as a library](library.md#json).
