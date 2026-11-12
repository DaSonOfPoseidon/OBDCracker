# Protocols

| Layer | Protocol | Used by | Status |
|---|---|---|---|
| Physical | CAN 500 kbit/s (OBD pins 6/14), 11- and 29-bit IDs | every US car since 2008 | done through the ELM driver: 11-bit, and 29-bit physical requests (ISO 15765-4 `0x18DA<module>F1` and VAG's `0x17FC00xx`, #111). The 29-bit OBD-II broadcast (`0x18DB33F1`) isn't sent yet |
| Physical | K-line (pin 7): ISO 9141-2, ISO 14230, VW KW1281 | pre-CAN cars, a few older modules | if a profile needs it |
| Physical | DoIP (ISO 13400, Ethernet on pins 3/11/12/13) | newer cars (around 2020+) | not yet; the transport trait leaves room |
| Physical | CAN FD | newer cars | not yet |
| Transport | ISO-TP (ISO 15765-2), normal and extended addressing | almost everyone; Toyota uses extended addressing | done (classic CAN, both addressing modes) |
| Transport | VW TP2.0 | older VAG module designs; likely the A7's comfort and infotainment modules, which don't answer on ISO-TP (#92) | channel setup, data transfer with ACKs and keep-alive, and disconnect, all built by the policy itself (`tp20::ChannelSession`, #142); through the ELM driver on an adapter that echoes each character (`scan --discover-tp20` opens VAG's `10 89` session, then reads each module's identification, by `22 F1 87` and `22 F1 9E` if it refuses `1A 9B` as not supported), and over raw CAN with `gsusb` and `socketcan` ([raw-can.md](raw-can.md#vw-tp20); run against a fake and `vcan`, not yet on a car); the timing on a real module, and the monitor-mode listening after each frame (#227), which acknowledges the frames it hears (#301), are rechecked in the next car session (#218, #169) |
| Diagnostic | OBD-II (SAE J1979) | every car | decoding done for mode 01 (the MIL and readiness monitors in PID 01, supported PIDs, load, coolant, RPM, speed, intake temp, MAF, throttle and pedal positions, run time, distances, warm-ups, barometric pressure, catalyst, ambient and oil temperatures, injection timing, fuel rate, torque, module voltage), mode 02 freeze frame values, mode 03, 07 and 0A DTCs, the mode 06 supported-monitor-ID bitmaps (the test results themselves aren't decoded yet), mode 09 VIN (with its fields, model years and check digit), CALID, CVN and ECU name |
| Diagnostic | UDS (ISO 14229) | most modules from about 2010 | decoding done for 0x22 (single and multi-DID), 0x19 (0x01, 0x02, 0x0A) and negative response codes; the extended session (0x10 03, kept with 0x3E 00, left with 0x10 01) for reads that need it |
| Diagnostic | KWP2000 (ISO 14230-3) over CAN | VAG TP2.0 modules, Toyota enhanced diagnostics before about 2018 | its own allowlist is done (#122); sent on TP2.0 channels (#142), one-frame requests of up to 5 bytes; not yet on ISO-TP |

## What the OBD port reaches

The OBD port only reaches what the car's gateway passes on, which is the diagnostic bus. Internal buses (body CAN,
FlexRay, MOST, LIN) need a direct tap. If that is ever supported, it will run in listen-only mode, where the adapter
can't transmit or acknowledge frames.

## ISO-TP decoding

`obdcracker-core`'s `isotp` module reads and builds classic CAN frames (8 data bytes) under ISO 15765-2, in normal and
extended addressing. With extended addressing the first data byte is the module's sub-address and every frame carries
one payload byte less.

- **Single frame** (`0x`): the length is 1 to 7 (6 with extended addressing) and must fit the frame. Bytes after the
  payload are padding and are ignored. A length of 0 is invalid on classic CAN: `00 <len>` is CAN FD's single frame
  escape, which isn't supported.
- **First frame** (`1x`): the 12-bit length is longer than a single frame holds, up to 4095. A length of 0 there is the escape (ISO 15765-2:2016): a 32-bit
  length follows and leaves 2 data bytes in the frame (1 with extended addressing), and only lengths over 4095 may use it. A length that would fit a
  single frame is invalid, and so is a first frame that isn't full (8 bytes on the wire).
- **Consecutive frame** (`2x`): a sequence number 0 to 15, wrapping, then at least one data byte. Every consecutive
  frame but the last must be full. The last may carry padding past the payload's end, which the reassembler drops.
- **Flow control** (`3x`): the status is continue (0), wait (1) or overflow (2); other values are reserved and invalid.
  Block size 0 means send every consecutive frame without waiting again. STmin `0x00..=0x7F` is milliseconds and
  `0xF1..=0xF9` hundreds of microseconds; reserved values read as the longest gap, 127 ms, as the standard requires.
  When encoding, a gap is rounded up to the next value STmin can express so it is never shorter than asked, and a gap over
  127 ms is refused.
- **Reassembly:** a new single or first frame always starts a new payload and drops an unfinished one. After an error the
  receiver is idle until the next such frame, except for a frame addressed to another module on a shared reply ID with
  extended addressing (Toyota body modules share one), which is ignored and leaves the transfer in progress.
- **Overflow:** a multi-frame payload longer than the buffer is answered with an overflow flow control frame. A single
  frame that doesn't fit needs no reply, since no transfer is open.

## Where we're stricter

Independent implementations (python-can-isotp, python-udsoncan; see [third-party.md](third-party.md)) tolerate some
input that the standards don't allow. `crates/obdcracker-core/tests/third_party.rs` pins our answer for each, because
ECU replies are untrusted input and a lenient parser can misread them.

- ISO-TP: a first frame whose length fits a single frame, or that isn't full, is invalid; so is an escaped length of
  4095 or less, and a consecutive frame with no data.
- ISO-TP padding sits outside the payload length. A UDS reply with bytes after its last DID or record is malformed, and
  a partial record is malformed; a whole all-zero record is a record (DTC `000000`), and telling it from a real code is
  left to the caller (#36 covers tolerating non-compliant ECUs).
- A reply with a fixed length (such as the DTC count of `19 01`) with an extra byte is malformed.
- A negative response is exactly `7F <service> <code>`; bytes after the code are malformed.
- Duplicate DTCs in a reply are both kept: avoiding duplicates is the module's job.

## Matching replies to requests

`response::answers` decides whether a reply belongs to a request, so a late reply to an earlier request isn't taken as
this one's. A positive reply must start with the request's service ID + 0x40 and echo what the request asked for:

| Service | Echo that must match |
|---|---|
| mode 01 | one of the requested PIDs (unsupported PIDs are left out of the reply) |
| mode 02 | the PID and the frame number |
| mode 06 | the monitor ID |
| mode 09 | the PID |
| `0x22` | one of the requested DIDs |
| `0x10`, `0x19`, `0x3E` | the subfunction, without the suppress-positive-response bit (bit 7) |
| `0x19` `0x04`/`0x06` | also the DTC, and the first record unless every record was asked for (`0xFF`, or `0xFE` for `0x06`); a reply with no record has none to compare and is accepted |
| everything else | the service ID alone |

A request with the suppress bit set gets no positive reply unless the module first sent response-pending (`7F <service>
78`); then ISO 14229-1 requires the final positive reply, which `answers_after_pending` accepts. A negative reply echoes
only the service ID, so any `7F <service> <code>` answers a request for that service. KWP2000 (`kwp2000_answers`) has no
suppress bit and some positive replies echo nothing (`7E` for `TesterPresent`); it checks the local ID for `0x21` and
the common ID for `0x22`, and matches the rest by service ID, since what follows is the manufacturer's record (ISO 14230-3). A decoder must still
check what it reads.

## OBD-II decoding

- Mode 03 is decoded in the CAN format (ISO 15765-4): a count byte, then that many two-byte codes, such as
  `43 02 04 01 01 13` for P0401 and P0113. The count must equal the codes in the reply, but P0000 isn't yielded: a
  module fills unused slots with it (SAE J1979), so `43 01 00 00` is a reply with no codes. Pre-CAN protocols (J1850, ISO 9141-2, ISO 14230-4) have no count byte and use
  zero-padded groups of three, so their replies aren't decoded. Mode 07 (pending) and mode 0A (permanent) use the same
  layout under `47` and `4A`.
- Mode 01 leaves out unsupported PIDs. A PID the decoder doesn't know ends the readings, as its length is unknown.
- Mode 09 text fields (VIN, CALID, ECU name) are printable ASCII after trimming 0x00 padding, and a field of nothing
  but padding is malformed, except a CALID slot, which is empty (the 2014 A7's engine sends one). A VIN uses digits and upper case letters except I, O and Q. An ECU name has no blanks
  between words (SAE J1979-DA), such as `EngineControl`.

### Monitor status (mode 01 PID 01)

`decode_monitor_status` reads exactly `41 01 A B C D`; `decode_current_data` still returns PID 01 as raw bytes. The bit
layout is SAE J1979 / ISO 15031-5 (PID 01):

| Byte | Bits |
|---|---|
| A | bit 7: MIL on; bits 6-0: confirmed DTC count (0 to 127) |
| B | bits 0-2: misfire, fuel system, components supported; bit 3: 0 spark ignition, 1 compression ignition; bits 4-6: misfire, fuel system, components **not** complete; bit 7 reserved |
| C | engine-specific monitors supported, by bit (below) |
| D | the same monitors **not** complete (a set bit means not complete) |

| Bit of C and D | Spark ignition | Compression ignition |
|---|---|---|
| 0 | catalyst | NMHC catalyst |
| 1 | heated catalyst | NOx/SCR |
| 2 | evaporative system | reserved |
| 3 | secondary air system | boost pressure |
| 4 | A/C refrigerant (reserved in newer editions) | reserved |
| 5 | oxygen sensor | exhaust gas sensor |
| 6 | oxygen sensor heater | PM filter |
| 7 | EGR and/or VVT | EGR and/or VVT |

A monitor's `complete` flag is the inverse of its not-complete bit and means something only if the monitor is
supported: it is reported as sent, and a set or clear bit on an unsupported monitor isn't an error. Reserved bits are
ignored. The 2014 A7's engine answers `00 2F 28 20`: a compression-ignition engine with misfire and components complete,
the fuel system not, boost pressure complete and the exhaust gas sensor not.

### Freeze frame (mode 02)

A request names one PID and one frame number (`02 <pid> <frame>`), and the reply echoes both (`42 <pid> <frame>` and the
value), so `decode_freeze_frame` takes the PID and frame that were asked for and refuses any other echo. The value is
decoded as in mode 01, and a PID with a known length must have exactly that many bytes. PID 02 is the code that stored
the frame: two bytes, where P0000 means none.

### On-board monitor test results (mode 06)

`decode_supported_monitor_ids` reads the supported-monitor-ID bitmaps (`06 00`, `06 20`, …, `06 E0`) as `46 <mid>` and four
bytes, laid out like the mode 01 PID bitmaps. The test records for any other monitor ID aren't decoded yet: the layout
of a record (monitor ID, test ID, unit and scaling ID, test value, minimum and maximum, and whether the monitor ID
repeats in each record) couldn't be checked against the standard or a permissively licensed implementation, and
the one public implementation found (python-OBD, GPL) is reference only. `scan` therefore reads only the bitmaps
(`ObdEcu::monitor_ids`); the records are tracked in #345.
