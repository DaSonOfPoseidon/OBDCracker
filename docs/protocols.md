# Protocols

| Layer | Protocol | Used by | Status |
|---|---|---|---|
| Physical | CAN 500 kbit/s (OBD pins 6/14), 11- and 29-bit IDs | every US car since 2008 | 11-bit done through the ELM driver; 29-bit planned |
| Physical | K-line (pin 7): ISO 9141-2, ISO 14230, VW KW1281 | pre-CAN cars, a few older modules | if a profile needs it |
| Physical | DoIP (ISO 13400, Ethernet on pins 3/11/12/13) | newer cars (around 2020+) | not yet; the transport trait leaves room |
| Physical | CAN FD | newer cars | not yet |
| Transport | ISO-TP (ISO 15765-2), normal and extended addressing | almost everyone; Toyota uses extended addressing | done (classic CAN, both addressing modes) |
| Transport | VW TP2.0 | older VAG module designs; likely the A7's comfort and infotainment modules, which don't answer on ISO-TP (#92) | planned after the protocol-aware policy (#122, #123) |
| Diagnostic | OBD-II (SAE J1979) | every car | decoding done for mode 01 (supported PIDs, load, coolant, RPM, speed, intake temp, MAF, throttle and pedal positions, run time, distances, warm-ups, barometric pressure, catalyst, ambient and oil temperatures, injection timing, fuel rate, torque, module voltage), mode 03 DTCs, mode 09 VIN, CALID, CVN and ECU name |
| Diagnostic | UDS (ISO 14229) | most modules from about 2010 | decoding done for 0x22 (single and multi-DID), 0x19 (0x01, 0x02, 0x0A) and negative response codes; the extended session (0x10 03, kept with 0x3E 00, left with 0x10 01) for reads that need it |
| Diagnostic | KWP2000 (ISO 14230-3) over CAN | VAG TP2.0 modules, Toyota enhanced diagnostics before about 2018 | its own allowlist is done (#122); nothing sends it yet (TP2.0 is #123) |

## What the OBD port reaches

The OBD port only reaches what the car's gateway passes on, which is the diagnostic bus. Internal buses (body CAN,
FlexRay, MOST, LIN) need a direct tap. If that is ever supported, it will run in listen-only mode, where the adapter
can't transmit or acknowledge frames.
