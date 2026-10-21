# Vehicle profiles

A profile is data, not code: module addresses, addressing mode, protocol per module, the identifiers to read and how to
decode them. Without a profile the tool falls back to generic OBD-II. Profiles are TOML files in
[`crates/obdcracker-profile/profiles/`](../crates/obdcracker-profile/profiles/); a profile has no field that names a
service, so it can't widen the [safety policy](safety.md).

| Profile | Expected setup (confirmed by a read-only module scan before use) |
|---|---|
| 2014 Audi A7 3.0 TDI (C7) | CAN 500k behind the J533 gateway; UDS on ISO-TP with 11-bit IDs: all 24 modules found so far answer UDS (#54), engine 0x7E0/0x7E8, head-up display 0x71B/0x785. A TP2.0/KWP2000-only module wouldn't show up in discovery, which only sends UDS. A 29-bit discovery range covers VAG's 0x17FC00xx IDs, untried on this car |
| 2014 Toyota Camry (XV50) | CAN 500k; OBD-II on 0x7DF/0x7E0+; enhanced diagnostics are KWP2000-style (e.g. 0x21 read by local ID) on ISO-TP; body modules sit behind 0x750 with an extended-address byte |
