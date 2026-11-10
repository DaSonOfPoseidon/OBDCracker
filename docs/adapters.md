# Adapters

An adapter backend has two parts: the **link** that carries bytes to the adapter, and the **driver** that speaks the
adapter's command set. The ELM driver takes any two-way byte stream, so serial, TCP and BLE share one tested driver.

| Driver | Hardware | Links | OS | Status |
|---|---|---|---|---|
| `mock` | none (tests) | — | all | done |
| `sim` | none: a simulated car from a vehicle profile and a fixture (`--sim a7`) | — | all | done |
| `elm` | ELM327 v2.0+ / STN (e.g. OBDLink EX, MX+, CX) | USB serial, Wi-Fi (TCP); Bluetooth LE and Classic planned | all | done for USB serial and TCP; three read-only sessions on the A7 over USB (OBDLink EX). Clones that refuse `AT CRA` with `X` digits are refused at connect ([clone policy](elm327.md#clones)). Multi-frame requests (`STPX`) on STN only, checked on an OBDLink EX (STN2232 v5.12.4, #215) |
| `gsusb` | CANable / candleLight (USB-C) and an OBD2-to-DB9 cable | USB | all | built on `nusb`, ISO-TP and VW TP2.0, with listen-only mode and a [bitrate check](gsusb.md#the-bitrate-check) before it goes on the bus; tested against a fake device, not yet on hardware ([details](gsusb.md)) |
| `socketcan` | any SocketCAN interface: a CANable on the kernel's `gs_usb` driver, PCAN-USB, Kvaser, a Pi CAN HAT, `vcan` | kernel | Linux | raw CAN on the [shared ISO-TP and VW TP2.0 core](raw-can.md), with listen-only mode; reads the interface's state, bitrate and modes and never changes them; run against `vcan` and a fake, not yet on a real controller ([details](socketcan.md)) |
| `j2534` | J2534 pass-thru (Tactrix OpenPort, Toyota Mini VCI, VAS 5054A clones) | vendor DLL | Windows | later |
| `dpdu` | ISO 22900 D-PDU API (what ODIS uses) | vendor DLL | Windows | maybe |

Leaving a wireless adapter plugged in drains the battery and lets anyone in range connect, so the CLI warns about it, and
the audit log records which link a session used.

## The ELM driver

The ELM driver sends single-frame requests (up to 7 bytes: the OBD-II reads, and UDS 0x22 with up to 3 DIDs), and on
an STN chip that echoes as it reads (such as the OBDLink EX) longer ones, up to 44 bytes, as `STPX`
([details](elm327.md#multi-frame-requests)). It never lets the adapter search for a protocol, and stops if the
adapter stops answering. On a plain ELM327 it paces a physical request's long reply to the link's speed, so its
512-byte buffer doesn't overflow (down to about 2300 baud).
Broadcasts can't be paced, so `scan`, `fingerprint` and `vin` ask each ECU for its long replies (mode 09 PIDs 02, 04, 06
and 0A, mode 03) by its own request ID where the driver paces ([`Transport::broadcasts_can_overflow`](scanning.md#module-discovery)):
every plain ELM327, and an STN below 115200 baud. A dry run has no adapter to judge, so it shows the broadcasts. Any
other broadcast whose ECUs send multi-frame replies, sent by a library caller, can still overflow a slow link, which
the driver reports as `BUFFER FULL`.

It sends VW TP2.0 frames raw (`AT CAF0`), and only on an adapter that echoes each character as it reads it, such as
the OBDLink EX; whole-line echoers, such as many clones, can't send them. On an open channel it stops the adapter
listening to send each ACK in time, rather than wait out its timeout, and keeps adaptive timing off so it listens for
the module's data after the ACK (#218); the timing on a real module is rechecked in the next car session (#169) ([details](elm327.md#vw-tp20-channel-frames)).

[`elm327.md`](elm327.md) lists the adapter behaviour it relies on, with datasheet pages. It's tested against a fake
adapter written from the datasheet, against the simulated A7, and against
[ELM327-emulator](https://github.com/Ircama/ELM327-emulator), an independent implementation. That last test is opt-in
(`#[ignore]`) and runs in a CI job that doesn't block merging yet.
