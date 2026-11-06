# gs_usb adapters

The `gsusb` backend drives a CANable, candleLight or any other `gs_usb` device (a CAN controller on USB) with no vendor
library and no kernel driver, on Linux, Windows and macOS. It is written on [`nusb`](https://crates.io/crates/nusb), in
`crates/obdcracker-transport/src/raw/gsusb/`. The bus side (padding, ordering, flow control, STmin, bus state) is the
shared [raw-CAN transport](raw-can.md); this page covers the USB side and the connect step. It is behind the `gsusb`
cargo feature, which the CLI turns on.

The protocol was read from Linux's `gs_usb.c` (GPL, reference only: nothing was copied) and the field layouts and
control requests were checked against it. It has run only against a fake device so far; real-hardware checks are listed
at the [end](#not-yet-checked-on-hardware).

## Devices

Only these USB IDs are opened (vendor:product): `1d50:606f` (Geschwister Schneider and many CANables), `1209:2323`
(candleLight), `1cd2:606f`, `16d0:10b8`, `16d0:0f30` and `1209:ca01`. Anything else is never opened, however it
describes itself.

- With one such device plugged in, it is used. With none, the CLI exits with status 2.
- With several and no serial number, it lists them (ID, product, serial) and exits with status 2, having written
  nothing to any of them. Pick one with `--gsusb=SERIAL`.
- Names and serial numbers come from the device, so anything but printable ASCII in them is shown as `?`. Type the serial
  as shown.

### Platforms

- **Linux:** the backend never detaches a kernel driver. While the kernel's `gs_usb` module is loaded it holds the
  device, and connecting fails with a message pointing to [`--socketcan`](socketcan.md) or to unloading the module
  (`sudo rmmod gs_usb`). Without the module you need permission to open the device; a udev rule does that
  ([install](install.md#gs_usb-adapters)).
- **Windows:** the device needs the WinUSB driver (installed per device, for example with Zadig). Without it,
  connecting fails with a message naming WinUSB.
- **macOS:** no driver is needed.

## The USB protocol

All numbers are little-endian. Control transfers are vendor requests to interface 0; the device's only interface has
one bulk IN and one bulk OUT endpoint, found from its descriptor.

| Request | Direction | wValue | Data |
|---|---|---|---|
| 0 host format | out | 1 | `EF BE 00 00` (`0x0000BEEF`: the host is little-endian) |
| 5 device config | in | 1 | 12 bytes: 3 reserved, channel count less one, firmware version, hardware version |
| 4 bit timing constants | in | channel | 40 bytes: features, clock, tseg1 min/max, tseg2 min/max, sjw max, brp min/max/step |
| 1 bit timing | out | channel | 20 bytes: prop seg, phase seg 1, phase seg 2, sjw, brp |
| 2 mode | out | channel | 8 bytes: 0 reset or 1 start, then flags |

Only channel 0 is used. Mode flags: bit 0 listen-only, bit 12 bus-error reporting (asked for when the device's features
say it has it). The device is refused if it lacks listen-only (the bitrate check needs it) or needs the LPC546xx USB
padding quirk.

A frame, in both directions on the bulk endpoints, is exactly 20 bytes: echo ID (4), CAN ID with flags (4: bit 31 =
29-bit, bit 30 = remote, bit 29 = error), DLC, channel, flags, reserved, 8 data bytes. No timestamp or CAN FD is
negotiated, so any other length is refused; so are flags other than "receive overflow" (bit 0), a DLC above 8, and an
11-bit frame with ID bits above 11. A frame received from the bus has echo ID `0xFFFFFFFF`; any other echo ID is the
controller confirming a frame we sent.

## Connecting

1. Send the host format, read the device config and the bit timing constants.
2. Refuse a device without listen-only, or one needing the LPC546xx quirk.
3. Compute the bit timing from the device's clock and limits for the bitrate (250000 or 500000). It must give that bitrate
   **exactly**, with a sample point between 75% and 90% (87.5% preferred); a device that can't gets a refusal that names
   the bitrate, and nothing has been sent that starts the controller. A nearby bitrate is never used.
4. Put the controller in reset (stopping whatever an earlier program left running), discard what the device had queued,
   and send the bit timing.
5. Unless `--listen-only` was asked for, run the bitrate check below.
6. Start the controller: listen-only, or active.

Every control transfer is logged as a `cmd` line in the audit log, including those of a connect that failed.

### The bitrate check

A wrong bitrate on an active controller destroys the frames on the car's bus with error frames, so the controller first
starts **listen-only** at the bitrate, for a window (1 s by default; a library caller may set up to 60 s, and more is refused before anything is sent), then goes back to reset, and only then, if the check passes,
is started active. The OBD port is silent behind a gateway until something asks, so silence alone can't be told from a
wrong bitrate:

| What the window heard | Bitrate from `--bitrate` or a profile | Bitrate guessed (500000, neither given) |
|---|---|---|
| frames (any ID) | goes active | goes active |
| silence | goes active, with a warning; the audit log gets a status line | refused |
| an error frame, bus-off or error-passive | refused | refused |

After going active, the raw-CAN latch is the backstop: a controller that gets no ACK fails its first write
(below), and a bus-off or error frame stops all sending.

The frames heard in the window are discarded, with everything else the device had queued, before the controller goes
active, so none of them can read as an answer to a request. `--listen-only` skips the check: it never goes active, on
any path, and its session sends nothing at all, flow control included.

`--bitrate` must agree with `--profile` when both are given.

## Sending

- A frame is written to the bulk OUT endpoint with an echo ID, and `write` returns only when the controller's
  confirmation for that ID arrives, so a transfer's frames reach the bus in order. Echo IDs cycle through 0 to 9.
- A confirmation for a different ID, one with nothing in flight, or a second one for the same frame is a protocol
  violation: the port stops, the controller is reset and nothing more is written or read.
- No confirmation within 500 ms means nobody ACKed the frame, and the controller would retry it for ever. The controller
  is reset at once, the send fails, and every later send and receive fails too. A bus fault (bus-off, error-passive,
  an error frame) seen while waiting ends the wait the same way.
- A write that fails on USB, or a read that fails (an unplugged device), stops the port too.
- The DLC is the frame's own: an ISO-TP frame is padded to 8 bytes, and a [VW TP2.0](raw-can.md#vw-tp20) frame goes out
  at its length (a setup is DLC 7, a disconnect DLC 1), with zeros in the data bytes after it. The confirmation is
  matched by echo ID, so it doesn't depend on the length.

## Receiving

- gs_usb has no hardware filters, so the port filters in software, by ID and ID width, as the transport asks. Remote
  frames and other channels' frames are never delivered. Error frames and bus events get through every filter.
- Frames wait in a queue of at most 1024 while a write waits for its confirmation; past that they are dropped and a
  receive overrun is reported. The device's own overflow flag (on any frame) is a receive overrun too, delivered before
  the frame it rode on. 16 USB reads are kept submitted, so the OS queues frames while the host is busy.
- Every read checks its deadline after each frame, so a flood of other IDs can't hold it past the deadline.
  A read that must not wait polls at most 4096 packets past its deadline; if the device hasn't run dry by then it fails
  with an adapter error instead of reporting an empty queue, so a request is never sent while a stale reply may still sit
  behind a flood (the next drain goes on from there).
- A read that must not wait (the drain before a request) takes what the OS has already handed over. A frame that
  reached the USB host controller a moment before may be handed over a moment after, so the drain can miss it: that is the
  one late-reply window it can't close, and the transport's reply window still checks its ID, width and shape.
- Error frames map onto the raw-CAN transport's events: bus-off (class bit 0x40) and error-passive (controller detail
  0x10 or 0x20) latch it; a receive overflow alone is an overrun; any other error frame (warning, bus error, restart)
  is an error frame, which latches too.

## Leaving the bus

The controller is put in reset when the adapter is dropped, when connecting fails, and when the port stops, so it
doesn't go on acknowledging frames after the tool exits. Dropping writes nothing but that one control transfer, also
while unwinding from a panic. A library caller can use `GsUsb::close` to learn whether the reset reached the device and to get its
control transfer for the audit log; the CLI does both, and says so if the reset failed (unplug the adapter then).

## Not yet checked on hardware

Everything above ran against a fake device. A car session needs these checked on a real adapter: STmin and latency
through USB, the WinUSB setup on Windows, how claiming behaves next to the kernel driver, whether the device sends bus
errors as described, and the timing a real bus gives. For VW TP2.0 (#259): that the device puts a DLC 7 setup and a
DLC 1 disconnect on the bus as sent, and that a module answers them (#272).
