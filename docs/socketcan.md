# SocketCAN interfaces

The `socketcan` backend (Linux only) carries requests over any CAN interface the kernel has a driver for: a CANable or
candleLight on the kernel's `gs_usb` driver, PCAN-USB, Kvaser, a Raspberry Pi CAN HAT, a USB serial CAN adapter on
`slcan`, and `vcan` for tests. It is in `crates/obdcracker-transport/src/raw/socketcan/`, behind the `socketcan` cargo
feature, which the CLI turns on. The bus side (padding, ordering, flow control, STmin, bus state) is the shared
[raw-CAN transport](raw-can.md); this page covers the socket, the checks made before it is used, and how a sent frame is
confirmed. It has run against the kernel's `vcan` (with and without a driver echo) and a fake interface, not yet on a
real controller ([end of page](#not-yet-checked-on-hardware)).

## Setting up an interface

The program reads an interface and opens a raw socket on it. It never sets the interface's bitrate or mode, brings it
up or down, or restarts it (see [what it never does](#what-it-never-does)), so set the interface up yourself, for
example:

```sh
sudo ip link set can0 up type can bitrate 500000
# berr-reporting on makes the controller report bus errors; without it the backend still sees error-passive and bus-off
sudo ip link set can0 up type can bitrate 500000 berr-reporting on
```

If the kernel's `gs_usb` module holds a CANable ([gs_usb page](gsusb.md#platforms)), it makes `can0` for you; this
backend is how to use it from Linux without unloading the module. For `vcan` (tests only; no car is involved):

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
```

## Using it

```sh
obdcracker --socketcan can0 --profile a7 vin
obdcracker --socketcan can0 --bitrate 500000 fingerprint
obdcracker --socketcan can0 --listen-only vin        # never transmits: every request fails
```

`--bitrate` (250000 or 500000) or the `--profile` gives the bitrate the car's bus runs at; given both, they must agree.
Here it is only a check against the interface's own setting: with neither, nothing is checked. The audit log's link names
the interface and the mode (`socketcan:can0:active`), and the log starts with a status line saying what was read from
the interface (state, bitrate, modes, whether the driver echoes) and a `CAN_RAW_FILTER` command line for every filter set
on the socket. `adapter` is for ELM327/STN adapters only.

## Connecting

Before the socket is opened, the interface is read (sysfs for its hardware type, flags and counters; netlink's
read-only `RTM_GETLINK` for its state, bitrate and modes), and the session is refused if:

| What was read | Active session | `--listen-only` session |
|---|---|---|
| name isn't 1 to 15 printable ASCII characters without `/` or `:`, or is `.` or `..` | refused | refused |
| not a CAN interface (`ARPHRD_CAN`) | refused | refused |
| down | refused | refused |
| state bus-off, error-passive, stopped or sleeping | refused | refused |
| the controller is in listen-only mode | refused (the kernel drops what is sent without saying so) | goes ahead |
| the controller is not in listen-only mode, or the driver doesn't say | goes ahead | goes ahead, with a warning and a note in the audit log: nothing is written, but the controller still acknowledges the frames it hears |
| the controller is in loopback mode | refused (its frames never reach the bus) | goes ahead |
| a bitrate was asked for and the interface reports another | refused, naming both | refused |
| a bitrate was asked for and the interface reports none (`vcan`, some drivers) | goes ahead, with a warning and a note in the audit log | the same |
| no echo and the transmit counter can't be read | refused | goes ahead |
| presumed acknowledgements, one-shot, error-warning | goes ahead, with a note in the audit log | the same |

The interface name is typed by a user and becomes part of a path under `/sys/class/net`, so the first row is checked
before anything is read. What the kernel prints in sysfs is read at most 64 bytes at a time and parsed as exactly a
number (or `0x` and hex digits) and a newline; anything else is an error, and is never echoed back.
A `--listen-only` session never writes a frame whatever the interface is set to: the check against the interface's mode
only decides whether an *active* session could have worked. Writing no frame is not the same as being silent on the bus,
though. A CAN controller acknowledges each frame it receives with a dominant bit, and only the controller's own
listen-only mode stops that, which this backend never sets. So on an interface that isn't in it, a listen-only session
says so, and a tap that must be invisible to the car needs `listen-only on` set up first (take the interface down, set it,
bring it up).

## What it never does

- It never sets or changes the interface's bitrate, bit timing, mode (listen-only, loopback, FD, berr-reporting), MTU,
  restart time or state, and never creates or deletes one. Of the netlink calls, only the read of the link is made. A
  test fails if the backend's source names any of the calls that set, bring up or down, restart, create or delete.
- It never uses the kernel's `CAN_ISOTP` sockets: they send flow control and consecutive frames that no `Approved` covers
  and the audit log doesn't record. Its socket is `CAN_RAW`, and ISO-TP is the shared transport's.
- It has no public way to write a frame: `SocketCan` is a `Transport` and nothing else, and the port under it is
  crate-private (doctests in `SocketCan`'s documentation fail to compile if either becomes reachable).

So the one thing it can't do is take a frame back. When a send ends in an error the backend stops for good (nothing more
is written or read), but a frame the driver already holds is left to it: the message says to take the interface down
yourself (`ip link set <interface> down`) if the bus is disturbed.

## Sending

Every frame is padded to 8 bytes with `0xAA` and sent through the socket's `write`. As in the other raw-CAN backend, the
next frame of a transfer goes out only after the previous one is confirmed, because several transmit mailboxes can send
consecutive frames out of order (#42).

- **The driver echoes** (`IFF_ECHO`, which most CAN drivers set; `vcan` only with `modprobe vcan echo=1`): the socket asks
  to receive the frames it sends itself (`CAN_RAW_RECV_OWN_MSGS`), and the driver returns each one when it has gone out on
  the bus. The kernel's receive filter applies to those copies too, so besides the transport's reply filter it also lets
  the sent frame's own ID through, for as long as that ID is the one being sent. A write returns when the same frame
  (ID, width and 8 data bytes) has come back. One limit it can't close yet: another program on the same interface
  sending the identical frame at the same instant would confirm the write too, because the kernel's `MSG_CONFIRM`
  mark isn't read ([#276](https://github.com/DaSonOfPoseidon/OBDCracker/issues/276)).
- **The driver doesn't echo**: the kernel makes a copy of every frame at the moment it is queued, which says nothing
  about the bus. The backend reads the driver's transmit counter (`/sys/class/net/<name>/statistics/tx_packets`) before
  the write and waits for it to move, reading it again about every millisecond (the socket wait's resolution). This is the best the interface offers, and it has
  one limit it can't close: another program sending on the same interface moves the counter too.

Either way, 500 ms without confirmation means nobody acknowledged the frame (or the interface can't send), and the
controller may be retrying it. The backend stops, as above. A bus fault (bus-off, error-passive, an error frame) seen
while waiting ends the wait the same way, even if the frame was confirmed in the same moment: the next frame of a transfer
must not go out on a faulted bus. A send the kernel refuses (the interface went down, the queue stayed full for
500 ms) stops the port too.

## Receiving

- The socket's kernel filter is set from the approved target by the shared transport (`CAN_RAW_FILTER`): the broadcast
  takes `0x7E8..=0x7EF`, a physical target its reply ID. The width and the remote-frame bit are part of each filter's
  mask, so an 11-bit filter never lets a 29-bit frame with the same low bits through, nor a remote frame. A port checks
  every frame again in software, as the transport itself does. A new socket receives nothing until filters are set.
- Error frames are asked for by the socket's error mask: every class but a lost arbitration, which the controller retries
  by itself. They map as on `gs_usb`: bus-off (class `0x040`) and error-passive (controller detail `0x10` or `0x20`)
  latch; a receive overflow alone (`0x01`) is an overrun; any other error frame (a warning, a restart, a transmit timeout,
  a protocol or acknowledgement error, a bus error) latches too. Whether bus errors are reported at all depends on the
  interface's `berr-reporting`, which this backend doesn't change.
- Lost frames: the socket asks the kernel for its drop counter (`SO_RXQ_OVFL`), which comes with every frame queued
  after a loss. A change in it is a receive overrun, delivered before the frame it came on, and the half-received reply
  is dropped. A loss is only seen when a later frame is queued: if the last frames of a reply are lost and nothing follows,
  the reply times out instead. A socket's queue holds about 280 classic frames (278 on the kernel it was tried on), which the
  filters keep to the replies being waited for.
- A frame that isn't 16 bytes (CAN FD), has a DLC above 8, or is an 11-bit frame with ID bits above 11 stops the port. The
  socket isn't FD-enabled, so the kernel doesn't deliver FD frames at all; this is the check that it kept to that.
- Every read checks its deadline after each frame, and a read that must not wait polls at most 4096 packets past its
  deadline, as on `gs_usb`, so a flood of other IDs can't hold it.
- `Response::bus_time` is not set: the socket's timestamps aren't read yet.

## Tests

- Golden frames, filters and the error-frame mapping, and proptests of the frame parser and the filters, are in
  `wire_tests.rs`. The port is tested against a fake interface that keeps the kernel's filter rules (`port_tests.rs`), and
  the checks and a session carrying requests, with and without an echo, in `connect_tests.rs`.
- `crates/obdcracker-cli/tests/socketcan_vcan.rs` runs the real binary and the library against the kernel's `vcan0`, with
  `obdcracker-sim` answering on the other end as ISO-TP frames. The CI job `vcan` loads the module, creates `vcan0`, and runs
  them twice, without and with a driver echo (`OBDCRACKER_VCAN_ECHO` says which, and the test fails if the interface
  disagrees). The job fails, not skips, if the module can't be installed or loaded, and the tests fail if `vcan0` is missing.
  The tests are ignored in an ordinary `cargo test`; to run them:

```sh
sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
cargo test -p obdcracker-cli --test socketcan_vcan -- --ignored --test-threads=1
```

## Not yet checked on hardware

Everything above ran against `vcan` and a fake. A car session needs these checked on a real controller: that its driver
echoes (and when, relative to the frame being on the bus), the timing a real bus gives, how the kernel reports
bus-off and error-passive on it, and `berr-reporting`.
