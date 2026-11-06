# Install

One command builds the `obdcracker` CLI from source. It installs whatever is missing (a C linker and rustup), and
doesn't need Git. Run it again to update.

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.ps1 | iex
```

```sh
# macOS and Linux (or `wget -qO- <url> | sh` without curl)
curl -fsSL https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.sh | sh
```

## Notes for each OS

- **Windows:** the first run installs the Visual C++ Build Tools, which is a few GB and asks for admin rights. If
  `obdcracker ports` doesn't list the adapter, install the [FTDI VCP driver](https://ftdichip.com/drivers/vcp-drivers/).
- **macOS:** if the Xcode Command Line Tools are missing, the script opens their installer; run it again once that's
  done. Use the `/dev/cu.*` port.
- **Linux:** the script adds you to the serial ports' group (`dialout` or `uucp`); log out and back in once.

## `gs_usb` adapters

A CANable or candleLight (`obdcracker --gsusb`) needs no driver on macOS. Elsewhere the program must be allowed to open
the USB device ([details](gsusb.md#platforms)):

- **Linux:** put the rules below in `/etc/udev/rules.d/70-gsusb.rules` and run `sudo udevadm control --reload` then
  replug the adapter. If the kernel's `gs_usb` module is loaded it holds the device, and `obdcracker` refuses (it never
  detaches a kernel driver): use the `can0` interface it makes with [`--socketcan`](socketcan.md), or unload the module
  with `sudo rmmod gs_usb`.
- **Windows:** install the WinUSB driver for the adapter (for example with [Zadig](https://zadig.akeo.ie/), choosing
  the adapter's interface 0).

```
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="606f", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="2323", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1cd2", ATTRS{idProduct}=="606f", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="16d0", ATTRS{idProduct}=="10b8", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="16d0", ATTRS{idProduct}=="0f30", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="ca01", MODE="0660", TAG+="uaccess"
```

## Building a branch or a checkout

- A branch: `-Ref <branch>` on Windows (`& ([scriptblock]::Create((irm <url>))) -Ref <branch>`), or
  `| sh -s -- --ref <branch>` elsewhere.
- A checkout: `scripts/install.ps1 -Source .` or `scripts/install.sh --source .`.

Next: [using the CLI](usage.md).
