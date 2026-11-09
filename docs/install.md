# Install

One command builds the `obdcracker` CLI from source. It installs whatever is missing (a C linker and rustup), and
doesn't need Git. Run it again, or [`obdcracker update`](#updating), to update.

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

- A branch, tag or commit: `-Ref <ref>` on Windows (`& ([scriptblock]::Create((irm <url>))) -Ref <ref>`), or
  `| sh -s -- --ref <ref>` elsewhere. The script asks GitHub which commit the ref names and builds exactly that one.
  How it reads `<ref>`:
  - A full commit hash (40 lower-case hex characters) is used as given, with no lookup.
  - `refs/tags/<name>` and `refs/heads/<name>` are looked up as written.
  - Any other name is looked up as a tag and as a branch. If only one exists, that one is built. If both exist,
    the script stops and asks for `refs/tags/<name>`, `refs/heads/<name>` or the commit hash, rather than guess.
  - A name that is neither a tag nor a branch is then looked up as given, so a short commit hash works.
  - A lookup that fails for any reason other than GitHub saying the ref doesn't exist (a rate limit, a server
    error, no network) never leads on to another name, so the script can't build a different ref than you asked for.
- A checkout: `scripts/install.ps1 -Source .` or `scripts/install.sh --source .`. The build is recorded as the
  checkout's commit only when the checkout is clean (no uncommitted or untracked files); otherwise it's `unknown`.

## Which commit is installed

`obdcracker --version` prints the version and the commit it was built from, for example
`obdcracker 0.1.0 (commit 0123456789abcdef0123456789abcdef01234567)`. The commit is `unknown` for a build the
install script didn't make, such as a plain `cargo build`; set `OBDCRACKER_COMMIT` to a full lower-case commit hash
when building to record one. Anything else in that variable is ignored.

## Updating

```sh
obdcracker update            # the highest release, if it is newer than this build
obdcracker update 0.2.0      # a release by version (v0.2.0 works too)
obdcracker update --main     # the newest commit on main
```

`obdcracker update` asks GitHub which commit the release (or `main`) names, checks that it is newer than the installed
build, and runs the install script for exactly that commit. It needs `curl` or `wget`, and builds from source like the
first install. `obdcracker --dry-run update` says what it would install and installs nothing. It never goes back to an
older version, or to a commit that isn't newer than the installed one, unless you pass `--allow-downgrade`. The rules
are in [using the CLI](usage.md#update).

A build whose `--version` says `commit unknown` (one made before `update` existed, or by a plain `cargo build`) can't
be compared with a release: `update` installs a release with a higher version, and refuses `--main` and the same
version. Run the install script once, with the command at the top of this page, to replace it with a build that
records its commit; after that `update` can compare.

Next: [using the CLI](usage.md).
