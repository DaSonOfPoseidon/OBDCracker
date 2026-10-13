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

## Building a branch or a checkout

- A branch: `-Ref <branch>` on Windows (`& ([scriptblock]::Create((irm <url>))) -Ref <branch>`), or
  `| sh -s -- --ref <branch>` elsewhere.
- A checkout: `scripts/install.ps1 -Source .` or `scripts/install.sh --source .`.

Next: [using the CLI](usage.md).
