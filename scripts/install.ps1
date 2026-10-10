# Installs the obdcracker command on Windows, from nothing but PowerShell (no Git needed):
#
#   irm https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.ps1 | iex
#
# It installs the Visual C++ Build Tools (Rust's linker on Windows) and rustup if they're missing,
# downloads the source, and builds the CLI into ~\.cargo\bin. Run it again to update. With options:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.ps1))) -Ref some-branch
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Source .   # build a checkout
#
# Failures throw rather than `exit`, which would close the window of someone running it through iex.

# Write-Host is the point here: progress for a person, kept out of the pipeline
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param(
    # Branch, tag or commit to build
    [string]$Ref = 'main',
    # Where the source and build cache live
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'obdcracker'),
    # Build this checkout instead of downloading one (-Ref is then ignored)
    [string]$Source = ''
)

function Install-ObdCracker {
    param([string]$Ref, [string]$Dir, [string]$Source)

    # Set here, not at the top, so running through iex doesn't change the caller's session
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 draws a progress bar so slowly that it dominates a download
    $ProgressPreference = 'SilentlyContinue'
    # Windows PowerShell 5.1 may not offer TLS 1.2, which GitHub and rustup require
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'DaSonOfPoseidon/OBDCracker'
    # Marks a directory this script made, so it never replaces one it didn't
    $marker = '.obdcracker-install'

    function Say([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
    function Note([string]$Message) { Write-Host "    $Message" }
    # Runs a native command and fails if it does
    function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed (exit code $LASTEXITCODE)" }
    }

    if ([string]::IsNullOrWhiteSpace($Dir)) { throw '-Dir is empty' }
    if (-not $Source -and ($Ref -notmatch '^[A-Za-z0-9._/-]+$' -or $Ref.StartsWith('-') -or $Ref.Contains('..'))) {
        throw "not a branch, tag or commit: '$Ref'"
    }

    # The 64-bit OS's architecture, even from a 32-bit PowerShell
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $triple = 'x86_64-pc-windows-msvc'; $vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
        'ARM64' { $triple = 'aarch64-pc-windows-msvc'; $vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' }
        default { throw "unsupported processor architecture: $arch (need 64-bit x86 or ARM)" }
    }
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $cargoBin = Join-Path $cargoHome 'bin'
    $pathHadCargo = ($env:Path -split ';') -contains $cargoBin
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("obdcracker-install-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        # 1. The MSVC linker
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $haveVc = (Test-Path $vswhere) -and (& $vswhere -products * -requires $vcComponent -property installationPath)
        if ($haveVc) {
            Note 'Visual C++ Build Tools: already installed'
        } else {
            Say 'Installing the Visual C++ Build Tools (Rust needs their linker). This is a few GB and can take 10-20 minutes; approve the admin prompt.'
            $installer = Join-Path $tmp 'vs_BuildTools.exe'
            Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $installer
            $vsArgs = @('--quiet', '--wait', '--norestart', '--nocache',
                '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--add', $vcComponent, '--includeRecommended')
            $proc = Start-Process -FilePath $installer -ArgumentList $vsArgs -Verb RunAs -Wait -PassThru
            # 3010: installed, but Windows wants a restart before it's fully usable
            if ($proc.ExitCode -eq 3010) {
                throw 'the Build Tools installed but need a restart: restart Windows, then run this script again'
            } elseif ($proc.ExitCode -ne 0) {
                throw "the Build Tools installer failed (exit code $($proc.ExitCode))"
            }
        }

        # 2. rustup
        $rustup = Join-Path $cargoBin 'rustup.exe'
        if ((Get-Command rustup -ErrorAction SilentlyContinue) -or (Test-Path $rustup)) {
            Note 'rustup: already installed'
        } else {
            Say 'Installing rustup'
            $rustupInit = Join-Path $tmp 'rustup-init.exe'
            Invoke-WebRequest -UseBasicParsing -Uri "https://static.rust-lang.org/rustup/dist/$triple/rustup-init.exe" -OutFile $rustupInit
            # The source tree's rust-toolchain.toml picks the toolchain, so don't install a default one
            Invoke-Checked $rustupInit @('-y', '--default-toolchain', 'none', '--profile', 'minimal')
        }
        # rustup adds this to the user's PATH for new windows; this one needs it too
        if (-not (($env:Path -split ';') -contains $cargoBin)) { $env:Path = "$cargoBin;$env:Path" }

        # 3. The install directory, refusing to take over one this script didn't create
        if ((Test-Path $Dir) -and -not (Test-Path (Join-Path $Dir $marker)) -and (Get-ChildItem -Force $Dir | Select-Object -First 1)) {
            throw "$Dir already exists and wasn't made by this script; pick another -Dir (or -Source to build a checkout)"
        }
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        # Absolute, because the build runs from inside the source tree
        $Dir = (Resolve-Path $Dir).Path
        New-Item -ItemType File -Force -Path (Join-Path $Dir $marker) | Out-Null

        # 4. The source
        if ($Source) {
            if (-not (Test-Path (Join-Path $Source 'Cargo.toml'))) { throw "-Source $Source has no Cargo.toml" }
            $src = (Resolve-Path $Source).Path
            Note "building the checkout in $src"
        } else {
            Say "Downloading $repo at $Ref"
            $zip = Join-Path $tmp 'source.zip'
            try {
                Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/$repo/zip/$Ref" -OutFile $zip
            } catch {
                throw "couldn't download ${Ref}: check the name, and that it's pushed to GitHub ($($_.Exception.Message))"
            }
            $unpacked = Join-Path $tmp 'source'
            Expand-Archive -Path $zip -DestinationPath $unpacked
            # The archive holds one folder, named after the repo and ref
            $top = @(Get-ChildItem -Directory $unpacked)
            if ($top.Count -ne 1 -or -not (Test-Path (Join-Path $top[0].FullName 'Cargo.toml'))) {
                throw "the download has no Cargo.toml; is '$Ref' an OBDCracker ref?"
            }
            # Replace the last run's copy only once the new one is complete
            $src = Join-Path $Dir 'src'
            if (Test-Path $src) { Remove-Item -Recurse -Force $src }
            Move-Item $top[0].FullName $src
        }

        # 5. Build
        Say 'Building obdcracker (the first run also downloads the pinned Rust toolchain)'
        Push-Location $src
        try {
            # Install what rust-toolchain.toml pins. rustup 1.28+ does it with `toolchain install`;
            # older rustup doesn't take that without a name, but installs it on `show`.
            & rustup toolchain install
            if ($LASTEXITCODE -ne 0) { Invoke-Checked rustup @('show') }
            # The build cache lives outside the source, so a re-run only rebuilds what changed
            # --root pins where the binary goes, whatever CARGO_INSTALL_ROOT or Cargo's install.root
            # say, so it lands in the directory rustup put on PATH
            Invoke-Checked cargo @('install', '--path', 'crates/obdcracker-cli', '--locked', '--force',
                '--target-dir', (Join-Path $Dir 'target'), '--root', $cargoHome)
        } finally {
            Pop-Location
        }

        # 6. Check it runs and can see the adapter
        Say 'Checking the install'
        $exe = Join-Path $cargoBin 'obdcracker.exe'
        Invoke-Checked $exe @('--version')
        $ports = @(& $exe ports | Where-Object { $_ })
        if ($LASTEXITCODE -ne 0) {
            Note "couldn't list serial ports"
        } elseif ($ports.Count -gt 0) {
            Note 'serial ports:'
            $ports | ForEach-Object { Note "  $_" }
        } else {
            Note "no serial ports found: plug in the adapter and run 'obdcracker ports'."
            Note "If it still isn't listed, install the FTDI VCP driver (ftdichip.com/drivers/vcp-drivers)."
        }

        Say 'Done. Next, with the adapter plugged into the car and the ignition on:'
        Note 'obdcracker ports                      # find the adapter''s port, e.g. COM3'
        Note 'obdcracker --serial COM3 adapter      # check the adapter; sends nothing to the car'
        Note 'obdcracker --serial COM3 vin'
        if (-not $pathHadCargo) { Note "open a new terminal first, so $cargoBin is on your PATH" }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-ObdCracker -Ref $Ref -Dir $Dir -Source $Source
