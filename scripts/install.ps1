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
        'AMD64' { $triple = 'x86_64-pc-windows-msvc'; $vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'; $sdkArch = 'x64' }
        'ARM64' { $triple = 'aarch64-pc-windows-msvc'; $vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.ARM64'; $sdkArch = 'arm64' }
        default { throw "unsupported processor architecture: $arch (need 64-bit x86 or ARM)" }
    }
    # Absolute, because the build runs from inside the source tree: a relative CARGO_HOME or
    # RUSTUP_HOME would land the toolchain or the binary under the source
    function Get-AbsolutePath([string]$Path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) }
    $cargoHome = Get-AbsolutePath $(if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' })
    $rustupHome = if ($env:RUSTUP_HOME) { Get-AbsolutePath $env:RUSTUP_HOME } else { '' }
    $cargoBin = Join-Path $cargoHome 'bin'
    $pathHadCargo = ($env:Path -split ';') -contains $cargoBin

    # Whether MSVC can link a Rust program: the compiler component, plus a Windows SDK with the
    # system and C runtime libraries for this architecture, which Visual Studio installs separately
    function Test-MsvcToolchain {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere)) { return $false }
        if (-not (& $vswhere -products * -requires $vcComponent -property installationPath)) { return $false }
        foreach ($key in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots',
            'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots') {
            $root = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).KitsRoot10
            if (-not $root) { continue }
            $lib = Join-Path $root 'Lib'
            if (-not (Test-Path -LiteralPath $lib)) { continue }
            foreach ($version in Get-ChildItem -LiteralPath $lib -Directory) {
                if ((Test-Path -LiteralPath (Join-Path $version.FullName "um\$sdkArch\kernel32.lib")) -and
                    (Test-Path -LiteralPath (Join-Path $version.FullName "ucrt\$sdkArch\ucrt.lib"))) { return $true }
            }
        }
        return $false
    }

    # Check the inputs before installing anything system-wide. User paths are literal throughout:
    # [ and ] are legal in Windows names, and -Path would treat them as wildcards.
    if ($Source) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source 'Cargo.toml'))) { throw "-Source $Source has no Cargo.toml" }
        $Source = (Resolve-Path -LiteralPath $Source).Path
    }
    # The install directory: refuse to take over one this script didn't create
    if ((Test-Path -LiteralPath $Dir) -and -not (Test-Path -LiteralPath (Join-Path $Dir $marker)) -and
        (Get-ChildItem -Force -LiteralPath $Dir | Select-Object -First 1)) {
        throw "$Dir already exists and wasn't made by this script; pick another -Dir (or -Source to build a checkout)"
    }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    # Absolute, because the build runs from inside the source tree
    $Dir = (Resolve-Path -LiteralPath $Dir).Path
    New-Item -ItemType File -Force -Path (Join-Path $Dir $marker) | Out-Null

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("obdcracker-install-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        # 1. The MSVC linker and Windows SDK
        if (Test-MsvcToolchain) {
            Note 'Visual C++ Build Tools and Windows SDK: already installed'
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
            if (-not (Test-MsvcToolchain)) {
                throw 'the C++ build tools or the Windows SDK are still missing: open Visual Studio Installer, choose Modify, and add "Desktop development with C++" with a Windows SDK'
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

        # 3. The source
        if ($Source) {
            $src = $Source
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
            Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
            # The archive holds one folder, named after the repo and ref
            $top = @(Get-ChildItem -Directory -LiteralPath $unpacked)
            if ($top.Count -ne 1 -or -not (Test-Path -LiteralPath (Join-Path $top[0].FullName 'Cargo.toml'))) {
                throw "the download has no Cargo.toml; is '$Ref' an OBDCracker ref?"
            }
            # Replace the last run's copy only once the new one is complete
            $src = Join-Path $Dir 'src'
            if (Test-Path -LiteralPath $src) { Remove-Item -Recurse -Force -LiteralPath $src }
            Move-Item -LiteralPath $top[0].FullName -Destination $src
        }

        # 4. Build
        Say 'Building obdcracker (the first run also downloads the pinned Rust toolchain)'
        Push-Location -LiteralPath $src
        # Environment the build changes, put back afterwards so an iex caller's session keeps its own
        $savedEnv = @{}
        foreach ($name in 'RUSTUP_TOOLCHAIN', 'RUSTC', 'CARGO_BUILD_TARGET', 'CARGO_HOME', 'RUSTUP_HOME') {
            $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            if ($env:CARGO_HOME) { $env:CARGO_HOME = $cargoHome }
            if ($rustupHome) { $env:RUSTUP_HOME = $rustupHome }
            # Name the pinned toolchain explicitly. rustup's own choice can be overridden
            # (RUSTUP_TOOLCHAIN, `rustup override`), and a cargo first on PATH may not be rustup's.
            $channel = Select-String -LiteralPath 'rust-toolchain.toml' -Pattern '^channel\s*=\s*"([^"]+)"' | Select-Object -First 1
            if (-not $channel) { throw "can't read the toolchain channel from rust-toolchain.toml" }
            $toolchain = $channel.Matches[0].Groups[1].Value
            Invoke-Checked rustup @('toolchain', 'install', $toolchain, '--profile', 'minimal')
            # `rustup run` puts that toolchain's cargo and rustc first. RUSTC or CARGO_BUILD_TARGET
            # from the caller's environment would still swap the compiler or the target, so drop them.
            $env:RUSTC = $null
            $env:CARGO_BUILD_TARGET = $null
            # The build cache lives outside the source, so a re-run only rebuilds what changed.
            # --root pins where the binary goes, whatever CARGO_INSTALL_ROOT or Cargo's install.root say.
            Invoke-Checked rustup @('run', $toolchain, 'cargo', 'install', '--path', 'crates/obdcracker-cli',
                '--locked', '--force', '--target-dir', (Join-Path $Dir 'target'), '--root', $cargoHome)
        } finally {
            foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
            Pop-Location
        }

        # 5. Check it runs and can see the adapter
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
        if (-not $pathHadCargo) {
            if (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $cargoBin) {
                Note "open a new terminal first, so $cargoBin is on your PATH"
            } else {
                Note "add $cargoBin to your PATH to run obdcracker from any terminal"
            }
        }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-ObdCracker -Ref $Ref -Dir $Dir -Source $Source
