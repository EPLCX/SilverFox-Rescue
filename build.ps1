$ErrorActionPreference = 'Stop'
$buildTarget = & (Join-Path $PSScriptRoot 'tools\resolve-cargo-target.ps1')
$env:CARGO_TARGET_DIR = $buildTarget
$env:TEMP = Join-Path $buildTarget 'tmp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
$buildDllRequested = $args -contains '--build-dll'
$projectRoot = $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    if ([string]::IsNullOrWhiteSpace($env:SILVERFOX_CLOUD_URL)) { $env:SILVERFOX_CLOUD_URL = 'https://ysmj4k.bond' }
    $releaseKeyRoot = if ([string]::IsNullOrWhiteSpace($env:SILVERFOX_KEY_DIR)) { Join-Path $projectRoot 'releaseSecrets' } else { $env:SILVERFOX_KEY_DIR }
    $releaseKeyRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($releaseKeyRoot.Trim())
    foreach ($kind in @('rules', 'program')) {
        $variable = if ($kind -eq 'rules') { 'SILVERFOX_RULE_PUBLIC_KEY_HEX' } else { 'SILVERFOX_PROGRAM_PUBLIC_KEY_HEX' }
        $publicPath = Join-Path $releaseKeyRoot "$kind-public.hex"
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($variable, 'Process')) -and (Test-Path -LiteralPath $publicPath)) {
            [Environment]::SetEnvironmentVariable($variable, [IO.File]::ReadAllText($publicPath).Trim(), 'Process')
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SILVERFOX_RULE_PUBLIC_KEY_HEX) -and $env:SILVERFOX_RULE_PUBLIC_KEY_HEX -notmatch '^[0-9a-fA-F]{64}$') { throw 'SILVERFOX_RULE_PUBLIC_KEY_HEX must be a 32-byte Ed25519 public key in hex.' }
    if (-not [string]::IsNullOrWhiteSpace($env:SILVERFOX_PROGRAM_PUBLIC_KEY_HEX) -and $env:SILVERFOX_PROGRAM_PUBLIC_KEY_HEX -notmatch '^[0-9a-fA-F]{64}$') { throw 'SILVERFOX_PROGRAM_PUBLIC_KEY_HEX must be a 32-byte Ed25519 public key in hex.' }
    # Verify that the engine DLL matches the engine embedded in the signed seed package.
    Add-Type -AssemblyName System.IO.Compression
    $seedPackage = Join-Path $projectRoot 'rules\seed\rules.package.zip'
    $engineDll = Join-Path $projectRoot 'engine\algorithms.dll'
    $archive = [System.IO.Compression.ZipFile]::OpenRead($seedPackage)
    try {
        $entry = $archive.GetEntry('algorithms.dll')
        if ($null -eq $entry) { throw 'rules/seed/rules.package.zip is missing algorithms.dll.' }
        $stream = $entry.Open()
        $buffer = New-Object System.IO.MemoryStream
        try { $stream.CopyTo($buffer); $packagedDll = $buffer.ToArray() }
        finally { $stream.Dispose(); $buffer.Dispose() }
    }
    finally { $archive.Dispose() }
    $currentDll = [System.IO.File]::ReadAllBytes($engineDll)
    if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$currentDll, [byte[]]$packagedDll)) {
        throw 'engine/algorithms.dll differs from the DLL in rules/seed/rules.package.zip. Regenerate the signed seed package and manifest for the current DLL before building.'
    }
    # Do not embed this workstation's source checkout path in Rust debug and
    # diagnostic metadata. Preserve a caller-supplied RUSTFLAGS value.
    $remapFlag = "--remap-path-prefix=$projectRoot=."
    if ([string]::IsNullOrWhiteSpace($env:RUSTFLAGS)) { $env:RUSTFLAGS = $remapFlag }
    elseif ($env:RUSTFLAGS -notlike "*$remapFlag*") { $env:RUSTFLAGS = "$($env:RUSTFLAGS) $remapFlag" }
    # Build the single release executable with the oldest supported Windows target.
    $env:RUSTC_BOOTSTRAP = '1'
    if ($env:RUSTFLAGS -notlike '*target-feature=+crt-static*') { $env:RUSTFLAGS = "$($env:RUSTFLAGS) -C target-feature=+crt-static".Trim() }
    cargo -Z build-std=std,panic_abort build --release --offline --target x86_64-win7-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Cargo release build failed.' }
    $output = if ([string]::IsNullOrWhiteSpace($env:SILVERFOX_DIST_DIR)) { Join-Path $projectRoot 'dist' } else { $env:SILVERFOX_DIST_DIR }
    $output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($output.Trim())
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    $clientSource = [IO.File]::ReadAllText((Join-Path $projectRoot 'src\main.rs'))
    $clientVersion = [regex]::Match($clientSource, 'const CLIENT_VERSION:&str="([^"]+)"').Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($clientVersion)) { throw 'Client version missing.' }
    $versionedExe = Join-Path $output "silverfox-rescue-$clientVersion.exe"
    $targetRoot = $env:CARGO_TARGET_DIR
    $unsigned = Join-Path $targetRoot 'release\silverfox-rescue.exe'
    Copy-Item -LiteralPath (Join-Path $targetRoot 'x86_64-win7-windows-msvc\release\silverfox-rescue.exe') -Destination $unsigned -Force
    $size = (Get-Item -LiteralPath $unsigned).Length
    if ($size -ge 50MB) { throw "Release is $size bytes and exceeds 50 MB" }
    if ([string]::IsNullOrWhiteSpace($env:SILVERFOX_PROGRAM_PUBLIC_KEY_HEX)) {
        $localExe = $versionedExe
        Copy-Item -LiteralPath $unsigned -Destination $localExe -Force
        Write-Host "Built offline source executable $localExe ($size bytes)."
    } else {
        $privatePath = Join-Path $releaseKeyRoot 'program-private.pem'
        if (Test-Path -LiteralPath $privatePath) {
            $python = Join-Path $projectRoot '.venv\Scripts\python.exe'
            if (-not (Test-Path -LiteralPath $python)) { $python = (Get-Command python -ErrorAction Stop).Source }
            $localExe = $versionedExe
            $signCode = @'
import os, sys, hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tools import sign_program
public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ['SILVERFOX_PROGRAM_PUBLIC_KEY_HEX']))
secret = serialization.load_pem_private_key(Path(sys.argv[2]).read_bytes(), password=None)
signed = sign_program.sign_bytes(Path(sys.argv[1]).read_bytes(), secret, public)
sign_program.atomic_write(Path(sys.argv[3]), signed)
sign_program.verify_pe(Path(sys.argv[3]).read_bytes(), public)
print(f'Signed and verified {sys.argv[3]} ({len(signed)} bytes), SHA-256: {hashlib.sha256(signed).hexdigest()}')
'@
            & $python -B -c $signCode $unsigned $privatePath $localExe
            if ($LASTEXITCODE -ne 0) { throw 'Program signing or verification failed.' }
        } else {
            throw "Release compiled with a program public key. Signing requires $privatePath. Unsigned output: $unsigned"
        }
    }
    try { Copy-Item -LiteralPath $versionedExe -Destination (Join-Path $output 'silverfox-rescue.exe') -Force -ErrorAction Stop }
    catch { Write-Host "Default executable could not be replaced. Signed version output: $versionedExe" }
    $driverRoot = Join-Path $projectRoot 'driver'
    $driverPackage = Join-Path $targetRoot 'silverfox-driver\package'
    if (-not $buildDllRequested -and -not (Test-Path -LiteralPath $driverPackage -PathType Container)) {
        $driverPackage = Join-Path $driverRoot 'build\package'
    }
    $driverProducts = @(
        (Join-Path $driverPackage 'SilverFoxProtect.sys'),
        (Join-Path $driverPackage 'SilverFoxProtect.inf'),
        (Join-Path $driverPackage 'silverfoxprotect.cat')
    )
    if ($buildDllRequested) {
        $kitInstall = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue
        $wdkRoot = if ($kitInstall.KitsRoot10) { Join-Path $kitInstall.KitsRoot10 'Include' } else { '' }
        $hasWdk = (Test-Path $wdkRoot) -and [bool](Get-ChildItem $wdkRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'km\ntddk.h') })
        if ($hasWdk) {
            & (Join-Path $driverRoot 'build-driver.ps1')
            if ($LASTEXITCODE -ne 0) { throw 'Driver build failed.' }
        } else {
            throw 'WDK not found; cannot build the driver package.'
        }
    } else {
        Write-Host 'Skipped driver compilation. Use --build-dll to rebuild SYS/INF/CAT.'
    }

    if (-not [bool]($driverProducts | Where-Object { -not (Test-Path -LiteralPath $_) })) {
        $driverOutput = Join-Path $output 'driver'
        New-Item -ItemType Directory -Force -Path $driverOutput | Out-Null
        foreach ($product in $driverProducts) {
            $destination = Join-Path $driverOutput ([IO.Path]::GetFileName($product))
            if ((Test-Path -LiteralPath $destination) -and ((Get-FileHash -LiteralPath $product).Hash -eq (Get-FileHash -LiteralPath $destination).Hash)) { continue }
            Copy-Item -LiteralPath $product -Destination $destination -Force
        }
    }
} finally { Pop-Location }
