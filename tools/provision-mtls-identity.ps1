param(
    [string]$Certificate,
    [string]$PrivateKey,
    [string]$DeviceId,
    [string]$DeviceSigningKey
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $keyRoot = if ([string]::IsNullOrWhiteSpace($env:SILVERFOX_KEY_DIR)) { Join-Path $projectRoot 'releaseSecrets' } else { $env:SILVERFOX_KEY_DIR }
    $keyRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($keyRoot.Trim())
} finally { Pop-Location }
if ([string]::IsNullOrWhiteSpace($Certificate)) { $Certificate = Join-Path $keyRoot 'mtls\client-cert.pem' }
if ([string]::IsNullOrWhiteSpace($PrivateKey)) { $PrivateKey = Join-Path $keyRoot 'mtls\client-key.pem' }
if ([string]::IsNullOrWhiteSpace($DeviceId)) { $DeviceId = Join-Path $keyRoot 'device-id.txt' }
if ([string]::IsNullOrWhiteSpace($DeviceSigningKey)) { $DeviceSigningKey = Join-Path $keyRoot 'device-private.hex' }
foreach ($file in @($Certificate, $PrivateKey, $DeviceId, $DeviceSigningKey)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Identity source file missing: $file" }
}
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$root = Join-Path $env:ProgramData 'SilverFoxRescue\identity'
if ((Get-Content -LiteralPath $DeviceId -Raw).Trim() -notmatch '^[0-9a-f]{32,64}$') { throw 'Invalid fixed device id.' }
if ((Get-Content -LiteralPath $DeviceSigningKey -Raw).Trim() -notmatch '^[0-9a-f]{64}$') { throw 'Invalid Ed25519 device seed.' }
New-Item -ItemType Directory -Force -Path $root | Out-Null
Copy-Item -LiteralPath $Certificate -Destination (Join-Path $root 'client-cert.pem') -Force
Copy-Item -LiteralPath $PrivateKey -Destination (Join-Path $root 'client-key.pem') -Force
Copy-Item -LiteralPath $DeviceId -Destination (Join-Path $root 'device-id.txt') -Force
Copy-Item -LiteralPath $DeviceSigningKey -Destination (Join-Path $root 'device-private.hex') -Force
& icacls.exe $root /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" "${currentUser}:(OI)(CI)(F)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the identity directory.' }
foreach($name in @('client-cert.pem','client-key.pem','device-id.txt','device-private.hex')) {
    & icacls.exe (Join-Path $root $name) /inheritance:r /grant:r "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "${currentUser}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not protect $name." }
}
Write-Host "Fixed device identity installed under $root with restricted ACL."
