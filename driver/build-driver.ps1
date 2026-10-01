$ErrorActionPreference = 'Stop'
$targetRoot = & (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\resolve-cargo-target.ps1')
$env:CARGO_TARGET_DIR = $targetRoot
$env:TEMP = Join-Path $targetRoot 'tmp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Installer not found.' }
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual C++ build tools not found.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
$kitRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10.TrimEnd('\')
$kitVersion = Get-ChildItem (Join-Path $kitRoot 'Include') -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'km\ntddk.h') } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1 -ExpandProperty Name
if (-not $kitVersion) { throw 'Windows Driver Kit kernel headers not found.' }

$driverTarget = Join-Path $targetRoot 'silverfox-driver'
$objectDirectory = Join-Path $driverTarget 'obj'
$outputDirectory = Join-Path $driverTarget 'build'
$packageDirectory = Join-Path $driverTarget 'package'
New-Item -ItemType Directory -Force -Path $objectDirectory,$outputDirectory,$packageDirectory | Out-Null
$source = Join-Path $PSScriptRoot 'SilverFoxProtect.c'
$object = Join-Path $objectDirectory 'SilverFoxProtect.obj'
$driver = Join-Path $outputDirectory 'SilverFoxProtect.sys'
$includeKm = Join-Path $kitRoot "Include\$kitVersion\km"
$includeShared = Join-Path $kitRoot "Include\$kitVersion\shared"
$libKm = Join-Path $kitRoot "Lib\$kitVersion\km\x64"

$compile = 'call "{0}" >nul && cl.exe /nologo /c /O2 /W4 /WX /GS /Gy /Zc:wchar_t /D_AMD64_ /DAMD64 /DWINNT=1 /DNTDDI_VERSION=0x0A00000C /I"{1}" /I"{2}" /Fo"{3}" "{4}"' -f $vcvars,$includeKm,$includeShared,$object,$source
cmd.exe /d /s /c $compile
if ($LASTEXITCODE -ne 0) { throw "Driver compilation failed with exit code $LASTEXITCODE" }

$link = 'call "{0}" >nul && link.exe /nologo /OUT:"{1}" /SUBSYSTEM:NATIVE /DRIVER /INTEGRITYCHECK /ENTRY:DriverEntry /MACHINE:X64 /NODEFAULTLIB /INCREMENTAL:NO /OPT:REF /OPT:ICF "{2}" "{3}\ntoskrnl.lib" "{3}\hal.lib" "{3}\wdmsec.lib" "{3}\BufferOverflowK.lib"' -f $vcvars,$driver,$object,$libKm
cmd.exe /d /s /c $link
if ($LASTEXITCODE -ne 0) { throw "Driver link failed with exit code $LASTEXITCODE" }

Copy-Item -LiteralPath $driver -Destination $packageDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SilverFoxProtect.inf') -Destination $packageDirectory -Force
$inf2cat = Join-Path $kitRoot "bin\$kitVersion\x86\Inf2Cat.exe"
if (Test-Path -LiteralPath $inf2cat) {
    & $inf2cat "/driver:$packageDirectory" /os:10_X64 /uselocaltime
    if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed with exit code $LASTEXITCODE" }
}
Get-Item -LiteralPath $driver | Select-Object FullName,Length,LastWriteTime
Write-Host 'The generated driver and catalog are unsigned. Sign the package through the official Microsoft driver signing flow before installation.'
