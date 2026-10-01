@echo off
setlocal
set "BUILD_TARGET="
for /f "usebackq delims=" %%I in (`powershell.exe -NoProfile -File "%~dp0..\tools\resolve-cargo-target.ps1"`) do set "BUILD_TARGET=%%I"
if not defined BUILD_TARGET exit /b 1
set "CARGO_TARGET_DIR=%BUILD_TARGET%"
set "TEMP=%BUILD_TARGET%\tmp"
set "TMP=%TEMP%"
set "BUILD_ROOT=%BUILD_TARGET%\silverfox-engine"
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "%BUILD_ROOT%" mkdir "%BUILD_ROOT%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 1
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL exit /b 1
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cl /nologo /utf-8 /std:c++17 /EHsc /O2 /MT /LD /W4 /WX /Fo:"%BUILD_ROOT%\algorithms.obj" /Fe:"%BUILD_ROOT%\algorithms.dll" "%~dp0algorithms.cpp" wintrust.lib crypt32.lib ws2_32.lib version.lib /link /IMPLIB:"%BUILD_ROOT%\algorithms.lib" /PDB:"%BUILD_ROOT%\algorithms.pdb"
if errorlevel 1 exit /b %errorlevel%
if "%~1"=="--no-copy" exit /b 0
copy /y "%BUILD_ROOT%\algorithms.dll" "%~dp0algorithms.dll" >nul
exit /b %errorlevel%
