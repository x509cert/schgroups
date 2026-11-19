<#
.SYNOPSIS
  Builds schgroups with the latest installed VS 2026 (MSVC v145) and the newest installed Windows SDK.

.EXAMPLE
  .\build.ps1                        # x64 Release via CMake
  .\build.ps1 -Arch arm64 -Config Debug
  .\build.ps1 -NoCMake               # direct cl.exe build in a VS dev shell
  .\build.ps1 -Clean
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64',
    [ValidateSet('Release', 'Debug')] [string] $Config = 'Release',
    [switch] $NoCMake,
    [switch] $Clean
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$buildDir = Join-Path $PSScriptRoot "build\$Arch"

if ($Clean) {
    Remove-Item -Recurse -Force (Join-Path $PSScriptRoot 'build') -ErrorAction SilentlyContinue
    Write-Host 'cleaned'
    return
}

# --- Locate VS 2026 (v18.x) with the C++ toolset --------------------------------------------
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; install Visual Studio 2026.' }
$vcComponent = if ($Arch -eq 'arm64') { 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' } else { 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
$vs = & $vswhere -latest -prerelease -products * -version '[18.0,19.0)' -requires $vcComponent -property installationPath
if (-not $vs) { throw "VS 2026 with $vcComponent not found." }
Write-Host "Visual Studio : $vs"

# --- Newest installed Windows SDK -------------------------------------------------------------
$sdkInclude = "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
$sdk = Get-ChildItem $sdkInclude -Directory -ErrorAction SilentlyContinue |
       Where-Object { $_.Name -match '^10\.0\.\d+\.\d+$' -and (Test-Path (Join-Path $_.FullName 'um\schannel.h')) } |
       Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $sdk) { throw 'No Windows 10/11 SDK found.' }
$sdkVer = $sdk.Name
if ([version]$sdkVer -lt [version]'10.0.28000.0') { Write-Warning "Newest SDK is $sdkVer (10.0.28000+ recommended)." }
Write-Host "Windows SDK   : $sdkVer"

$exe = $null

if (-not $NoCMake) {
    # --- CMake path (VS-bundled cmake if not on PATH) -------------------------------------------
    $cmake = Get-Command cmake -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
    if (-not $cmake) {
        $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
        if (-not (Test-Path $cmake)) { throw 'cmake not found; install the VS "C++ CMake tools" component or use -NoCMake.' }
    }
    Write-Host "CMake         : $cmake"

    & $cmake --preset "vs2026-$Arch" "-DCMAKE_SYSTEM_VERSION=$sdkVer"
    if ($LASTEXITCODE) { throw "CMake configure failed ($LASTEXITCODE)" }
    & $cmake --build $buildDir --config $Config --parallel
    if ($LASTEXITCODE) { throw "CMake build failed ($LASTEXITCODE)" }
    $exe = Join-Path $buildDir "$Config\schgroups.exe"
}
else {
    # --- Direct cl.exe path ---------------------------------------------------------------------
    $hostArch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $tgtArch  = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }
    Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -Arch $tgtArch -HostArch $hostArch `
                     -DevCmdArguments "-winsdk=$sdkVer -no_logo" | Out-Null
    Set-Location $PSScriptRoot

    $outDir = Join-Path $buildDir $Config
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $exe = Join-Path $outDir 'schgroups.exe'

    $cflags = @('/nologo', '/std:c++latest', '/permissive-', '/Zc:__cplusplus', '/utf-8', '/EHsc', '/W4', '/sdl',
                '/guard:cf', '/wd4865', '/DUNICODE', '/D_UNICODE', '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX',
                '/D_WIN32_WINNT=0x0A00', "/Fo$outDir\", "/Fd$outDir\", "/Fe$exe")
    $cflags += if ($Config -eq 'Debug') { @('/Od', '/Zi', '/MTd') } else { @('/O2', '/Zi', '/MT', '/DNDEBUG') }
    $lflags = @('/link', '/DEBUG', '/guard:cf', '/CETCOMPAT', '/DYNAMICBASE', '/NXCOMPAT',
                'ws2_32.lib', 'secur32.lib', 'crypt32.lib', 'ncrypt.lib', 'bcrypt.lib', 'advapi32.lib')
    if ($Arch -eq 'arm64') { $lflags = $lflags | Where-Object { $_ -ne '/CETCOMPAT' } }

    Write-Host "cl            : $((Get-Command cl).Source)"
    & cl.exe @cflags schgroups.cpp schannel_groups.cpp @lflags
    if ($LASTEXITCODE) { throw "cl failed ($LASTEXITCODE)" }
}

Write-Host "`nBuilt: $exe" -ForegroundColor Green
