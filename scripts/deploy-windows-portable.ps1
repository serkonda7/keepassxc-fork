<#
.SYNOPSIS
Creates a self-contained portable KeePassXC bundle for Windows (MSYS2/MinGW).

.DESCRIPTION
Copies built executables, deploys Qt runtime/plugins via windeployqt, recursively
copies MinGW/third-party DLL dependencies, and stages required share data.
Intended for internal distribution from a MinGW build (e.g. build-unity).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [string]$OutputDir,
    [Parameter(Mandatory = $true)][string]$MinGWBin,
    [Parameter(Mandatory = $true)][string]$Windeployqt,
    [ValidateSet('Debug', 'Release')][string]$Config = 'Release',
    [switch]$NoClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ExistingPath([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "${Label} not found: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

$BuildDir = Resolve-ExistingPath $BuildDir 'BuildDir'
$SourceDir = Resolve-ExistingPath $SourceDir 'SourceDir'
$MinGWBin = Resolve-ExistingPath $MinGWBin 'MinGWBin'
$Windeployqt = Resolve-ExistingPath $Windeployqt 'Windeployqt'

if (-not $OutputDir) {
    $OutputDir = Join-Path $BuildDir 'dist\KeePassXC'
}

$objdump = Join-Path $MinGWBin 'objdump.exe'
if (-not (Test-Path -LiteralPath $objdump)) {
    throw "objdump.exe not found in MinGWBin: $objdump"
}

$wdqtMode = if ($Config -eq 'Debug') { '--debug' } else { '--release' }

$exeCandidates = @(
    (Join-Path $BuildDir 'src\KeePassXC.exe'),
    (Join-Path $BuildDir 'src\cli\keepassxc-cli.exe'),
    (Join-Path $BuildDir 'src\proxy\keepassxc-proxy.exe')
)
$exes = @($exeCandidates | Where-Object { Test-Path -LiteralPath $_ })
if ($exes.Count -eq 0) {
    throw "No KeePassXC executables found under: $BuildDir"
}

if ((Test-Path -LiteralPath $OutputDir) -and -not $NoClean) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

Write-Host "Deploying portable bundle to: $OutputDir"
foreach ($exe in $exes) {
    Copy-Item -LiteralPath $exe -Destination $OutputDir -Force
}

$mainExe = Join-Path $OutputDir 'KeePassXC.exe'
if (Test-Path -LiteralPath $mainExe) {
    Write-Host "Running windeployqt ($Config)..."
    & $Windeployqt $wdqtMode '--no-translations' '--compiler-runtime' $mainExe
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "windeployqt exited with code $LASTEXITCODE; checking deployed files..."
    }
}

# Recursively copy non-system DLL dependencies that exist in MinGWBin.
$processed = @{}
$changed = $true
while ($changed) {
    $changed = $false
    $files = Get-ChildItem -LiteralPath $OutputDir -Recurse -File -Include *.exe, *.dll
    foreach ($file in $files) {
        $key = $file.FullName.ToLowerInvariant()
        if ($processed.ContainsKey($key)) { continue }
        $processed[$key] = $true
        $lines = & $objdump -p $file.FullName 2>$null
        foreach ($line in $lines) {
            if ($line -match 'DLL Name:\s*(\S+)') {
                $dll = $Matches[1]
                $dst = Join-Path $OutputDir $dll
                if (Test-Path -LiteralPath $dst) { continue }
                $src = Join-Path $MinGWBin $dll
                if (Test-Path -LiteralPath $src) {
                    Copy-Item -LiteralPath $src -Destination $dst -Force
                    $changed = $true
                }
            }
        }
    }
}

# Stage share data. On Windows Resources::dataPath() looks for <exe dir>/share.
$shareOut = Join-Path $OutputDir 'share'
New-Item -ItemType Directory -Force -Path $shareOut | Out-Null

$buildTranslations = Join-Path $BuildDir 'share\translations'
if (Test-Path -LiteralPath $buildTranslations) {
    Copy-Item -LiteralPath $buildTranslations -Destination $shareOut -Recurse -Force
}

$sourceWordlists = Join-Path $SourceDir 'share\wordlists'
if (Test-Path -LiteralPath $sourceWordlists) {
    Copy-Item -LiteralPath $sourceWordlists -Destination $shareOut -Recurse -Force
}

$sourceIcons = Join-Path $SourceDir 'share\icons'
if (Test-Path -LiteralPath $sourceIcons) {
    Copy-Item -LiteralPath $sourceIcons -Destination $shareOut -Recurse -Force
}

# Sanity check: direct deps of main exe should resolve to dist or system dirs.
if (Test-Path -LiteralPath $mainExe) {
    $missing = @()
    $lines = & $objdump -p $mainExe 2>$null
    foreach ($line in $lines) {
        if ($line -match 'DLL Name:\s*(\S+)') {
            $dll = $Matches[1]
            if (Test-Path -LiteralPath (Join-Path $OutputDir $dll)) { continue }
            if (Test-Path -LiteralPath (Join-Path $MinGWBin $dll)) { $missing += "mingw:$dll"; continue }
            $sys32 = Join-Path $env:WINDIR 'System32'
            $syswow = Join-Path $env:WINDIR 'SysWOW64'
            if ((Test-Path -LiteralPath (Join-Path $sys32 $dll)) -or (Test-Path -LiteralPath (Join-Path $syswow $dll))) { continue }
            $missing += "unresolved:$dll"
        }
    }
    if ($missing.Count -gt 0) {
        Write-Warning ("Unresolved/missing DLLs for KeePassXC.exe: " + ($missing -join ', '))
    } else {
        Write-Host 'KeePassXC.exe direct dependencies: OK'
    }
}

Write-Host "Portable bundle ready: $OutputDir"
