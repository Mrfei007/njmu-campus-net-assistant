# build_release.ps1
# Build the release package from THIS repository (single source of truth).
#
# ASCII only on purpose: Windows PowerShell 5.1 reads .ps1 as ANSI.
#
# Usage:
#   pwsh .\build_release.ps1                  # build + copy zip/sha256 to <workspace>\releases\<major.minor>.x
#   pwsh .\build_release.ps1 -NoCopy          # build only (trial build, does not touch releases)
#   pwsh .\build_release.ps1 -Vendor 'D:\x\vendor'
#   pwsh .\build_release.ps1 -RebuildBridge   # force rebuilding native\bin\NpcapBridge.exe
#
# What it does:
#   1. read the version from app\src\campus_net_assistant\version.py
#   2. rebuild native\bin\NpcapBridge.exe when its source changed (or -RebuildBridge)
#   3. run app\build_local.py (PyInstaller onedir + Rawether bridge + GUI smoke check + bridge selftest)
#   4. verify the reported sha256 against the freshly computed hash
#   5. copy the zip and its .sha256.txt to <OutDir>\<major.minor>.x
#   6. write releases\<version>.json into THIS repository (tracked: the version index)

param(
    [string]$Vendor = '<workspace>\archive\build_stage\work\campus-net-assistant\vendor',
    [string]$OutDir = $PSScriptRoot + '\..\releases',
    [switch]$NoCopy,
    [switch]$RebuildBridge
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$App = Join-Path $Here 'app'

function Fail([string]$message) {
    Write-Host ''
    Write-Host ('[x] ' + $message) -ForegroundColor Red
    exit 1
}

# ---- 1. version --------------------------------------------------------------
$versionSource = Join-Path $App 'src\campus_net_assistant\version.py'
if (-not (Test-Path -LiteralPath $versionSource)) { Fail "version.py not found: $versionSource" }
$match = Select-String -LiteralPath $versionSource -Pattern 'VERSION\s*=\s*"([^"]+)"'
if (-not $match) { Fail "cannot parse VERSION from $versionSource" }
$version = $match.Matches[0].Groups[1].Value
Write-Host "product version : $version"

# ---- 2. dependencies ---------------------------------------------------------
if (-not (Test-Path -LiteralPath (Join-Path $Vendor 'PyInstaller'))) { Fail "vendor not found: $Vendor" }
Write-Host "vendor          : $Vendor"
Write-Host "app tree        : $App"

# ---- 3. bridge ---------------------------------------------------------------
# NpcapBridge.exe is a --onefile binary that build_local.py only copies. Rebuild it
# when its source is newer (or when forced), otherwise a bridge change would silently
# ship as an old binary (this is exactly how 1.5.8-1.5.9.2 kept the same bridge hash).
$env:NJMU_DEPENDENCY_VENDOR = $Vendor
$env:PYTHONSAFEPATH = '1'
$env:PYTHONIOENCODING = 'utf-8'
$bridgeExe = Join-Path $App 'src\campus_net_assistant\native\bin\NpcapBridge.exe'
$bridgeArgs = @('-P', 'tools\build_npcap_bridge.py')
if ($RebuildBridge) { $bridgeArgs += '--force' }
Push-Location -LiteralPath $App
try {
    & python @bridgeArgs
    if ($LASTEXITCODE -ne 0) { Fail "build_npcap_bridge.py failed with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
if (-not (Test-Path -LiteralPath $bridgeExe)) { Fail "bridge missing: $bridgeExe" }
$bridgeSha = (Get-FileHash -LiteralPath $bridgeExe -Algorithm SHA256).Hash.ToLower()
Write-Host "bridge sha256   : $bridgeSha"

# ---- 4. build ----------------------------------------------------------------
Push-Location -LiteralPath $App
try {
    & python -P build_local.py
    if ($LASTEXITCODE -ne 0) { Fail "build_local.py failed with code $LASTEXITCODE" }
} finally {
    Pop-Location
    Remove-Item Env:\NJMU_DEPENDENCY_VENDOR -ErrorAction SilentlyContinue
}

# ---- 5. locate and verify the zip -------------------------------------------
$releaseRoot = Join-Path $App 'release'
$zip = Get-ChildItem -LiteralPath $releaseRoot -Filter "*-$version-Windows-x64.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Fail "no release zip for version $version under $releaseRoot" }

$shaFile = "$($zip.FullName).sha256.txt"
if (-not (Test-Path -LiteralPath $shaFile)) { Fail "sha256 file missing: $shaFile" }
$reported = ((Get-Content -LiteralPath $shaFile -Raw) -split '\s+')[0].Trim().ToLower()
$computed = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash.ToLower()
if ($reported -ne $computed) { Fail "sha256 mismatch: manifest=$reported computed=$computed" }

$buildId = Get-ChildItem -LiteralPath (Join-Path $App 'dist-builds') -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty Name

# ---- 6. publish --------------------------------------------------------------
Write-Host ''
Write-Host "zip     : $($zip.FullName)"
Write-Host "size    : $([math]::Round($zip.Length / 1MB, 1)) MB"
Write-Host "sha256  : $computed"
Write-Host "build id: $buildId"

if (-not $NoCopy) {
    # Layout convention: <workspace>\releases\<major.minor>.x\<zip + sha256>  (binaries, not tracked)
    #                    <repo>\releases\<version>.json                     (index, tracked by git)
    $family = (($version -split '\.')[0..1] -join '.') + '.x'
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $outRoot = (Resolve-Path -LiteralPath $OutDir).Path
    $destination = Join-Path $outRoot $family
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-Item -LiteralPath $zip.FullName -Destination $destination -Force
    Copy-Item -LiteralPath $shaFile -Destination $destination -Force
    Write-Host "copied  : $(Join-Path $destination $zip.Name)"

    $recordsDir = Join-Path $Here 'releases'
    New-Item -ItemType Directory -Force -Path $recordsDir | Out-Null
    $record = [ordered]@{
        version  = $version
        build_id = $buildId
        zip      = $zip.Name
        size_bytes = $zip.Length
        sha256   = $computed
        recorded_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        source   = 'repo/app'
        bridge_sha256 = $bridgeSha
        release_dir = $family
    }
    ($record | ConvertTo-Json) | Set-Content -LiteralPath (Join-Path $recordsDir "$version.json") -Encoding utf8
    Write-Host "record  : $(Join-Path $recordsDir "$version.json")"
    Write-Host "next    : pwsh .\publish_release.ps1 -DryRun   # preview the GitHub upload, then drop -DryRun"
} else {
    Write-Host 'NoCopy: release zip left in app\release'
}