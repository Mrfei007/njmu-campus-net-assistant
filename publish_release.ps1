# publish_release.ps1
# Upload one already-built release to GitHub Releases.
#
# ASCII only on purpose: Windows PowerShell 5.1 reads .ps1 as ANSI.
#
# Layout this script relies on (see README.md):
#   <workspace>\releases\<major.minor>.x\<zip + .sha256.txt>   built package (never tracked by git)
#   <repo>\releases\<version>.json                             version index (tracked by git)
#
# Usage:
#   pwsh .\publish_release.ps1 -DryRun          # print everything it would do, change nothing
#   pwsh .\publish_release.ps1                  # create tag v<version> + upload zip/sha256
#   pwsh .\publish_release.ps1 -Draft           # upload as draft release
#   pwsh .\publish_release.ps1 -Version 1.6.4   # explicit version instead of version.py
#   pwsh .\publish_release.ps1 -Repo owner/name # override the detected GitHub repository
#
# Prerequisites: git remote 'origin' pointing at GitHub and the GitHub CLI (gh) installed.
# Credentials resolve automatically, in this order: `gh auth login`, GH_TOKEN/GITHUB_TOKEN,
# then the token in the git credential manager (the one already used to push).
# The script checks each and explains what is missing.
#
# Note: `gh auth login` rejects classic tokens without the read:org scope, but the same token
# still works for release calls through GH_TOKEN - so a push-only token is enough.

param(
    [string]$Version = '',
    [string]$Repo = '',
    [string]$Remote = 'origin',
    [string]$NotesFile = '',
    [switch]$Draft,
    [switch]$Prerelease,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Workspace = (Resolve-Path -LiteralPath (Join-Path $Here '..')).Path

function Fail([string]$message) {
    Write-Host ''
    Write-Host ('[x] ' + $message) -ForegroundColor Red
    exit 1
}

function Step([string]$message) {
    Write-Host ''
    Write-Host ('== ' + $message) -ForegroundColor Cyan
}

# ---- 1. version --------------------------------------------------------------
Step 'version'
if (-not $Version) {
    $versionSource = Join-Path $Here 'app\src\campus_net_assistant\version.py'
    if (-not (Test-Path -LiteralPath $versionSource)) { Fail "version.py not found: $versionSource" }
    $match = Select-String -LiteralPath $versionSource -Pattern 'VERSION\s*=\s*"([^"]+)"'
    if (-not $match) { Fail "cannot parse VERSION from $versionSource" }
    $Version = $match.Matches[0].Groups[1].Value
}
$family = (($Version -split '\.')[0..1] -join '.') + '.x'
Write-Host ("version     : " + $Version)
Write-Host ("tag         : v" + $Version)
Write-Host ("release dir : releases\" + $family)

# ---- 2. artifacts ------------------------------------------------------------
Step 'artifacts'
$recordPath = Join-Path $Here ("releases\" + $Version + '.json')
if (-not (Test-Path -LiteralPath $recordPath)) {
    Fail ("version index not found: " + $recordPath + " - build first: pwsh .\build_release.ps1")
}
$record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
$releaseDir = Join-Path $Workspace ('releases\' + $family)
$zipPath = Join-Path $releaseDir $record.zip
$shaPath = $zipPath + '.sha256.txt'
if (-not (Test-Path -LiteralPath $zipPath)) { Fail "release zip not found: $zipPath" }
Write-Host ("zip         : " + $zipPath)
Write-Host ("sha256 file : " + $shaPath + $(if (Test-Path -LiteralPath $shaPath) { '' } else { ' (missing, will not upload)' }))
Write-Host ("record sha  : " + $record.sha256)

# ---- 3. integrity ------------------------------------------------------------
Step 'integrity'
$actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $record.sha256.ToLower()) {
    Fail ("sha256 mismatch - refusing to publish`n    record: " + $record.sha256 + "`n    actual: " + $actual)
}
$size = (Get-Item -LiteralPath $zipPath).Length
if ($record.PSObject.Properties.Name -contains 'size_bytes' -and $size -ne [int64]$record.size_bytes) {
    Fail ("size mismatch - refusing to publish: record " + $record.size_bytes + " / actual " + $size)
}
Write-Host ("OK          : sha256 and size match the version index (" + [math]::Round($size / 1MB, 1) + " MB)")

# ---- 4. git state ------------------------------------------------------------
Step 'git'
$tag = 'v' + $Version
$head = (git -C $Here rev-parse --short HEAD).Trim()
Write-Host ("HEAD        : " + $head)
$dirty = (git -C $Here status --porcelain)
if ($dirty) {
    Write-Host 'WARNING: working tree has uncommitted changes - commit them first, or the tag will not describe the shipped code.' -ForegroundColor Yellow
}
$localTag = (git -C $Here tag -l $tag)
if ($localTag) {
    Write-Host ("local tag   : " + $tag + " exists (will be pushed if missing on the remote)")
} else {
    Write-Host ("local tag   : " + $tag + " not created yet (will be created at HEAD)")
}
if ($record.PSObject.Properties.Name -contains 'build_id') {
    Write-Host ("build id    : " + $record.build_id)
}

# ---- 5. remote ---------------------------------------------------------------
Step 'remote'
$remoteUrl = ''
try { $remoteUrl = (git -C $Here remote get-url $Remote 2>$null) } catch { $remoteUrl = '' }
if (-not $remoteUrl) {
    Write-Host ("[!] no git remote '" + $Remote + "' configured yet.") -ForegroundColor Yellow
    Write-Host '    Add it once, then re-run this script:'
    Write-Host ('      git -C "' + $Here + '" remote add origin https://github.com/<owner>/<repo>.git')
    Write-Host ('      git -C "' + $Here + '" push -u origin main --tags')
    if (-not $DryRun) { Fail 'cannot upload without a GitHub remote' }
    if (-not $Repo) { $Repo = '<owner>/<repo>' }
} else {
    Write-Host ("remote      : " + $Remote + " -> " + $remoteUrl)
    if (-not $Repo) {
        if ($remoteUrl -match 'github\.com[:/](?<slug>[^/]+/[^/.]+?)(\.git)?$') {
            $Repo = $Matches['slug']
        } else {
            Fail ("cannot infer owner/name from remote URL: " + $remoteUrl + " - pass -Repo owner/name")
        }
    }
}
Write-Host ("repository  : " + $Repo)

# ---- 6. notes ----------------------------------------------------------------
Step 'release notes'
if (-not $NotesFile) {
    $changelog = Join-Path $Here 'CHANGELOG.md'
    if (Test-Path -LiteralPath $changelog) {
        $lines = Get-Content -LiteralPath $changelog
        $start = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match ('^##\s+' + [regex]::Escape($Version) + '(\s|$)')) { $start = $i; break }
        }
        if ($start -ge 0) {
            $end = $lines.Count - 1
            for ($i = $start + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^##\s') { $end = $i - 1; break }
            }
            $body = ($lines[$start..$end] -join "`n").Trim()
            $tmp = Join-Path $env:TEMP ('njmu-release-notes-' + $Version + '.md')
            Set-Content -LiteralPath $tmp -Value $body -Encoding utf8
            $NotesFile = $tmp
            Write-Host ('notes       : from CHANGELOG.md section ' + $Version + ' -> ' + $tmp)
        } else {
            Write-Host ('notes       : no CHANGELOG.md section for ' + $Version + ' - gh will ask for notes') -ForegroundColor Yellow
        }
    }
} else {
    Write-Host ('notes       : ' + $NotesFile)
}

# ---- 7. gh -------------------------------------------------------------------
Step 'github cli'

# Authentication can come from three places, checked in this order:
#   1. gh auth login            (interactive; needs a token with repo + read:org)
#   2. GH_TOKEN / GITHUB_TOKEN  (already exported in the environment)
#   3. git credential manager   (the token this machine already uses to push; needs repo, not read:org)
# gh only validates scopes on `gh auth login`; a plain token in GH_TOKEN works for API/release calls.
function Get-TokenFromGitCredential {
    $savedPrompt = $env:GIT_TERMINAL_PROMPT
    $savedGcm = $env:GCM_INTERACTIVE
    $env:GIT_TERMINAL_PROMPT = '0'
    $env:GCM_INTERACTIVE = 'never'
    try {
        $creds = ("protocol=https`nhost=github.com`n`n" | git credential fill 2>$null) -split "`n"
        $t = ($creds | Where-Object { $_ -match '^password=' }) -replace '^password=', ''
        if ($t) { return $t.Trim() }
        return ''
    } catch {
        return ''
    } finally {
        $env:GIT_TERMINAL_PROMPT = $savedPrompt
        $env:GCM_INTERACTIVE = $savedGcm
    }
}

$gh = Get-Command gh -ErrorAction SilentlyContinue
$ghPath = ''
if ($gh) { $ghPath = $gh.Source }
else {
    # winget installs to Program Files but an already-running shell keeps the old PATH
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'GitHub CLI\gh.exe'),
        (Join-Path $env:LOCALAPPDATA 'GitHub CLI\gh.exe')
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $ghPath = $candidate; break }
    }
}
if (-not $ghPath) {
    Write-Host '[x] GitHub CLI (gh) is not installed.' -ForegroundColor Red
    Write-Host '    Install it:'
    Write-Host '      winget install --id GitHub.cli'
    Write-Host ''
    Write-Host '    Manual alternative (upload with browser):'
    Write-Host ('      https://github.com/' + $Repo + '/releases/new?tag=' + $tag)
    Write-Host ('      asset 1: ' + $zipPath)
    if (Test-Path -LiteralPath $shaPath) { Write-Host ('      asset 2: ' + $shaPath) }
    if ($NotesFile) { Write-Host ('      body   : ' + $NotesFile) }
    if (-not $DryRun) { Fail 'cannot upload without gh' }
} else {
    $authMode = ''
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $ghPath auth status *> $null
    if ($LASTEXITCODE -eq 0) { $authMode = 'gh auth login' }
    $ErrorActionPreference = $savedEap

    if (-not $authMode) {
        foreach ($v in @('GH_TOKEN', 'GITHUB_TOKEN')) {
            $val = [Environment]::GetEnvironmentVariable($v)
            if ($val) { $authMode = ('environment ' + $v) }
        }
    }
    if (-not $authMode) {
        $storedToken = Get-TokenFromGitCredential
        if ($storedToken) {
            $env:GH_TOKEN = $storedToken
            Remove-Variable storedToken
            $authMode = 'git credential manager'
        }
    }

    if (-not $authMode) {
        Write-Host 'gh          : installed but no credentials found' -ForegroundColor Red
        Write-Host '              run `gh auth login` once (needs a token with scopes repo + read:org),'
        Write-Host '              or export GH_TOKEN, or configure a git credential helper for github.com.'
        if (-not $DryRun) { Fail 'cannot upload without credentials' }
    } else {
        Write-Host ('gh          : installed, auth = ' + $authMode)
    }
}

# ---- 8. upload ---------------------------------------------------------------
Step 'upload'
$assets = @($zipPath)
if (Test-Path -LiteralPath $shaPath) { $assets += $shaPath }

$ghArgs = @('release', 'create', $tag) + $assets + @('--repo', $Repo, '--title', $tag)
if ($NotesFile) { $ghArgs += @('--notes-file', $NotesFile) } else { $ghArgs += @('--generate-notes') }
if ($Draft) { $ghArgs += '--draft' }
if ($Prerelease) { $ghArgs += '--prerelease' }

$pretty = 'gh ' + (($ghArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
Write-Host $pretty

if (-not $localTag) {
    $tagCmd = 'git -C "' + $Here + '" tag -a ' + $tag + ' -m "' + $Version + '"'
    Write-Host ''
    Write-Host 'Also creating the annotated tag locally:'
    Write-Host ('  ' + $tagCmd)
    if (-not $DryRun) { git -C $Here tag -a $tag -m $Version }
}

if ($DryRun) {
    Write-Host ''
    Write-Host 'DryRun: nothing was uploaded. Re-run without -DryRun to publish.' -ForegroundColor Yellow
    exit 0
}

& $ghPath @ghArgs
if ($LASTEXITCODE -ne 0) { Fail 'gh release create failed - see the message above' }

Write-Host ''
Write-Host ('published   : https://github.com/' + $Repo + '/releases/tag/' + $tag) -ForegroundColor Green
if (-not $Draft) {
    Write-Host 'remember    : push the tag too (gh creates it on the remote; keep the local one):' 
    Write-Host ('  git -C "' + $Here + '" push origin ' + $tag)
}