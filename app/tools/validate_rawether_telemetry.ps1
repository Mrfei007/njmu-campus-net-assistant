param([string]$BridgePath, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (-not $BridgePath) { $BridgePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\campus_net_assistant\native\bin\RawetherBridge.exe' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) 'output\tun-monitor-validation\telemetry-contract' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$assembly = [Reflection.Assembly]::LoadFile([IO.Path]::GetFullPath($BridgePath))
$bridgeType = $assembly.GetType('RawetherBridge', $true)
$flags = [Reflection.BindingFlags]'NonPublic,Static'
$bridgeType.GetField('TelemetryAdapter', $flags).SetValue($null, 'Intel "Ethernet"\Test')
$bridgeType.GetField('TelemetryState', $flags).SetValue($null, 'running')
$bridgeType.GetField('TelemetrySends', $flags).SetValue($null, 3)
$bridgeType.GetField('TelemetryLastSuccess', $flags).SetValue($null, [DateTime]::UtcNow.ToString('o'))
$bridgeType.GetField('TelemetryLastFailure', $flags).SetValue($null, [DateTime]::UtcNow.ToString('o'))
$bridgeType.GetField('TelemetryLastFailureStatus', $flags).SetValue($null, [uint32]31)
$bridgeType.GetField('TelemetrySendDuration', $flags).SetValue($null, [long]12)
$bridgeType.GetField('TelemetryAttempt', $flags).SetValue($null, 2)
$bridgeType.GetField('TelemetryRetryRecoveries', $flags).SetValue($null, 1)
$save = $bridgeType.GetMethod('SaveKeepaliveTelemetry', $flags)
# Exercise only the file writer. Never invoke Main, authentication or packet send.
$save.Invoke($null, @([IO.Path]::GetFullPath($OutputDirectory))) | Out-Null
$target = Join-Path $OutputDirectory 'native-keepalive-state.json'
$first = Get-Content -LiteralPath $target -Raw -Encoding utf8 | ConvertFrom-Json
if ($first.successful_sends -ne 3 -or $first.adapter_description -ne 'Intel "Ethernet"\Test') { throw 'Telemetry serialization check failed' }
$bridgeType.GetField('TelemetrySends', $flags).SetValue($null, 4)
$save.Invoke($null, @([IO.Path]::GetFullPath($OutputDirectory))) | Out-Null
$second = Get-Content -LiteralPath $target -Raw -Encoding utf8 | ConvertFrom-Json
if ($second.successful_sends -ne 4) { throw 'Atomic replacement check failed' }
if ($second.last_failure_status -ne 31 -or $second.send_duration_ms -ne 12 -or $second.retry_recoveries -ne 1) { throw 'Failure summary missing after recovery' }
if (Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.tmp') { throw 'Temporary telemetry files were left behind' }
$forbidden = @('password','identity','packet','payload','key','digest','challenge')
foreach ($name in $second.PSObject.Properties.Name) {
 if ($forbidden -contains $name) { throw 'Private field present in telemetry' }
}
$blockedDirectory = Join-Path $OutputDirectory 'not-a-directory'
Set-Content -LiteralPath $blockedDirectory -Value 'I/O failure test' -Encoding ascii
$save.Invoke($null, @([IO.Path]::GetFullPath($blockedDirectory))) | Out-Null
$diagnosticSave = $bridgeType.GetMethod('SaveSendDiagnostic', $flags)
$old = Join-Path $OutputDirectory 'native-keepalive-2000-01-01.jsonl'
$unrelated = Join-Path $OutputDirectory 'unrelated-2000-01-01.jsonl'
Set-Content -LiteralPath $old -Value '{}' -Encoding ascii
Set-Content -LiteralPath $unrelated -Value '{}' -Encoding ascii
[IO.File]::SetLastWriteTimeUtc($old, [DateTime]::UtcNow.AddDays(-8))
[IO.File]::SetLastWriteTimeUtc($unrelated, [DateTime]::UtcNow.AddDays(-8))
$diagnosticSave.Invoke($null, @([IO.Path]::GetFullPath($OutputDirectory))) | Out-Null
if ((Test-Path -LiteralPath $old) -or -not (Test-Path -LiteralPath $unrelated)) { throw 'Scoped seven-day retention failed' }
$daily = Join-Path $OutputDirectory ('native-keepalive-' + [DateTime]::UtcNow.ToString('yyyy-MM-dd') + '.jsonl')
$entry = Get-Content -LiteralPath $daily -Tail 1 | ConvertFrom-Json
if ($entry.last_failure_status -ne 31 -or $entry.state -ne 'running') { throw 'Recovered diagnostic missing' }
foreach ($name in $entry.PSObject.Properties.Name) {
 if ($forbidden -contains $name) { throw 'Private field present in diagnostics' }
}
$diagnosticSave.Invoke($null, @([IO.Path]::GetFullPath($blockedDirectory))) | Out-Null
@{ serialization='passed'; atomic_replacement='passed'; io_failure_isolation='passed'; no_private_payload='passed'; recovery_summary='passed'; seven_day_retention='passed'; diagnostic_jsonl='passed' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'validation.json') -Encoding utf8
Write-Output 'Telemetry contract: passed (no authentication or packet sends)'
