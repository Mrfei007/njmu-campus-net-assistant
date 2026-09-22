$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $projectRoot 'src\campus_net_assistant\native\RawetherBridge.cs'
$outputFolder = Join-Path $projectRoot 'src\campus_net_assistant\native\bin'
$output = Join-Path $outputFolder 'RawetherBridge.exe'
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'

New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
& $compiler /nologo /platform:x64 /optimize+ /target:exe /reference:System.ServiceProcess.dll "/out:$output" $source
if ($LASTEXITCODE -ne 0) { throw "RawetherBridge compile failed: $LASTEXITCODE" }
Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
