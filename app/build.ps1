$ErrorActionPreference = 'Stop'
py -3 "$PSScriptRoot\build_local.py"
Write-Output 'Formal Windows x64 package created under the release directory.'
