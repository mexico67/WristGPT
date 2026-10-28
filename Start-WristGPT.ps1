param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$bridgeRoot = Join-Path $PSScriptRoot 'Bridge'
$runtimeDirectory = Join-Path $PSScriptRoot '.venv'
$pythonExecutable = Join-Path $runtimeDirectory 'Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonExecutable)) {
    python -m venv $runtimeDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ required.' }
    & $pythonExecutable -m pip install -r (Join-Path $bridgeRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
$privateDirectory = Join-Path $env:LOCALAPPDATA 'WristGPT/private'
New-Item -ItemType Directory -Force -Path $privateDirectory | Out-Null
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $privateDirectory /inheritance:r /grant:r ($currentIdentity + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict credential directory permissions.' }
$env:WRISTGPT_STATE = $privateDirectory
if ($NoBrowser) { & $pythonExecutable (Join-Path $bridgeRoot 'bridge.py') --no-browser }
else { & $pythonExecutable (Join-Path $bridgeRoot 'bridge.py') }
