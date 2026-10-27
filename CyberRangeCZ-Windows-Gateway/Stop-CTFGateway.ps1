[CmdletBinding()]
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Gateway.Common.ps1')
$runtimeDir = Join-Path $PSScriptRoot 'runtime'
$statePath = Join-Path $runtimeDir 'gateway-state.json'
$stopPath = Join-Path $runtimeDir 'stop.request'
$script:GatewayLogPath = Join-Path $PSScriptRoot 'logs' ('gateway-stop-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    Write-GatewayLog 'No managed tunnel state found; no process was stopped.' 'WARN'
    exit 0
}

try {
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $pidValue = [int]$state.processId
    $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-GatewayLog "Managed process $pidValue is already stopped."
        Remove-Item -LiteralPath $statePath -Force
        exit 0
    }

    # ConvertFrom-Json parses ISO-8601 timestamps into DateTime values. Casting
    # that UTC DateTime to string first drops the Z suffix and shifts it by the
    # local timezone, so compare the typed value directly.
    $expectedStart = ([DateTime]$state.processStartTimeUtc).ToUniversalTime()
    $actualStart = $process.StartTime.ToUniversalTime()
    $sameStart = [Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -lt 2
    $sameExecutable = [string]::Equals($process.Path, [string]$state.sshExecutable, [StringComparison]::OrdinalIgnoreCase)
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue
    if (-not $cim -or [string]::IsNullOrWhiteSpace([string]$cim.CommandLine)) {
        throw "Cannot verify the command line for PID $pidValue. Run Stop-CTFGateway.ps1 from an elevated PowerShell window; the process was left untouched."
    }
    $commandLine = [string]$cim.CommandLine
    $hasConfig = $commandLine.Contains([string]$state.sshConfig)
    $hasForwards = $true
    foreach ($forward in $state.forwards) { if (-not $commandLine.Contains([string]$forward)) { $hasForwards = $false } }

    if (-not ($sameStart -and $sameExecutable -and $hasConfig -and $hasForwards)) {
        throw "PID $pidValue no longer matches the SSH process recorded by this gateway script. It was left untouched."
    }

    Set-Content -LiteralPath $stopPath -Value 'stop' -Encoding ASCII
    Write-GatewayLog "Stopping only script-owned ssh.exe PID $pidValue."
    Stop-Process -Id $pidValue -Force
    Wait-Process -Id $pidValue -Timeout 8 -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Write-GatewayLog 'Managed SSH process stopped. The Start script will see the stop request and will not restart it.'
} catch {
    Write-GatewayLog $_.Exception.Message 'ERROR'
    exit 1
}
