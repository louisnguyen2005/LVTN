[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch]$Json
)

# Read-only status of every forward: host PC listener -> SSH tunnel -> sandbox VM port.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Gateway.Common.ps1')

$config = Get-GatewayConfig -Path $ConfigPath
$statePath = Join-Path (Join-Path $PSScriptRoot 'runtime') 'gateway-state.json'
$tunnelPid = $null
if (Test-Path -LiteralPath $statePath) {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if (Get-Process -Id ([int]$state.processId) -ErrorAction SilentlyContinue) { $tunnelPid = [int]$state.processId }
}

$rows = foreach ($service in $config.services) {
    $port = [int]$service.gatewayPort
    $listening = @(Get-NetTCPConnection -State Listen -LocalAddress $config.gatewayIp -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $reachable = $listening -and (Test-ForwardBackend -Address $config.gatewayIp -Port $port)
    [pscustomobject]@{
        name = [string]$service.name
        gateway = '{0}:{1}' -f $config.gatewayIp, $port
        vm = '{0}:{1}' -f $service.sandboxIp, $service.sandboxPort
        listening = $listening
        status = if ($reachable) { 'UP' } else { 'DOWN' }
        latencyMs = [int]$watch.ElapsedMilliseconds
    }
}

if ($Json) {
    [pscustomobject]@{ tunnelPid = $tunnelPid; checkedAt = (Get-Date).ToUniversalTime().ToString('o'); links = @($rows) } |
        ConvertTo-Json -Depth 4
} else {
    Write-Host ('SSH tunnel: {0}' -f $(if ($tunnelPid) { "running (PID $tunnelPid)" } else { 'not running' }))
    $rows | Format-Table name, gateway, vm, listening, status, latencyMs -AutoSize
}
if (@($rows | Where-Object status -ne 'UP').Count) { exit 1 }
