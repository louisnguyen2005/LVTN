[CmdletBinding()]
param(
    [string]$BindAddress='127.0.0.1',
    [string]$RuntimeDir=(Join-Path $PSScriptRoot 'runtime-sla')
)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$gatewayDir=Join-Path $root 'CyberRangeCZ-Windows-Gateway'
$config=Get-Content -LiteralPath (Join-Path $gatewayDir 'config.json') -Raw | ConvertFrom-Json
$assigned=Get-NetIPAddress -AddressFamily IPv4 -IPAddress $config.gatewayIp -ErrorAction SilentlyContinue
if (-not $assigned) { throw "Gateway IP $($config.gatewayIp) is not assigned. Reconnect to the correct network or update configuration first." }
$watcher=$null
try {
    $listeners=@($config.services | ForEach-Object {
        Get-NetTCPConnection -LocalAddress $config.gatewayIp -LocalPort $_.gatewayPort -State Listen -ErrorAction SilentlyContinue
    })
    if ($listeners.Count -eq 0) {
        $powershell=(Get-Command powershell.exe -ErrorAction Stop).Source
        $script=Join-Path $gatewayDir 'Start-CTFGateway.ps1'
        $watcher=Start-Process -FilePath $powershell -ArgumentList ('-NoProfile -WindowStyle Hidden -File "{0}"' -f $script) `
            -WorkingDirectory $root -WindowStyle Hidden -PassThru
        $deadline=(Get-Date).AddSeconds(30)
        do {
            if ($watcher.HasExited) { throw "Gateway stopped. Read $gatewayDir\logs." }
            $listeners=@($config.services | ForEach-Object {
                Get-NetTCPConnection -LocalAddress $config.gatewayIp -LocalPort $_.gatewayPort -State Listen -ErrorAction SilentlyContinue
            })
            if ($listeners.Count -eq @($config.services).Count) { break }
            Start-Sleep -Seconds 1
        } while ((Get-Date) -lt $deadline)
    }
    if ($listeners.Count -ne @($config.services).Count) { throw 'Only some gateway ports are listening. Run gateway preflight and fix the mapping first.' }
    & (Join-Path $PSScriptRoot 'Start-Competition.ps1') -BindAddress $BindAddress -RuntimeDir $RuntimeDir -StartEvent
} finally {
    # Leave a gateway that was already running under another operator untouched.
    if ($watcher) {
        & (Join-Path $gatewayDir 'Stop-CTFGateway.ps1')
        $watcher.WaitForExit(10000) | Out-Null
        if (-not $watcher.HasExited) { Stop-Process -Id $watcher.Id -Force -ErrorAction SilentlyContinue }
    }
}
