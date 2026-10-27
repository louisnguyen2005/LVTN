[CmdletBinding()]
param([string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'))

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Gateway.Common.ps1')

$logsDir = Join-Path $PSScriptRoot 'logs'
$runtimeDir = Join-Path $PSScriptRoot 'runtime'
$statePath = Join-Path $runtimeDir 'gateway-state.json'
$stopPath = Join-Path $runtimeDir 'stop.request'
New-Item -ItemType Directory -Force -Path $logsDir, $runtimeDir | Out-Null
$script:GatewayLogPath = Join-Path $logsDir ('gateway-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Save-GatewayState {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$SshExe,
          [Parameter(Mandatory)][string[]]$ForwardSpecs, [Parameter(Mandatory)][string]$SshConfig)
    $state = [ordered]@{
        processId = $Process.Id
        processStartTimeUtc = $Process.StartTime.ToUniversalTime().ToString('o')
        sshExecutable = $SshExe
        sshConfig = $SshConfig
        sshHost = [string]$config.sshHost
        forwards = @($ForwardSpecs)
        log = $script:GatewayLogPath
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Stop-OwnedSshProcess {
    param($Process)
    if ($Process -and -not $Process.HasExited) {
        Write-GatewayLog "Stopping managed ssh.exe process $($Process.Id)."
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Start-TunnelProcess {
    param([Parameter(Mandatory)][string]$SshExe, [Parameter(Mandatory)][string]$SshConfig,
          [Parameter(Mandatory)][string[]]$ForwardSpecs, [Parameter(Mandatory)][string]$HostAlias)

    $args = @('-F', $SshConfig, '-N', '-g', '-o', 'BatchMode=yes',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3')
    foreach ($forward in $ForwardSpecs) { $args += @('-L', $forward) }
    $args += $HostAlias

    $runId = [guid]::NewGuid().ToString('N')
    $stderrPath = Join-Path $logsDir ("ssh-$runId.stderr.log")
    $stdoutPath = Join-Path $logsDir ("ssh-$runId.stdout.log")
    $argumentLine = ($args | ForEach-Object { '"' + ([string]$_ -replace '"', '\"') + '"' }) -join ' '
    Write-GatewayLog "Launching OpenSSH tunnel for alias '$HostAlias' with $($ForwardSpecs.Count) forward(s)."
    $process = Start-Process -FilePath $SshExe -ArgumentList $argumentLine -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    try {
        Save-GatewayState -Process $process -SshExe $SshExe -ForwardSpecs $ForwardSpecs -SshConfig $SshConfig

        $deadline = (Get-Date).AddSeconds([int]$config.startupTimeoutSeconds)
        do {
            if ($process.HasExited) {
                $tail = if (Test-Path -LiteralPath $stderrPath) { (Get-Content -LiteralPath $stderrPath -Tail 20 -ErrorAction SilentlyContinue) -join ' | ' } else { '' }
                throw "ssh.exe exited with code $($process.ExitCode). See $stderrPath. $tail"
            }
            $allListening = $true
            foreach ($service in $config.services) {
                $listen = @(Get-NetTCPConnection -State Listen -LocalAddress $config.gatewayIp -LocalPort ([int]$service.gatewayPort) -ErrorAction SilentlyContinue)
                if ($listen.Count -eq 0) { $allListening = $false; break }
            }
            if ($allListening) { break }
            Start-Sleep -Seconds 1
        } while ((Get-Date) -lt $deadline)

        if (-not $allListening) { throw "Forward listener did not appear before timeout. See $stderrPath." }
        foreach ($service in $config.services) {
            if (-not (Test-ForwardBackend -Address $config.gatewayIp -Port ([int]$service.gatewayPort))) {
                throw "Forwarded destination for '$($service.name)' did not accept TCP on gateway port $($service.gatewayPort). See $stderrPath."
            }
        }
        Write-GatewayLog "Tunnel process $($process.Id) is listening and all configured backends accepted TCP."
        return $process
    } catch {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        throw
    }
}

$activeProcess = $null
$restartCount = 0
$exitReason = 'watcher stopped'
try {
    if (Test-Path -LiteralPath $statePath) {
        $oldState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $oldProcess = Get-Process -Id ([int]$oldState.processId) -ErrorAction SilentlyContinue
        if ($oldProcess -and -not $oldProcess.HasExited) {
            throw "A managed gateway process is already recorded as PID $($oldState.processId). Use Stop-CTFGateway.ps1 first."
        }
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $stopPath -Force -ErrorAction SilentlyContinue

    $config = Get-GatewayConfig -Path $ConfigPath
    $preflight = Assert-GatewayReady -Config $config -RequireApprovedClientScope
    $forwardSpecs = Get-ForwardArguments -Config $config
    foreach ($service in $config.services) {
        Test-LocalPortAvailable -Address $config.gatewayIp -Port ([int]$service.gatewayPort)
    }

    Write-GatewayLog "Resolved alias '$($config.sshHost)' => $($preflight.SshDetails.user)@$($preflight.SshDetails.hostname); ProxyJump='$($preflight.SshDetails.proxyjump)'."
    Write-GatewayLog 'Starting SSH port forwards directly; this account may not provide an interactive shell.'
    $activeProcess = Start-TunnelProcess -SshExe $preflight.SshExe -SshConfig $preflight.SshConfig `
        -ForwardSpecs $forwardSpecs -HostAlias $config.sshHost

    Write-GatewayLog 'Monitoring the tunnel. Press Ctrl+C or run Stop-CTFGateway.ps1 to stop.'
    while ($true) {
        Start-Sleep -Seconds ([int]$config.healthCheckIntervalSeconds)
        if (Test-Path -LiteralPath $stopPath) { $exitReason = 'stop requested'; break }

        $failure = $null
        if ($activeProcess.HasExited) { $failure = "SSH process exited with code $($activeProcess.ExitCode)." }
        else {
            foreach ($service in $config.services) {
                if (-not (Test-ForwardBackend -Address $config.gatewayIp -Port ([int]$service.gatewayPort))) {
                    $failure = "Health check failed for '$($service.name)' on $($config.gatewayIp):$($service.gatewayPort)."
                    break
                }
            }
        }
        if (-not $failure) { continue }

        Write-GatewayLog $failure 'WARN'
        Stop-OwnedSshProcess -Process $activeProcess
        if ($restartCount -ge [int]$config.maxRestartAttempts) {
            $exitReason = 'restart limit reached'
            Write-GatewayLog "Restart limit $($config.maxRestartAttempts) reached." 'ERROR'
            break
        }
        $restartCount++
        Write-GatewayLog "Reconnect attempt $restartCount/$($config.maxRestartAttempts) in $($config.restartDelaySeconds)s."
        Start-Sleep -Seconds ([int]$config.restartDelaySeconds)
        if (Test-Path -LiteralPath $stopPath) { $exitReason = 'stop requested'; break }
        try {
            $activeProcess = Start-TunnelProcess -SshExe $preflight.SshExe -SshConfig $preflight.SshConfig `
                -ForwardSpecs $forwardSpecs -HostAlias $config.sshHost
        } catch {
            Write-GatewayLog $_.Exception.Message 'ERROR'
            if ($restartCount -ge [int]$config.maxRestartAttempts) { $exitReason = 'restart limit reached'; break }
        }
    }
} catch {
    $exitReason = 'startup/runtime error'
    if ($script:GatewayLogPath) { Write-GatewayLog $_.Exception.Message 'ERROR' }
    else { Write-Error $_ }
    exit 1
} finally {
    Stop-OwnedSshProcess -Process $activeProcess
    Remove-Item -LiteralPath $statePath, $stopPath -Force -ErrorAction SilentlyContinue
    if ($script:GatewayLogPath) { Write-GatewayLog "Gateway stopped: $exitReason." }
}
