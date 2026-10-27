[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch]$CheckSsh
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Gateway.Common.ps1')
$script:GatewayLogPath = Join-Path $PSScriptRoot 'logs' ('gateway-test-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

try {
    $config = Get-GatewayConfig -Path $ConfigPath
    $preflight = Assert-GatewayReady -Config $config
    $testFailed = $false
    Write-GatewayLog "Gateway IP $($config.gatewayIp) is assigned to this Windows machine."
    Write-GatewayLog "OpenSSH Client: $($preflight.SshExe)"
    Write-GatewayLog "SSH alias '$($config.sshHost)' resolves to $($preflight.SshDetails.user)@$($preflight.SshDetails.hostname)."
    Write-GatewayLog "Resolved ProxyJump: $($preflight.SshDetails.proxyjump)"
    foreach ($identityFile in @($preflight.SshDetails.identityfile)) {
        $exists = Test-Path -LiteralPath $identityFile -PathType Leaf
        Write-GatewayLog "SSH IdentityFile '$identityFile' exists=$exists (path only; key contents are never read or logged)."
    }

    foreach ($service in $config.services) {
        $listener = @(Get-NetTCPConnection -State Listen -LocalAddress $config.gatewayIp -LocalPort ([int]$service.gatewayPort) -ErrorAction SilentlyContinue)
        if ($listener.Count -eq 0) {
            Write-GatewayLog "No listener for $($service.name) at $($config.gatewayIp):$($service.gatewayPort)." 'WARN'
        } else {
            Write-GatewayLog "Listener present for $($service.name) at $($config.gatewayIp):$($service.gatewayPort), PID $($listener[0].OwningProcess)."
            if (Test-ForwardBackend -Address $config.gatewayIp -Port ([int]$service.gatewayPort)) {
                Write-GatewayLog "TCP through-forward check succeeded for $($service.name)."
            } else {
                Write-GatewayLog "TCP through-forward check failed for $($service.name)." 'ERROR'
                $testFailed = $true
            }
        }

        if ($service.protocol -in @('http', 'https') -and $listener.Count -gt 0) {
            $scheme = [string]$service.protocol
            $url = '{0}://{1}:{2}/' -f $scheme, $config.gatewayIp, $service.gatewayPort
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8
                Write-GatewayLog "HTTP check $url returned status $([int]$response.StatusCode)."
            } catch {
                Write-GatewayLog "HTTP check $url failed: $($_.Exception.Message)" 'ERROR'
                $testFailed = $true
            }
        }
    }

    if ($CheckSsh) {
        Write-GatewayLog 'Testing authenticated SSH port forwarding with temporary loopback-only listeners.'
        $verifiedForwards = Test-SshServiceForwards -SshExe $preflight.SshExe `
            -SshConfig $preflight.SshConfig -HostAlias $config.sshHost -Config $config
        foreach ($forward in $verifiedForwards) {
            Write-GatewayLog "SSH forwarding succeeded for $($forward.Service.name) through 127.0.0.1:$($forward.Port)."
        }
        Write-GatewayLog 'Temporary loopback SSH process stopped after preflight.'
    }
    if ($testFailed) { exit 2 }
} catch {
    Write-GatewayLog $_.Exception.Message 'ERROR'
    exit 1
}
