Set-StrictMode -Version Latest
$script:GatewayLogPath = $null

function Write-GatewayLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [string]$Path = $script:GatewayLogPath
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'), $Level, $Message
    if ($Path) { Add-Content -LiteralPath $Path -Value $line -Encoding UTF8 }
    Write-Host $line
}

function Get-GatewayConfig {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Config JSON not found: $Path"
    }

    try { $cfg = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Could not parse config JSON '$Path': $($_.Exception.Message)" }

    foreach ($field in @('gatewayIp', 'sshConfig', 'sshHost', 'allowedClientSubnets', 'services')) {
        if ($null -eq $cfg.PSObject.Properties[$field]) { throw "Missing required config property: $field" }
    }
    $defaults = @{
        maxRestartAttempts = 5
        restartDelaySeconds = 5
        healthCheckIntervalSeconds = 15
        startupTimeoutSeconds = 15
    }
    foreach ($entry in $defaults.GetEnumerator()) {
        if ($null -eq $cfg.PSObject.Properties[$entry.Key]) {
            $cfg | Add-Member -NotePropertyName $entry.Key -NotePropertyValue $entry.Value
        }
    }

    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$cfg.gatewayIp, [ref]$parsedIp) -or
        $parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "gatewayIp must be a valid IPv4 address: $($cfg.gatewayIp)"
    }

    $serviceNames = @{}
    $gatewayPorts = @{}
    if (@($cfg.services).Count -lt 1) { throw 'services must contain at least one forwarded service.' }
    foreach ($service in $cfg.services) {
        foreach ($field in @('name', 'gatewayPort', 'sandboxIp', 'sandboxPort')) {
            if ($null -eq $service.PSObject.Properties[$field]) { throw "A service is missing required property '$field'." }
        }
        if ($null -eq $service.PSObject.Properties['protocol']) {
            $service | Add-Member -NotePropertyName protocol -NotePropertyValue 'tcp'
        }
        if ([string]::IsNullOrWhiteSpace([string]$service.name)) { throw 'Service name cannot be empty.' }
        if ($serviceNames.ContainsKey([string]$service.name)) { throw "Duplicate service name: $($service.name)" }
        $serviceNames[[string]$service.name] = $true

        foreach ($portField in @('gatewayPort', 'sandboxPort')) {
            $port = 0
            if (-not [int]::TryParse([string]$service.$portField, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                throw "Service '$($service.name)' has an invalid $portField."
            }
        }
        if ($gatewayPorts.ContainsKey([int]$service.gatewayPort)) {
            throw "Multiple services cannot bind gateway port $($service.gatewayPort)."
        }
        $gatewayPorts[[int]$service.gatewayPort] = $true

        $vmIp = $null
        if (-not [System.Net.IPAddress]::TryParse([string]$service.sandboxIp, [ref]$vmIp) -or
            $vmIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Service '$($service.name)' sandboxIp must be a confirmed IPv4 address."
        }
        if ($service.protocol -notin @('http', 'https', 'tcp')) {
            throw "Service '$($service.name)' protocol must be http, https, or tcp."
        }
    }

    foreach ($subnet in @($cfg.allowedClientSubnets)) {
        $address = [string]$subnet
        if ($address -notmatch '^\d{1,3}(\.\d{1,3}){3}(/(\d|[12]\d|3[0-2]))?$') {
            throw "Invalid allowedClientSubnets entry '$subnet'. Use CIDR notation confirmed by the LAN administrator."
        }
        $baseIp = $address.Split('/')[0]
        $parsedSubnetIp = $null
        if (-not [System.Net.IPAddress]::TryParse($baseIp, [ref]$parsedSubnetIp) -or
            $parsedSubnetIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Invalid IPv4 client subnet: $subnet"
        }
    }

    if ($cfg.maxRestartAttempts -lt 0 -or $cfg.restartDelaySeconds -lt 1 -or
        $cfg.healthCheckIntervalSeconds -lt 5 -or $cfg.startupTimeoutSeconds -lt 3) {
        throw 'Restart and health-check settings must be positive (maxRestartAttempts may be zero).'
    }
    return $cfg
}

function Resolve-SshConfigPath {
    param([Parameter(Mandatory)][string]$ConfiguredPath)

    $resolved = [Environment]::ExpandEnvironmentVariables($ConfiguredPath)
    if ($resolved -match '<[^>]+>') { throw "Replace the placeholder in sshConfig before use: $resolved" }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "SSH config file not found: $resolved. Download the user SSH access ZIP from CyberRangeCZ, extract it, then update config.json."
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

function Get-SshExecutable {
    $command = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $command) { throw 'OpenSSH Client (ssh.exe) is not installed or not on PATH. Install the Windows OpenSSH Client capability, then retry.' }
    return $command.Source
}

function Get-SshHostDetails {
    param(
        [Parameter(Mandatory)][string]$SshExe,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$HostAlias
    )

    $output = @(& $SshExe -G -F $ConfigPath $HostAlias 2>$null)
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) {
        throw "SSH alias '$HostAlias' could not be resolved from config '$ConfigPath'. Check the Host entries and SSH config syntax."
    }
    $details = @{}
    foreach ($line in $output) {
        if ($line -match '^([^\s]+)\s+(.+)$') { $details[$matches[1].ToLowerInvariant()] = $matches[2].Trim() }
    }
    if (-not $details.ContainsKey('hostname') -or -not $details.ContainsKey('user')) {
        throw "SSH alias '$HostAlias' is missing HostName or User in the resolved SSH configuration."
    }
    if (-not $details.ContainsKey('proxyjump')) { $details['proxyjump'] = 'none' }
    if (-not $details.ContainsKey('identityfile')) { $details['identityfile'] = @() }
    return $details
}

function New-SafeSshConfig {
    param([Parameter(Mandatory)][string]$OriginalConfigPath)

    $runtimeDir = Join-Path $PSScriptRoot 'runtime'
    New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
    $wrapperPath = Join-Path $runtimeDir 'ssh-safe.conf'
    $knownHostsPath = Join-Path $runtimeDir 'known_hosts'
    $knownHostsForSsh = $knownHostsPath.Replace('\', '/')
    $originalForSsh = $OriginalConfigPath.Replace('\', '/')
    $contents = @(
        'Host *'
        "    StrictHostKeyChecking ask"
        "    UserKnownHostsFile `"$knownHostsForSsh`""
        "Include `"$originalForSsh`""
        ''
    ) -join "`n"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($wrapperPath, $contents, $utf8NoBom)
    return [pscustomobject]@{ ConfigPath = $wrapperPath; KnownHostsPath = $knownHostsPath }
}

function Get-ForwardArguments {
    param([Parameter(Mandatory)]$Config)

    $forwards = @()
    foreach ($service in $Config.services) {
        $forwards += '{0}:{1}:{2}:{3}' -f $Config.gatewayIp, $service.gatewayPort, $service.sandboxIp, $service.sandboxPort
    }
    return ,$forwards
}

function Assert-GatewayReady {
    param(
        [Parameter(Mandatory)]$Config,
        [switch]$RequireApprovedClientScope
    )

    $assigned = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Config.gatewayIp -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' })
    if ($assigned.Count -eq 0) { throw "Gateway IP $($Config.gatewayIp) is not assigned to this Windows machine." }

    if ($RequireApprovedClientScope -and @($Config.allowedClientSubnets).Count -eq 0) {
        throw 'allowedClientSubnets is empty. Confirm the student IP scope with the LAN administrator before exposing the tunnel.'
    }

    $sshConfig = Resolve-SshConfigPath -ConfiguredPath $Config.sshConfig
    $sshExe = Get-SshExecutable
    $details = Get-SshHostDetails -SshExe $sshExe -ConfigPath $sshConfig -HostAlias $Config.sshHost
    $safeConfig = New-SafeSshConfig -OriginalConfigPath $sshConfig
    return [pscustomobject]@{
        SshExe = $sshExe
        OriginalSshConfig = $sshConfig
        SshConfig = $safeConfig.ConfigPath
        KnownHostsPath = $safeConfig.KnownHostsPath
        SshDetails = $details
    }
}

function Test-LocalPortAvailable {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port)

    $existing = @(Get-NetTCPConnection -State Listen -LocalAddress $Address -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) { throw "Port $Port is already listening on $Address (PID $($existing[0].OwningProcess))." }
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($Address), $Port)
        $listener.Start()
    } catch {
        throw "Cannot bind ${Address}:${Port}: $($_.Exception.Message)"
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

function Test-ForwardBackend {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(3000)) { return $false }
        $client.EndConnect($connect)
        return $true
    } catch { return $false }
    finally { $client.Dispose() }
}

function Test-SshServiceForwards {
    param(
        [Parameter(Mandatory)][string]$SshExe,
        [Parameter(Mandatory)][string]$SshConfig,
        [Parameter(Mandatory)][string]$HostAlias,
        [Parameter(Mandatory)]$Config
    )

    $runtimeDir = Join-Path $PSScriptRoot 'runtime'
    New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
    $runId = [guid]::NewGuid().ToString('N')
    $stderrPath = Join-Path $runtimeDir "ssh-preflight-$runId.stderr.log"
    $localForwards = @()
    foreach ($service in $Config.services) {
        $reservation = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        try {
            $reservation.Start()
            $localPort = ([System.Net.IPEndPoint]$reservation.LocalEndpoint).Port
        } finally { $reservation.Stop() }
        $localForwards += [pscustomobject]@{ Port = $localPort; Service = $service }
    }

    $sshArgs = @('-F', $SshConfig, '-N', '-T', '-o', 'BatchMode=yes',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=15',
        '-o', 'ServerAliveInterval=15')
    foreach ($forward in $localForwards) {
        $sshArgs += @('-L', ('127.0.0.1:{0}:{1}:{2}' -f $forward.Port,
            $forward.Service.sandboxIp, $forward.Service.sandboxPort))
    }
    $sshArgs += $HostAlias
    $argumentLine = ($sshArgs | ForEach-Object { '"' + ([string]$_ -replace '"', '\"') + '"' }) -join ' '
    $process = $null
    try {
        $process = Start-Process -FilePath $SshExe -ArgumentList $argumentLine -PassThru -WindowStyle Hidden `
            -RedirectStandardError $stderrPath
        $deadline = (Get-Date).AddSeconds([int]$Config.startupTimeoutSeconds)
        $allReachable = $false
        do {
            if ($process.HasExited) { break }
            $allReachable = $true
            foreach ($forward in $localForwards) {
                if (-not (Test-ForwardBackend -Address '127.0.0.1' -Port $forward.Port)) {
                    $allReachable = $false
                    break
                }
            }
            if ($allReachable) { break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)

        if (-not $allReachable) {
            $tail = if (Test-Path -LiteralPath $stderrPath) {
                (Get-Content -LiteralPath $stderrPath -Tail 20 -ErrorAction SilentlyContinue) -join ' | '
            } else { '' }
            throw "SSH loopback forwarding preflight failed. ExitCode=$($process.ExitCode). $tail"
        }
        return $localForwards
    } finally {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            try { $process.WaitForExit(5000) | Out-Null } catch {}
        }
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}
