[CmdletBinding()]
param(
    [string]$RuntimeDir,
    [string]$BindAddress,
    [ValidateRange(0,65535)][int]$Port = 0,
    [switch]$StartEvent
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$selectionPath=Join-Path $PSScriptRoot 'local.json'
$selection=if(Test-Path -LiteralPath $selectionPath){Get-Content -LiteralPath $selectionPath -Raw | ConvertFrom-Json}else{$null}
if(-not $RuntimeDir){$RuntimeDir=if($selection){Join-Path $project $selection.active_runtime}else{Join-Path $PSScriptRoot 'runtime-sla'}}
if(-not $BindAddress){$BindAddress=if($selection){$selection.backend_bind}else{'127.0.0.1'}}
if($Port -eq 0){$Port=if($selection){[int]$selection.backend_port}else{9000}}
if(-not(Test-Path -LiteralPath $RuntimeDir)){throw 'Configure the allocation first using Configure-Deployment.ps1.'}
$runtime = (Resolve-Path -LiteralPath $RuntimeDir).Path
$python = (Get-Command python.exe -ErrorAction Stop).Source
$config = Join-Path $runtime 'config.json'
$workerConfig = Join-Path $runtime 'worker.json'
$operatorConfig = Join-Path $runtime 'operator.json'
$workerData = Get-Content -LiteralPath $workerConfig -Raw | ConvertFrom-Json
$backendUri = [Uri]$workerData.backend_url
if ($backendUri.Port -ne $Port) { throw 'The -Port argument must match backend_url in worker.json.' }
$eventId = (Get-Content -LiteralPath $config -Raw | ConvertFrom-Json).event_id
$logs = Join-Path $runtime 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$backend = $null
$worker = $null
$runId = Get-Date -Format 'yyyyMMdd-HHmmss-fff'

function Launch-Module {
    param([string]$Module, [string[]]$ExtraArgs, [string]$Name)
    $tokens = @('-u','-m',$Module) + $ExtraArgs
    $line = ($tokens | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
    Start-Process -FilePath $python -ArgumentList $line -WorkingDirectory $project `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logs "$Name-$runId.stdout.log") `
        -RedirectStandardError (Join-Path $logs "$Name-$runId.stderr.log")
}

try {
    # Fail before launching a second backend on an occupied port.
    $existing = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($existing.Count) { throw "Port $Port is occupied; stop the existing competition first." }
    $backend = Launch-Module -Module 'gameserver.server' -Name 'backend' `
        -ExtraArgs @('--config',$config,'--host',$BindAddress,'--port',"$Port")
    $deadline = (Get-Date).AddSeconds(20)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($backend.HasExited) { throw "Backend exited; read $logs." }
        try {
            $status = Invoke-RestMethod -Uri ($workerData.backend_url + '/api/scoreboard') -TimeoutSec 2
            if ($status.event_id -ne $eventId) { throw 'Backend event identity does not match the selected runtime.' }
            $ready = $true
            break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'Backend did not become ready; verify backend_url, bind address and port.' }
    if ($status.phase -eq 'finished') { throw 'This event has finished. Create a new runtime directory for a new event.' }
    if ($status.phase -eq 'ready') {
        Push-Location $project
        try {
            & $python -m gameserver.worker --config $workerConfig --preflight
            if ($LASTEXITCODE -ne 0) { throw 'Service preflight failed. Check service endpoints and start the gateway first.' }
        } finally { Pop-Location }
    }
    $worker = Launch-Module -Module 'gameserver.worker' -Name 'worker' -ExtraArgs @('--config',$workerConfig)
    if ($StartEvent) {
        Push-Location $project
        try {
            & $python -m gameserver.control start --config $operatorConfig
            if ($LASTEXITCODE -ne 0) { throw 'Could not start event.' }
        } finally { Pop-Location }
    }
    Write-Host "Competition processes running. Scoreboard: $($workerData.backend_url)/"
    Write-Host 'Keep this window open. Ctrl+C stops backend and worker; event time continues.'
    Write-Host "Logs: $logs"
    while ($true) {
        Start-Sleep -Seconds 2
        if ($backend.HasExited) { throw 'Backend stopped unexpectedly; read logs.' }
        if ($worker.HasExited) {
            if ($worker.ExitCode -eq 0) {
                Write-Host 'Worker completed. Scoreboard remains open; Ctrl+C to close.'
                $worker = $null
                while (-not $backend.HasExited) { Start-Sleep -Seconds 2 }
                throw 'Backend stopped.'
            }
            throw 'Worker stopped unexpectedly; read logs.'
        }
    }
} finally {
    foreach ($process in @($worker,$backend)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
}
