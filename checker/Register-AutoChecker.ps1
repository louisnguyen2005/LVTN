[CmdletBinding()]
param(
    [ValidateRange(1, 3600)][int]$Interval = 10,
    [switch]$Functional,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$taskName = 'LVTN Auto Checker'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($Remove) {
    if ($existing) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    Write-Host "Removed scheduled task '$taskName'."
    return
}

$python = (Get-Command python.exe -ErrorAction Stop).Source
$script = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'auto_check.py')).Path
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$arguments = '"{0}" --interval {1}' -f $script, $Interval
if ($Functional) {
    $credentials = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'credentials.json') -ErrorAction Stop).Path
    $arguments += ' --credentials "{0}"' -f $credentials
}
if ($existing) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
$action = New-ScheduledTaskAction -Execute $python `
    -Argument $arguments -WorkingDirectory $project
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
$principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description 'Checks team ServiceDesk services every few seconds' -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Started '$taskName'. Results: $(Join-Path $PSScriptRoot 'results\latest.json')"
