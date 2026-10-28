[CmdletBinding()]
param([switch]$Remove)
$ErrorActionPreference='Stop'
$name='LVTN Attack Defense Controller'
if ($Remove) {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
    return
}
$account=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell=(Get-Command powershell.exe -ErrorAction Stop).Source
$script=Join-Path $PSScriptRoot 'Start-Stack.ps1'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$action=New-ScheduledTaskAction -Execute $powershell `
    -Argument ('-NoProfile -WindowStyle Hidden -File "{0}"' -f $script) -WorkingDirectory $root
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $account
$principal=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'Starts the SSH gateway, local CTF backend and round checker after sign-in on the correct network.' -Force | Out-Null
Write-Host "Registered '$name' for next sign-in. First verify SSH fingerprints, network and preflight manually."
