[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SshConfig,
    [ValidateSet('local','lan')][string]$Access='local',
    [string]$GatewayIp='auto',
    [string[]]$ClientCidr=@(),
    [string]$EventId,
    [ValidateRange(1024,65535)][int]$BackendPort=9000,
    [switch]$DryRun
)
$ErrorActionPreference='Stop'
$python=(Get-Command python.exe -ErrorAction Stop).Source
$arguments=@('-m','gameserver.configure','--ssh-config',$SshConfig,'--access',$Access,
    '--gateway-ip',$GatewayIp,'--backend-port',"$BackendPort")
if($EventId){$arguments+=@('--event-id',$EventId)}
foreach($cidr in $ClientCidr){$arguments+=@('--client-cidr',$cidr)}
if($DryRun){$arguments+='--dry-run'}
Push-Location $PSScriptRoot
try { & $python @arguments; if($LASTEXITCODE -ne 0){throw 'Deployment configuration failed; see the error above.'} }
finally {Pop-Location}
