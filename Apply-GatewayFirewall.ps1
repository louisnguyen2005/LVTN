[CmdletBinding()]
param([switch]$Remove)
$ErrorActionPreference='Stop'
$configPath=Join-Path $PSScriptRoot 'CyberRangeCZ-Windows-Gateway\config.json'
$localPath=Join-Path $PSScriptRoot 'gameserver\local.json'
if(-not(Test-Path $configPath) -or -not(Test-Path $localPath)){throw 'Run Configure-Deployment.ps1 first.'}
$cfg=Get-Content $configPath -Raw | ConvertFrom-Json
$selected=Get-Content $localPath -Raw | ConvertFrom-Json
if($cfg.gatewayIp -eq '127.0.0.1'){Write-Host 'Local mode needs no inbound LAN firewall rule.';return}
$scopes=@($cfg.allowedClientSubnets)
if($scopes.Count -eq 0 -or $scopes -contains '0.0.0.0/0'){throw 'Configure the confirmed client CIDRs before creating a LAN rule.'}
$ruleName='LVTN-SLA-'+(Split-Path $selected.active_runtime -Leaf)
if($Remove){Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue;return}
$ports=@($cfg.services | Where-Object {$_.name -ne 'Shared organizer ServiceDesk'} | ForEach-Object {[int]$_.gatewayPort})
$ports+=[int]$selected.backend_port
if(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $ruleName}
New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow `
    -Protocol TCP -LocalAddress $cfg.gatewayIp -LocalPort $ports -RemoteAddress $scopes -Profile Any | Out-Null
Write-Host "Created $ruleName for service ports and dashboard; source CIDRs: $($scopes -join ', ')."
