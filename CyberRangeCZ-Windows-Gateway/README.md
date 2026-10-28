# Windows SSH gateway generated after allocation

Run `Configure-Deployment.ps1` from the project root with the current allocation's user SSH config. The script creates this folder's `config.json` from `deployment.json`; the upload ZIP contains only `config.example.json`. Private keys remain in your `.ssh` folder.

Local mode binds `127.0.0.1`; LAN mode uses the selected/auto-detected interface address. The default manifest creates these mappings for four teams:

- Service01: local/gateway ports 8011–8014 → each team VM port 8080.
- Service02: ports 8021–8024 → each team VM port 8081.
- Shared organizer service: port 8080 → server:80; not included in contestant firewall rules.

Change team counts/IPs and ports in the manifest, regenerate the cloud definition, deploy it, then configure a fresh allocation/event. No allocated pool ID, sandbox UUID or personal path is shipped in the example config.

## Preflight and host trust

In this directory:

```powershell
.\Test-CTFGateway.ps1
```

This creates `runtime/ssh-safe.conf` with host-key checking enabled and a dedicated known-hosts store. Verify new landing/man fingerprints with the platform administrator before accepting them. To seed the prompts with a temporary loopback-only tunnel, use the configured shared destination:

```powershell
$cfg = Get-Content .\config.json -Raw -Encoding UTF8 | ConvertFrom-Json
$service = $cfg.services | Where-Object name -eq 'Shared organizer ServiceDesk'
$forward = '127.0.0.1:18080:{0}:{1}' -f $service.sandboxIp,$service.sandboxPort
ssh -F .\runtime\ssh-safe.conf -N -L $forward $cfg.sshHost
```

After authenticated forwarding is established, Ctrl+C ends the temporary tunnel. Then:

```powershell
.\Test-CTFGateway.ps1 -CheckSsh
```

The command checks temporary loopback forwards for all configured backends. It does not expose LAN listeners or change firewall rules. No listener before gateway startup is normal; wrong key/config/allocation, a missing service or unknown host key must be resolved before starting the event.

## Start and stop

```powershell
.\Start-CTFGateway.ps1
# from another terminal:
.\Stop-CTFGateway.ps1
```

The start script monitors its SSH process and retries failures according to config. Keep its terminal open. The stop script verifies the recorded process identity before stopping that process. Logs are in `logs/`; state and host-key files are in `runtime/`.

Normally run `gameserver/Start-Stack.ps1` from the project root to manage gateway, backend and checker together. Already-running gateway processes are reused and left under their original owner.

`allowedClientSubnets` is configuration metadata; the SSH scripts do not apply source filtering. For LAN mode run the root `Apply-GatewayFirewall.ps1` as administrator after supplying confirmed CIDRs to Configure-Deployment. For local mode no inbound firewall rule is required.

If your gateway address changes, configure the transport again before creating the next event. Do not silently retarget a running scored event. The local checker binding is independent of the Wi-Fi address when using local mode.
