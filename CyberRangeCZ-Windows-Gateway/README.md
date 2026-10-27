# CyberRangeCZ Windows SSH Gateway

This folder exposes selected HTTP/TCP services from one CyberRangeCZ sandbox through the existing Windows PC at `10.13.128.29`. The Windows machine opens SSH local forwards through the CyberRangeCZ user SSH config and the `man` alias. Contestants browse to `http://10.13.128.29:<gatewayPort>`; they do not need SSH, a VPN, or a bridged network. These forwards do not make sandbox IPs directly routable from contestant PCs.

The sandbox has four Kali VMs with identity pages on port 80. The provisioning playbook now installs a separate ServiceDesk instance on port 8080 on each attacker VM; each instance uses its own VM-local SQLite database. `config.json` maps those team services to gateway ports 8011–8014 and maps the shared server ServiceDesk (`10.80.0.20:80`) to 8080. Confirm the sandbox has been reprovisioned with the team services before restarting the gateway tunnel. The supplied SSH config identifies `10.32.8.175` as an SSH jump host; it is not used as a web service target.

## Map the example diagram to this deployment

The addresses in the diagram are examples. The repository records the pool 96 allocation below; confirm that it is still active before starting the gateway:

| Diagram role | Actual address/configuration | Status |
| --- | --- | --- |
| Windows Gateway | `10.13.128.29` | Present on this Windows PC |
| Contestant PCs | Not provided | Obtain the exact subnet or IP allowlist from the LAN administrator |
| CyberRangeCZ SSH jump host | `10.32.8.175:22` | SSH host from the supplied user config; verify its fingerprint on first use |
| MAN alias | `user@192.168.64.120` via `10.32.8.175` | Resolved from the supplied SSH config |
| IDOR ServiceDesk | `10.80.0.20:80` | Server VM and service port in `topology.yml` and `README.md` |
| Attacker VM identity pages | `10.80.0.11:80`–`10.80.0.14:80` | Static health/identity pages |
| Per-team ServiceDesk | `10.80.0.11`–`10.80.0.14:8080` | One independent database per attacker VM; gateway ports 8011–8014 after reprovisioning |
| Sandbox router | `10.80.0.1` | Routing only; not a CTF web service |
| SQLi VM | Not found in this sandbox topology/config | Do not add the example `10.32.8.176` without a deployed VM and service confirmation |

The jump host is an SSH hop, not a web server. The configured forwards map `10.13.128.29:8080` to `10.80.0.20:80` and ports 8011–8014 to `10.80.0.11`–`10.80.0.14:8080`. The four team targets become available after the sandbox is reprovisioned. No SQLi VM is present in this sandbox topology.

## Environment checked

- This Windows machine has Wi-Fi IPv4 `10.13.128.29` with mask `255.255.224.0` (`/19`); that confirms the gateway address, **not** the contestant scope.
- Windows OpenSSH Client is installed at `C:\Windows\System32\OpenSSH\ssh.exe` (OpenSSH for Windows 9.5p1).
- The SSH config and key recorded for pool 96 are expected in `%USERPROFILE%\.ssh`. They were not present on this Windows PC when the gateway IP was updated. Download the access ZIP for the active allocation and update `sshConfig` in `config.json` before starting the tunnel. The private-key ACL must grant read access only to the current Windows account.
- The supplied config disables host-key checking and sends known hosts to `/dev/null`. The scripts preserve that original file but connect through a generated wrapper that sets `StrictHostKeyChecking ask` and a dedicated `runtime\known_hosts` file for every hop. Check the jump host and MAN fingerprints with the platform administrator and accept them into the dedicated known-hosts store before the first start (the MAN host key can change with every new allocation).
- The requested client scope is all IPv4 sources (`0.0.0.0/0`) that can route to the private gateway address. This includes the whole reachable LAN and any other routed private networks; narrow it if contestants should be limited to a smaller scope.

## Configure

1. Put the current user SSH config and key at `%USERPROFILE%\.ssh\pool-id-96-sandbox-id-8aec30a6-4bca-4e2f-9f07-536622b1c6f6-user-config` and the matching `...-user-key` (this is the path in `config.json`). If the sandbox is reallocated, download the **user SSH access ZIP for that allocation** and update `sshConfig` and the key reference in its SSH config. Keep the private key on this gateway; do not put it in this project folder or share it with contestants.
2. `sshHost` is set to `man`; `Test-CTFGateway.ps1` resolves it from the actual config. The diagram's `10.32.8.175` is configured as an SSH jump host, not as the IDOR HTTP target.
3. Confirm service IPs and ports against the allocated sandbox/topology. The repo's current setup keeps attacker identity pages on `10.80.0.11`–`10.80.0.14:80`, adds team ServiceDesk instances on `10.80.0.11`–`10.80.0.14:8080`, and keeps shared ServiceDesk at `10.80.0.20:80`.
4. Ask the LAN administrator for the exact client subnet(s) or source IP allowlist. Enter only the confirmed CIDRs in `allowedClientSubnets`. The observed `/19` adapter mask describes the gateway's LAN; it is not automatically used as an allowlist.
5. Run the preflight in PowerShell to validate the path and create the safe SSH wrapper:

   ```powershell
   .\Test-CTFGateway.ps1
   ```

   Verify MAN (`192.168.64.120`) and its proxy jump (`10.32.8.175`) fingerprints with the platform administrator, then seed the dedicated known-hosts file interactively if this is a new sandbox allocation. The supplied account has no interactive shell, so use a loopback-only forward for the prompt:

   ```powershell
   ssh -F .\runtime\ssh-safe.conf -N -L 127.0.0.1:18080:10.80.0.20:80 man
   ```

   Compare each prompted fingerprint with the platform administrator before typing `yes`; press Ctrl+C after the local forward is established. Then check the configured service forward:

   ```powershell
   .\Test-CTFGateway.ps1 -CheckSsh
   ```

   `-CheckSsh` briefly creates loopback-only forwards to the configured services and stops them after checking. It does not expose a LAN listener or change the firewall. The MAN account does not provide an interactive shell, so the test uses forwarding rather than sending a remote `exit` command.

## Firewall rules

No `CyberRangeCZ-CTFGateway-8011`–`8014` Windows Firewall rules were found on this PC when the gateway IP was updated. Local checks on the gateway do not require inbound LAN rules. For contestant access, obtain the contestant source CIDR and create rules for ports 8011–8014. Port 8080 is the shared ServiceDesk forward; give it a separate rule only if contestants need it. Example:

```powershell
8011, 8012, 8013, 8014 | ForEach-Object {
  New-NetFirewallRule `
    -Name "CyberRangeCZ-CTFGateway-$_" `
    -DisplayName "CyberRangeCZ CTF Gateway TCP $_" `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalAddress 10.13.128.29 -LocalPort $_ `
    -RemoteAddress '<CONFIRMED_CONTESTANT_CIDR>' -Profile Any
}
```

The intended rule scope is:

| Protocol | Local address | Local port | Remote address scope |
| --- | --- | ---: | --- |
| TCP | `10.13.128.29` | `8011`–`8014` | Confirmed contestant CIDR only |

`Start-CTFGateway.ps1` does not create firewall rules, even when the allowlist is populated.

## Start and stop

After provisioning the sandbox with the team services, restart the monitored tunnel so it loads the current `config.json` mappings:

```powershell
.\Start-CTFGateway.ps1
```

This starts the SSH tunnel bound only to `10.13.128.29`, then monitors every configured forward. It restarts a failed SSH/backend connection up to `maxRestartAttempts`, logs each attempt, and stops after the retry limit. Keep the PowerShell window open; Ctrl+C stops its child SSH process. To stop it from another PowerShell window:

```powershell
.\Stop-CTFGateway.ps1
```

The stop script verifies the recorded PID, process start time, executable, SSH config path, and forwarding arguments before stopping anything. It will leave a process untouched if those checks do not match.

Logs go to `logs\`. Process state and the stop signal go to `runtime\`. These folders contain no private key material.

## Test from the gateway and a contestant PC

On the Windows gateway:

```powershell
Get-NetTCPConnection -LocalAddress 10.13.128.29 -LocalPort 8080 -State Listen
curl.exe http://10.13.128.29:8080/
```

From a contestant PC on an approved subnet:

```powershell
Test-NetConnection 10.13.128.29 -Port 8080
```

Then open these URLs in a browser:

- ServiceDesk: `http://10.13.128.29:8080/`
- attacker1 ServiceDesk: `http://10.13.128.29:8011/`
- attacker2 ServiceDesk: `http://10.13.128.29:8012/`
- attacker3 ServiceDesk: `http://10.13.128.29:8013/`
- attacker4 ServiceDesk: `http://10.13.128.29:8014/`

Each team signs in with username `alice` and a unique random password generated during provisioning. The password is written to `~/lab-addresses.txt` on that team's attacker VM, readable only by `user-access`, and is omitted from provisioning output. Reprovisioning generates a new password. The shared ServiceDesk gets a separate random password and remains isolated from attacker VMs by the network policy.

A TCP listener alone does not prove that the sandbox web service is healthy; the HTTP/TCP checks in `Test-CTFGateway.ps1` verify the forwarding path. Add corresponding inbound firewall ports for 8011–8014, limited to the approved contestant scope, before exposing the new forwards. The sandbox IPs themselves remain unreachable directly unless the network is separately routed to the sandbox. The four ports require a sandbox reprovision after the new per-team services are added; the current running allocation still has identity pages on port 80 until then.

## Add another service

Add another entry under `services` in `config.json`, for example:

```json
{
  "name": "CTF SSH",
  "protocol": "tcp",
  "gatewayPort": 2222,
  "sandboxIp": "<confirmed VM IP>",
  "sandboxPort": 22
}
```

Use a unique gateway port and a VM address/port verified from the deployed sandbox. Add the new gateway port to the firewall proposal and obtain approval before exposing it. All forwards bind to the configured `gatewayIp` only.

## Troubleshooting

- **IP not assigned:** the script exits if `10.13.128.29` is not assigned to this PC. Check the Wi-Fi/LAN adapter and DHCP reservation.
- **SSH config missing or placeholder remains:** extract the CyberRangeCZ user SSH ZIP and update `sshConfig`.
- **`man` alias not found:** inspect the downloaded config's `Host` sections and set `sshHost` to the real alias. The scripts use `ssh -G`; they do not guess aliases.
- **SSH authentication fails:** check the matching `IdentityFile` path, key permissions, sandbox assignment, and platform access. The scripts never display private-key contents.
- **Host key prompt/check fails:** verify the host fingerprint through CyberRangeCZ administration; do not disable host-key checking.
- **Forward port already in use:** choose a free `gatewayPort` or identify the existing listener before changing anything.
- **Tunnel listens but web page fails:** confirm the deployed VM IP/port, that its service is running, and that MAN can reach that VM address. Read the matching `logs\ssh-*.stderr.log` and gateway log.
- **Contestant PC cannot connect:** confirm the already-approved Windows Firewall scope, contestant subnet, Wi-Fi client isolation, and the exact inbound TCP port.
- **Tunnel repeatedly reconnects:** check MAN reachability, CyberRange SSH credentials/config, target service availability, and logs. Retries stop at the configured limit.

## Safety boundaries

- The gateway config maps 8011–8014 to each attacker's ServiceDesk on port 8080. Confirm that the active sandbox has been provisioned with those four services before starting the tunnel.
- LAN reachability depends on the gateway tunnel, a route to `10.13.128.29`, and Windows Firewall rules for the confirmed contestant source CIDR.
- No router port forwarding or network bridging is configured.
- The SSH private key stays in the extracted SSH directory and is not copied into this folder or logged.
- Only `Start-CTFGateway.ps1`-started SSH processes recorded in `runtime\gateway-state.json` are managed by the stop script.
