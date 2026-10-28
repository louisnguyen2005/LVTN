# One sandbox: four team VMs and one server

## Attack/defense game server

`py -3 -m gameserver.demo --fast` runs a full offline attack/defense game: per-tick signed flags placed and retrieved by a traced CHECK → PUT → GET checker (statuses UP / CORRUPT / MUMBLE / DOWN), flag submission over HTTP (`/api/submit`) and TCP (line protocol), SQLite tables for flags, captures, submissions, checker actions and per-flag integrity, host → gateway → VM link probes that verify VM identity (`py -3 -m gameserver.pool`), and a game-style scoreboard at `http://127.0.0.1:19000/`. The web flag-submission page `/submit` is still a placeholder. Details in [the Vietnamese guide](gameserver/README.vi.md).

## Automatic service SLA per tick

The `gameserver/` backend now defaults to a one-hour SLA event: two 30-minute competition rounds, one service per round, and a 2-minute tick (15 ticks per round, 30 total). Each service records a configured vulnerability count of five. The checker measures the active service once per team/tick; UP earns 1 SLA by default, DOWN earns 0. Results are stored in SQLite and displayed with round, tick, active service and per-tick history. Vulnerability count is metadata; health checks do not exploit five vulnerabilities.

Start an offline demo with `py -3 -m gameserver.demo`, then open `http://127.0.0.1:19000/`. Add `--fast` to simulate all 30 ticks in 60 seconds; demo team02 goes DOWN at tick 3 and recovers at tick 4. Both services are local simulations. For real deployment, fill both services in `gameserver/services.example.json`, then follow [the Vietnamese operations guide](gameserver/README.vi.md). New live events use `gameserver/runtime-sla/`. The existing health endpoint is sufficient for health mode; no flag placement or tickets-v2 deployment is required for these checks.

This is one CyberRangeCZ Sandbox Definition. Create **one pool of size 1** from this repository root. The single sandbox contains four Kali attacker VMs (one per team), one Debian ServiceDesk server VM, and a separate gateway router.

It combines two access models that work together:

1. **Per-team SSH/console login by password.** Each team logs in to its own VM with its own password. SSH keys are disabled for the trainee account, so one team cannot enter another team's VM.
2. **Windows gateway for web access from outside the sandbox.** A Windows PC on the school LAN forwards selected ports through the CyberRangeCZ jump host, so contestants browse to the gateway instead of needing a route into the sandbox. See `CyberRangeCZ-Windows-Gateway/README.md`.

| Node | IP | Services |
| --- | --- | --- |
| attacker1 (team01) | `10.80.0.11` | identity page `:80`, team ServiceDesk `:8080` |
| attacker2 (team02) | `10.80.0.12` | identity page `:80`, team ServiceDesk `:8080` |
| attacker3 (team03) | `10.80.0.13` | identity page `:80`, team ServiceDesk `:8080` |
| attacker4 (team04) | `10.80.0.14` | identity page `:80`, team ServiceDesk `:8080` |
| server | `10.80.0.20` | shared ServiceDesk on `:80` (isolated from attackers) |
| gateway (sandbox router) | `10.80.0.1` | routing only |
| Windows gateway (outside the sandbox) | `10.13.128.29` | forwards `8011`-`8014` to the team ServiceDesks, `8080` to the shared one |

**Traffic policy:** Each attacker can ping and open HTTP on the other three attackers. The server can ping and open HTTP on all four attackers. New connections from any attacker to `10.80.0.20` are blocked, including ping and HTTP. The server does not forward packets. The shared ServiceDesk remains on the server at `http://127.0.0.1/`; each attacker also runs a separate ServiceDesk instance on port 8080 with its own local SQLite database. Attacker VMs can reach one another, so these are separate datasets but not network-isolated from other teams inside the sandbox. HTTP access among the permitted machines uses port 80 without adding `:80` to the URL.

## Team login (SSH and topology console)

The trainee account is `user-access` on every attacker VM. Its password is different on each VM and SSH key login is turned off for it (`PubkeyAuthentication no`, `AuthenticationMethods password`, `authorized_keys` removed):

| Team / host | IP | Password |
| --- | --- | --- |
| team01 / attacker1 | `10.80.0.11` | `mekodatactf202001` |
| team02 / attacker2 | `10.80.0.12` | `mekodatactf202002` |
| team03 / attacker3 | `10.80.0.13` | `mekodatactf202003` |
| team04 / attacker4 | `10.80.0.14` | `mekodatactf202004` |

The passwords live in `provisioning/group_vars/all.yml` (`lab_team_passwords`). Change them there and reprovision. Give each team only its own password; `training-definition.json` deliberately does not contain them.

Reaching a VM from your own computer takes three hops. The first two (landing host and `man`) use the platform's sandbox key from the **user SSH access ZIP** (`Get SSH Config` in the portal). The last hop is the password:

```
your PC --(key)--> landing host --(key)--> man --(password)--> attacker VM
```

Per-team SSH config (values in `<...>` come from the downloaded `...-user-config`; they change with every allocation):

```sshconfig
Host landing
    HostName 10.32.8.175
    User <landing user from user-config>
    IdentityFile ~/.ssh/<pool-id-...-user-key>
    IdentitiesOnly yes

Host man
    HostName <man ip from user-config>
    User user
    IdentityFile ~/.ssh/<pool-id-...-user-key>
    ProxyJump landing
    IdentitiesOnly yes

Host team01
    HostName 10.80.0.11
    User user-access
    PreferredAuthentications password
    PubkeyAuthentication no
    ProxyJump man
```

```bash
ssh -F <path-to-that-config> team01
```

Do not hand the sandbox `user-key` and the complete `user-config` to the teams: that key logs in as the platform account `user` on every VM and bypasses the per-team passwords. Keep them with the organizers.

## Deploy (in this order)

1. Put this directory at the root of a Git repository accessible to CyberRangeCZ. `topology.yml` and `provisioning/` must be at the repository root. Use a **private** repository: `group_vars/all.yml` contains every team's password.
2. Create one Sandbox Definition from that Git URL and revision. Create one pool with **size 1**, then Allocate it. The provisioning playbook configures all five hosts and fails if the required connectivity policy does not work. Editing the repository does not change a running pool; recreate or reprovision the pool to apply changes.
3. Import `training-definition.json`, review and release it, then create one cloud Training Instance and assign the pool. Open a run to see the five hosts in the topology.
4. Download the user SSH access ZIP for the new allocation. Give teams their own password and (if you want them to SSH from their own computers) the `landing`/`man` hops of the config above.
5. On the Windows gateway, copy the new SSH config and key, update `sshConfig` in `CyberRangeCZ-Windows-Gateway/config.json`, and run `Start-CTFGateway.ps1` (details in the gateway README). Do this after every new allocation: the jump host details change.

The image and flavor names in `topology.yml` must exist in your cloud. The platform runner needs Ansible, the `user-access` role, and `ansible.posix` from `provisioning/requirements.yml`. The five host IPs and gateway subnet must not conflict with the platform's management network.

## What provisioning does (playbook order)

1. **All hosts:** generate a unique random ServiceDesk password per VM and record the sandbox identity in `/etc/idor-lab-identity.json`.
2. **Server:** install the nftables ACL that blocks new connections from the attackers, keep IP forwarding off, start the shared ServiceDesk on port 80 and check its health.
3. **Each attacker:**
   - create `user-access` with that VM's password from `lab_team_passwords`;
   - write the sshd drop-in that allows only password login for `user-access` and delete its `authorized_keys`;
   - start the identity page on port 80 and the team ServiceDesk on port 8080 (own database, own random password);
   - write `~/lab-addresses.txt` (mode `0600`) with the lab URLs and the team's ServiceDesk login;
   - check both local health endpoints, including that `:8080/health` reports this VM's identity.
4. **All hosts:** verify attacker peer connectivity and the HTTP identity of every attacker.
5. **Attackers:** verify that ping and HTTP to `10.80.0.20` fail.

Each team's ServiceDesk login is username `alice` and the password in `~/lab-addresses.txt` on its VM. The password is omitted from provisioning output, and reprovisioning generates a new one. The shared ServiceDesk gets its own random password; attacker VMs cannot reach it because of the network policy.

## Verify inside the sandbox

On each attacker, its own ServiceDesk instance is available at `http://127.0.0.1:8080/` and reports a host-specific sandbox identity at `/health`. The four team instances use separate local databases. On attacker1, these must succeed:

```bash
ping -c 1 10.80.0.12
ping -c 1 10.80.0.13
ping -c 1 10.80.0.14
curl --noproxy '*' -fsS http://10.80.0.12/health
curl --noproxy '*' -fsS http://10.80.0.13/health
curl --noproxy '*' -fsS http://10.80.0.14/health
curl --noproxy '*' -fsS http://10.80.0.12:8080/health
```

These must fail from every attacker:

```bash
ping -c 1 -W 2 10.80.0.20
curl --noproxy '*' --connect-timeout 3 http://10.80.0.20/
```

On the server, `curl --noproxy '*' http://127.0.0.1/health` must succeed, and `sudo nft list table inet idor_server_acl` must show the rule blocking new attacker connections. The server can also ping and curl all four attacker addresses.

On an attacker VM, `sudo sshd -T -C user=user-access,host=localhost,addr=127.0.0.1 | grep -Ei 'pubkeyauthentication|authenticationmethods|passwordauthentication'` should show public-key login off and password login on.

The server ACL has its own nftables table and systemd unit; it does not replace other firewall tables. The provisioning playbook tests all permitted and blocked paths before it finishes. A private `10.x.x.x` URL is accessible only from the lab network or an approved tunnel.

## Health checker

`checker/web_health.py` polls the four team ServiceDesk `/health` endpoints and prints UP/DOWN with latency (Python 3, no extra packages):

```bash
# from a machine that can route to 10.80.0.0/24
python3 checker/web_health.py --config checker/web_targets.json
# from a PC on the school LAN, through the Windows gateway (ports 8011-8014)
python3 checker/web_health.py --config checker/web_targets_gateway.json --interval 10
```

`--json` prints machine-readable rounds and `--interval N` repeats every N seconds. The exit code is non-zero if any target is down.

### Diagnostic automatic checker with local JSON results

The external checker runs through the Windows gateway; do not install it on a team VM or the sandbox router. Start the gateway tunnel first, and make sure the current allocation has the four ServiceDesk services on port 8080. The checker reads the sandbox UUID from `CyberRangeCZ-Windows-Gateway/config.json` and requires each response to identify the matching `attacker1`–`attacker4` VM. Update the gateway config after a new allocation.

From this repository root, run one round to inspect the current state:

```powershell
python checker/auto_check.py --rounds 1
```

Run continuously (one round every 10 seconds, stop with Ctrl+C):

```powershell
python checker/auto_check.py --interval 10
```

Each round is printed as JSON and saved to `checker/results/history.jsonl`. `checker/results/latest.json` always holds the most recent complete round. Both files are ignored by Git. `UP` means the check passed, `DOWN` means a connection failure, `MUMBLE` means the service responded incorrectly or identified the wrong sandbox, and `ERROR` means an unexpected checker failure. `all_up` is true only when every team is `UP`.

For a functional check, copy `checker/credentials.example.json` to `checker/credentials.json`, replace the four placeholder values with the ServiceDesk passwords from each team's private `~/lab-addresses.txt`, then run:

```powershell
python checker/auto_check.py --credentials checker/credentials.json --interval 10
```

This diagnostic mode also logs in as `alice`, reads the ticket list and reads Alice's ticket without changing service data. A failed login or invalid ticket response is `MUMBLE`. `checker/credentials.json` is ignored by Git; update it after reprovisioning changes the passwords. Use `gameserver.worker` for the scheduled 2-minute ticks and SQLite-backed SLA results; `auto_check.py` remains a separate diagnostic tool.

On the Windows gateway, you can register the checker to start automatically when your account signs in:

```powershell
.\checker\Register-AutoChecker.ps1
```

The scheduled task uses health mode by default. After filling in the private credentials file, run `.\checker\Register-AutoChecker.ps1 -Functional` to register and start the functional checker instead. The task writes the same result files. To remove it, run `.\checker\Register-AutoChecker.ps1 -Remove`.

## Local source checks

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m unittest discover -s tests -v
```

The tests cover the ServiceDesk application, the topology and training definition, the password-only SSH policy, and that the gateway ports, checker targets and provisioned services agree with each other.
