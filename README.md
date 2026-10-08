# Horse Plinko Blue-Team Toolkit

This repo is for preparing for Horse Plinko and similar CCDC-style competitions. The focus is on getting useful information from a box, changing selected local credentials, setting up a firewall around required services, and checking for persistence. It is organized for a four-person team working across Linux and Windows machines.

The goal is to make the first few steps repeatable while keeping scored services running. Read the scripts, work on one box at a time, and verify each change. **The included firewall configs are web-server examples. Update them for the actual host and competition requirements.**

## What's included

| Task | Linux | Windows |
|---|---|---|
| Read-only reconnaissance | `linux/recon.py` | `windows/Recon.ps1` |
| Rotate one selected local account | `linux/credentials.py` | `windows/Credentials.ps1` |
| Preview, apply, back up, roll back firewall changes | `linux/firewall.py` | `windows/Firewall.ps1` |
| Read-only persistence evidence | `linux/persistence.py` | `windows/Persistence.ps1` |

The Linux scripts use Python, and the Windows scripts use PowerShell. Each runs locally on the machine being defended. Recon and persistence audits are read-only; credential and firewall changes require explicit action. Normal OS logs can still record the read-only commands.

The scripts do not install packages, disable accounts, disable SELinux, wipe existing firewall rules, or save passwords to plaintext files.

## Requirements

- **Linux:** Python 3.8+ with no third-party Python packages. Recon uses tools such as `ip`, `ss`, `systemctl`, `sshd`, and the installed firewall utilities. Missing commands and permission errors are included in the report. Firewall changes require root, systemd, `nft`, and kernel nftables support. The firewall script stops if UFW or firewalld is active. For legacy iptables, BSD, non-systemd, or manager-controlled systems, use a reviewed procedure for that platform. Do not replace the firewall manager during competition just to run this script.
- **Windows:** 64-bit Windows PowerShell 5.1 on Windows 10/11 or Server 2016+, with NetSecurity, LocalAccounts, ScheduledTasks, and CIM cmdlets. Run changes as Administrator. Audit sections report missing providers individually. The credential script only handles local accounts and refuses domain controllers; coordinate AD password changes with whoever owns the domain. Follow the host's execution policy and inspect downloaded scripts before unblocking trusted files.
- **Both:** tested console access, a second management session, the required service list and scoring source addresses, an offline copy of the toolkit, and an approved password manager. Keep the scripts in a directory untrusted users cannot modify.
- **Recovery:** there is no automatic rollback timer. Verify console access before applying a firewall change so you can recover if remote access drops.

## Team setup

| Person | Primary responsibility | Partner check |
|---|---|---|
| 1 | Linux pair A, service inventory | Person 2 verifies external service access |
| 2 | Linux pair B, persistence baselines | Person 1 verifies changes |
| 3 | Windows pair A, domain coordination | Person 4 verifies management access |
| 4 | Windows pair B, inject/deadline tracking | Person 3 verifies changes |

This is a starting split for four Linux and four Windows boxes. Adjust it based on the actual environment and what each teammate is comfortable handling. Keep one person responsible for changes on each host at a time, and hand off inject tracking when needed. Use the [team worksheet](docs/TEAM-WORKSHEET.md) for ownership, dependencies, and verification results. Keep passwords in the password manager.

## Order of operations

1. **Figure out what each box needs to do.** Read the competition packet and identify its role, approved accounts, dependencies, scored services, and management sources. A listening port alone does not tell you whether a service is required.
2. **Make sure you can get back in.** Test console access, keep your current session open, and establish a second session. Check the required services from another machine before changing anything.
3. **Collect a baseline.** Run recon and persistence audits, save the reports privately, and review any errors. Missing output means that check still needs attention.
4. **Change selected local credentials.** Check dependencies first, change one approved human/admin account at a time, and test a fresh login immediately. Handle domain and service accounts separately with the responsible teammate.
5. **Apply the host's firewall plan.** Edit a copy of the example config, review it with a teammate, and run the preview. Apply from the tested console, then check **new** management connections and the actual scored services. Roll back if access or functionality breaks.
6. **Keep checking.** Compare later audits with the baseline, investigate unexpected changes, and stay on top of injects. Record what changed and when. Practice this sequence with the lab checklist before competition day.

## Linux quick start

Run these commands from the toolkit directory on the Linux host. The report folder is private to your user. Use new report filenames for later checks so you keep the original baseline.

```bash
umask 077
mkdir -p reports
chmod 700 reports
sudo python3 linux/recon.py > reports/linux-before.json
sudo python3 linux/persistence.py > reports/linux-persistence-before.json

# Exact local account; preview first. No password is passed on the command line.
sudo python3 linux/credentials.py alice
sudo python3 linux/credentials.py alice --apply --ack-service-impact

cp config/linux-web.example.json config/this-host.json
# Edit this-host.json: management source IPs, actual SSH port, required services.
python3 linux/firewall.py plan --config config/this-host.json
sudo python3 linux/firewall.py apply --config config/this-host.json --console-confirmed

# From the console if access or a required service regresses:
sudo python3 linux/firewall.py rollback
```

Replace `alice` with the exact local account you intend to change. The script uses the native `passwd` prompt, which hides password entry, asks for confirmation, and follows the host's password policy. It does not back up the old password.

On domain-joined Linux hosts, review PAM/NSS behavior first, especially when a local and domain account share a name. A password reset does not revoke SSH keys, tokens, or existing sessions. Those need separate review.

## Windows quick start

Open **64-bit Windows PowerShell as Administrator** in the toolkit directory on the Windows host. The commands below create a report folder restricted to Administrators and SYSTEM using their SIDs. Choose a new folder name for each baseline.

```powershell
$reports = Join-Path $env:ProgramData 'HorsePlinkoReports-Baseline'
New-Item -ItemType Directory -Path $reports -ErrorAction Stop | Out-Null
icacls.exe $reports /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Could not protect report directory' }
.\windows\Recon.ps1 | Out-File (Join-Path $reports 'recon.json') -Encoding utf8
.\windows\Persistence.ps1 | Out-File (Join-Path $reports 'persistence.json') -Encoding utf8

.\windows\Credentials.ps1 -User alice
.\windows\Credentials.ps1 -User alice -Apply -AckServiceImpact

Copy-Item .\config\windows-web.example.json .\config\this-host.json
# Edit actual management ports/sources and required services before applying.
.\windows\Firewall.ps1 -Config .\config\this-host.json
.\windows\Firewall.ps1 -Config .\config\this-host.json -Apply -ConsoleConfirmed

# From the console if needed:
.\windows\Firewall.ps1 -Rollback
```

The firewall script also accepts `-WhatIf` to preview an apply or rollback without writing state.

Credential changes use `Read-Host -AsSecureString` and do not log or export plaintext passwords. Save the intended password in your approved password manager, enter it carefully, and test a fresh login with `HOSTNAME\alice`. Administrative password resets can affect EFS/DPAPI data and services or tasks that use the account. The script does not update those dependencies or change domain credentials.

## Setting up the firewall config

Both platforms use the same JSON structure:

- `management.sources`: one or more management client IPs/CIDRs. Unrestricted `/0` sources are rejected here.
- `management.tcp_ports`: one or more actual management ports, such as the configured SSH, RDP, or WinRM port.
- `services`: entries containing exactly `name`, `protocol`, `ports`, and `sources`. Use `tcp` or `udp` and integer ports from 1–65535. Port ranges are not supported.

Use network addresses for CIDRs: for example, `192.0.2.0/24`, not `192.0.2.10/24`. DNS needs separate TCP and UDP entries. An empty `services: []` list is valid when the host only needs management access.

**Replace `192.0.2.10/32` before applying.** It is a placeholder for the management client, not the server being defended. If NAT is involved, use the source address the server actually sees.

The web examples allow public IPv4 and IPv6 access. Keep `::/0` only when the service should be public on IPv6, and add your management IPv6 source separately if you use it. Check custom management ports against the host's configuration. Linux DHCP clients may need inbound UDP 68/546 rules from the relevant DHCP sources; test lease renewal too.

Build the config for the role of the box. A web-server example does not cover a domain controller, DNS server, mail server, database, router, or container host. AD/RPC, passive FTP, monitoring, backups, and clusters can need additional traffic. Use the packet and service behavior to build the list, and check dynamic-port requirements with the service owner. The scripts do not change RPC ranges or automatically identify scoring requirements.

### Linux behavior and rollback

- Adds only `table inet horse_plinko`, with a default-drop **input** chain covering IPv4/IPv6, loopback, established/related traffic, ICMP/ICMPv6, and your reviewed allows. Outbound, forwarding and NAT are untouched. Container-published or routed traffic may traverse forwarding and is outside this guard's protection.
- Existing tables remain. Their drops still apply even when this table allows traffic. Established connections are retained, including potentially unwanted ones; no connection-killing behavior is included.
- Runs `nft --check` before apply, saves a full textual ruleset snapshot and the proposed table in root-only `/var/lib/horse-plinko`, and applies one atomic nft transaction. An active journal blocks another apply; rollback before replacing the plan. Do not let another operator or firewall manager change policy during a transaction.
- Rollback deletes only the owned table and clears the active journal. It does **not** replay the full snapshot or flush other tables. Snapshots remain on disk; the next successful apply replaces the two Linux snapshot files, so archive them privately if needed.
- **Runtime only:** no startup configuration is installed. Reboot or firewall-manager reload can remove the guard. After a reboot, run rollback to clear stale state, re-review, and reapply if appropriate. Never blindly paste the snapshot into a ruleset restore command.

### Windows behavior and rollback

- Adds uniquely named inbound allow rules on all profiles, enables all profiles, and sets their default inbound action to Block. Existing allow/block rules and outbound policy remain. A broad existing allow can still expose a port; an explicit block can defeat your new allow. This is a conservative change, not an exclusive allowlist.
- Refuses detected disabled local-rule merging, shields-up policy, or exempt interfaces. Checks effective profiles and rule presence after apply, but external functional tests are still required, especially with Group Policy/IPsec.
- Stores a `.wfw` backup and a transaction journal under `%ProgramData%\HorsePlinko`, restricted to SYSTEM/Administrators. Windows changes persist across reboot.
- Rollback restores the saved local profile Enabled/DefaultInboundAction values and removes only this transaction's rule IDs. It leaves other rules in place. Coordinate with teammates: rollback could overwrite later changes to those same two profile settings. It does not restore domain policy.
- A failed apply attempts rollback. An interrupted apply or incomplete rollback leaves a journal for `-Rollback`. A full `.wfw` import is an exceptional manual disaster-recovery operation that replaces wider policy; the toolkit never performs it automatically.

## Reading the audit results

The Linux persistence audit collects file hashes and metadata for cron, systemd, startup files, SSH keys, and authentication configuration. It also lists timers, unit files, at jobs, and modules. Review changed files locally to understand what they do.

The Windows audit checks scheduled tasks, services, drivers, startup files, autoruns, Image File Execution Options (IFEO), WMI subscriptions, and Defender exclusions. It only inspects user registry hives that are already loaded.

Treat the results as investigation leads. An unfamiliar entry is not automatically malicious, and an audit with no obvious findings does not prove the host is clean.

Keep the reports private. They can contain IPs, usernames, paths, and secrets that were already embedded in service, task, or autorun arguments. The scripts do not read password hashes or create password logs, but collected configuration can still contain sensitive data.

Do not push reports, state files, backups, or real competition configs to GitHub. Check the staged diff before committing, even with `.gitignore` in place.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q linux tests
```

```powershell
.\tests\Test-Windows.ps1
```

The Python tests simulate system commands, so they can run on macOS without changing passwords or firewall settings. All 22 portable tests passed. The PowerShell test script checks Windows script syntax and valid/invalid dry-run inputs.

Live Linux firewall behavior, Windows execution, and actual credential changes still need testing on the target operating systems. Use disposable VMs and work through [LAB-TESTS.md](docs/LAB-TESTS.md), including rollback and service checks. [TEST-RESULTS.md](docs/TEST-RESULTS.md) records what has and has not been verified.

## References

[caol777/CCDC](https://github.com/caol777/CCDC) was the reference for the general workflow and areas to cover. Its README, Linux inventory/firewall scripts, and Windows firewall script were reviewed on October 8, 2026. This repo uses separate implementations and does not bundle the upstream scripts.

Technical references:

- [nftables chain behavior](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- [Windows firewall profile settings](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)

No license has been selected for this repository yet.
