# Horse Plinko blue-team field kit

A small, local toolkit for a four-person team defending mixed Windows/Linux hosts. Read each script before running it. Run on one host at a time, record the result, and test scored services after every change. The example configs are **web-server examples, not the competition service list**.

## What's included

| Task | Linux | Windows |
|---|---|---|
| Read-only reconnaissance | `linux/recon.py` | `windows/Recon.ps1` |
| Rotate one selected local account | `linux/credentials.py` | `windows/Credentials.ps1` |
| Preview, apply, back up, roll back firewall changes | `linux/firewall.py` | `windows/Firewall.ps1` |
| Read-only persistence evidence | `linux/persistence.py` | `windows/Persistence.ps1` |

Linux uses Python for explicit validation and error handling; Windows uses PowerShell. No downloads, package installation, host fan-out, account disabling, SELinux changes, or password files. Recon/audit commands do not change configuration, but normal OS access/audit logs may record their execution.

## Prerequisites

- **Linux:** Python 3.8+, standard library only. Recon uses available `ip`, `ss`, `systemctl`, `sshd`, and firewall utilities; missing/denied commands appear in the report. Firewall apply requires root, systemd, `nft`, and kernel nftables support. It refuses active UFW/firewalld rather than stopping them. Legacy-only iptables, BSD, non-systemd, and manager-controlled hosts need their own reviewed native firewall workflow. Do not install/replace firewall managers mid-competition just to use this script.
- **Windows:** 64-bit Windows PowerShell 5.1 on Windows 10/11 or Server 2016+, with NetSecurity, LocalAccounts, ScheduledTasks and CIM cmdlets. Run changes elevated. Missing read-only providers are reported per section. Local credential rotation deliberately refuses domain controllers; AD passwords need a separate domain-owner procedure. Honor your execution policy: inspect/unblock trusted downloaded files individually if needed; these scripts do not bypass policy.
- **Both:** approved console access tested before firewall apply; a second management connection; a known service list including scoring source addresses; offline copies of scripts; an approved password manager. Do not run scripts from a directory writable by untrusted users, especially when elevated.
- No automatic rollback timer is installed. The console requirement is intentional. A firewall apply is a real change, not a connectivity guarantee.

## Four-person ownership

| Person | Primary responsibility | Partner check |
|---|---|---|
| 1 | Linux pair A, service inventory | Person 2 verifies external service access |
| 2 | Linux pair B, persistence baselines | Person 1 verifies changes |
| 3 | Windows pair A, domain coordination | Person 4 verifies management access |
| 4 | Windows pair B, inject/deadline tracking | Person 3 verifies changes |

Adjust to actual strengths and assigned boxes. Each host has one change owner at a time; the inject tracker can hand off work. Use [the team worksheet](docs/TEAM-WORKSHEET.md) to record ownership, service dependencies and checks. Never put passwords in it.

## Deployment order

1. Read competition rules/packet. Identify each host, its role, approved accounts, dependencies, score checks, and allowed management sources. Do not infer required services from listening ports alone.
2. Confirm console access, keep your current session, and establish a second session. Record a baseline of service functionality from another host.
3. Run reconnaissance and persistence audits into a private report directory. Review errors; a partial report is not a clean bill of health.
4. Rotate explicitly chosen human/admin local accounts, one at a time, after checking dependencies. Test a new login immediately. Coordinate any domain or service-account changes separately.
5. Copy and edit a firewall example for this host. Review it with a teammate, preview, then apply from the tested console. Test **new** management connections and application-level scored services immediately. Roll back if something regresses.
6. Compare later audits with the baseline, investigate changes, and handle injects. Record timestamps and each change. Practice the lab checklist before competition use.

## Linux quick start

Run from the toolkit directory. The report directory below is private to your user; it is not a shared team drop.

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

Replace `alice` with a reviewed existing account. `passwd` supplies the native hidden, repeated password prompt and applies the host's password policy. No old-password backup exists. Linux PAM/NSS integrations must be reviewed on domain-joined machines, particularly if local and domain names collide. Changing a password does not revoke SSH keys, tokens, or existing sessions; audit those separately.

## Windows quick start

Open **64-bit Windows PowerShell as Administrator** in the toolkit directory. Store reports in a new private directory; the following example restricts access to Administrators and SYSTEM using language-independent SIDs. Use a different directory name for each baseline.

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

`-WhatIf` also previews an apply/rollback without state writes. Credential rotation uses `Read-Host -AsSecureString`; no plaintext password logging or export is performed. Store the intended password in your approved password manager first, enter it carefully, and test a new local login using `HOSTNAME\alice`. Administrative resets can affect EFS/DPAPI data and services/tasks using that account. The script does not update dependent credentials or domain accounts.

## Firewall configuration

Both platforms use the same JSON shape. `management.sources` is a nonempty list of literal IPs/CIDRs and cannot contain `/0`; `tcp_ports` is a nonempty integer list. Each service needs exactly `name`, `protocol` (`tcp` or `udp`), `ports` (integers 1–65535), and `sources`. CIDRs must have host bits cleared. DNS service needs separate TCP and UDP entries; port ranges are not accepted. `services: []` is allowed when only management is needed.

The example management address `192.0.2.10/32` is a documentation placeholder: **replace it**. Public web examples allow both IPv4 and IPv6. Only add `::/0` if the service should be public on IPv6. Add the real management IPv6 source separately if used. If NAT is involved, use the source address the server actually sees. Custom SSH/RDP/WinRM ports must match the host. Linux DHCP clients may need explicit UDP 68/546 inbound entries from the relevant DHCP sources; test renewal, not just initial connectivity.

Do not paste a web config onto a domain controller, DNS server, mail server, database server, router or container host. AD/RPC, passive FTP, monitoring, backup and cluster traffic have additional dependencies. Build a host-specific list from the packet and observed operation; review dynamic-port needs with the service owner. This kit does not change RPC ranges or guess what the scorer needs.

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

## Audits and sensitive data

Linux persistence reports hash/metadata baselines for cron, systemd, startup files, SSH keys and authentication configuration; they also list timers, unit files, at jobs and modules. Read changed files locally to understand them. Windows audits scheduled tasks, services, drivers, startup files, autoruns, IFEO, WMI subscriptions and Defender exclusions. Only loaded user registry hives are inspected. Neither audit is a complete rootkit detector or a malware verdict.

Reports can expose IPs, usernames, paths and pre-existing secrets embedded in service/task/autorun arguments. Treat them as private evidence. The toolkit never reads password hashes or creates password logs, but it cannot sanitize secrets already embedded in system configuration. Do not upload reports, state, backups or real competition configs to GitHub. `.gitignore` is a convenience, not a guarantee; review staged files yourself.

## Tests and readiness

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q linux tests
```

```powershell
.\tests\Test-Windows.ps1
```

Portable tests use mocked system commands; they never change the host firewall or passwords. The PowerShell script parses all Windows scripts and checks good/bad dry-run inputs. Run [LAB-TESTS.md](docs/LAB-TESTS.md) on disposable VMs for actual privilege, password-policy, firewall, service and rollback behavior. See [TEST-RESULTS.md](docs/TEST-RESULTS.md) for the delivery's exact verification status.

## Reference and publishing

Conceptual reference: [caol777/CCDC](https://github.com/caol777/CCDC), particularly its README, Linux inventory/firewall scripts and Windows firewall script, reviewed October 8, 2026. This kit is a separate implementation; no upstream script code is bundled. Source-specific operational documentation: [nftables chain behavior](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains) and [Windows firewall profile settings](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile).

The directory is ready for your review and your own GitHub upload. No Git repository, commit, remote, or push is created by this kit. Choose your preferred license before publishing; none is assumed.
