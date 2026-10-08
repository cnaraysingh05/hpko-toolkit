# Host handoff

Keep the completed copy with private team notes. Use this before switching to injects or giving a box to another teammate. A completed script is one step; it does not prove the host is secure.

- Host/IP and role: ____
- Change owner and checking teammate: ____
- Required services and allowed clients from packet: ____
- Console access tested at: ____
- Private baseline report location: ____
- Approved local accounts rotated (names only): ____
- Fresh login tested from another session at: ____
- Firewall applied, declined, or unsupported, and why: ____
- External service checks before/after (time and result): ____
- Actual application checks (web content/login, DNS query, share access, etc.): ____
- Unexpected users, keys, tasks, services, sudo grants, AV exclusions or settings reviewed: ____
- Unresolved findings, missing tools, and command errors: ____
- Rollback command/location and next owner: ____
- Next recheck time and person: ____

## Linux review priorities

Confirm approved accounts, UID 0 users, sudo/wheel/docker membership, SSH keys, effective SSH settings, cron/systemd persistence, and service exposure. `visudo -c` checks syntax only; read the grants locally. `sshd -T` without connection context does not prove every Match block is safe. Do not disable password authentication until alternative access is tested. Review application credentials and patch requirements separately.

## Windows review priorities

Confirm local administrators, enabled accounts, scheduled tasks, services, autoruns, Defender status/exclusions, RDP NLA, SMB1/signing, and firewall rules already present. Passive Defender can be expected when another approved antivirus is installed. Coordinate compatibility and reboot requirements before remediation. A list of recent hotfixes does not prove patch coverage.

## When to stop and escalate

Escalate a lost service, inaccessible console, unknown privileged account/key, suspected persistence, unsupported firewall manager, or unexpected domain role. Record the finding and keep an owner assigned. Do not bulk delete accounts, kill services, or run updates to clear a checklist.

Linux firewall changes are runtime-only. After a reboot or firewall reload, recheck them. On Windows, preserved broad allow rules can still permit access. Password changes do not invalidate every existing session or key. Keep checking throughout the round.
