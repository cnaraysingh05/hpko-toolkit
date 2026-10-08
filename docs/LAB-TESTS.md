# Disposable-VM acceptance checks

Use snapshots and console access. Do not run these mutation checks on your workstation or production machines. Test with a second client and, for source-restriction checks, a third client outside the management CIDR. Record OS/build, command, expected/actual result and timestamps.

## Both platforms

1. Run the portable tests and native PowerShell parser tests. Correct any failures before proceeding.
2. Run both audits as a standard user, then elevated. Missing/denied sections must be visible; verify no configuration changed. Save two baselines and compare them after a harmless lab-only scheduled-task/cron change. Confirm the changed artifact appears. Remove your test artifact manually.
3. Create a disposable local test account with the OS's native account tool. Preview rotation: existing credentials must still work. Apply to that one account with a strong lab password. Verify new password works and old password fails in **fresh** sessions. Verify a second control account remains unchanged. Check password-policy rejection and confirmation mismatch. Never use a real service account for this test.
4. Review terminal history and toolkit artifacts: passwords must not appear. Do not capture keystrokes/password-manager screens as evidence. Existing sessions may still work and are not a valid password test.
5. Set up a test web listener and a separate unlisted test listener. Confirm both are reachable beforehand. Make a config allowing management and web only, with real client IPs. Include IPv6 when available. Preview must not modify rules, profiles or state.
6. Apply using the console. From the allowed client establish a **new** SSH/RDP/WinRM connection and perform an HTTP request. Test denied-source management access from the third client. On Windows, first inspect existing allow rules: if one already permits the test, preserved rules can explain access. Do not treat a TCP connect alone as a complete score check.
7. Roll back. Compare unrelated rules and outbound settings with baseline, verify original profile settings on Windows, and confirm pre-change connectivity. Run another apply/rollback cycle. A second apply while active must fail without changing rules.

## Linux-specific cases

- `nft --check` must accept the generated policy on the target kernel/tool version. Apply with UFW/firewalld active must refuse without stopping either manager. Test a missing `nft` or unusable systemd environment: fail without mutation.
- Verify `nft list table inet horse_plinko` matches the plan; verify a pre-existing unrelated table survives apply and rollback. A pre-existing table with this reserved name must be refused.
- Test DNS with both TCP and UDP, IPv6 neighbor discovery, and DHCP renewal if used. Add explicit inbound service requirements first. Validate router/container traffic separately; the input guard does not govern forwarded traffic.
- After a VM reboot, expect the guard to be absent unless external configuration restores it; the toolkit adds no persistence. Rollback should clear stale journal state when the table is absent.
- Simulate an nft validation rejection in a lab/mock, and verify no active journal or policy mutation. The portable tests cover rejection of an atomic apply and journal-before-mutation ordering.

## Windows-specific cases

- Inspect all three effective profiles and the created `HorsePlinko-*` rules. Check that a pre-existing unrelated rule survives rollback and that Enabled/DefaultInboundAction return to original values.
- Test a domain-managed lab member with local-rule merging disabled: apply must refuse. Test shields-up/disabled-interface settings too. Local rules may be present yet ineffective due to policy; always test remotely.
- Reboot after apply: rules should persist. `-Rollback` should still restore local settings using the saved journal.
- From a lab debugger or controlled test harness, interrupt apply after the journal is written. Restart the script with `-Rollback`; any partially created rules should be removed and profile defaults restored. Do not delete the journal to bypass a failed change.
- Simulate a denied rule creation or profile update and confirm the error triggers rollback. If rollback is denied too, the journal must remain and the output must clearly call for console recovery.
- Credential rotation on a domain controller must refuse. Audit output may show missing LocalAccounts support there; other sections should still be collected.

Do not mark native integration tests passed based on the mocked tests. Keep your lab results with the private competition notes.

## Guided workflow and service checks

- On a Linux VM with Python available, run `bash linux/start.sh --check`; no packages or firewall settings should change. Open the menu as root, collect a baseline, and confirm the report directory is root-only. Review all three reports, including errors.
- On a disposable supported Linux VM without Python, `--check` must fail without installing anything. Then test `--install-python`: cancelling must leave packages alone; confirming uses the system repositories and the package manager prompt. Check repository/network failure and Python older than 3.8. Do not remove the system Python from a working host to make this test possible.
- On Windows, run `tests/Test-Windows.ps1` to parse the new menu and review scripts too. In an elevated menu session, collect the baseline and check its Administrators/SYSTEM-only ACL. Confirm no report contains a password entered during rotation.
- Cancel menu credential and firewall confirmations. No change should occur. Try an invalid config and verify apply is not reached. A failed subcommand must be shown as a failure, and the menu must not declare the host secure.
- From the management client, edit `checks.local.json` for a lab SSH/RDP port and web endpoint. Preview should generate no traffic. Run should report the expected results. Stop the lab listener or deliberately use a wrong expected HTTP status and confirm a failing check gives exit code 1. Invalid configuration must fail with exit code 2 before contacting any target.
- Test HTTPS using a correctly trusted certificate, then an untrusted one. The latter should fail, not skip certificate validation. A redirect should not be followed automatically.
- Complete HANDOFF.md with a partner, including actual login/application tests and the next check time. Report collection and a successful TCP handshake alone are not enough.
