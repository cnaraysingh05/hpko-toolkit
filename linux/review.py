#!/usr/bin/env python3
"""Read-only review leads. Does not read /etc/shadow or remove users/keys."""
from pathlib import Path
from common import collect, report, require_linux, main_guard


def account_findings(text):
    findings = []
    for line in text.splitlines():
        row = line.split(":")
        if len(row) != 7:
            findings.append("Malformed passwd entry; inspect /etc/passwd locally.")
            continue
        name, _, uid, _, _, home, shell = row
        if uid == "0" and name != "root":
            findings.append("Additional UID 0 account: " + name)
        if shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""):
            findings.append("Review interactive account: {} (UID {}, home {})".format(name, uid, home))
    return findings


def ssh_findings(result):
    if result.get("returncode") != 0:
        return ["Effective SSH settings unavailable; review the command error."]
    values = dict(line.split(None, 1) for line in result["stdout"].splitlines() if len(line.split(None, 1)) == 2)
    findings = []
    for key in ("permitemptypasswords", "permitrootlogin"):
        if values.get(key) == "yes":
            findings.append(key + " is enabled; review access requirements before changing it.")
    if values.get("passwordauthentication") == "yes":
        findings.append("SSH password authentication enabled. Keep it until alternative access is tested; rotate approved passwords.")
    return findings


def main():
    require_linux()
    ssh = collect(["/usr/sbin/sshd", "-T"])
    report({
        "account_review": account_findings(Path("/etc/passwd").read_text()),
        "local_groups": collect(["cat", "/etc/group"]),
        "ssh_review": ssh_findings(ssh),
        "ssh_effective": ssh,
        "sudo_policy_syntax": collect(["visudo", "-c"]),
        "privileged_group_sudo": collect(["getent", "group", "sudo"]),
        "privileged_group_wheel": collect(["getent", "group", "wheel"]),
        "privileged_group_docker": collect(["getent", "group", "docker"]),
        "sessions": collect(["who"]),
        "selinux": collect(["getenforce"]),
        "apparmor": collect(["aa-status"]),
        "note": "Review leads, not verdicts. sshd -T without connection context may omit Match-specific behavior. Also inspect persistence reports, sudo grants and authorized_keys locally. No settings changed."})


if __name__ == "__main__":
    main_guard(main)
