#!/usr/bin/env python3
"""Read-only persistence inventory; findings are leads, not malware verdicts."""
import hashlib
import os
import stat
from pathlib import Path
from common import collect, report, require_linux, main_guard


def metadata(path):
    try:
        s = path.lstat()
        item = {"path": str(path), "mode": oct(stat.S_IMODE(s.st_mode)),
                "uid": s.st_uid, "gid": s.st_gid, "mtime": s.st_mtime}
        if path.is_symlink():
            item["symlink"] = os.readlink(path)
        elif stat.S_ISREG(s.st_mode) and s.st_size <= 2_000_000:
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return item
    except OSError as e:
        return {"path": str(path), "error": str(e)}


def main():
    require_linux()
    roots = [Path(p) for p in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/etc/systemd/system",
        "/usr/local/lib/systemd/system", "/etc/init.d", "/etc/profile.d", "/etc/sudoers.d",
        "/etc/pam.d", "/etc/ssh/sshd_config.d"]]
    files = [Path(p) for p in ["/etc/crontab", "/etc/rc.local", "/etc/profile", "/etc/bash.bashrc",
        "/etc/ld.so.preload", "/etc/sudoers", "/etc/ssh/sshd_config"]]
    for line in Path("/etc/passwd").read_text().splitlines():
        fields = line.split(":")
        if len(fields) == 7 and fields[5].startswith("/"):
            home = Path(fields[5])
            files.extend(home / p for p in [".ssh/authorized_keys", ".ssh/authorized_keys2",
                ".bashrc", ".bash_profile", ".profile"])
            roots.extend([home / ".config/systemd/user", home / ".config/autostart"])
    errors = []
    for root in roots:
        # os.walk does not follow directory symlinks. Permission failures are reported.
        if root.is_symlink():
            files.append(root)
            continue
        for directory, dirs, names in os.walk(root, followlinks=False,
                onerror=lambda e: errors.append(str(e))):
            files.extend(Path(directory) / n for n in names)
            files.extend(Path(directory) / d for d in dirs if (Path(directory) / d).is_symlink())
    report({"files": [metadata(p) for p in sorted(set(files)) if os.path.lexists(p)],
        "walk_errors": errors,
        "timers": collect(["systemctl", "list-timers", "--all", "--no-pager"]),
        "unit_files": collect(["systemctl", "list-unit-files", "--no-pager"]),
        "at_jobs": collect(["atq"]),
        "modules": collect(["lsmod"]),
        "note": "Hashes and metadata only. Review changed files locally; do not execute them. No clean verdict."})


if __name__ == "__main__":
    main_guard(main)
