#!/usr/bin/env python3
"""Rotate one explicitly named LOCAL account via the native hidden passwd prompt."""
import argparse
import os
import subprocess
from pathlib import Path
from common import require_linux, main_guard


def local_account(name, passwd_text):
    if not name or name.startswith("-") or any(c in name for c in ":\n\r/"):
        raise ValueError("Invalid local account name.")
    rows = [line.split(":") for line in passwd_text.splitlines()]
    matches = [r for r in rows if len(r) == 7 and r[0] == name]
    if len(matches) != 1:
        raise ValueError("Name must match exactly one account in /etc/passwd.")
    return matches[0]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("user")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--ack-service-impact", action="store_true")
    a = p.parse_args()
    require_linux()
    row = local_account(a.user, Path("/etc/passwd").read_text())
    print("Selected local account: {} (UID {}, shell {}).".format(row[0], row[2], row[6]))
    print("Password resets can affect jobs, services, and encrypted data. No password backup is made.")
    if not a.apply:
        print("DRY RUN: would invoke passwd for this account only.")
        return
    if os.geteuid() != 0 or not os.isatty(0):
        raise RuntimeError("Apply requires root and an interactive terminal.")
    if not a.ack_service_impact:
        raise ValueError("Review dependencies, then supply --ack-service-impact.")
    if input("Type the exact account name to rotate: ") != a.user:
        raise ValueError("Confirmation did not match.")
    # Password never enters Python, command arguments, environment, or a report.
    subprocess.run(["passwd", a.user], check=True)
    print("Test a NEW login before closing your current session. Existing sessions/keys remain valid.")


if __name__ == "__main__":
    main_guard(main)
