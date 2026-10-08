#!/usr/bin/env python3
"""Interactive wrapper around the individual scripts; never auto-remediate findings."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from common import require_linux, main_guard

HERE = Path(__file__).resolve().parent


def invoke(name, *args, output=None):
    result = subprocess.run([sys.executable, str(HERE / name), *args], stdout=output)
    if result.returncode:
        raise RuntimeError(name + " failed. Read the error; do not mark this step complete.")


def baseline():
    # Random, root-owned directory avoids predictable report paths and overwrites.
    directory = Path(tempfile.mkdtemp(prefix="horse-plinko-reports-", dir="/var/tmp"))
    directory.chmod(0o700)
    print("Private reports: " + str(directory))
    for script in ("recon.py", "persistence.py", "review.py"):
        with (directory / (script[:-3] + ".json")).open("x") as out:
            invoke(script, output=out)
    print("Reports collected. Review errors and findings before making changes.")


def main():
    require_linux()
    if os.geteuid() != 0 or not sys.stdin.isatty():
        raise RuntimeError("Run the menu as root in an interactive terminal.")
    os.umask(0o077)
    while True:
        print("\n1 Collect private baseline reports\n2 Review security settings on screen"
              "\n3 Rotate ONE local password\n4 Preview firewall config\n5 Apply firewall config"
              "\n6 Roll back toolkit firewall\n7 Handoff checklist\n0 Exit")
        try:
            choice = input("Choose a step: ").strip()
            if choice == "0":
                return
            if choice == "1":
                baseline()
            elif choice == "2":
                invoke("review.py")
            elif choice == "3":
                user = input("Exact local account name: ").strip()
                invoke("credentials.py", user)
                if input("Dependencies reviewed? Type ROTATE to proceed: ") == "ROTATE":
                    invoke("credentials.py", user, "--apply", "--ack-service-impact")
                    print("Now test a fresh login from another session; keep this session open.")
            elif choice in ("4", "5"):
                config = str(Path(input("Path to your edited host JSON config: ").strip()).resolve())
                invoke("firewall.py", "plan", "--config", config)
                if choice == "5" and input("Console tested and service list reviewed? Type APPLY: ") == "APPLY":
                    invoke("firewall.py", "apply", "--config", config, "--console-confirmed")
                    print("Test NEW remote connections and application functions now. Roll back on regression.")
            elif choice == "6":
                if input("Remove this toolkit's firewall guard? Type ROLLBACK: ") == "ROLLBACK":
                    invoke("firewall.py", "rollback")
            elif choice == "7":
                print("Before handing off: fresh login tested; required services checked externally;"
                      " audit errors/findings reviewed; firewall behavior verified; console and rollback ready;"
                      " unresolved issues recorded; next check assigned. See docs/HANDOFF.md."
                      " This menu does not certify a host as secure.")
            else:
                print("Choose a listed step.")
        except (OSError, RuntimeError, ValueError) as e:
            print("STOP: " + str(e), file=sys.stderr)


if __name__ == "__main__":
    try:
        main_guard(main)
    except (KeyboardInterrupt, EOFError):
        print("\nMenu closed. Applied changes remain; use rollback if needed.")
