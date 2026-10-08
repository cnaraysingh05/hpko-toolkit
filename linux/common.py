"""Shared read-only collection helpers; no package dependencies."""
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone


def require_linux():
    if platform.system() != "Linux":
        raise RuntimeError("Run this operation on Linux.")


def collect(argv):
    """Never use a shell; missing commands and denied reads remain visible."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return {"command": argv, "returncode": p.returncode,
                "stdout": p.stdout, "stderr": p.stderr}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"command": argv, "error": str(e)}


def report(sections):
    print(json.dumps({"host": platform.node(),
                      "utc": datetime.now(timezone.utc).isoformat(),
                      "sections": sections}, indent=2))


def main_guard(fn):
    try:
        fn()
    except subprocess.CalledProcessError as e:
        print("ERROR: " + str(e), file=sys.stderr)
        if e.stderr:
            print(e.stderr.strip(), file=sys.stderr)
        sys.exit(1)
    except (ValueError, RuntimeError, OSError) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        sys.exit(1)
