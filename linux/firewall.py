#!/usr/bin/env python3
"""Preview/apply an isolated runtime nftables input guard; rollback only this table."""
import argparse
import fcntl
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from common import require_linux, main_guard

TABLE = "horse_plinko"
STATE = Path("/var/lib/horse-plinko")


def ports(values):
    if not isinstance(values, list) or not values:
        raise ValueError("ports must be a nonempty list of integers.")
    if any(type(v) is not int or not 1 <= v <= 65535 for v in values):
        raise ValueError("Ports must be integers 1..65535.")
    return sorted(set(values))


def sources(values):
    if not isinstance(values, list) or not values:
        raise ValueError("sources must be a nonempty list of IP/CIDR strings.")
    if not all(isinstance(v, str) and '%' not in v for v in values):
        raise ValueError("Every source must be an IP/CIDR string without a zone ID.")
    return [ipaddress.ip_network(v, strict=True) for v in values]


def validate(config):
    if not isinstance(config, dict) or set(config) != {"management", "services"}:
        raise ValueError("Expected only management and services keys.")
    m = config["management"]
    if not isinstance(m, dict) or set(m) != {"sources", "tcp_ports"}:
        raise ValueError("management needs sources and tcp_ports.")
    nets = sources(m["sources"])
    if any(n.prefixlen == 0 for n in nets):
        raise ValueError("Management may not use an unrestricted /0 source.")
    rules = [("management", "tcp", ports(m["tcp_ports"]), nets)]
    if not isinstance(config["services"], list):
        raise ValueError("services must be a list (empty allowed).")
    for s in config["services"]:
        if not isinstance(s, dict) or set(s) != {"name", "protocol", "ports", "sources"}:
            raise ValueError("Each service needs name, protocol, ports, sources.")
        if not isinstance(s["name"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", s["name"]):
            raise ValueError("Service name: 1..40 letters, numbers, underscore or hyphen.")
        if s["protocol"] not in ("tcp", "udp"):
            raise ValueError("Protocol must be tcp or udp.")
        rules.append((s["name"], s["protocol"], ports(s["ports"]), sources(s["sources"])))
    return rules


def render(config):
    rules = validate(config)
    lines = ["table inet " + TABLE + " {", " chain input {",
             "  type filter hook input priority 10; policy drop;",
             '  iifname "lo" accept', "  ct state established,related accept",
             "  meta l4proto { icmp, ipv6-icmp } accept"]
    for name, proto, ps, nets in rules:
        for net in nets:
            family = "ip" if net.version == 4 else "ip6"
            lines.append('  {} saddr {} {} dport {{ {} }} accept comment "{}"'.format(
                family, net, proto, ", ".join(map(str, ps)), name))
    lines.extend([" }", "}", ""])
    return "\n".join(lines)


def run(argv, data=None):
    return subprocess.run(argv, input=data, text=True, capture_output=True, check=True).stdout


def secure_state():
    STATE.mkdir(mode=0o700, exist_ok=True)
    s = STATE.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o700:
        raise RuntimeError("State directory must be a real root-owned directory mode 0700.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["plan", "apply", "rollback"])
    p.add_argument("--config", type=Path)
    p.add_argument("--console-confirmed", action="store_true")
    a = p.parse_args()
    if a.action != "rollback":
        if not a.config:
            raise ValueError("--config is required.")
        script = render(json.loads(a.config.read_text()))
        if a.action == "plan":
            print(script)
            print("# DRY RUN. Input only; ICMP and established traffic retained. No writes.")
            return
    require_linux()
    if os.geteuid() != 0:
        raise RuntimeError("Apply/rollback require root.")
    os.umask(0o077)
    secure_state()
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending = STATE / "active.json"
        if a.action == "rollback":
            if not pending.exists():
                raise RuntimeError("No managed change is recorded; refusing to delete a table.")
            if json.loads(pending.read_text()).get("table") != TABLE:
                raise RuntimeError("Invalid state record.")
            listing = json.loads(run(["nft", "-j", "list", "tables"]))
            exists = any(x.get("table", {}).get("name") == TABLE and
                         x.get("table", {}).get("family") == "inet" for x in listing["nftables"])
            if exists:
                run(["nft", "delete", "table", "inet", TABLE])
            pending.unlink()
            print("Rollback complete. Other firewall tables untouched; backup retained.")
            return
        if not a.console_confirmed:
            raise ValueError("Test out-of-band console access first; supply --console-confirmed.")
        if pending.exists():
            raise RuntimeError("An earlier change is active. Roll back before applying a new plan.")
        # Managers may reload the entire ruleset. Refuse rather than stop them.
        for service in ("firewalld", "ufw"):
            check = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
            if check.returncode == 0:
                raise RuntimeError(service + " is active; use its native policy workflow instead.")
            if check.returncode not in (3, 4):
                raise RuntimeError("Cannot reliably determine firewall manager state.")
        listing = json.loads(run(["nft", "-j", "list", "tables"]))
        if any(x.get("table", {}).get("name") == TABLE and
               x.get("table", {}).get("family") == "inet" for x in listing["nftables"]):
            raise RuntimeError("Reserved table already exists; refusing to modify it.")
        run(["nft", "--check", "--file", "-"], script)
        # Full snapshot is reference evidence only: never restore with 'flush ruleset'.
        (STATE / "before.nft").write_text(run(["nft", "list", "ruleset"]))
        (STATE / "applied.nft").write_text(script)
        pending.write_text(json.dumps({"table": TABLE}))
        try:
            run(["nft", "--file", "-"], script)  # One atomic nft transaction.
        except subprocess.CalledProcessError:
            pending.unlink()  # A rejected atomic transaction makes no changes.
            raise
        print("Applied runtime guard. Backup: " + str(STATE))
        print("Immediately test NEW management + scored-service connections from another host.")
        print("Rollback: sudo python3 linux/firewall.py rollback")


if __name__ == "__main__":
    main_guard(main)
