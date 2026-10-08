#!/usr/bin/env python3
"""Read-only local inventory. JSON goes to stdout; redirect to a private file."""
from common import collect, report, require_linux, main_guard


def main():
    require_linux()
    commands = {
        "os": ["cat", "/etc/os-release"],
        "kernel": ["uname", "-a"],
        "addresses": ["ip", "-brief", "address"],
        "routes": ["ip", "route"],
        "ipv6_routes": ["ip", "-6", "route"],
        "local_users": ["cat", "/etc/passwd"],
        "local_groups": ["cat", "/etc/group"],
        "sudo_policy": ["sudo", "-n", "-l"],
        "listeners": ["ss", "-lntup"],
        "connections": ["ss", "-ntup"],
        "services": ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
        "ssh_effective": ["/usr/sbin/sshd", "-T"],
        "nftables": ["nft", "list", "ruleset"],
        "ufw": ["ufw", "status", "verbose"],
        "firewalld": ["firewall-cmd", "--list-all-zones"],
        "selinux": ["getenforce"],
        "apparmor": ["aa-status"],
        "logins": ["last", "-n", "20"],
    }
    report({name: collect(argv) for name, argv in commands.items()})


if __name__ == "__main__":
    main_guard(main)
