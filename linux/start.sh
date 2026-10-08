#!/usr/bin/env bash
# Bootstrap only. Never download an interpreter from an arbitrary URL.
set -euo pipefail
mode="${1:-}"
case "$mode" in
  ''|--check|--install-python) ;;
  *) echo 'Usage: bash linux/start.sh [--check | --install-python]' >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then echo 'Only one option is accepted.' >&2; exit 2; fi
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Run this starter on a Linux host. Portable tests can run on your Mac.' >&2
  exit 1
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_ready() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'
}
if ! python_ready; then
  if [[ "$mode" != --install-python ]]; then
    echo 'Python 3.8+ is required. No packages were changed.' >&2
    echo 'If competition rules allow it, run: sudo bash linux/start.sh --install-python' >&2
    exit 1
  fi
  if [[ $EUID -ne 0 || ! -t 0 ]]; then
    echo 'Installation requires root and an interactive terminal.' >&2; exit 1
  fi
  # Read the OS ID as data. Do not source shell code from the file.
  distro="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '\"')"
  case "$distro" in
    ubuntu|debian|linuxmint) install_cmd=(apt-get install python3) ;;
    fedora|rhel|centos|rocky|almalinux)
      if command -v dnf >/dev/null 2>&1; then install_cmd=(dnf install python3)
      else install_cmd=(yum install python3); fi ;;
    *) echo "Automatic installation is unsupported for: $distro. Ask the host owner." >&2; exit 1 ;;
  esac
  command -v "${install_cmd[0]}" >/dev/null || { echo 'Package manager unavailable.' >&2; exit 1; }
  echo 'This installs Python and dependencies from the configured system repositories.'
  echo 'It needs repository access and can change packages. No full update/upgrade is run.'
  printf 'Command: '; printf '%q ' "${install_cmd[@]}"; printf '\n'
  read -r -p 'Type INSTALL to continue: ' approval
  [[ "$approval" == INSTALL ]] || { echo 'Installation cancelled.'; exit 1; }
  "${install_cmd[@]}"  # Keep the package manager's own confirmation prompt.
  python_ready || { echo 'Python 3.8+ is still unavailable. Stop and review the host.' >&2; exit 1; }
fi
echo 'Python prerequisite: OK'
for tool in ip ss systemctl nft passwd; do
  if command -v "$tool" >/dev/null 2>&1; then echo "$tool: available"
  else echo "$tool: MISSING (dependent functions will not work)"; fi
done
if [[ "$mode" == --check ]]; then exit 0; fi
if [[ $EUID -ne 0 ]]; then echo 'Start the menu with sudo bash linux/start.sh' >&2; exit 1; fi
exec python3 "$script_dir/start.py"
