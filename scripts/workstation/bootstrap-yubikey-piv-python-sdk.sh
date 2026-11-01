#!/usr/bin/env bash
# Isolated PIV Python SDK bootstrap. Check-only by default; opt-in installation.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'Execute with bash, never source.\n' >&2; return 2
fi
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
venv="${NABLA_PIV_VENV:-${HOME}/.local/share/nabla/piv-sdk-venv}"
apply=false
while (($#)); do
  case "$1" in
    --check) shift ;;
    --apply) apply=true; shift ;;
    --help|-h) printf 'Usage: bash scripts/workstation/bootstrap-yubikey-piv-python-sdk.sh [--check|--apply]\nDefault: check-only. --apply creates private venv and installs pinned SDK; never touches a YubiKey.\n'; exit 0 ;;
    *) nabla_status error 'Unknown option'; exit 2 ;;
  esac
done
[[ "$venv" == /* && "$venv" != / ]] || { nabla_status error 'Absolute private venv path required'; exit 2; }
[[ ! -L "$venv" ]] || { nabla_status error 'Refusing symlink venv'; exit 2; }
if [[ -x "$venv/bin/python" ]]; then
  NABLA_PIV_PYTHON="$venv/bin/python" bash "$(dirname -- "${BASH_SOURCE[0]}")/check-yubikey-piv-python-sdk.sh"
  exit $?
fi
if [[ "$apply" == false ]]; then
  nabla_status warn "Isolated SDK venv missing: $venv"
  nabla_status info 'Run --apply after reviewing pinned dependency versions and network trust'
  exit 3
fi
command -v python3 >/dev/null || { nabla_status error 'python3 missing'; exit 1; }
umask 077
mkdir -p -- "$(dirname -- "$venv")"
python3 -m venv "$venv"
# Pinned top-level packages. Resolve transitive versions to a locked artifact before production use.
"$venv/bin/python" -m pip install --disable-pip-version-check 'yubikey-manager==5.8.0' 'cryptography==46.0.3'
NABLA_PIV_PYTHON="$venv/bin/python" bash "$(dirname -- "${BASH_SOURCE[0]}")/check-yubikey-piv-python-sdk.sh"
