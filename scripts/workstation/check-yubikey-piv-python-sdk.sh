#!/usr/bin/env bash
# Offline capability discovery: no PIV opening, PIN entry or hardware writes.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'Execute with bash; do not source.\n' >&2; return 2
fi
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
python_bin="${NABLA_PIV_PYTHON:-python3}"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  printf 'Usage: bash scripts/workstation/check-yubikey-piv-python-sdk.sh (offline, read-only)\n'; exit 0
fi
(($# == 0)) || { nabla_status error 'Unexpected argument'; exit 2; }
command -v "$python_bin" >/dev/null || { nabla_status error "Python unavailable: $python_bin"; exit 1; }
if "$python_bin" - <<'PY'
import importlib.util
import sys
modules = ["ykman", "yubikit", "cryptography"]
missing = [mod for mod in modules if importlib.util.find_spec(mod) is None]
if missing:
    print("Missing Python SDK modules: " + ", ".join(missing))
    sys.exit(2)
from ykman.piv import sign_certificate_builder
from cryptography import x509
from yubikit.piv import SLOT, KEY_TYPE
assert callable(sign_certificate_builder)
assert hasattr(x509, "UnrecognizedExtension")
assert hasattr(SLOT, "RETIRED1")
assert hasattr(KEY_TYPE, "ECCP256")
print("Python SDK imports and signing-builder capability available")
PY
then
  nabla_status ok 'SDK capability gate: custom X.509 signing API is available without downgrading AES'
else
  nabla_status warn 'SDK gate not satisfied in current Python; do not provision a key'
  nabla_status info 'Use an isolated virtual environment with pinned yubikey-manager, yubikit and cryptography after review'
  exit 3
fi
nabla_status warn 'SDK availability is not proof of token interoperability. Hardware writes remain blocked.'
