#!/usr/bin/env bash
# Read-only compatibility triage. NEVER modifies token settings or retries PINs.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo 'Execute with bash, do not source this script.' >&2; return 2
fi
set -euo pipefail
# shellcheck source=scripts/workstation/shell-status.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
serial=''
while (($#)); do
  case "$1" in
    --serial) (($# > 1)) || exit 2; serial="$2"; shift 2 ;;
    --help|-h) echo 'Usage: bash scripts/workstation/check-age-yubikey-aes-compat.sh --serial SERIAL (read-only)'; exit 0 ;;
    *) nabla_status error 'Unknown option'; exit 2 ;;
  esac
done
[[ "$serial" =~ ^[0-9]+$ ]] || { nabla_status error 'Provide explicit numeric serial'; exit 2; }
for cmd in ykman age-plugin-yubikey; do
  command -v "$cmd" >/dev/null || { nabla_status error "Missing $cmd"; exit 1; }
done
mapfile -t devices < <(ykman list --serials | grep -E '^[[:space:]]*[0-9]+[[:space:]]*$' | tr -d '[:space:]' || true)
if (( ${#devices[@]} != 1 )) || [[ "${devices[0]:-}" != "$serial" ]]; then
  nabla_status error 'Connect exactly the requested YubiKey and no others'
  exit 2
fi
info="$(ykman --device "$serial" piv info)" || { nabla_status error 'PIV status unavailable'; exit 1; }
if grep -Eq 'Management key algorithm:[[:space:]]*AES(128|192|256)' <<< "$info"; then
  nabla_status warn 'AES PIV management key detected. age-plugin-yubikey 0.5.1 generation is BLOCKED.'
  nabla_status info 'Preserve AES; research compatible on-card P-256 and certificate workflows before proceeding.'
  nabla_status info 'Do not enter PIN, downgrade to TDES, reset PIV, or use --force.'
  exit 3
fi
nabla_status info 'Management key algorithm not identified as AES. No generation performed.'
nabla_status warn 'Manual security review required; this tool never approves provisioning.'
exit 3
