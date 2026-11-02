#!/usr/bin/env bash
# Read-only capture of the PIV82 response for troubleshooting parser mismatches.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'Execute using bash, not source.\n' >&2; return 2
fi
set -euo pipefail
PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"
BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"
if [[ "${1:-}" == "--help" ]]; then
  echo 'Usage: bash scripts/workstation/diagnose-age-yubikey-piv82-response.sh --serial 11110002|11110001'; exit 0
fi
[[ "${1:-}" == "--serial" && $# == 2 ]] || { echo 'Explicit --serial required' >&2; exit 2; }
serial="$2"
case "${serial}" in "${BACKUP_SERIAL}"|"${PRIMARY_SERIAL}") ;; *) echo 'Unexpected YubiKey serial' >&2; exit 2 ;; esac
command -v ykman >/dev/null || { echo 'ykman is missing' >&2; exit 2; }
inventory="$(ykman list --serials)" || { echo 'Cannot enumerate devices' >&2; exit 3; }
mapfile -t attached < <(printf '%s\n' "${inventory}" | grep -E '^[[:space:]]*[0-9]+[[:space:]]*$' | tr -d '[:space:]' || true)
if (( ${#attached[@]} != 1 )) || [[ "${attached[0]:-}" != "$serial" ]]; then
  echo 'Connect exactly the requested YubiKey' >&2; exit 3
fi
# This command reads key metadata only; it cannot unlock or mutate the token.
message="$(ykman --device "${serial}" piv keys info 82 2>&1)" && code=0 || code=$?
printf 'ykman exit code: %s\n' "${code}"
printf 'PIV82 diagnostic output (PUBLIC key metadata only; review before sharing):\n'
printf '%s\n' "${message}"
echo 'NO-GO: no provisioning is authorized by this diagnostic'
exit 0
