#!/usr/bin/env bash
# Hardware read-only inventory. No PIN, authentication, signing or writes.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo 'Execute with bash, not source.' >&2; return 2
fi
set -euo pipefail
PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"
BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
serial=''
while (($#)); do
  case "$1" in
    --serial) (($# > 1)) || exit 2; serial="$2"; shift 2 ;;
    --help|-h) echo 'Usage: bash scripts/workstation/inspect-age-yubikey-aes256-hardware.sh --serial 11110002|11110001 (read-only, no PIN)'; exit 0 ;;
    *) nabla_status error 'Unexpected option'; exit 2 ;;
  esac
done
case "${serial}" in
  "${BACKUP_SERIAL}") label='backup' ;;
  "${PRIMARY_SERIAL}") label='principal' ;;
  *) nabla_status error 'Only inventoried serials are allowed'; exit 2 ;;
esac
command -v ykman >/dev/null || { nabla_status error 'Missing ykman'; exit 1; }
# Capture command failures without silently assuming no device was found.
if ! inventory="$(ykman list --serials)"; then
  nabla_status error 'Unable to list YubiKeys'; exit 3
fi
mapfile -t attached < <(printf '%s\n' "${inventory}" | grep -E '^[[:space:]]*[0-9]+[[:space:]]*$' | tr -d '[:space:]' || true)
if (( ${#attached[@]} != 1 )) || [[ "${attached[0]:-}" != "${serial}" ]]; then
  nabla_status error 'Exactly one matching YubiKey must be connected'; exit 3
fi
if ! piv="$(ykman --device "${serial}" piv info)"; then
  nabla_status error 'Unable to inspect PIV status'; exit 3
fi
if ! grep -Eq 'Management key algorithm:[[:space:]]*AES256' <<<"${piv}"; then
  nabla_status error 'AES256 management-key algorithm not confirmed'; exit 3
fi
if ! grep -Fq 'Management key is stored on the YubiKey, protected by PIN.' <<<"${piv}"; then
  nabla_status error 'PIN-protected management-key storage not confirmed'; exit 3
fi
# ykman piv keys info may exit nonzero on an empty slot. Never mistake errors
# such as transport failures or permission denial for proof of emptiness.
slot82="$(ykman --device "${serial}" piv keys info 82 2>&1)" && rc82=0 || rc82=$?
# Some ykman versions report an empty slot with exit status 1.
# Accept only explicit empty-slot messages with rc 0 or 1.
# Yubico Manager 5.8.0 raises CliFail("No key stored in slot {slot}.")
# Click may prefix its single error line with "Error: "; PIV slot 82 is RETIRED1.
# Match the WHOLE response to avoid trusting a transport error with incidental text.
empty_slot_pattern='^[[:space:]]*(ERROR:[[:space:]]*)?No key stored in slot 82[[:space:]]*\(RETIRED1\)[.]?[[:space:]]*$'
if (( rc82 > 1 )) || ! grep -Eiq "$empty_slot_pattern" <<<"${slot82}"; then
  nabla_status warn "PIV82 unverified (ykman exit=${rc82}); no provisioning permitted"
  if grep -Eiq "permission|access denied|pcsc|smart.card|connection|timeout" <<<"${slot82}"; then
    nabla_status info 'Category: reader / access / transport error'
  elif grep -Eiq "key type|algorithm|pin policy|touch policy|public key" <<<"${slot82}"; then
    nabla_status info 'Category: key metadata reported; inspect slot separately'
  else
    nabla_status info 'Category: unsupported or unrecognized ykman response'
  fi
  exit 3
fi
slot9a="$(ykman --device "${serial}" piv keys info 9a 2>&1)" || {
  nabla_status error 'Cannot read PIV9A key metadata'; exit 3
}
if grep -Eiq "No key stored|No key in slot" <<<"${slot9a}"; then
  nabla_status error 'Previously populated PIV9A appears missing'; exit 3
fi
nabla_status ok "Read-only inventory: ${label} (${serial}), AES256/PIN-protected management key, PIV82 empty, PIV9A key metadata present"
nabla_status warn 'No PIN entered; AES256 authentication and age decrypt are NOT validated. Hardware writes remain NO-GO.'
