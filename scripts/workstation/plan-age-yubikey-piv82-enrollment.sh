#!/usr/bin/env bash
# Read-only, fail-closed operator plan for YubiKey PIV82 external age enrollment.
# Deliberately no apply path; two-phase provisioning must be executed manually.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo 'Run using bash, never source.' >&2; return 2
fi
set -euo pipefail
PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"
BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
serial=''
while (($#)); do
  case "$1" in
    --serial) (($# > 1)) || exit 2; serial="$2"; shift 2 ;;
    --help|-h) printf '%s\n' 'Usage: bash scripts/workstation/plan-age-yubikey-piv82-enrollment.sh --serial 11110002|11110001'; exit 0 ;;
    *) nabla_status error 'Unknown option'; exit 2 ;;
  esac
done
case "$serial" in
  "${BACKUP_SERIAL}") label='yubikey-5-nabla backup' ;;
  "${PRIMARY_SERIAL}") label='yubikey-5-nabla principal' ;;
  *) nabla_status error 'Unexpected serial: only inventoried devices are supported'; exit 2 ;;
esac
for command in ykman age-plugin-yubikey; do
  command -v "$command" >/dev/null || { nabla_status error "Missing dependency: $command"; exit 1; }
done
# Reuse the single verified, fail-closed hardware inventory. It checks AES256,
# the exact empty RETIRED1 response AND the presence of PIV9A key metadata.
# Never maintain a second copy of the PIV82 parser in the enrollment plan.
if ! bash "$(dirname -- "${BASH_SOURCE[0]}")/inspect-age-yubikey-aes256-hardware.sh" --serial "$serial"; then
  nabla_status error 'Hardware inventory did not pass; enrollment plan blocked'
  exit 3
fi
nabla_status ok "Read-only gate passed for selected serial $serial; PIV82 is empty, AES256 management key preserved"
nabla_status info "PIV PIN vault label: LastPass '$label' (never disclose the value)"
nabla_status warn 'PREPARATION ONLY: writing an irreversible on-card P-256 key needs a separate manual approval'
nabla_status info 'Manual key operation, after independent review: ykman --device SERIAL piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 82 OUTPUT_PUBLIC.pem'
nabla_status warn 'The second phase MUST create a plugin-compatible certificate with subject O=age-plugin-yubikey, OU=0.5.1 and policy OID 1.3.6.1.4.1.41482.3.8 = 03 02'
nabla_status warn 'Do not generate before the certificate phase is independently validated; a slot filled without usable cert may require recovery'
nabla_status info 'Verify by age-plugin-yubikey --list-all and a synthetic age encrypt/decrypt; preserve OTP2, PIV9A, AES256 and software SOPS recovery'
exit 0
