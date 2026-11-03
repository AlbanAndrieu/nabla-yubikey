#!/usr/bin/env bash
# End-to-end SOPS recovery smoke test; execute with bash, NEVER source.
# Does not touch PIV/OTP, shell profiles, or the original software identity.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'ERROR: execute using bash script-path, never source it (set -e and EXIT trap).\n' >&2
  return 2
fi
set -euo pipefail
# shellcheck source=scripts/workstation/shell-status.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
umask 077
backup=''
usb_identity=''
recipient='age1t8wn2gqcpzxwvwhjwxwtdwp0tvr6k2z9j39v4q2fr55qhmqz7f2qvn25cp'
usage() {
  printf '%s\n' 'Usage: bash scripts/workstation/test-sops-usb-recovery.sh --backup PATH.age --usb-identity PATH'
  printf '%s\n' 'Runs isolated synthetic SOPS roundtrip using recovered software age identity in /dev/shm.'
}
while (( $# )); do
  case "$1" in
    --backup) (( $# >= 2 )) || exit 2; backup="$2"; shift 2 ;;
    --usb-identity) (( $# >= 2 )) || exit 2; usb_identity="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'Unknown option' >&2; exit 2 ;;
  esac
done
[[ -f "${backup}" && ! -L "${backup}" && -r "${backup}" && -f "${usb_identity}" && ! -L "${usb_identity}" && -r "${usb_identity}" ]] || {
  echo 'Backup and USB identity must be regular readable files' >&2; exit 2;
}
[[ "$(stat -c %a "${usb_identity}")" == 600 ]] || { echo 'USB identity permissions must be 600' >&2; exit 2; }
[[ "$(findmnt -n -o FSTYPE -T /dev/shm)" == tmpfs ]] || { echo '/dev/shm is not tmpfs' >&2; exit 2; }
for cmd in age age-keygen sops mktemp grep; do
  command -v "${cmd}" >/dev/null || {
    echo "Missing dependency: ${cmd}" >&2
    exit 1
  }
done
tmp="$(mktemp -d /dev/shm/nabla-sops-smoke.XXXXXXXX)"
cleanup() {
  rm -f -- "${tmp}/restored.txt" "${tmp}/test.yaml" "${tmp}/encrypted.yaml" "${tmp}/decrypted.yaml"
  rmdir -- "${tmp}"
}
trap cleanup EXIT
age -d -i "${usb_identity}" -o "${tmp}/restored.txt" "${backup}"
[[ "$(age-keygen -y "${tmp}/restored.txt" 2>/dev/null)" == "${recipient}" ]] || {
  echo 'Recovered age identity mismatch' >&2; exit 1;
}
printf 'message: sops-recovery-ok\n' > "${tmp}/test.yaml"
sops encrypt --age "${recipient}" --input-type yaml --output-type yaml "${tmp}/test.yaml" > "${tmp}/encrypted.yaml"
# Prevent SOPS from falling back to the workstation home identity.
SOPS_AGE_KEY_FILE="${tmp}/restored.txt" SOPS_AGE_KEY='' \
  sops decrypt "${tmp}/encrypted.yaml" > "${tmp}/decrypted.yaml"
grep -Fxq 'message: sops-recovery-ok' "${tmp}/decrypted.yaml"
nabla_status ok 'PASS: SOPS recovery with USB-backed escrow'
