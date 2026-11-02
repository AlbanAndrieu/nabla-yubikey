#!/usr/bin/env bash
# Verify that a USB-held independent age key restores the original SOPS identity.
# Only writes restored plaintext to a private RAM-backed temporary directory.
set -euo pipefail
umask 077
backup=''
identity=''
expected='age1t8wn2gqcpzxwvwhjwxwtdwp0tvr6k2z9j39v4q2fr55qhmqz7f2qvn25cp'
usage() {
  echo 'Usage: verify-sops-age-escrow.sh --backup PATH.age --identity USB/recovery-identity.txt'
  echo 'Decryption occurs only in private tmpfs (/dev/shm); no private key material is printed.'
}
while (($#)); do
  case "$1" in
    --backup) (($# > 1)) || exit 2; backup="$2"; shift 2 ;;
    --identity) (($# > 1)) || exit 2; identity="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'Unknown option' >&2; exit 2 ;;
  esac
done
[[ -f "${backup}" && ! -L "${backup}" && -f "${identity}" && ! -L "${identity}" ]] || {
  echo 'Existing regular backup and USB identity required' >&2; exit 2;
}
[[ "$(stat -c %a "${identity}")" == 600 ]] || {
  echo 'USB recovery identity must have mode 600' >&2; exit 2;
}
[[ -d /dev/shm && "$(findmnt -n -o FSTYPE -T /dev/shm)" == tmpfs ]] || {
  echo 'Secure tmpfs is required for test material' >&2; exit 2;
}
for tool in age age-keygen mktemp; do
  command -v "${tool}" >/dev/null || exit 1
done
tmp="$(mktemp -d /dev/shm/nabla-sops-recovery.XXXXXXXX)"
chmod 700 "${tmp}"
cleanup() { rm -f -- "${tmp}/restored-identity.txt"; rmdir -- "${tmp}"; }
trap cleanup EXIT
age -d -i "${identity}" -o "${tmp}/restored-identity.txt" "${backup}" >/dev/null
restored="$(age-keygen -y "${tmp}/restored-identity.txt" 2>/dev/null)" || {
  echo 'Restored age private identity is invalid' >&2; exit 1;
}
[[ "${restored}" == "${expected}" ]] || { echo 'Restored identity does not match SOPS recipient' >&2; exit 1; }
echo 'PASS: TrueNAS encrypted backup decrypted with USB key and recovered original SOPS public recipient.'
echo 'NOTE: this verifies identity recovery, not full SOPS decrypt; test fixture separately.'
