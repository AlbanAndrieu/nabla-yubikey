#!/usr/bin/env bash
# Encrypt a SOPS age identity locally BEFORE sending it to backup storage.
# The recipient must be an INDEPENDENT offsite escrow identity, not the identity being backed up.
set -euo pipefail
# shellcheck source=scripts/workstation/shell-status.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
umask 077
source_file="${HOME}/.config/sops/age/keys.txt"
destination=''
recipient=''
apply=false
usage() {
  cat <<'EOF'
Usage: backup-sops-age-identity.sh --destination EXISTING_DIR --recipient age1... [--apply]
  --apply  Create one encrypted age file in the existing destination; never overwrite.
  Default: check only. Destination must reside on a mounted non-root filesystem.
  Use an INDEPENDENT recovery identity whose private key is stored OFF the workstation.
  Does not print, export, or decrypt any private key.
EOF
}
while (($#)); do
  case "$1" in
    --destination) (($#>1)) || exit 2; destination="$2"; shift 2 ;;
    --recipient) (($#>1)) || exit 2; recipient="$2"; shift 2 ;;
    --apply) apply=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'Unknown option' >&2; exit 2 ;;
  esac
done
[[ -n "${destination}" && "${recipient}" =~ ^age1[023456789acdefghjklmnpqrstuvwxyz]+$ ]] || {
  echo 'Provide an existing backup directory and a valid age recipient' >&2; exit 2;
}
for tool in age age-keygen findmnt stat mktemp sha256sum; do
  command -v "${tool}" >/dev/null || { echo "Missing tool: ${tool}" >&2; exit 1; }
done
[[ -f "${source_file}" && ! -L "${source_file}" ]] || { echo 'Source identity absent/symlink' >&2; exit 1; }
[[ "$(stat -c %u "${source_file}")" == "$(id -u)" && "$(stat -c %a "${source_file}")" == 600 ]] || {
  echo 'Source identity needs current-user ownership and mode 600' >&2; exit 1;
}
[[ "$(stat -c %a "$(dirname "${source_file}")")" == 700 ]] || {
  echo 'Source directory needs mode 700' >&2; exit 1;
}
existing_recipient="$(age-keygen -y "${source_file}")" || { echo 'Cannot derive existing identity public recipient' >&2; exit 1; }
[[ "${recipient}" != "${existing_recipient}" ]] || {
  echo 'Escrow recipient must be independent of source identity' >&2; exit 2;
}
[[ -d "${destination}" && ! -L "${destination}" ]] || { echo 'Existing destination directory required' >&2; exit 2; }
destination="$(realpath -e -- "${destination}")"
mount_target="$(findmnt -n -o TARGET -T "${destination}")"
[[ -n "${mount_target}" && "${mount_target}" != / ]] || {
  echo 'Destination must be on a separately mounted backup filesystem' >&2; exit 2;
}
[[ -w "${destination}" ]] || { echo 'Destination not writable' >&2; exit 2; }
nabla_status ok 'Escrow preflight OK: mounted destination verified; local identity permissions 600/700; independent recipient provided.'
if ! "${apply}"; then
  nabla_status info 'CHECK ONLY: no file created. Pass --apply after safeguarding independent escrow private key.'
  exit 0
fi
# Never print recipient, private key, ciphertext or sensitive path in routine output.
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="${destination}/sops-age-identity-${stamp}.age"
[[ ! -e "${output}" ]] || { echo 'Refusing overwrite' >&2; exit 2; }
temp="$(mktemp "${destination}/.sops-age-identity.XXXXXXXX")"
cleanup() { rm -f -- "${temp}"; }
trap cleanup EXIT
age -e -r "${recipient}" -o "${temp}" "${source_file}"
[[ -s "${temp}" ]] || { echo 'Empty encrypted backup' >&2; exit 1; }
chmod 600 "${temp}"
# Fail rather than overwriting another process's file.
ln "${temp}" "${output}"
rm -- "${temp}"
trap - EXIT
nabla_status ok 'Encrypted backup created (age recipient escrow); OFFLINE DECRYPTION/RECOVERY TEST STILL REQUIRED.'
nabla_status warn 'Do not delete the current identity or provision PIV keys until offline restore passes.'
