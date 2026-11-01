#!/usr/bin/env bash
# Safe, reversible test of pcsc-shared in the existing user's GnuPG home.
# No keys, PINs or slots are changed. Run only when other GPG work is idle.
set -euo pipefail
mode="${1:---check}"
case "${mode}" in
  --check|--trial) ;;
  -h|--help) printf '%s\n' 'Usage: trial-gpg-pcsc-shared.sh [--check|--trial]'; exit 0 ;;
  *) echo 'Unknown option' >&2; exit 2 ;;
esac
[[ "${EUID}" -ne 0 ]] || { echo '❌ Refusing root execution' >&2; exit 2; }
for cmd in gpgconf gpg timeout cmp mktemp cp mv grep; do
  command -v "${cmd}" >/dev/null || { echo "❌ Missing ${cmd}" >&2; exit 2; }
done
home="$(gpgconf --list-dirs homedir)"
cfg="${home}/scdaemon.conf"
backup="${cfg}.before-reader-port"
[[ -f "${cfg}" && -f "${backup}" && -r "${cfg}" && -r "${backup}" ]] ||
  { echo '❌ Missing readable original config or verified backup' >&2; exit 1; }
[[ ! -L "${cfg}" && ! -L "${backup}" ]] ||
  { echo '❌ Symlinked config or backup not supported' >&2; exit 1; }
cmp -s -- "${cfg}" "${backup}" ||
  { echo '❌ Current config differs from historical verified backup' >&2; exit 1; }
grep -Eq '^[[:space:]]*disable-ccid([[:space:]]|$)' "${cfg}" ||
  { echo '❌ disable-ccid missing' >&2; exit 1; }
if grep -Eq '^[[:space:]]*(pcsc-shared|reader-port)([[:space:]]|$)' "${cfg}"; then
  echo '❌ Conflicting or already-enabled option; refusing trial' >&2
  exit 1
fi
if ! /usr/lib/gnupg/scdaemon --dump-options 2>/dev/null | grep -qx -- '--pcsc-shared'; then
  echo '❌ Installed scdaemon lacks pcsc-shared option' >&2; exit 1
fi
echo '✅ Validated original configuration and pcsc-shared support'
if [[ "${mode}" == --check ]]; then
  echo 'ℹ️ Read-only preflight; no change to GnuPG'
  exit 0
fi
echo '⚠️ Trial will momentarily replace scdaemon.conf and restart scdaemon ONLY.'
echo '⚠️ Do not run with concurrent signatures, decryption or other card clients.'
umask 077
stage=''
changed=false
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "${stage}" ]]; then rm -f -- "${stage}"; fi
  if [[ "${changed}" == true ]]; then
    if cp -p -- "${backup}" "${cfg}" && cmp -s -- "${cfg}" "${backup}"; then
      echo '✅ Historical configuration restored byte-for-byte'
      gpgconf --kill scdaemon >/dev/null 2>&1 ||
        echo '⚠️ Could not refresh scdaemon after restore' >&2
    else
      echo "❌ RESTORE FAILED — recover manually from: ${backup}" >&2
      rc=1
    fi
  fi
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage="$(mktemp "${home}/.scdaemon-pcsc-shared.XXXXXXXX")"
cp -p -- "${cfg}" "${stage}"
printf '\npcsc-shared\n' >> "${stage}"
changed=true
mv -f -- "${stage}" "${cfg}"
stage=''
gpgconf --kill scdaemon
if timeout 18 gpg --batch --card-status >/dev/null 2>&1; then
  echo '✅ Main GnuPG profile detects OpenPGP with pcsc-shared enabled temporarily'
else
  echo '❌ Main GnuPG profile still cannot select OpenPGP card'
  exit 1
fi
echo 'ℹ️ Rolling back even after success; persistent enablement is NOT performed.'
