#!/usr/bin/env bash
# Transactional workstation-only PC/SC reader selection experiment.
set -euo pipefail
READER='Yubico YubiKey OTP+FIDO+CCID 00 00'
MODE="${1:---check}"
case "${MODE}" in
  --check|--apply) ;;
  -h|--help) echo 'Usage: test-gpg-reader-port.sh [--check|--apply]'; exit 0 ;;
  *) echo 'Invalid mode' >&2; exit 2 ;;
esac
[[ "${EUID}" -ne 0 ]] || { echo '❌ Do not run as root' >&2; exit 2; }
for cmd in gpgconf gpg timeout pcsc_scan cmp mktemp cp mv; do
  command -v "${cmd}" >/dev/null || { echo "❌ Missing ${cmd}" >&2; exit 1; }
done
cfg="$(gpgconf --list-dirs homedir)/scdaemon.conf"
backup="${cfg}.before-reader-port"
[[ -f "${cfg}" && -r "${cfg}" && -f "${backup}" && -r "${backup}" ]] || {
  echo '❌ Config or preexisting backup missing'; exit 1;
}
cmp -s "${cfg}" "${backup}" || { echo '❌ Current config differs from verified backup'; exit 1; }
grep -Eq '^[[:space:]]*disable-ccid([[:space:]]|$)' "${cfg}" || {
  echo '❌ disable-ccid missing'; exit 1;
}
if grep -Eq '^[[:space:]]*reader-port([[:space:]]|$)' "${cfg}"; then
  echo '❌ reader-port already configured'; exit 1
fi
scan="$(timeout 6 pcsc_scan -n 2>&1 || true)"
[[ "${scan}" == *"${READER}"* && "${scan}" == *'Card inserted'* ]] || {
  echo '❌ Expected PC/SC reader not confirmed'; exit 1;
}
echo '✅ PC/SC and original backup preflight passed'
[[ "${MODE}" == --check ]] && exit 0
echo '⚠️ Temporary scdaemon restart is required; no Git signing or backups may be active'
umask 077
stage=''
changed=false
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "${stage}" ]]; then rm -f -- "${stage}"; fi
  if [[ "${changed}" == true ]]; then
    if cp -p -- "${backup}" "${cfg}" && cmp -s "${cfg}" "${backup}"; then
      echo '✅ Original scdaemon.conf restored'
      gpgconf --kill scdaemon >/dev/null 2>&1 || true
    else
      echo "❌ ROLLBACK FAILED: restore manually from ${backup}" >&2
      rc=1
    fi
  fi
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage="$(mktemp "${cfg}.trial.XXXXXXXX")"
cp -p -- "${cfg}" "${stage}"
printf '\nreader-port %s\n' "${READER}" >> "${stage}"
changed=true
mv -f -- "${stage}" "${cfg}"
stage=''
if ! gpgconf --kill scdaemon; then
  echo '⚠️ scdaemon could not be refreshed; restoring'; exit 1
fi
if timeout 15 gpg --card-status >/dev/null 2>&1; then
  echo '✅ Card selected with explicit reader-port; restoring original anyway'
else
  echo '⚠️ GnuPG cannot select card with explicit reader-port; restoring original'
fi
