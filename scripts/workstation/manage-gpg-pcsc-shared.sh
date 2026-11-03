#!/usr/bin/env bash
# Explicit persistent pcsc-shared enablement with verified rollback.
set -euo pipefail
mode="${1:---check}"
case "${mode}" in
  --check|--verify|--apply|--rollback) ;;
  --help|-h) echo 'Usage: manage-gpg-pcsc-shared.sh [--check|--verify|--apply|--rollback]'; exit 0 ;;
  *) echo 'Invalid option' >&2; exit 2 ;;
esac
[[ "${EUID}" -ne 0 ]] || { echo '❌ Refusing root' >&2; exit 2; }
for cmd in gpg gpgconf timeout cmp mktemp cp mv grep; do
  command -v "${cmd}" >/dev/null || { echo "❌ Missing ${cmd}" >&2; exit 2; }
done
home="$(gpgconf --list-dirs homedir)"
cfg="${home}/scdaemon.conf"
original="${cfg}.before-reader-port"
[[ -f "${cfg}" && -f "${original}" && -r "${cfg}" && -r "${original}" && ! -L "${cfg}" && ! -L "${original}" ]] || {
  echo '❌ Config or historical backup missing or symlinked' >&2; exit 1;
}
grep -Eq '^[[:space:]]*disable-ccid([[:space:]]|$)' "${original}" || {
  echo '❌ Historical configuration does not use PC/SC' >&2; exit 1;
}
if grep -Eq '^[[:space:]]*(pcsc-shared|reader-port)([[:space:]]|$)' "${original}"; then
  echo '❌ Historical config is not the unmodified baseline' >&2; exit 1
fi
if ! /usr/lib/gnupg/scdaemon --dump-options 2>/dev/null | grep -qx -- '--pcsc-shared'; then
  echo '❌ pcsc-shared unsupported' >&2; exit 1
fi
umask 077
# Compare to a canonical derived representation, not only a grep, to detect unrelated edits.
expected=''
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "${expected}" ]]; then rm -f -- "${expected}"; fi
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
expected="$(mktemp "${home}/.scdaemon-expected.XXXXXXXX")"
cp -p -- "${original}" "${expected}"
printf '\npcsc-shared\n' >> "${expected}"
if cmp -s -- "${cfg}" "${original}"; then
  current=original
elif cmp -s -- "${cfg}" "${expected}"; then
  current=shared
else
  echo '❌ Configuration drift detected; refusing to change' >&2; exit 1
fi
echo "ℹ️ Current managed state: ${current}"
if [[ "${mode}" == --check ]]; then
  echo '✅ Baseline and managed-state verification complete (no profile changes)'
  exit 0
fi
if [[ "${mode}" == --verify ]]; then
  if timeout 18 gpg --batch --card-status >/dev/null 2>&1; then
    echo '✅ Live OpenPGP selection operational (no config change)'
  else
    echo '❌ Live OpenPGP selection failed despite saved configuration state' >&2
    echo 'ℹ️ Check other PC/SC clients and stale scdaemon state; do not reapply blindly' >&2
    exit 1
  fi
  exit 0
fi
if [[ "${mode}" == --apply && "${current}" == shared ]]; then
  echo 'ℹ️ pcsc-shared already configured; validating actual card access'
  if timeout 18 gpg --batch --card-status >/dev/null 2>&1; then
    echo '✅ Live OpenPGP selection operational'
  else
    echo '❌ Live OpenPGP selection failed; leaving configuration unchanged' >&2
    exit 1
  fi
  exit 0
fi
if [[ "${mode}" == --rollback && "${current}" == original ]]; then
  echo '✅ Original configuration already active (no change)'
  exit 0
fi
echo '⚠️ Ensure no GPG operation, Git signature or card client is active.'
stage="$(mktemp "${home}/.scdaemon-switch.XXXXXXXX")"
# No trap guarantees restoration on SIGKILL or power loss; operator retains original.
trap 'rm -f -- "${stage}"; cleanup' EXIT
if [[ "${mode}" == --apply ]]; then
  cp -p -- "${expected}" "${stage}"
else
  cp -p -- "${original}" "${stage}"
fi
mv -f -- "${stage}" "${cfg}"
trap cleanup EXIT
if ! gpgconf --kill scdaemon; then
  echo '❌ scdaemon refresh failed; attempting rollback' >&2
  cp -p -- "${original}" "${cfg}"
  gpgconf --kill scdaemon >/dev/null 2>&1 || true
  exit 1
fi
if [[ "${mode}" == --rollback ]]; then
  cmp -s -- "${cfg}" "${original}" || { echo '❌ Rollback verification failed' >&2; exit 1; }
  echo '✅ Original configuration restored; card access under original mode not expected'
  exit 0
fi
if timeout 18 gpg --batch --card-status >/dev/null 2>&1; then
  echo '✅ Persistent pcsc-shared enabled and OpenPGP detected'
  echo '⚠️ Card detection does not validate PIN, Git signing or decryption'
else
  echo '❌ Detection failed; restoring original configuration' >&2
  cp -p -- "${original}" "${cfg}"
  gpgconf --kill scdaemon >/dev/null 2>&1 || true
  cmp -s -- "${cfg}" "${original}" || echo '❌ Manual recovery needed' >&2
  exit 1
fi
