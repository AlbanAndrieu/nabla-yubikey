#!/usr/bin/env bash
# Compare OpenPGP detection over PC/SC vs integrated CCID in isolated GnuPG homes.
set -euo pipefail
mode="${1:---check}"
case "${mode}" in
  --check|--run|--pcsc-shared) ;;
  -h|--help) echo 'Usage: compare-gpg-card-transports.sh [--check|--run|--pcsc-shared]'; exit 0 ;;
  *) echo 'Invalid option' >&2; exit 2 ;;
esac
[[ ${EUID} -ne 0 ]] || { echo '❌ Do not run as root.' >&2; exit 2; }
for cmd in gpg gpgconf timeout mktemp; do
  command -v "${cmd}" >/dev/null || { echo "❌ Missing ${cmd}" >&2; exit 1; }
done
printf '🔐 Isolated OpenPGP transport comparison\n'
if [[ "${mode}" == --check ]]; then
  echo '✅ Dependencies present; no GPG profile or YubiKey configuration changed.'
  echo 'ℹ️ --run contacts the card and may temporarily compete for its CCID interface.'
  exit 0
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/gpg-transport.XXXXXXXX")"
chmod 700 "${work}"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  for profile in pcsc ccid pcsc-shared; do
    if [[ -d "${work}/${profile}" ]]; then
      GNUPGHOME="${work}/${profile}" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    fi
  done
  rm -rf -- "${work}"
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ "${mode}" == --pcsc-shared ]]; then
  transports=(pcsc-shared)
else
  transports=(pcsc ccid)
fi
for transport in "${transports[@]}"; do
  profile="${work}/${transport}"
  mkdir -m 700 "${profile}"
  case "${transport}" in
    pcsc) printf 'disable-ccid\n' > "${profile}/scdaemon.conf" ;;
    pcsc-shared) printf 'disable-ccid\npcsc-shared\n' > "${profile}/scdaemon.conf" ;;
    ccid) : > "${profile}/scdaemon.conf" ;;
  esac
  chmod 600 "${profile}/scdaemon.conf"
  echo "🔎 Testing ${transport} (isolated agent, no keys imported)"
  if GNUPGHOME="${profile}" timeout 18 gpg --batch --card-status >/dev/null 2>"${work}/${transport}.stderr"; then
    echo "✅ ${transport}: OpenPGP card detected"
  else
    rc=$?
    if [[ "${rc}" -eq 124 ]]; then
      echo "⚠️ ${transport}: timed out"
    elif grep -q 'No such device' "${work}/${transport}.stderr"; then
      echo "⚠️ ${transport}: No such device"
    else
      echo "⚠️ ${transport}: card access failed (details suppressed)"
    fi
  fi
done
echo '✅ Temporary GnuPG profiles will be removed; primary profile unchanged.'
