#!/usr/bin/env bash
# Read-only preparation for a supervised GnuPG PC/SC reader-port experiment.
set -euo pipefail
case "${1:---check}" in
  --check) ;;
  -h|--help) printf '%s\n' 'Usage: bash scripts/workstation/plan-gpg-reader-port.sh --check'; exit 0 ;;
  *) printf '%s\n' 'Unknown option; use --check' >&2; exit 2 ;;
esac
if [[ ${EUID} -eq 0 ]]; then
  printf '%s\n' '❌ Run as workstation user, never root.' >&2; exit 2
fi
if ! command -v gpgconf >/dev/null || ! command -v pcsc_scan >/dev/null; then
  printf '%s\n' '⚠️ gpgconf and pcsc_scan are needed for reader selection.'; exit 1
fi
cfg="$(gpgconf --list-dirs homedir)/scdaemon.conf"
printf '%s\n' '🔐 GnuPG PC/SC reader-port preflight (read-only)'
if [[ ! -f "${cfg}" || ! -r "${cfg}" ]]; then
  printf '%s\n' '⚠️ scdaemon.conf missing/unreadable. Do not create it implicitly.'; exit 1
fi
if grep -Eq '^[[:space:]]*reader-port([[:space:]]|$)' "${cfg}"; then
  printf '%s\n' '⚠️ reader-port already present; review existing settings, do not append.'; exit 1
fi
if ! grep -Eq '^[[:space:]]*disable-ccid([[:space:]]|$)' "${cfg}"; then
  printf '%s\n' '⚠️ disable-ccid not detected; investigate transport choice before reader-port.'; exit 1
fi
if [[ -e "${cfg}.before-reader-port" ]]; then
  printf '%s\n' '⚠️ Previous backup exists; preserve it and review manually.'; exit 1
fi
scan="$(timeout 5 pcsc_scan -n 2>&1 || true)"
if [[ "${scan}" != *'Yubico YubiKey OTP+FIDO+CCID 00 00'* || "${scan}" != *'Card inserted'* ]]; then
  printf '%s\n' '⚠️ Expected YubiKey PC/SC reader and inserted card not confirmed.'; exit 1
fi
printf '%s\n' '✅ Expected PC/SC reader present; configuration eligible for manual trial.'
printf '%s\n' 'ℹ️ No changes made. Read docs/workstation-yubikey-gpg-vault-roadmap.md'
printf '%s\n' 'ℹ️ Complete signed Git and GPG backup tasks before supervised trial.'
