#!/usr/bin/env bash
# Offline software-key model of PIV82 CSR -> self-signed age plugin certificate.
# NEVER accesses YubiKey; only creates ephemeral files in a private temp directory.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo 'Execute using bash, do not source.' >&2; return 2
fi
set -euo pipefail
umask 077
dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/workstation/shell-status.sh
source "$dir/shell-status.sh"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: bash scripts/workstation/test-age-yubikey-csr-offline.sh (software fixture only)\n'; exit 0
fi
(($# == 0)) || { nabla_status error 'Unexpected arguments'; exit 2; }
for tool in openssl mktemp; do command -v "$tool" >/dev/null || { nabla_status error "Missing $tool"; exit 1; }; done
scratch="$(mktemp -d)"
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$scratch/fixture.key" >/dev/null 2>&1
openssl req -new -key "$scratch/fixture.key" -subj '/O=age-plugin-yubikey/OU=0.5.1/CN=nabla-age-backup' -out "$scratch/fixture.csr" >/dev/null 2>&1
cat >"$scratch/policy.cnf" <<'EOF'
[ext]
1.3.6.1.4.1.41482.3.8=DER:03:02
EOF
openssl x509 -req -in "$scratch/fixture.csr" -signkey "$scratch/fixture.key" -days 1 -extfile "$scratch/policy.cnf" -extensions ext -out "$scratch/fixture.crt" >/dev/null 2>&1
openssl req -in "$scratch/fixture.csr" -noout -verify >/dev/null 2>&1
openssl x509 -in "$scratch/fixture.crt" -pubkey -noout >"$scratch/cert.pub"
openssl pkey -in "$scratch/fixture.key" -pubout >"$scratch/key.pub"
cmp -s "$scratch/cert.pub" "$scratch/key.pub" || { nabla_status error 'Certificate does not match generated key'; exit 1; }
openssl x509 -in "$scratch/fixture.crt" -noout -text | grep -Fq '1.3.6.1.4.1.41482.3.8' || { nabla_status error 'Policy OID missing'; exit 1; }
nabla_status ok 'Offline CSR, P-256 self-signature, matching public key and policy OID'
nabla_status warn 'Software fixture only: no PIV slot, hardware PIN/touch or age-plugin decrypt validated'
