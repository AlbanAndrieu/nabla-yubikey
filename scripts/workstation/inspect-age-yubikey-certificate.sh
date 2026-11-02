#!/usr/bin/env bash
# Offline, read-only X.509 inspection for externally provisioned age/YubiKey certificates.
# This is NOT a provisioning tool, and cannot prove private-key or decrypt compatibility.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo 'Execute with bash; do not source.' >&2; return 2
fi
set -euo pipefail
# shellcheck source=scripts/workstation/shell-status.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/shell-status.sh"
certificate=''
while (($#)); do
  case "$1" in
    --certificate) (($# >= 2)) || exit 2; certificate="$2"; shift 2 ;;
    --help|-h) echo 'Usage: bash scripts/workstation/inspect-age-yubikey-certificate.sh --certificate PATH.pem (offline, read-only)'; exit 0 ;;
    *) nabla_status error 'Unknown argument'; exit 2 ;;
  esac
done
[[ -f "$certificate" && ! -L "$certificate" && -r "$certificate" ]] || {
  nabla_status error 'Provide a readable regular certificate, not a symlink'; exit 2;
}
command -v openssl >/dev/null || { nabla_status error 'openssl is required'; exit 1; }
# No raw certificate dump; public metadata only. Never read PINs or management keys.
subject="$(openssl x509 -in "$certificate" -noout -subject -nameopt RFC2253)" || {
  nabla_status error 'Cannot parse X.509 certificate'; exit 1;
}
algorithm="$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -text -noout)" || {
  nabla_status error 'Cannot inspect public key'; exit 1;
}
if ! grep -Eq 'ASN1 OID: prime256v1|NIST CURVE: P-256' <<< "$algorithm"; then
  nabla_status error 'Certificate does not expose an EC P-256 public key'; exit 3
fi
nabla_status ok 'X.509 public-key algorithm: EC P-256'
if grep -Fq 'O=age-plugin-yubikey' <<< "$subject"; then
  nabla_status ok 'Subject organization matches age-plugin-yubikey discovery convention'
else
  nabla_status warn 'Subject lacks O=age-plugin-yubikey; automatic plugin discovery may not work'
fi
# Require the Yubico attestation policy extension exactly once and non-critical.
# OpenSSL renders the policy payload as two bytes following the OID.
extensions="$(openssl x509 -in "$certificate" -noout -ext 1.3.6.1.4.1.41482.3.8 2>&1)" || {
  nabla_status error 'Cannot inspect policy extension'; exit 3;
}
# OpenSSL versions vary in rendering, so do not infer policy bytes from human text.
# DER is parsed in the synthetic unittest contract; real certificate policy remains pending.
if grep -Eiq 'No extensions|not found|does not contain' <<< "$extensions"; then
  nabla_status warn 'PIV policy extension not found; PIN/touch certificate metadata unverified'
else
  nabla_status info 'PIV policy extension reported; exact DER bytes require separate inspection'
fi
nabla_status warn 'Certificate-only inspection cannot verify PIN/touch OIDs, slot binding, management-key behavior or successful age decryption'
nabla_status info 'Next validation requires explicit plugin --list-all/--identity and synthetic age decrypt on an approved test device'
exit 3
