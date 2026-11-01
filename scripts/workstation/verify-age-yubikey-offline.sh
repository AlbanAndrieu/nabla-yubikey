#!/usr/bin/env bash
# Offline quality gate. No YubiKey, PIN, management key or provisioning required.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf '%s\n' 'Execute using bash, never source.' >&2
  return 2
fi
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
# shellcheck source=scripts/workstation/shell-status.sh
source "${script_dir}/shell-status.sh"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: bash scripts/workstation/verify-age-yubikey-offline.sh\n'
  exit 0
fi
if (($#)); then
  nabla_status error 'Unexpected arguments'; exit 2
fi
for required in python3 openssl bash; do
  command -v "${required}" >/dev/null || { nabla_status error "Missing ${required}"; exit 1; }
done
nabla_status info 'Running offline YubiKey security contracts; no hardware required'
# Fail fast on syntax errors before any tests. These files never need a connected YubiKey.
for python_source in \
  "${repo_root}/tests/test_yubikey_keepassxc_diagnostic_contract.py" \
  "${script_dir}/inspect-age-yubikey-piv-aes256-sdk-api.py" \
  "${script_dir}/test-age-yubikey-piv-signing-sdk-offline.py" \
  "${script_dir}/test-age-yubikey-aes256-auth-offline.py" \
  "${script_dir}/test-age-yubikey-piv-aes256-handshake-offline.py" \
  "${script_dir}/test-age-yubikey-piv82-inventory-fake-offline.py" \
  "${script_dir}/test-age-yubikey-certificate-negative-offline.py" \
  "${script_dir}/verify-age-yubikey-piv82-certificate.py" \
  "${script_dir}/plan-age-yubikey-piv82-transaction.py" \
  "${script_dir}/verify-age-yubikey-piv82-attestation.py" \
  "${script_dir}/test-age-yubikey-piv82-attestation-offline.py" \
  "${script_dir}/verify-age-yubikey-f9-root-offline.py" \
  "${script_dir}/report-age-yubikey-piv82-readiness.py" \
  "${script_dir}/inspect-age-yubikey-piv82-secondary.py" \
  "${script_dir}/inspect-yubikey-recovery-readonly.py" \
  "${script_dir}/inspect-yubikey-applications-readonly.py" \
  "${script_dir}/inspect-yubikey-workstation-readonly.py" \
  "${script_dir}/diagnose-yubikey-readonly-batch.py" \
  "${script_dir}/inspect-gpg-agent-readonly.py" \
  "${repo_root}/tests/test_yubikey_gpg_agent_readonly.py" \
  "${repo_root}/tests/test_yubikey_readonly_batch.py" \
  "${repo_root}/tests/test_yubikey_workstation_readonly.py" \
  "${repo_root}/tests/test_yubikey_applications_readonly.py" \
  "${repo_root}/tests/test_yubikey_recovery_readonly.py" \
  "${repo_root}/tests/test_yubikey_piv82_secondary_inventory.py" \
  "${repo_root}/tests/test_yubikey_piv82_readiness_report.py" \
  "${script_dir}/test-age-yubikey-f9-root-offline.py" \
  "${repo_root}/tests/test_yubikey_piv82_transaction.py" \
  "${repo_root}/tests/test_yubikey_f9_inventory.py" \
  "${repo_root}/tests/test_yubikey_git_checkout_diagnostic.py" \
  "${repo_root}/tests/test_yubikey_f9_export.py" \
  "${repo_root}/tests/test_yubikey_pr274_readonly_runner.py"
do
  python3 -m py_compile "${python_source}"
done
for bash_source in \
  "${script_dir}/inspect-age-yubikey-aes256-hardware.sh" \
  "${script_dir}/plan-age-yubikey-piv82-enrollment.sh" \
  "${script_dir}/check-yubikey-piv-python-sdk.sh" \
  "${script_dir}/bootstrap-yubikey-piv-python-sdk.sh" \
  "${script_dir}/verify-age-yubikey-offline.sh" \
  "${script_dir}/inspect-age-yubikey-f9-chain.sh" \
  "${script_dir}/diagnose-age-yubikey-git-checkout.sh" \
  "${script_dir}/run-age-yubikey-pr274-readonly.sh"
do
  bash -n "${bash_source}"
done
python3 -m unittest discover -s "${repo_root}/tests" -p 'test_yubikey*.py' -v
# The cryptographic attestation fixture requires cryptography, not a live reader.
sdk_python="${HOME}/.local/share/nabla/piv-sdk-venv/bin/python"
if [[ ! -x "${sdk_python}" ]]; then
  sdk_python=python3
fi
if ! "${sdk_python}" -c 'import cryptography.x509' >/dev/null 2>&1; then
  nabla_status error 'Missing local cryptography SDK: attestation crypto gate cannot pass'
  exit 3
fi
"${sdk_python}" "${script_dir}/test-age-yubikey-piv82-attestation-offline.py"
"${sdk_python}" "${script_dir}/test-age-yubikey-f9-root-offline.py"
nabla_status ok 'Offline test suite passed'
nabla_status warn 'Not a hardware GO: AES256 compatible certificate install and real decrypt remain unverified'
