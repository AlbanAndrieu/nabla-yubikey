#!/usr/bin/env bash
# Non-destructive workstation YubiKey / KeePassXC diagnostics.
set -euo pipefail
export LC_ALL=C
challenge=00112233445566778899aabbccddeeff00112233
reference=781ce55cb1a8f41790f0cc758d26171f60f39c3c
serial=''
check_slots=false
verify_secret=false
usage() {
  cat <<'EOF'
Usage: bash scripts/workstation/diagnose-yubikey-keepassxc.sh [--serial SERIAL] [--challenge] [--verify-secret]
  --challenge      Read-only HMAC-SHA1 probe (responses suppressed).
  --verify-secret  Verify exported HMAC_SECRET against previously observed
                   reference response; never print secret or digest.
  --serial SERIAL  Choose device; leave only one YubiKey connected.
No command changes OTP/PIV/FIDO2 slots or KeePassXC databases.
EOF
}
while (($#)); do
  case "$1" in
    --serial) (($# > 1)) || { echo 'Missing serial' >&2; exit 2; }; serial="$2"; shift 2 ;;
    --challenge) check_slots=true; shift ;;
    --verify-secret) verify_secret=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "${serial}" && ! "${serial}" =~ ^[0-9]+$ ]]; then echo 'Invalid serial' >&2; exit 2; fi
if "${verify_secret}"; then
  command -v python3 >/dev/null || { echo 'python3 missing' >&2; exit 1; }
  # Suppress echoing/debug; inherited environment already holds HMAC_SECRET.
  python3 - <<'PY'
import hashlib
import hmac
import os
import sys

raw = os.environ.get("HMAC_SECRET", "")
key = "".join(raw.split())
if len(key) != 40 or any(c not in "0123456789abcdefABCDEF" for c in key):
    sys.exit("FAIL: HMAC_SECRET must contain 40 hexadecimal characters")
expected = hmac.new(
    bytes.fromhex(key),
    bytes.fromhex("00112233445566778899aabbccddeeff00112233"),
    hashlib.sha1,
).hexdigest()
if not hmac.compare_digest(expected, "781ce55cb1a8f41790f0cc758d26171f60f39c3c"):
    sys.exit("FAIL: HMAC_SECRET differs from verified reference")
print("PASS: exported HMAC_SECRET matches verified reference (secret hidden)")
PY
fi
command -v ykman >/dev/null || { echo 'Missing ykman: use bootstrap-yubikey-manager.sh --check' >&2; exit 1; }
echo '== Tools =='
ykman --version
if command -v keepassxc >/dev/null; then keepassxc --version 2>&1 | head -n 2 || true; fi
echo '== Connected devices =='
ykman list --serials
devices="$(ykman list --serials | grep -Ec '^[0-9]+$' || true)"
if [[ "${devices}" != 1 ]]; then
  echo 'Connect exactly one key for reliable device diagnosis.' >&2
  exit 2
fi
connected="$(ykman list --serials | grep -E '^[0-9]+$' | head -n 1)"
if [[ -n "${serial}" && "${connected}" != "${serial}" ]]; then
  echo 'Requested serial is not the connected device' >&2; exit 2
fi
args=(--device "${connected}")
ykman "${args[@]}" info
ykman "${args[@]}" otp info
echo '== USB HID =='
if command -v lsusb >/dev/null; then lsusb -d 1050: || true; fi
if command -v udevadm >/dev/null; then
  for dev in /dev/hidraw*; do
    [[ -e "${dev}" ]] || continue
    props="$(udevadm info --query=property --name="${dev}" 2>/dev/null || true)"
    if [[ "${props}" == *'ID_VENDOR_ID=1050'* || "${props}" == *'00001050'* ]]; then
      stat -c '%n %A %U:%G' "${dev}"
      [[ -r "${dev}" && -w "${dev}" ]] || echo "WARN: no user-level HID access: ${dev}"
    fi
  done
fi
if "${check_slots}"; then
  echo '== HMAC-SHA1 probes (responses suppressed) =='
  for slot in 1 2; do
    if result="$(ykman "${args[@]}" otp calculate "${slot}" "${challenge}" 2>&1)" &&
        [[ "${result}" =~ ^[[:xdigit:]]{40}$ ]]; then
      echo "slot ${slot}: HMAC-SHA1 responds"
      if [[ "${slot}" == 2 ]]; then
        if [[ "${result,,}" == "${reference}" ]]; then
          echo 'slot 2: MATCH with verified KeePassXC reference'
        else
          echo 'slot 2: DIFFERENT from verified KeePassXC reference'
        fi
      fi
    else
      echo "slot ${slot}: not HMAC-SHA1 responsive (OTP rejection or transport error)"
    fi
  done
fi
echo 'No device configuration was modified.'
