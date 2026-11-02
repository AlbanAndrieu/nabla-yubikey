#!/usr/bin/env bash
# Safe read-only YubiKey application inventory; ANSI colours when terminal supports them.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"
BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"
expected=''
challenge=false
usage() {
  echo 'Usage: audit-yubikey-capabilities.sh [--primary|--backup|--serial SERIAL] [--challenge]'
  echo 'Requires exactly one connected, recognized YubiKey; reads PIV slots only.'
}
while (($#)); do
  case "$1" in
    --primary) [[ -z "${expected}" ]] || { echo 'Select only one device' >&2; exit 2; }; expected="${PRIMARY_SERIAL}"; shift ;;
    --backup) [[ -z "${expected}" ]] || { echo 'Select only one device' >&2; exit 2; }; expected="${BACKUP_SERIAL}"; shift ;;
    --serial) [[ $# -ge 2 && -z "${expected}" && "$2" =~ ^[0-9]+$ ]] || { echo 'Invalid serial/selection' >&2; exit 2; }; expected="$2"; shift 2 ;;
    --challenge) challenge=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
command -v ykman >/dev/null || { echo 'ykman missing' >&2; exit 1; }
device_lines="$(ykman list --serials)" || { echo 'Device discovery failed' >&2; exit 1; }
mapfile -t devices < <(printf '%s\n' "${device_lines}" | grep -E '^[0-9]+$' || true)
[[ "${#devices[@]}" -eq 1 ]] || { echo 'Exactly one YubiKey must be connected' >&2; exit 2; }
connected="${devices[0]}"
case "${connected}" in
  "${PRIMARY_SERIAL}") role=primary ;;
  "${BACKUP_SERIAL}") role=backup ;;
  *) echo 'Unrecognized YubiKey; refusing to audit unknown device' >&2; exit 2 ;;
esac
[[ -z "${expected}" || "${expected}" == "${connected}" ]] || {
  echo 'Connected YubiKey does not match requested serial' >&2; exit 2;
}
args=(--device "${connected}")
printf 'Selected YubiKey: %s (serial %s), verified single device\n' "${role}" "${connected}"
diag_args=(--serial "${connected}")
if "${challenge}"; then diag_args+=(--challenge); fi
# Colors honour TTY, NO_COLOR and TERM=dumb through common.sh.
# shellcheck source=../lib/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../lib/common.sh"
nabla_ui_init
green="${NABLA_UI_GREEN}" yellow="${NABLA_UI_YELLOW}"
blue="${NABLA_UI_BLUE}" reset="${NABLA_UI_RESET}"
heading() { printf '\n%s🔐 %s%s\n' "${blue}" "$1" "${reset}"; }
ok() { printf '%s✅ %s%s\n' "${green}" "$1" "${reset}"; }
warn() { printf '%s⚠️  %s%s\n' "${yellow}" "$1" "${reset}"; }
heading 'YubiKey / KeePassXC'
bash "${here}/diagnose-yubikey-keepassxc.sh" "${diag_args[@]}"
heading 'FIDO2'
if ykman "${args[@]}" fido info; then ok 'FIDO2 disponible'; else warn 'FIDO2 non accessible'; fi
heading 'PIV / certificats'
if piv="$(ykman "${args[@]}" piv info 2>&1)"; then
  # Redact the unique CHUID; dates/slots/fingerprints can still be identifying.
  printf '%s\n' "${piv}" | sed -E 's/^(CHUID:).*/\1 [REDACTED]/'
  ok 'PIV disponible'
else warn 'PIV non accessible'; fi
# ykman 5.8.0 has no `piv certificates list`; inventory is reported by piv info.
# Check certificate expiry without requiring a PIN and without revealing key material.
if command -v python3 >/dev/null && [[ -n "${piv:-}" ]]; then
  PIV_AUDIT_TEXT="${piv}" python3 - <<'PY'
import datetime
import os
import re
text = os.environ["PIV_AUDIT_TEXT"]
now = datetime.datetime.now(datetime.timezone.utc)
for block in re.split(r"(?=Slot [0-9A-Fa-f]{2} \()", text):
    slot = re.search(r"Slot ([0-9A-Fa-f]{2})", block)
    expiry = re.search(r"Not after:\s*(\d{4}-\d\d-\d\dT\S+)", block)
    if slot and expiry:
        try:
            expires = datetime.datetime.fromisoformat(expiry.group(1))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=datetime.timezone.utc)
            status = "EXPIRED ⚠️" if expires < now else "VALID ✅"
            print(f"Certificate PIV slot {slot.group(1)}: {status} ({expires.date()})")
        except ValueError:
            print(f"Certificate PIV slot {slot.group(1)}: unknown expiry")
PY
fi
heading 'PIV : inventory 9C/9D/9E and retired 82-95 (read only)'
empty=0; occupied=0; unknown=0
slots=(9C 9D 9E 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95)
for slot in "${slots[@]}"; do
  result="$(ykman "${args[@]}" piv keys info "${slot}" 2>&1)" && rc=0 || rc=$?
  if [[ ${rc} -ne 0 && "${result}" == *'No key stored'* ]]; then
    printf '%s : EMPTY\n' "${slot}"
    empty=$((empty + 1))
  elif [[ ${rc} -eq 0 && "${result}" == *'Key slot:'* ]]; then
    printf '%s : OCCUPIED\n' "${slot}"
    occupied=$((occupied + 1))
  else
    printf '%s : UNKNOWN (tool/status error; raw output hidden)\n' "${slot}"
    unknown=$((unknown + 1))
  fi
done
printf 'PIV slot summary for %s: empty=%s occupied=%s unknown=%s / %s\n' "${role}" "${empty}" "${occupied}" "${unknown}" "${#slots[@]}"
if ((unknown > 0)); then warn 'PIV inventory incomplete; do NOT provision a slot based on this scan'; fi

heading 'OpenPGP'
if ykman "${args[@]}" openpgp info; then ok 'OpenPGP disponible'; else warn 'OpenPGP non accessible'; fi
heading 'OATH'
if ykman "${args[@]}" oath info; then ok 'OATH disponible'; else warn 'OATH non accessible'; fi
heading 'Inventaire attendu : usage vs emplacement'
printf '%s\n' '⚠️ Historique déclaré : OTP slot 2 HMAC-SHA1 prévu pour KeePassXC ; configuration réelle NON VÉRIFIÉE par cet audit (aucun challenge exécuté)'
printf '%s\n' '✅ Confirmé : clé GPG logicielle RSA4096 [SC], sous-clé RSA4096 [E] ; signature et chiffrement/déchiffrement de test validés'
printf '%s\n' 'ℹ️ OpenPGP slots are separate from PIV and must be verified on the selected device.'
printf '%s\n' '⚠️ Non validé : clés SSH stockées sur YubiKey, FIDO2 discoverable credentials, slots PIV SSH, ssh-agent ou PIV comme backend de SSH.'
printf '%s\n' '⚠️ Non validé : signature de commit Git, git-crypt et restauration PostgreSQL en conditions réelles.'
heading 'SSH local (aucune empreinte ni clé affichée)'
if command -v ssh-add >/dev/null 2>&1; then
  if ssh-add -l >/dev/null 2>&1; then
    ok 'SSH agent contient au moins une identité ; provenance YubiKey non démontrée'
  else
    warn 'Aucune identité SSH utilisable confirmée par ssh-add -l (ou agent inaccessible)'
  fi
fi
if command -v ssh-keygen >/dev/null 2>&1; then
  ok 'ssh-keygen disponible ; aucune opération de création/export de clé exécutée'
fi
heading 'OpenPGP : état des emplacements (lecture seule, valeurs masquées)'
if command -v gpg >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  card="$(timeout 15 gpg --card-status 2>/dev/null || true)"
  if [[ "${card}" == *'Application type .: OpenPGP'* ]]; then
    ok 'OpenPGP reconnu par scdaemon'
    for label in 'Signature key' 'Encryption key' 'Authentication key'; do
      if printf '%s\n' "${card}" | grep -Eq "^${label}[.[:space:]]*:[[:space:]]*\\[none\\]"; then
        printf 'ℹ️ %s: vide sur la carte connectée\n' "${label}"
      elif printf '%s\n' "${card}" | grep -Eq "^${label}[.[:space:]]*:"; then
        printf 'ℹ️ %s: présent ou indéterminé (identifiant masqué)\n' "${label}"
      else
        printf '⚠️ %s: non déterminé\n' "${label}"
      fi
    done
  else
    warn 'Carte OpenPGP non accessible via GnuPG (absente, transport ou client)'
  fi
fi

heading 'Outils SSH / GPG / age / PAM / Keyring'
for tool in gpg ssh-keygen pamu2fcfg age age-plugin-yubikey secret-tool seahorse; do
  if command -v "${tool}" >/dev/null 2>&1; then ok "${tool} installé"; else warn "${tool} absent"; fi
done
heading 'SOPS / age : possibilité de clé matérielle (lecture seule)'
if command -v sops >/dev/null 2>&1; then
  ok 'sops installé ; vérifier la version et le support des destinataires age plugin'
else
  warn 'sops non trouvé dans PATH'
fi
if command -v age-plugin-yubikey >/dev/null 2>&1; then
  ok 'age-plugin-yubikey installé ; aucun slot provisionné automatiquement'
else
  warn 'age-plugin-yubikey absent : identité age matérielle non vérifiée'
fi
printf '%s\n' 'ℹ️ age X25519 existant de fastapi-sample : identité logicielle ; non importable telle quelle dans PIV.'
printf '%s\n' 'ℹ️ PIV 9A has a historical certificate; retired 82-95 were inspected on the selected device above.'
printf '%s\n' 'ℹ️ Une identité age YubiKey serait un destinataire SOPS supplémentaire, jamais un remplacement sans tests.'

heading 'SOPS age: private identity permissions (metadata only)'
age_identity="${HOME}/.config/sops/age/keys.txt"
if [[ -L "${age_identity}" ]]; then
  warn 'SOPS age identity is a symlink: manually verify destination security'
elif [[ -f "${age_identity}" ]]; then
  owner="$(stat -c '%u' "${age_identity}" 2>/dev/null || true)"
  mode="$(stat -c '%a' "${age_identity}" 2>/dev/null || true)"
  if [[ "${owner}" == "$(id -u)" && "${mode}" == 600 ]]; then
    ok 'SOPS age identity owned by current user with mode 600'
  else
    warn "SOPS age identity file has unsafe or unverified owner/mode (${mode:-unknown}); expected 600"
    printf '%s\n' 'ℹ️ Suggested local fix: chmod 600 ~/.config/sops/age/keys.txt'
  fi
else
  warn 'No default SOPS age identity file detected (may use environment identity)'
fi

heading 'Sécurité'
warn 'Ne pas réinitialiser PIV : sauvegarder et examiner les usages du certificat expiré.'
ok 'Aucune opération de provisionnement ou modification PAM effectuée.'
printf '📚 Documentation : docs/workstation-yubikey-full-capabilities.md\n'
