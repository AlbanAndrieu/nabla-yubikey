#!/usr/bin/env bash
# Read-only GnuPG smartcard transport triage; never restart services or edit config.
set -euo pipefail
export LC_ALL=C
host_only=false
# shellcheck source=../lib/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../lib/common.sh"
nabla_ui_init
green="${NABLA_UI_GREEN}" yellow="${NABLA_UI_YELLOW}"
cyan="${NABLA_UI_BLUE}" reset="${NABLA_UI_RESET}"
heading() { printf '\n%s🔐 %s%s\n' "${cyan}" "$1" "${reset}"; }
warn() { printf '%s⚠️  %s%s\n' "${yellow}" "$1" "${reset}"; }
ok() { printf '%s✅ %s%s\n' "${green}" "$1" "${reset}"; }
case "${1:---check}" in
  --check) ;;
  --host-only) host_only=true ;;
  -h|--help) echo 'Usage: bash scripts/workstation/diagnose-gpg-smartcard.sh [--check|--host-only]'; exit 0 ;;
  *) echo 'Unknown option' >&2; exit 2 ;;
esac
heading 'Contexte GnuPG (sans secrets)'
for tool in gpg gpgconf gpg-connect-agent ykman systemctl; do
  if command -v "${tool}" >/dev/null; then ok "${tool} présent"; else warn "${tool} absent"; fi
done
if command -v gpg >/dev/null; then gpg --version | head -n 2; fi
if command -v gpgconf >/dev/null; then
  printf 'GPG homedir: %s\n' "$(gpgconf --list-dirs homedir)"
fi
heading 'Services utilisateur et PCSC'
if command -v systemctl >/dev/null; then
  for unit in pcscd.socket pcscd.service; do
    printf '%s: ' "${unit}"
    systemctl is-active "${unit}" 2>/dev/null || true
  done
  printf 'gpg-agent user: '
  systemctl --user is-active gpg-agent.service 2>/dev/null || true
fi
heading 'Configuration effective (noms de directives seulement)'
cfg="${GNUPGHOME:-${HOME}/.gnupg}/scdaemon.conf"
if [[ -r "${cfg}" ]]; then
  for setting in disable-ccid pcsc-shared pcsc-driver reader-port; do
    if grep -Eq "^[[:space:]]*${setting}([[:space:]]|$)" "${cfg}"; then
      if [[ "${setting}" == pcsc-driver || "${setting}" == reader-port ]]; then
        warn "${setting} défini (valeur masquée)"
      else ok "${setting} défini"; fi
    else warn "${setting} absent"; fi
  done
else warn 'scdaemon.conf absent ou non lisible'; fi
heading 'Mode de diagnostic'
if "${host_only}"; then
  ok 'Mode host-only : vérification GPG/PCSC sans carte';
elif ! command -v ykman >/dev/null 2>&1 && ! { command -v lsusb >/dev/null 2>&1 && lsusb -d 1050: 2>/dev/null | grep -q '1050:'; }; then
  warn 'Aucune YubiKey détectée localement. Contrôle matériel ignoré (utiliser --host-only sur TrueNAS).'
  host_only=true
fi
if "${host_only}"; then
  printf '✅ Contrôle serveur terminé; pas de test OpenPGP matériel attendu.\n'
  exit 0
fi
heading 'Interfaces'
if command -v ykman >/dev/null; then
  ykman list --serials || true
  ykman openpgp info || warn 'Applet OpenPGP inaccessible à ykman'
fi
if command -v gpg-connect-agent >/dev/null; then
  # scdaemon may be auto-started by SCD; no key material is requested.
  result="$(printf 'SCD GETINFO version\n/bye\n' | timeout 8 gpg-connect-agent 2>&1 || true)"
  if [[ "${result}" == *'D '* && "${result}" == *'OK'* ]]; then
    ok 'scdaemon répond à GETINFO version'
  else warn 'scdaemon ne répond pas correctement à GETINFO'; fi
fi
heading 'Sélection PC/SC et isolation du lecteur'
if command -v gpg-connect-agent >/dev/null && command -v timeout >/dev/null; then
  for scd_command in 'SCD GETINFO reader_list' 'SCD SERIALNO'; do
    probe="$(printf '%s\n/bye\n' "${scd_command}" | timeout 8 gpg-connect-agent 2>&1 || true)"
    # Never print device serials or raw smartcard IDs.
    if [[ "${probe}" == *'ERR '* ]]; then
      warn "${scd_command}: refusé ou lecteur inaccessible"
    elif [[ "${scd_command}" == 'SCD GETINFO reader_list' && "${probe}" == *'card or a reader'* ]]; then
      warn 'scdaemon retourne un message sans lecteur exploitable; OK confirme seulement le protocole'
    elif [[ "${probe}" == *'OK'* ]]; then
      ok "${scd_command}: requête acceptée (données masquées)"
    else
      warn "${scd_command}: résultat non exploitable"
    fi
  done
fi
if command -v pcsc_scan >/dev/null 2>&1 && command -v timeout >/dev/null; then
  scan="$(timeout 4 pcsc_scan -n 2>&1 || true)"
  if [[ "${scan}" == *'Yubico'* || "${scan}" == *'YubiKey'* ]]; then
    ok 'Lecteur YubiKey visible par PC/SC'
  elif [[ "${scan}" == *'No readers found'* ]]; then
    warn 'PC/SC : aucun lecteur détecté'
  else
    warn 'PC/SC : présence du lecteur non confirmée'
  fi
else
  warn 'pcsc_scan absent : installer pcsc-tools sur la workstation si nécessaire'
fi
heading 'Clients PC/SC GNOME (lecture seule)'
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -u "$(id -u)" -x seahorse >/dev/null 2>&1; then
    warn 'Seahorse actif : client GPG/PCSC potentiel, pas une preuve de verrouillage'
  else
    ok 'Seahorse non actif actuellement'
  fi
fi
if command -v coredumpctl >/dev/null 2>&1; then
  warn 'Si erreur libpcsclite observée, consulter coredumpctl list (jamais dump)'
fi
heading 'Clients YubiKey concurrents (lecture seule)'
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -u "$(id -u)" -f '(^|/)(ykman-gui|yubikey-manager-qt)([[:space:]]|$)' >/dev/null 2>&1; then
    warn 'ykman-gui actif : client YubiKey potentiel ; fermer normalement la GUI avant un prochain test contrôlé'
    warn 'Sa présence seule ne prouve pas un verrouillage de la carte'
  else
    ok 'Aucun ykman-gui actif détecté'
  fi
fi
if command -v lsusb >/dev/null 2>&1; then
  if lsusb -d 1050:0407 2>/dev/null | grep -q '1050:0407'; then
    ok 'YubiKey USB composite 1050:0407 visible (usbfs sur CCID est attendu)'
  else
    warn 'YubiKey USB 1050:0407 non confirmée'
  fi
fi
printf '%s\n' 'ℹ️ Journal pcscd vide : pas une preuve de panne ; aucun service redémarré.'

heading 'Conflits potentiels et état scdaemon'
if command -v pgrep >/dev/null 2>&1; then
  scd_count="$(pgrep -u "$(id -u)" -xc scdaemon 2>/dev/null || true)"
  printf 'Instances scdaemon utilisateur : %s\n' "${scd_count:-0}"
fi
if command -v gpgconf >/dev/null 2>&1; then
  gpgconf --check-programs 2>/dev/null | awk -F: '$1 ~ /scdaemon/ { if ($3 == "1") print "⚠️ scdaemon signale une erreur de programme"; else print "ℹ️ scdaemon référencé dans GnuPG" }' || true
fi
if [[ -r "${cfg}" ]] && grep -Eq '^[[:space:]]*disable-ccid([[:space:]]|$)' "${cfg}" && ! grep -Eq '^[[:space:]]*pcsc-shared([[:space:]]|$)' "${cfg}"; then
  warn 'disable-ccid sans pcsc-shared : ancien état ayant échoué à sélectionner la carte'
  printf 'ℹ️ Le contournement confirmé est PC/SC partagé ; ne pas répéter reader-port.\n'
fi
printf '%s\n' 'ℹ️ GnuPG logiciel et OpenPGP sur YubiKey sont indépendants ; la carte de secours observée avait ses trois clés OpenPGP absentes.'
heading 'Référence P1 GPG logiciel (sans export de clé)'
if command -v gpg >/dev/null 2>&1; then
  key_info="$(gpg --batch --with-colons --list-secret-keys F4C4B79A80826A5E5ADAD2C8B12DECD437E9E1C8 2>/dev/null || true)"
  if printf '%s\n' "${key_info}" | grep -q '^sec:'; then
    ok 'Clé secrète de signature Git présente dans le trousseau local (usage déjà testé avec Good signature)'
  else warn 'Clé secrète Git de référence non présente'; fi
  if printf '%s\n' "${key_info}" | grep -q '^ssb:.*:e:'; then
    ok 'Sous-clé secrète de chiffrement répertoriée (roundtrip de fixture déjà testé)'
  elif printf '%s\n' "${key_info}" | grep -q '^ssb:'; then
    ok 'Sous-clé secrète répertoriée ; vérifier les capacités séparément'
  else warn 'Sous-clé secrète de chiffrement non trouvée'; fi
fi
printf '%s\n' 'ℹ️ Attendu établi : signature GPG logicielle PASS ; roundtrip RSA4096 [E] PASS ; Git commit signé / git-crypt réels non validés.'
heading 'Diagnostic matériel GPG (sans sortie brute)'
if command -v gpg >/dev/null; then
  if output="$(timeout 15 gpg --card-status 2>&1)"; then
    ok 'GnuPG détecte la carte OpenPGP'
  elif [[ "${output}" == *'No such device'* ]]; then
    warn 'GnuPG: No such device — vérifier scdaemon/PCSC et conflits CCID'
  else
    warn 'GnuPG ne détecte pas la carte (sortie volontairement masquée)'
  fi
fi
printf '\n📚 Procédure et rollback : docs/workstation-yubikey-gpg-vault-roadmap.md\n'
echo 'Aucune clé, aucun PIN, service ou fichier de configuration modifié.'
