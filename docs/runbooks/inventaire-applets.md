# Runbook — inventaire des applets YubiKey (lecture seule)

> **Attesté le 31/10/2026** sur Workstation (YubiKey 5 NFC, firmware 5.4.3) : **GO**, aucun bloquant, trois conseils.
> **04/11/2026, secondaire** : **GO** après la configuration ci-dessous ; les trois conseils restent affichés (voir [Configuration appliquée](#configuration-appliquée)).

```bash
just applets-readonly
```

La sonde lance seulement `ykman list`, `ykman info`, `ykman fido info`, `ykman openpgp info` et `ykman piv info`. Elle ne demande aucun PIN, n'écrit rien sur la carte et n'affiche ni numéro de série, ni AAGUID, ni sujet de certificat : seulement compteurs, drapeaux et noms de slots PIV. Plus d'une clé branchée = `NO-GO` (`DEVICE_COUNT_NOT_ONE`).

## Interprétation stricte des diagnostics

Les réponses `ykman` qui ne contiennent pas explicitement les deux slots OTP, les compteurs requis pour FIDO2/PIV/OpenPGP ou les informations firmware/applications sont classées `*_UNREADABLE` et **NO-GO** : une sortie tronquée ne prouve jamais une configuration saine. Les commandes matériellement modificatrices sont refusées par une allowlist fixe.

Les compteurs dupliqués, les messages supplémentaires dans le rapport OTP et les états USB/NFC inconnus sont également classés illisibles. Le rôle est dérivé localement de `YUBIKEY_ROLES` et seules les étiquettes publiques `principale`, `secondaire`, `secours`, `primary` ou `backup` sont acceptées ; une attribution ambiguë devient `UNKNOWN`, jamais une valeur libre issue de l'environnement.

Les sondes renvoient un **document JSON** avec `status: GO | NO-GO`. Leur code de sortie 0 signifie que le rapport a été émis, **pas** que l'état matériel est GO. Les compteurs et états reflètent uniquement la clé branchée au moment du contrôle. Pour vérifier les deux clés, les brancher successivement, jamais simultanément.

## Bloquants (`NO-GO`)

| Code | Signification |
| --- | --- |
| `*_UNREADABLE` | `ykman` absent, échec ou sortie suspecte : rien n'est conclu |
| `FIDO2_PIN_NOT_SET` | Clés SSH-sk / WebAuthn utilisables sans PIN |
| `*_ALMOST_BLOCKED` | Un compteur PIN/PUK/Admin PIN est à 1 ou 0 : ne plus rien tenter avant décision |
| `PIV_DEFAULT_CREDENTIALS` | PIN, PUK ou clé de gestion PIV d'usine |

## Conseils (n'empêchent pas `GO`)

Chaque correction est une **écriture matérielle** : décision explicite, commande lancée par le titulaire, sonde relancée ensuite.

| Code | Risque | Correction possible |
| --- | --- | --- |
| `OTP_USB_ENABLED` | Un effleurement tape une chaîne OTP dans la fenêtre active | `ykman config usb --disable OTP` si Yubico OTP n'est pas utilisé |
| `NFC_ENABLED` | Applets joignables sans contact par un lecteur proche | Restreindre le NFC aux usages du téléphone (voir ci-dessous), ou `ykman config nfc --disable-all` si le NFC n'est pas utilisé ; le conseil reste tant qu'**une** application est ouverte en NFC |
| `OPENPGP_KDF_DISABLED` | Le PIN OpenPGP transite en clair vers la carte | `kdf-setup` dans `gpg --card-edit` (mode admin), **avant** de charger des clés ; vérifier la documentation GnuPG/Yubico sur la réinitialisation des PIN avant de le lancer |

Ne pas désactiver une application sans inventaire de ses usages : FIDO U2F/FIDO2 (SSH-sk, WebAuthn), OpenPGP (signature des commits si la clé est sur carte), PIV (slot `9A` occupé sur la clé attestée), OATH (codes TOTP de Yubico Authenticator), Yubico OTP (slot 1 : Vaultwarden, lisible en NFC par Bitwarden mobile ; slot 2 : challenge-response KeePassXC, USB seulement), YubiHSM Auth (identifiants pour un YubiHSM 2, aucun ici).

## Configuration appliquée

Écritures sans PIN, réversibles, décidées par le titulaire. La clé redémarre après chaque `ykman config`.

| Application | USB | NFC | Pourquoi |
| --- | --- | --- | --- |
| Yubico OTP | oui | oui | Vaultwarden (slot 1, lisible en NFC par Bitwarden mobile) ; KeePassXC (slot 2) |
| FIDO U2F / FIDO2 | oui | oui | SSH-sk, passkeys sur le poste et le téléphone |
| OATH | oui | oui | codes TOTP de Yubico Authenticator (poste et téléphone) |
| PIV | oui | **non** | slot `9A` utilisé en USB seulement ; en NFC, un lecteur proche lisait le certificat et pouvait épuiser les essais de PIN |
| OpenPGP | oui | **non** | carte utilisée en USB seulement ; même raison qu'au-dessus |
| YubiHSM Auth | **non** | **non** | aucun YubiHSM 2 ; déjà désactivé sur la principale |

| Clé | Date | État |
| --- | --- | --- |
| Secondaire | 04/11/2026 | appliqué, sonde **GO**, PIN FIDO2 inchangé |
| Principale | — | YubiHSM Auth déjà désactivé (USB et NFC) ; NFC **pas encore restreint** |

Une clé à la fois, seule branchée :

```bash
ykman config usb --disable HSMAUTH --force
ykman config nfc --disable HSMAUTH --disable PIV --disable OPENPGP --force
ykman info        # colonnes USB / NFC du tableau ci-dessus
just applets-readonly
```

Retour arrière : `ykman config nfc --enable PIV --enable OPENPGP --force` et `ykman config usb --enable HSMAUTH --force` (puis `nfc --enable HSMAUTH`).
