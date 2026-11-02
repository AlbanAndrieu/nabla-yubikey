# Runbook — sous-clé de chiffrement `pass` sur les deux YubiKey (lot 0)

Objectif : `pass` (donc `bw-unlock`, voir [déverrouillage Vaultwarden](vaultwarden-unlock.md)) ne déchiffre
plus qu'avec une YubiKey branchée, PIN OpenPGP et contact, **chacune des deux suffisant seule**.
Toutes les commandes sont lancées par le titulaire, dans son terminal ; aucun agent ne saisit de PIN
ni de phrase de passe.

## État relevé le 01/11/2026 (lecture seule)

| Élément | État |
| --- | --- |
| Clé de `pass` (`~/.password-store/.gpg-id`) | RSA 4096 `[SC]` + sous-clé RSA 4096 `[E]`, **logicielles**, sans expiration, distincte de la clé de signature des commits |
| Certificat de révocation | Présent dans `~/.gnupg/openpgp-revocs.d/` et dans l'archive `age` hors ligne |
| Applet OpenPGP (secondaire) | Version 3.4, attributs `rsa2048` ×3, 3/3 emplacements vides, PIN 3, admin 3, KDF off, contact off |

## Ce que fait `keytocard`

Il **déplace** la sous-clé : après `save`, `~/.gnupg` ne garde qu'un talon pointant vers **une** carte.
Pour l'avoir sur deux cartes : écrire la première **sans enregistrer** (la copie locale reste), puis
la seconde **en enregistrant**. La sauvegarde de l'étape 1 est la seule voie de retour.

## 1. Sauvegarde testée (avant toute écriture)

```bash
ID="$(head -1 ~/.password-store/.gpg-id)"
gpg --export-secret-keys --armor "$ID" | age -p -o /run/media/$USER/<USB>/pass-gpg-$(date +%Y%m%d).asc.age
```

Prouver la restauration dans un trousseau jetable, sans toucher à `~/.gnupg` :

```bash
T="$(mktemp -d)"; chmod 700 "$T"
age -d /run/media/$USER/<USB>/pass-gpg-*.asc.age | gpg --homedir "$T" --import
echo test | gpg --homedir "$T" --trust-model always -e -r "$ID" | gpg --homedir "$T" -d
gpgconf --homedir "$T" --kill all; rm -rf "$T"
```

**GO** seulement si `test` s'affiche. Ranger la phrase de passe `age` hors du coffre KeePassXC.

## 2. Préparer chaque carte (admin PIN)

`gpg --card-status` doit répondre ; sinon `gpgconf --kill scdaemon` (conflit PC/SC connu).

```bash
gpg --card-edit        # admin → key-attr → (1) RSA 4096 / (2) RSA 4096 / (3) RSA 4096 → quit
ykman openpgp keys set-touch dec on     # contact exigé à chaque déchiffrement
gpgconf --kill scdaemon                 # ykman et scdaemon ne partagent pas la carte
```

KDF : laissé `off` (conseil `OPENPGP_KDF_DISABLED` de la sonde) ; l'activer est une décision séparée,
à prendre carte vide.

## 3. Écrire la secondaire, sans enregistrer

```bash
gpg --edit-key "$ID"   # key 1 → keytocard → (2) Encryption key → quit → Save changes? **N**
```

## 4. Écrire la principale, en enregistrant

Débrancher la secondaire, brancher la principale, `gpgconf --kill scdaemon`, refaire l'étape 2, puis :

```bash
gpg --edit-key "$ID"   # key 1 → keytocard → (2) Encryption key → save
gpg -K "$ID"           # attendu : ssb> (talon) ; sec reste logiciel
```

## 5. Prouver chaque clé seule

```bash
gpg-connect-agent "scd serialno" "learn --force" /bye   # après chaque changement de clé
pass show vaultwarden/master >/dev/null && echo PASS_OK
```

À faire avec la principale seule, puis la secondaire seule : PIN OpenPGP + contact demandés, `PASS_OK`.
Puis `export BW_SESSION="$(bw-unlock)"` avec chacune.

## Retour arrière

Carte perdue ou test KO : `age -d …/pass-gpg-*.asc.age | gpg --import` restaure la sous-clé logicielle.
Une carte se vide avec `ykman openpgp reset` (efface les 3 emplacements et remet les PIN d'usine) :
décision séparée, jamais pendant ce runbook.

**NO-GO :** sauvegarde non relue, `gpg --card-status` instable, ou une seule carte écrite et `save` déjà fait.
