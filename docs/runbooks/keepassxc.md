# Runbook — coffre KeePassXC (mot de passe + fichier clé + YubiKey)

> **31/10/2026** : mot de passe maître remplacé par une phrase de passe ; KDBX 4.0, AES-256, **Argon2id 256 Mio** ; diagnostic `just keepassxc-readonly` **GO** (reste `SSH_FILE_KEY_ON_DISK`).
>
> | YubiKey | Modèle | Slot 2 | Ouverture du coffre |
> | --- | --- | --- | --- |
> | Secondaire | 5 NFC (USB-A) | programmé le 31/10 | **PASS** avec la nouvelle phrase de passe |
> | Principale | 5C NFC (USB-C) | déjà programmé (même secret) | **PASS** avec la nouvelle phrase de passe |
>
> Copie NAS : encore à l'ancien mot de passe, **à remplacer puis attester**.

## Identifier la clé branchée

Les deux clés ont le même firmware ; ne jamais conclure sur la seule clé « branchée en ce moment ». Déclarer localement (jamais dans ce dépôt) les 4 derniers chiffres de chaque numéro de série :

```bash
# ~/.config/environment.d/50-yubikey-roles.conf ou profil shell
YUBIKEY_ROLES=XXXX=principale,YYYY=secondaire
```

`just applets-readonly` affiche alors `"role": "principale"` ou `"secondaire"` (`UNLABELED` sinon), plus l'état des slots OTP, sans jamais afficher le numéro.

## Modèle de protection

Le coffre exige les **trois** éléments ; perdre l'un d'eux = coffre perdu.

| Élément | Emplacement | Règle |
| --- | --- | --- |
| Mot de passe maître | Mémoire | Jamais saisi par un script ou un agent IA |
| Fichier clé | Local `~/.local/share/keepassxc/` (600) + copie hors ligne (USB) | **Jamais** à côté du coffre ni dans le même cloud |
| Challenge-response HMAC-SHA1 | Slot 2 de **chaque** YubiKey, même secret | Secret conservé hors ligne ; `--touch` recommandé |

Le coffre (Dropbox) et ses copies (NAS) sont chiffrés : seuls, ils ne suffisent pas à l'ouvrir.

**Lecture KDBX renforcée :** l'inspection n'ouvre que des fichiers réguliers (aucun lien symbolique ni périphérique) et vérifie les champs externes avec une taille bornée. Un en-tête tronqué, un format cryptographique inconnu ou des métadonnées KDF incohérentes entraînent un **NO-GO**, sans essayer de déchiffrer le coffre. Le JSON de `just keepassxc-readonly` reste contractuel ; code de sortie 0 ≠ déverrouillage validé.

## Diagnostic sans mot de passe

```bash
just keepassxc-readonly
```

Lit l'en-tête KDBX non chiffré, les droits, `ykman list` / `ykman otp info` et `[SSHAgent]` de `keepassxc.ini`. N'envoie aucun challenge, n'affiche ni chemin ni numéro de série. `yubikey_role` indique quelle clé a été vérifiée (via `YUBIKEY_ROLES`). Surcharges : `KEEPASSXC_DB`, `KEEPASSXC_KEYFILE`.

| Bloquant | Correction |
| --- | --- |
| `KEYFILE_IN_CLOUD`, `KEYFILE_LEFT_IN_CLOUD`, `KEYFILE_WITH_DATABASE` | Déplacer le fichier clé hors du cloud et du dossier du coffre |
| `DATABASE_MODE_NOT_600`, `KEYFILE_MODE_NOT_600` | `chmod 600` |
| `YUBIKEY_SLOT2_EMPTY` | Programmer le slot 2 (ci-dessous) |
| `YUBIKEY_SLOT2_DEVICE_COUNT_n` | Une seule YubiKey branchée |

Conseils : `KDF_NOT_ARGON2ID` / `KDF_MEMORY_BELOW_256MIB` → *Base de données → Sécurité → Chiffrement* : Argon2id, 256 Mio, bouton « Tester » pour ~1 s ; `SSH_FILE_KEY_ON_DISK` → section agent SSH.

## Programmer une YubiKey avec le secret existant

Écriture matérielle, lancée par le titulaire. Le secret est la valeur **hexadécimale HMAC** (40 caractères) notée à la création, ni un PIN ni une passphrase ; ne jamais le passer en argument ni le coller dans un outil.

```bash
 ykman otp chalresp --touch 2      # une seule clé branchée ; ykman demande le secret
```

À `Program a challenge-response credential in slot 2? [y/N]` : **N** si le slot contient déjà le bon secret. Une faute de frappe rend cette clé inutilisable pour le coffre : ne réécrire une clé qu'après avoir prouvé que **l'autre** ouvre le coffre.

## Vérifier l'ouverture (mot de passe saisi par le titulaire)

`--yubikey` attend `slot:numéro_de_série` ; `2` seul cherche la série 0 (« Could not find interface for hardware key with serial number 0 »).

```bash
keepassxc-cli db-info --key-file ~/.local/share/keepassxc/<coffre>.key \
  --yubikey "2:$(ykman list --serials | head -1)" <coffre>.kdbx
```

À faire avec **chaque** YubiKey seule, puis sur chaque copie de sauvegarde : une copie jamais ouverte n'est pas une sauvegarde.

## Agent SSH de KeePassXC

Une entrée du coffre peut porter une clé SSH privée en pièce jointe : KeePassXC l'ajoute à l'agent (`SSH_AUTH_SOCK`, ici `gcr-ssh-agent`) au déverrouillage et la retire au verrouillage. Utile pour `id_ed25519` (serveurs) ; inutile pour `id_ed25519_sk` (déjà dans la YubiKey).

1. *Paramètres → Agent SSH* : intégration activée, connexion à l'agent OK.
2. Entrée « SSH id_ed25519 » : mot de passe = passphrase de la clé ; *Avancé → Pièces jointes* : `id_ed25519`.
3. Onglet *Agent SSH* : ajouter à l'ouverture, retirer au verrouillage, exiger une confirmation.
4. Enregistrer, sauvegarder le coffre, tester : coffre ouvert `ssh-add -l` montre la clé et `ssh truenas` fonctionne ; coffre verrouillé, elle disparaît.
5. Seulement ensuite, retirer `~/.ssh/id_ed25519` en gardant `~/.ssh/id_ed25519.pub` (ssh retrouve la clé de l'agent par le `.pub`). Tant que le fichier reste, `gcr-ssh-agent` le charge lui-même et le test ne prouve rien.

**Dépendance circulaire à éviter :** si le fichier clé n'est que sur le NAS et que la clé SSH du NAS n'est que dans le coffre, une panne NFS bloque les deux. Garder la copie locale du fichier clé.
