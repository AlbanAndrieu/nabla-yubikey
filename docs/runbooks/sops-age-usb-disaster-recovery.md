# Runbook PRA — SOPS/age, SanDisk LUKS2 et TrueNAS

État confirmé par l'opérateur le **17 octobre 2026**. Cette page donne la procédure autonome de récupération **sans secrets privés**. La source de vérité des scripts est `scripts/workstation/`. Ne jamais copier la phrase secrète LUKS, la clé age privée, le secret HMAC KeePassXC ni les PIN YubiKey dans Git, les tickets ou les journaux.

## Inventaire et localisation

| Élément | Emplacement ou identification |
| --- | --- |
| Clé SOPS de production (privée, en clair dans le home chiffré) | `~/.config/sops/age/keys.txt` ; dossier 700 / fichier 600 |
| Destinataire SOPS actuel (public) | `age1t8wn2gqcpzxwvwhjwxwtdwp0tvr6k2z9j39v4q2fr55qhmqz7f2qvn25cp` |
| Clé USB | SanDisk 3.2Gen1, 114,6 Gio, LUKS2 + ext4 `NABLA_ESCROW` |
| UUID de la partition LUKS | `3742c7b9-ccb7-4b5e-b1db-18bcf916c548` (ne pas confondre avec l'UUID ext4) |
| Référence phrase secrète LUKS | **LastPass → « USB SANDISK LUKS2 »** (aucun secret ici) |
| Clé privée de récupération | `age-escrow/recovery-identity.txt` **sur la clé USB déverrouillée uniquement** |
| Destinataire de récupération public | `age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938` |
| Clé USB montée par GNOME/udisks | `/run/media/$USER/NABLA_ESCROW/age-escrow/recovery-identity.txt` |
| Clé USB montée manuellement | `/mnt/nabla-escrow/age-escrow/recovery-identity.txt` |
| Sauvegarde chiffrée sur TrueNAS | `/media/backup/lab/secret/keepass/sops-age-identity-20261017T183615Z.age` côté workstation |
| Emplacement TrueNAS correspondant | `/mnt/cpool/backup/lab/secret/keepass/` |
| Copie chiffrée locale | `~/.local/share/nabla/age-backups/sops-age-identity-20261017T183615Z.age` |
| Première copie chiffrée renommée | `~/Downloads/sops-age-identity-20261017T183525Z.age.log` ; **extension trompeuse** |

La sauvegarde TrueNAS du 17/10 et sa copie locale ont eu le même SHA-256 :
`1bf047c688a871865b1d87c197806dd3b3616e7f0d9b8ac7db6b754c5f0411d4`.
Cette empreinte valide l'égalité des deux copies, pas leur authenticité cryptographique à elle seule. La sauvegarde TrueNAS a réussi la restauration age et le test de fixture SOPS a affiché `PASS: SOPS recovery with USB-backed escrow`.

## PRA en cas de perte de la workstation

1. Retrouver **une copie du fichier .age** sur TrueNAS (ou la copie locale chiffrée si elle a survécu) et la SanDisk. Sans la SanDisk ou une **autre sauvegarde de sa clé privée age**, le seul fichier `.age` ne suffit pas.
2. Brancher la SanDisk, vérifier `lsblk -o NAME,TRAN,SIZE,FSTYPE,UUID,MOUNTPOINTS`. Ne pas supposer que son nom restera `/dev/sdd`. Déverrouiller via le gestionnaire de disques GNOME, ou utiliser le script de gestion ci-dessous. Entrer la phrase secrète depuis le coffre LastPass, jamais en argument de commande.
3. Vérifier `age-keygen -y "/run/media/$USER/NABLA_ESCROW/age-escrow/recovery-identity.txt"` (ou l'autre point de montage) et comparer **exactement** au destinataire escrow public ci-dessus. Ne jamais afficher le contenu de la clé privée.
4. Tester d'abord l'enveloppe sans exposer la clé en sortie :
   ```bash
   bash scripts/workstation/verify-sops-age-escrow.sh \
     --backup /media/backup/lab/secret/keepass/sops-age-identity-20261017T183615Z.age \
     --identity "/run/media/$USER/NABLA_ESCROW/age-escrow/recovery-identity.txt"
   ```
5. Tester ensuite le déchiffrement SOPS synthétique à partir de l'identité restaurée (isolé en `/dev/shm`, **ne pas source** le script) :
   ```bash
   bash scripts/workstation/test-sops-usb-recovery.sh \
     --backup /media/backup/lab/secret/keepass/sops-age-identity-20261017T183615Z.age \
     --usb-identity "/run/media/$USER/NABLA_ESCROW/age-escrow/recovery-identity.txt"
   ```
6. En cas de restauration réelle de workstation : dans un système de confiance, déchiffrer le backup `.age` vers le nouveau `~/.config/sops/age/keys.txt` avec `umask 077`, répertoire 700 et fichier 600, en évitant l'historique, stdout, journaux et supports non chiffrés. Vérifier `age-keygen -y ~/.config/sops/age/keys.txt` contre le destinataire SOPS **public** ci-dessus avant usage. **Ne jamais écraser une identité existante sans archivage et plan de restauration.**
7. Après usage, fermer le support et vérifier qu'il est démonté, puis stocker physiquement hors ligne.

Pour ouvrir/fermer par UUID : `bash scripts/workstation/manage-age-escrow-usb.sh --luks-uuid 3742c7b9-ccb7-4b5e-b1db-18bcf916c548 --check|--open|--close`. `--open` détecte un montage GNOME/udisks existant.

## Recréation d'une SanDisk perdue / cassée

**Le LUKS et age sont deux couches distinctes.** La phrase secrète LastPass « USB SANDISK LUKS2 » sert à déverrouiller l'ancien conteneur LUKS, **pas** à reconstruire l'identité age de récupération. Un nouveau `luksFormat` + `mkfs.ext4` recrée un **support vide**, et `age-keygen` génère une **nouvelle clé incompatible** avec le destinataire d'origine.

Pour recréer une clé USB à l'identique, il faut : (1) une autre copie de `recovery-identity.txt` authentifiée et protégée ; (2) préparer une **nouvelle** clé USB sous LUKS2/ext4 après identification matérielle et validation d'effacement ; (3) réinstaller la **même** identité privée `recovery-identity.txt` à permissions 600 ; (4) vérifier `age-keygen -y` contre le destinataire escrow connu ; (5) tester le déchiffrement d'une sauvegarde age de bout en bout. **Ne jamais reformater l'unique SanDisk opérationnelle.**

Sauvegarder l'en-tête LUKS dans un lieu chiffré indépendant, avec contrôle d'accès et essai de restauration. Une copie chiffrée indépendante de la clé age privée du support USB constitue **le principal jalon encore ouvert** (single point of failure). LastPass seul, avec la phrase secrète LUKS, ne résout pas cette lacune.

## Droits NFS et conservation

TrueNAS NFSv4.2 `sec=sys`, `/media/backup/lab/secret` et `keepass` modes 700 (UID 1000). Sur NFS, `sudo` client peut subir le root squash ; copier **sans sudo** vers un home protégé, ne pas déplacer l'unique exemplaire.
La première sauvegarde `sops-age-identity-20261017T183525Z.age` a été déplacée dans `~/Downloads` avec suffixe `.age.log`. Ne pas la traiter comme un log, ni la publier sur un ticket.

## Retours d'expérience et gates YubiKey

- Deux clés YubiKey : OTP2 HMAC KeePassXC doit rester intact, PIV9A historique intact, PIV82 réservé au nouveau age-plugin-yubikey.
- Le précontrôle PIV82 a initialement échoué `Connect exactly the selected single YubiKey` (secours) et `PIV 82 info unavailable` (principale). Les deux **ne prouvent pas une occupation de slot** ; rejouer le contrôle corrigé avec une seule carte et capturer les erreurs **sans secrets**.
- Les tests manuels matériels et la deuxième copie de la clé d'escrow restent à faire avant de déclarer un PRA multi-support robuste.
