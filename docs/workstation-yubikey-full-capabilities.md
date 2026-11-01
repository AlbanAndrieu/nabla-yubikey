# YubiKey workstation — full feature inventory and migration from nabla

> **Ownership (ADR-WKS-001, 27 octobre 2026) :** ce dépôt est la source de vérité pour toutes les opérations et preuves *matérielles* YubiKey. Le bundle historique `ansible-workstation/tasks/yubikey.yml` et son template PAM sont retirés dans une PR Ansible, sans suppression de paquets ni modification du poste. `ansible-workstation` garde uniquement les politiques et dépendances OS, en mode opt-in sans mutation PAM. Voir [ADR](adr/adr-workstation-option-a.md) et [roadmap YubiKey](roadmap-workstation-yubikey.md).

> **No automatic enrollment.** Keep the working KeePassXC OTP slot 2 untouched
> on both keys (primary 11110001, backup 11110002).
> The two devices share a verified HMAC-SHA1 response. Other applications
> (PIV, OpenPGP, FIDO2, OATH) are logically separate from OTP slot 2.

## Scope and original sources

The original `nabla/env/linux/run-yubikey-ca.sh`,
`run-yubikey-webauthn.sh`, `run-yubikey.sh`, `run-yubikey-old.sh`,
`run-ssh-keygen.sh`, `run-gpg.sh`, and `run-keepass2.sh` mixed
documentation and commands with side effects. Preserve the intent below.
History is recoverable from nabla master (before PR #66) and Git history.
**Do not execute old scripts as-is.** In particular, avoid `set -x`,
PIV reset, hard-coded management secrets, private-key exports into the repo,
clobbering PAM files, and `ssh-add -D`.

## Capability and credential separation

| Capability | Key storage / workflow | Validation | Caveat |
|---|---|---|---|
| KeePassXC | OTP slot 2, HMAC-SHA1 challenge response | `diagnose-yubikey-keepassxc.sh --challenge` | BOTH keys already configured; preserve |
| FIDO2/WebAuthn | FIDO2 authenticator, resident/discoverable credentials | `ykman fido info` | Register each key separately per relying party |
| SSH FIDO2 | OpenSSH security key `ed25519-sk` or `ecdsa-sk` | `ssh-keygen -lf ~/.ssh/id_ed25519_sk.pub` | private *handle* stays on disk; private key material stays inside authenticator |
| SSH PIV | PIV slot 9a/9c via PKCS#11 (alternative) | `ykman piv info`, `ssh-add -s /usr/lib/.../opensc-pkcs11.so` | Do not mix with SSH FIDO setup blindly |
| Smart-card CA / TLS | PIV asymmetric slots 9a/9c/9d/9e and certificates | `ykman piv certificates list` | 9a is authentication, 9c signing; CA key policy requires offline root and separate CA design |
| GPG signing/encryption | OpenPGP applet; smart-card-backed GPG subkeys | `gpg --card-status` | Move or generate *subkeys*, keep offline backup and revocation certificate |
| age encryption | `age-plugin-yubikey` using PIV identity | `age-plugin-yubikey --list` (where supported) | age X25519 identities are not interchangeable with GPG or KeePass HMAC; plugin typically uses PIV slot |
| PAM login/sudo | pam_u2f enrollment; one key per registration | `pamu2fcfg` (enrollment), inspect `~/.config/Yubico/u2f_keys` | never edit PAM automatically; test backup login |
| GNOME keyring | GNOME Keyring/libsecret (Seahorse) independent of token | `secret-tool`/Seahorse inventory | YubiKey does not natively unlock GNOME Keyring; requires a carefully reviewed integration |
| OATH TOTP | Yubico Authenticator OATH applet | `ykman oath info` | Back up recovery codes; OATH is separate from OTP slot 2 |
| PIV Windows/macOS login | Platform-specific smart-card workflow | platform validation | outside Linux workstation scope |

## Safe read-only inventory

With one YubiKey connected:
```bash
bash scripts/workstation/bootstrap-yubikey-manager.sh --check
bash scripts/workstation/diagnose-yubikey-keepassxc.sh --challenge
ykman fido info
ykman piv info
ykman piv certificates list
ykman openpgp info
ykman oath info
gpg --card-status
ssh -V
command -v age-plugin-yubikey || true
```
Some GPG tools may prompt for PIN or connect via pcscd; these commands
do not deliberately change applet credentials. Do not post unredacted
smart-card serials, PIN attempts, public identities or detailed logs.

## PIV certificates and historical CA

The historical `run-yubikey-ca.sh` described a locally generated
self-signed RSA-2048 `CN=nabla` certificate with an expiry in 2036,
import into 9a using files `cnf/ca-nabla.cer` and `cnf/ca-nabla.key`,
plus management key rotation. **These are historical notes, not proof
of the present hardware state.** Do not blindly reset PIV or import
the old software private key.

Recommended flow after explicit inventory/backup and approval:

1. Inventory existing PIV objects/slots and certificate chains; identify
   actual ownership and workloads, including any SSH or age integrations.
2. Secure PIN/PUK and management key in a vault, avoiding command-line
   arguments and logs; record recovery procedures.
3. For *new* keys prefer on-device key generation in intended PIV slots;
   use an externally reviewed CA and a CSR/signing workflow, rather than
   uploading a CA root private key to a general-purpose device.
4. For SSH authentication consider slot 9a via PKCS#11. For certificate
   signing use 9c only after algorithm/application compatibility testing.
5. Validate certificate chain, expiry, hardware-bound private-key use,
   revocation, and backup/offline recovery.

Reference: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html

## SSH: recommended FIDO2 first

For a **new separate SSH key**, after confirming support and having
a recovery route, provision interactively:
```bash
ssh-keygen -t ed25519-sk -O verify-required -C "yubikey-workstation"
ssh-keygen -lf ~/.ssh/id_ed25519_sk.pub
```
Avoid overwriting an existing `id_ed25519_sk`; choose a unique `-f`
path per key. Add each public key individually to GitHub/GitLab/hosts.
A second authenticator cannot reproduce the first one's private SSH
key; enroll it separately. Resident keys are optional (`-O resident`)
and influence portability and credential capacity. Prefer PIN/touch
and do not disable existing software SSH identities before testing.
Check existing `run-ssh-keygen.sh` intentions: SSH agent, Git signing,
GitHub and GitLab authentication, authorized signers.

Reference: https://developers.yubico.com/SSH/

## OpenPGP/GPG: signing, encryption, authentication

The original `run-gpg.sh` recorded `pass`, Git commit signing,
Docker credential-store, and GPG subkeys. Before migrating existing
key material, capture **fingerprints** with `gpg --list-secret-keys
--with-subkey-fingerprint`, verify where existing secret keys are
actually stored, and make an encrypted **offline** backup plus a
revocation certificate. Do not run `gpg --export-secret-keys` into
worktrees or in CI.

Preferred strategy: keep an offline primary key, create independent
signing/encryption/authentication subkeys, and place intended subkeys
on the OpenPGP card (after verified recovery). `gpg --edit-key` /
`keytocard` can move existing subkeys and may remove local usable
copies; only do so after verification and approval. Test GPG signing,
file decryption and optional SSH via gpg-agent on **each** key before
changing git config or password-store recipients.

OpenPGP card keys and PIV keys are separate applets, both available on
YubiKey 5; using one does not imply mirroring the other.

Reference: https://developers.yubico.com/PGP/

## age: two supported architectures

- Native age file keys (`age-keygen`) live in a software file — not
  automatically on YubiKey.
- `age-plugin-yubikey` implements hardware-backed age identities using
  the PIV functionality of the token. Check available PIV slots first
  and document plugin/version compatibility. Enrollment may consume a
  PIV credential and could conflict with existing PIV CA/SSH plans.
  Provision *distinct identities* for both YubiKeys, then encrypt to
  **both recipient identities** for recoverability.
- `age`, `sops`, and their version-specific plugin integrations
  should be tested with one throwaway test document first.

Reference: https://github.com/str4d/age-plugin-yubikey

## PAM U2F (sudo/login) and keyring

Historical `run-yubikey-webauthn.sh` used `pamu2fcfg` but
overwrote `~/.config/Yubico/u2f_keys`, then proposed editing
`/etc/pam.d/sudo` and `/etc/pam.d/gdm-password`. NEVER apply this
automatically: a wrong PAM line can lock out console, sudo, and recovery.
Create an operator-reviewed enrollment with **both** keys, append
additional authenticators to the same identity, maintain a separate
administrator/recovery route and working root session, test sudo/login
before enabling a required factor. Do not confuse PAM U2F with
`ykpamcfg` / legacy challenge-response PAM modules.

GNOME Keyring/libsecret/Seahorse is not a YubiKey applet. Explore
independent PAM/keyring auto-unlock settings and the effects of FIDO2
authentication, particularly when the user does not enter a login
password. Never assume FIDO2 automatically unlocks encrypted keyrings.

References:
- https://developers.yubico.com/pam-u2f/
- https://github.com/Yubico/pam-u2f

## Acceptance / roadmap (no provisioning yet)

- [x] KeePassXC challenge-response identical on both YubiKeys.
- [x] Central read-only diagnostic and bootstrap `ykman`.
- [ ] Inventory PIV slot occupancy/certificates for both devices.
- [ ] Inventory OpenPGP, OATH, FIDO2 discoverable-credential usage.
- [ ] Decide SSH FIDO2 vs SSH PIV; register **both keys** and test.
- [ ] Choose GPG offline primary/subkey and disaster recovery policy.
- [ ] Evaluate age-plugin-yubikey slots and dual-recipient recovery.
- [ ] Stage PAM U2F dual-key enrollment with rollback, not production edits.
- [ ] Evaluate GNOME Keyring effects; avoid circular unlock dependency.
- [ ] Add fixture-based tests, shellcheck and a no-secrets/no-destructive-ops gate.

## Hardware audit evidence — backup YubiKey 11110002, 2026-10-16

Validated on workstation with ykman 5.8.0 and KeePassXC 2.7.10:

| Capability | Finding | Priority |
| --- | --- | --- |
| OTP slot 2 | HMAC-SHA1 matches primary 11110001 | ✅ Preserve |
| FIDO2 | AAGUID detected, PIN enabled, 8 attempts left | ✅ Inventory credential registrations |
| PIV key slot 9A | RSA2048 key with self-signed Nabla Root CA certificate | ⚠️ Determine actual usage |
| PIV certificate | Expired 2025-01-22 (issued 2024-12-23) | 🔴 Replace only after dependency and recovery analysis |
| PIV management | AES256 protected by PIN | ✅ Protect management recovery |
| PIV PIN / PUK | 3 / 3 attempts remaining | ⚠️ Avoid PIN/PUK guessing |
| OpenPGP | v3.4; user PIN 3 tries; admin PIN 3 tries; reset code 0 | ⚠️ Inventory card keys and recovery before any attempt |
| OATH | Password protection disabled | ⚠️ Review device threat model and backup codes |
| SSH | ssh-keygen available | ⏳ Provision distinct FIDO2 identities after inventory |
| age | age installed, age-plugin-yubikey absent | ⏳ Plan plugin/recipients after PIV slot inventory |
| PAM | pamu2fcfg absent | ⏳ Keep existing login working |
| Keyring | secret-tool and Seahorse installed | ⏳ Check existing keyrings/read-only |

`ykman piv certificates list` **does not exist in ykman 5.8.0**. The
canonical audit now relies on `ykman piv info`, redacts CHUID from its
output, checks the certificate expiry, and reports actionable statuses
with ANSI colours on terminals (respects `NO_COLOR`).

Never place the raw CHUID, HMAC_SECRET, PIN or PUK in public logs. A
self-signed certificate having “Root CA” in its common name does not
prove correct CA key usage or trust anchor registration: verify the
certificate extensions, trust stores and dependent applications.

No hardware changes have been made by these scripts; the manually
programmed HMAC slot 2 is retained.

## Critical ownership: future Vault PKI and existing PostgreSQL GPG backups

Operator clarified on 2026-10-16 that the historical **Nabla Root CA**
was probably intended to be the master trust anchor of a future Vault
deployment, and existing GPG material signs Git commits **and is used for
PostgreSQL backups**. These are different security domains. Treat the
latter as *production recovery-critical* until proven otherwise.

### PKI: audit before choosing a Vault architecture

- The current certificate in PIV slot 9A is self-signed and expired.
  Its subject name `Nabla Root CA` alone does **not** establish
  `basicConstraints=CA:TRUE` nor `keyCertSign`. Export the **public**
  certificate for inspection, never the private key:
  ```bash
  ykman --device 11110002 piv certificates export 9a /tmp/nabla-9a-public.pem
  openssl x509 -in /tmp/nabla-9a-public.pem -noout -text
  ```
- First verify provenance and trust stores, certificate extensions,
  certificate validity, whether the 9A key is actually on-token or was
  imported, and whether any service depends upon it.
- A future Vault/OpenBao PKI intermediate may be signed by an **offline**
  Root CA only with a supported signing mechanism and proper CA key
  policy. A PIV 9A authentication slot should not be assumed to be an
  appropriate long-lived CA signing slot.
- Plan CA recovery, publication of trust anchors, revocation/CRL,
  path-length constraints, intermediate rotation and short-lived
  leaf certificate issuance. Keep the trust-root independent of Vault
  availability; avoid a circular bootstrap dependency.
- Do **not** renew/reissue/import or reset PIV automatically.

### OpenPGP/GPG: PostgreSQL backup recovery is P0

- Signing Git commits and decrypting encrypted backups are **different
  cryptographic capabilities**. Determine whether the same primary key
  owns both signing and encryption subkeys; never infer from the
  OpenPGP applet's mere availability that the required backup-decryption
  secret material lives on the token.
- Inventory locally without exporting secrets:
  ```bash
  gpg --list-secret-keys --with-subkey-fingerprint --keyid-format LONG
  gpg --card-status
  git config --get user.signingkey || true
  ```
- Inventory backup scripts for `gpg`, `pg_dump`, `pgbackrest`,
  `wal-g`, `barman`, and `age`: identify encrypting recipients and
  private key escrow. Do not dump PostgreSQL credentials or backup
  paths into CI logs.
- **P0 acceptance**: decrypt an existing, encrypted PostgreSQL backup
  into an isolated and access-controlled test environment, validate
  checksums, and perform an actual test restore into a disposable
  PostgreSQL database, with zero changes to production. A GPG decrypt
  success alone is not proof of a usable backup.
- Before moving subkeys to any YubiKey, make verified encrypted offline
  backups and revocation material. `gpg --edit-key keytocard` can
  remove locally usable secret material; never do it as a diagnostic.
- For future backups, use a documented encryption recipient/rotation
  strategy that retains access to historical data. An offline escrow
  decryption key or well-controlled recovery recipient may be
  appropriate. A hardware YubiKey cannot simply be cloned by copying a
  GPG smart-card private key from one token to another.

### Acceptance order

1. [ ] Map PostgreSQL backup encryption scripts and key/subkey IDs.
2. [ ] Demonstrate decryption and isolated PostgreSQL restore of a
       representative encrypted backup.
3. [ ] Inspect public 9A cert and current CA dependencies.
4. [ ] Approve offline root + Vault/OpenBao PKI intermediate model.
5. [ ] Only then consider GPG subkey placement and PIV reprovisioning.


## Répartition cible multi-usages, deux YubiKeys (17 octobre 2026)

Le plan d'exécution détaillé, la matrice de récupération, les
critères d'acceptation et l'inventaire des emplacements sont
centralisés dans
[`workstation-yubikey-gpg-vault-roadmap.md`](workstation-yubikey-gpg-vault-roadmap.md)
(section **Architecture cible « YubiKey full capabilities »**).

Résumé opérationnel :

| Application | Usage ciblé | Emplacement / gouvernance |
| --- | --- | --- |
| OTP | KeePassXC | Slot 2 HMAC SHA1 programmé sur les deux clés, ne jamais modifier |
| PIV | SOPS / age | Retired 82 sur chaque YubiKey (nouvelle identité P-256 indépendante), 83 pour rotation |
| OpenPGP | Git signé, chiffrement e-mail, fichiers, PDF enveloppés GPG | Sign / Encrypt / Auth à provisionner seulement après protection de la récupération |
| FIDO2 | SSH humain, passkeys, authentification forte | Identités séparées par clé, secours SSH obligatoire |
| PIV 9C | S/MIME / signature PDF PAdES avec X.509 | Certificat compatible et outil de vérification requis |
| PIV 9D | Confidentialité S/MIME / clients | Non confirmé libre ; ne pas écraser |
| PIV 9A | Historique Nabla Root CA, import RSA2048 | **OCCUPÉ** ; certificat expiré, pas d'écrasement |
| PIV 9E | Authentification de carte | À inventorier |
| TLS public | Certificats de sites web | ACME côté proxy/serveur ; ne pas nécessiter présence de YubiKey |
| Vault/OpenBao | Administration, amorçage, parts de récupération, PKI | Root CA hors ligne, intermédiaire, recovery partagé ; ne pas considérer YubiKey comme auto-unseal HA |
| Chiffrement backups | TrueNAS/Postgres et fichiers | Destinataires de récupération indépendants, fixture et test de restauration isolé |

**État réel constaté sur la carte de secours :** `ykman piv keys
info 9A` indique RSA2048 **IMPORTED** avec PIN **ONCE** et touch
**NEVER**. `ykman piv keys info 82` et `83` affichent
`No key stored` : ils sont vides **sur cette seule carte**.
L'état des 18 autres slots retired et de 9C/9D/9E n'est pas
connu. Aucune nouvelle clé age/PIV n'a été provisionnée.

**Sécurité :** ne pas substituer une clé physique à un plan
de récupération ; garder l'identité SOPS X25519, distribuer
plusieurs destinataires matériels et tester la perte de carte
sans manipuler de secrets de production. Le firmware 5.4.3
n'autorise pas de présumer les fonctions introduites en 5.7.

### Mise à jour de l'inventaire principal/secours (PR #258)

La principale (11110001) a été inspectée avec
`ykman piv info` : firmware 5.4.3, PIN/PUK PIV 3/3,
management key AES256 protégée par PIN, slot 9A avec
certificat Nabla Root CA historique expiré le 2025-01-22.
`age-plugin-yubikey --list` n'a trouvé aucune identité.
L'état réel des slots retired 82–95 et des slots 9C/9D/9E
**reste inconnu sur la principale**.

La secours (11110002) a été inventoriée avec
`ykman piv keys info` : 9C/9D/9E **vides** et
82–95 **tous vides** ; 9A reste occupé. Les certificats
9A affichés sont identiques dans les sorties, mais
la correspondance avec les clés privées ne constitue pas
une preuve cryptographique sans opération de vérification.

Allocation cible inchangée : slot 82 pour une identité age
distincte par YubiKey après inventaire et validation de
l'escrow X25519 ; slot 83 réservé aux rotations.
Les autres usages SSH, GPG, PDF, S/MIME, Vault et backups
sont planifiés sans provisionnement automatique.

## Audit de migration avant fusion de nabla PR #66 (17 octobre 2026)

Source effectivement revue : `AlbanAndrieu/nabla` PR #66,
`refactor(security): centraliser les diagnostics YubiKey et KeePassXC`,
six chemins modifiés. **Décision :** les wrappers restent
dans `nabla` pour compatibilité, et l'implémentation
canonique ainsi que la documentation d'exploitation restent
dans `nabla-compose`.

| Fichier historique / PR #66 | Information utile conservée | Sort |
| --- | --- | --- |
| `env/linux/YUBIKEY-DIAGNOSTIC.md` | Incident HMAC-SHA1 du 16 octobre, restauration du slot OTP2 de secours, précautions HMAC_SECRET, nécessité du test d'ouverture KDBX avec chacune des cartes | Couvert par `docs/workstation-yubikey-keepassxc.md`; conserver le wrapper et la référence |
| `env/linux/run-yubikey.sh` | Ancien enchaînement PCSC, PIV, PAM/U2F, yubikey-agent, SSH FIDO2, OpenSC | Roadmap d'exploitation ici ; **ne pas** récupérer les commandes de purge de paquets, changement de PAM et génération de clés |
| `env/linux/run-yubikey-old.sh` | Références historiques ykman, personnalisation, attestation PIV, PKCS#11 | Documentation historique, wrapper déprécié |
| `env/linux/run-yubikey-webauthn.sh` | Enrôlement PAM U2F, `pamu2fcfg`, `~/.config/Yubico/u2f_keys`, login GNOME/sudo | Prévoir contrôle et rollback sur session secondaire ; **ne jamais écraser** `u2f_keys` ni modifier PAM sans plan de récupération |
| `env/linux/run-yubikey-ca.sh` | Projet de CA Nabla, ancien certificat PIV 9A importé, ykman/PIV, diagnostics PCSC | Conserver l'architecture de PKI ; **ne pas reprendre** reset PIV, PIN par défaut, echo de passphrase ni import non contrôlé de clé CA |
| `env/linux/yubikey-diagnostic.sh` | Résolution `NABLA_COMPOSE_ROOT` puis dépôts voisins ou `$HOME/w/nabla-compose` | Wrapper de compatibilité à laisser dans `nabla` |

**Références historiques supplémentaires** évoquées dans l'ancien
`run-yubikey.sh` : `run-ssh-keygen.sh`, `run-gpg.sh`,
`run-keepass2.sh`. Elles ne sont **pas** modifiées dans
la PR #66 et leur contenu n'est **pas** garanti migré ligne par
ligne par ce contrôle des six fichiers. Pour les supprimer ensuite,
faire un audit séparé et conserver seulement usages, diagnostics et
procédures sûres. L'historique Git demeure une source d'archive,
pas un runbook à exécuter.

### Points de migration à verrouiller

1. `nabla-compose` reste la source de vérité pour les
   diagnostics et l'inventaire : `diagnose-yubikey-keepassxc.sh`,
   `audit-yubikey-capabilities.sh`, bootstrap, age/SOPS et tests.
2. PR #66 garde des wrappers minces pour `run-yubikey*.sh` ;
   l'utilisateur doit pouvoir définir `NABLA_COMPOSE_ROOT`.
   Ne pas supprimer ces wrappers avant vérification des appels
   par cron, scripts, documentation ou autres dépôts.
3. L'ancien `ykman piv certificates list` n'est pas pris en
   charge par la version ykman 5.8.0 constatée ; préférer
   `ykman piv info` et `ykman piv keys info SLOT`
   avec identité de carte liée au numéro de série.
4. Le certificat 9A historique de « Nabla Root CA »
   est expiré depuis janvier 2025. Vérifier les dépendances
   avant rotation ; préserver la clé PIV et tout coffre CA
   historique. Ne pas exposer dans Git d'anciens noms de
   fichier de clé privée CA, de passphrases ou de PIN.
5. Garder les preuves des tests de récupération : OTP2 sur
   les deux cartes, PIV 23 slots libres sur chaque carte,
   sauvegarde age TrueNAS restaurable avec la SanDisk.
   L'ouverture KDBX sur chaque carte et le déchiffrement
   SOPS complet avec identité restaurée restent des gates
   distincts de reprise après sinistre.
6. Ne pas réécrire les vieux fichiers de `nabla` au-delà
   des wrappers sûrs sans une vérification indépendante
   des consommateurs. **Aucun merge automatique.**

### Nouvel état de la copie de récupération age

Une sauvegarde chiffrée age créée le 17 octobre 2026
a été déplacée vers `~/Downloads/` avec suffixe
`.age.log`, mais elle reste un fichier age chiffré,
pas un journal. La seconde copie est toujours sur
`/media/backup/lab/secret/keepass/` et a été copiée
sous `~/.local/share/nabla/age-backups/` ; les deux
copies de ce second fichier ont la même empreinte
SHA-256 déclarée par l'opérateur. La copie TrueNAS
a **PASS** au test de récupération de l'identité age
avec la clé indépendante conservée sur la SanDisk.
Aucun contenu privé ni passphrase enregistré dans Git.
