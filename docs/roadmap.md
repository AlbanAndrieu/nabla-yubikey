# Roadmap — extraction YubiKey / age / SOPS (30 octobre 2026)

> **Source de vérité cible :** `nabla-yubikey`. Cette roadmap suit uniquement le code client et les procédures matérielles. L'infrastructure NFS/ZFS et les exports appartiennent à `nabla-compose` ; les dépendances Ubuntu à `ansible-workstation`. Le dépôt public ne contient aucun secret. **Aucune opération sur la carte n'est autorisée par ce document.**

## État vérifié dans Git

- Dépôt dédié créé ; PR [#1](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1) **Draft, non fusionnée** au contrôle du 30/10.
- **Lot 1 importé dans cette PR** : `inspect-yubikey-dependencies-readonly.py` et ses tests hermétiques ; aucun accès smartcard, aucune modification système. Le `justfile` contient `test`, `dependencies-readonly`, `ssh-fido2-readonly`, `applets-readonly`, `keepassxc-readonly` et `check` (tout).
- `nabla-compose` [PR #295](https://github.com/AlbanAndrieu/nabla-compose/pull/295) **fusionnée** : les anciennes recettes et scripts YubiKey restent la référence temporaire jusqu'à parité documentée.
- Les prérequis OS sont déjà traités par `ansible-workstation` ; ne pas réintroduire de tâches PAM globales.
- **31/10** : clé SSH FIDO2 résidente générée sur décision explicite et signature via `gcr-ssh-agent` PASS ; procédure et piège askpass/Wayland dans le [runbook SSH FIDO2](runbooks/ssh-fido2.md). Clé publique ajoutée sur GitHub (push PASS, PIN demandé) ; commits signés OpenPGP « Verified ». truenas/pfsense restent sur `id_ed25519`, sans transfert d'agent. Sonde `just ssh-fido2-readonly` : **GO**.
- **31/10, déverrouillage Vaultwarden** : `bw unlock` exige encore le mot de passe maître. L'OTP YubiKey est déjà actif dans Vaultwarden, mais il ne sert qu'à `bw login --method 3`, pas à `unlock`. Constats en lecture seule : la YubiKey testée a **0/3 emplacement OpenPGP rempli** et la clé de `pass` (`~/.password-store/.gpg-id`) est **logicielle**. `gpg --card-status` répondait `Card error` jusqu'à `gpgconf --kill scdaemon`.
- **31/10, KeePassXC** : fichier clé sorti de Dropbox (local 600), coffre en Argon2id 256 Mio avec phrase de passe, ouverture **PASS** avec les deux YubiKeys ; [runbook](runbooks/keepassxc.md), sonde `just keepassxc-readonly` **GO**. La clé SSH `ssh:nabla` et 7 identifiants FIDO2 (GitHub, Microsoft, AWS ×2, Bitwarden, Stripe, OpenAI) ne sont **que sur la secondaire**. Rapport de santé du coffre : 148/176 mots de passe faibles, 108 réutilisés (jusqu'à 29 fois).

## Refactoring lecture seule — novembre 2026

- [x] **Inventaire des applets** : allowlist de commandes `ykman`, refus des sorties OTP contradictoires et compteurs FIDO2/PIV/OpenPGP incomplets (`*_UNREADABLE` plutôt que faux `GO`).
- [x] **KeePassXC** : parsing borné du seul en-tête externe KDBX, refus des champs malformés, des fichiers spéciaux et des algorithmes inconnus ; sélection locale du dernier fichier tolérante aux suppressions concurrentes.
- [x] **SSH FIDO2** : exécution de sondes limitée aux commandes autorisées, traitement unifié des timeouts/sorties, état `ForwardAgent` ambigu classé `UNKNOWN`.
- [x] **Justfile** : `just test` concis, `just test-verbose` pour investigations.
- [x] **Helpers partagés** : `probe_common.py` refuse les sorties OTP supplémentaires/contradictoires et les rôles libres ou ambigus ; limites d'exécution des commandes et contenu d'erreur Git stricts.
- [x] **Applets** : un état USB/NFC inconnu ou un compteur PIN/KDF répété ne peut plus produire un faux `GO`.
- [x] **SSH** : sortie d'erreur Git non vide et métadonnées d'agent manquantes/dupliquées deviennent `UNKNOWN` bloquant.
- [x] **KeePassXC** : détection des liens symboliques de fichier clé dans le cloud, `cloud_keyfile_scan` triétat, rejet des dossiers et des champs cryptographiques KDBX dupliqués.
- [x] **Prérequis système** : contrôles des binaires PostgreSQL regroupés dans `trusted_executable`, émission JSON partagée, sans commande d'administration.
- [x] **Contrats hermétiques** : scénarios de rejet ajoutés aux tests ; aucune exécution des tests ni diagnostic matériel demandée dans cette itération.
- [ ] **Preuve d'exécution sur le HEAD** : `just test` puis `just dependencies-readonly`, `just ssh-fido2-readonly`, `just applets-readonly`, `just keepassxc-readonly` exécutés localement sur la workstation (une YubiKey à la fois). **Non exécuté par cet agent** en l'absence de checkout/réseau Git dans son environnement.
- [x] **Comparateur statique Compose** : `scripts/ops/compare-compose-contracts.py` (AST uniquement), champs `snapshot()` de `inspect-yubikey-dependencies-readonly.py`, état `SCHEMA_MATCH/NO-GO`, `runtime_parity_verified=false`, aucun appel Git/sonde ; recette `just compose-contract` et tests hermétiques ajoutés.
- [x] **Sortie JSON partagée** : les quatre sondes conservent leur `mode` lors d'une exception ; erreur expurgée, `status=NO-GO`, `blocking=[PROBE_EXCEPTION]` sans chemin privé ni traceback.
- [x] **Parité des valeurs simulées préparée** : `compare-probe-fixtures.py` compare les champs et les codes de sortie enregistrés sur scénarios synthétiques avec différences expurgées ; recette `just fixture-contract` (deux fichiers explicitement fournis).
- [x] **Comparaison hermétique Compose ↔ YubiKey préparée** : `test_compose_runtime_parity.py` couvre les valeurs de snapshots, `status=NO-GO`, code 0 du rapport JSON et refus des arguments code 2 ; `just parity-tests` exige un checkout Compose local. Aucune commande d'observation effective durant les scénarios mockés.
- [ ] **Preuve d'exécution et parité matérielle** : les deux comparateurs et la suite de tests ne sont pas exécutés dans cette itération. `FIXTURES_MATCH` / `SCHEMA_MATCH` ne prouvent ni la parité runtime ni les comportements matériels ; les anciennes recettes Compose restent maintenues.

## File de travail priorisée

| Priorité | Lot | Livrable | Gate / état |
| --- | --- | --- | --- |
| **P0 — maintenant** | 0 — déverrouillage Vaultwarden par YubiKey | Sous-clé de chiffrement OpenPGP sur la YubiKey principale **et** la YubiKey de secours (sauvegarde hors carte testée avant `keytocard`) ; mot de passe maître Vaultwarden dans `pass` chiffré pour cette clé ; déverrouillage depuis la Workstation `pass show … \| ssh truenas '… bw unlock --raw --passwordenv …'`, mot de passe jamais écrit sur disque ni tapé ; runbook + sonde lecture seule | **Décidé le 31/10, à faire maintenant** ; partie `pass` prête : [`bw-unlock`](runbooks/vaultwarden-unlock.md) (dotfiles), clé `pass` encore logicielle ; opération matérielle sur décision explicite de l'opérateur, après preuve de restauration sur la clé de secours |
| **P0 — maintenant** | 0b — paire de YubiKey interchangeables | Voir [liste « Paire de YubiKey »](#paire-de-yubikey-à-faire) ci-dessous | **En cours** : la perte de la secondaire coupe aujourd'hui SSH GitHub et 7 comptes FIDO2 |
| P0 | 1 — prérequis offline | Collecteur de dépendances + fixtures + `just test` | **Code dans PR #1 ; gate sur la branche non encore attesté ici** |
| P0 | 2 — lecture seule Workstation | Inventaire des commandes YubiKey actuellement exécutées depuis Compose ; tests host, GPG-agent, PC/SC, versions, état SSH-sk/FIDO2 **sans PIN ni données personnelles** | **À importer** avec les tests et états `UNKNOWN/NO-GO` |
| P0 | 3 — récupération age/SOPS | Vérification des métadonnées de deux copies indépendantes (USB + cible hors support commun), test synthétique et restauration isolée | **Partiel** : une récupération SOPS avec identité USB a déjà été signalée PASS ; cela ne démontre pas deux copies indépendantes ni un PRA complet |
| P0 | 4 — escrow USB/NFS | Sonde client readonly + contrats de chemin NFS ; permissions strictes et cas d'échec NFS non monté | **À importer** ; exports/ACL côté TrueNAS restent Compose |
| P1 | 5 — protocole matériel | Inventaire FIDO2, OpenPGP, OTP2, PIV et 0x82 ; NO-GO par défaut | **Partiel** : SSH FIDO2 fait ([runbook](runbooks/ssh-fido2.md), sonde `ssh-fido2-readonly` + tests) ; inventaire FIDO2/OpenPGP/PIV/OTP en lecture seule fait ([runbook](runbooks/inventaire-applets.md), sonde `applets-readonly` : **GO**, conseils KDF/NFC/OTP non appliqués) ; slot PIV 0x82 et usages OATH non inventoriés |
| P1 | 6 — compatibilité | Parité du `just --list`, chemins/imports, statuts/codes sortie 0/2 et wrappers Compose | **Partiel (01/11)** : les sondes ajoutées partagent `probe_common.py` (commande bornée sans stdin, échec fermé, JSON trié, sortie 0/2) et `just check` lance tests + sondes ; la sonde du lot 1 reste identique à l'original Compose. Wrappers Compose **à prouver sur Workstation** |
| P1 | 7 — cutover GitOps | Marquer les anciens scripts Compose comme dépréciés, transférer les liens de runbook, puis supprimer seulement les doublons sans consommateurs | **Bloqué par parité et revue** |
| P2 | 8 — intégration dans Compose | Évaluer `security/nabla-yubikey` piné, sans submodule automatique ni données runtime | **Différé** jusqu'à release/commit testé |

## Paire de YubiKey (à faire)

Objectif : chacune des deux clés suffit seule. Les écritures matérielles restent lancées par l'opérateur, une clé branchée à la fois, en testant l'autre clé avant toute réécriture.

1. [x] **KeePassXC — principale** : `keepassxc-cli db-info … --yubikey "2:<série>"` avec elle seule : **PASS le 31/10** (slot 2 déjà programmé avec le même secret).
2. [x] **Copie NAS du coffre** (31/10) : remplacée par la version à la nouvelle phrase de passe (identique octet pour octet au coffre Dropbox), ouverte avec la principale : Argon2id 256 Mio, 176 entrées. La secondaire ouvre le même contenu (testée sur le coffre Dropbox).
3. [ ] **Fichier clé** : copie sur l'USB d'escrow chiffrée LUKS (`keepassxc-escrow/`, 700/600) **faite le 01/11**, identique aux copies locale et NAS. Reste : retrait de la copie NAS rangée à côté du coffre, sur décision de l'opérateur.
4. [x] **SSH principale** (31/10) : `id_ed25519_sk_principale` créée, sur GitHub, acceptée avec la principale seule. `id_ed25519` reste sur GitHub en secours manuel mais n'est plus proposée à `github.com` (`Match host "*,!github.com"`), sinon elle authentifiait sans PIN quand la secondaire était absente ([runbook](runbooks/ssh-fido2.md)). Secours manuel `id_ed25519` attesté (commande du runbook). Fichiers `_sk` et `.pub` sauvegardés dans `lab/secret/ssh` (600/644), clés privées de cette sauvegarde passées en 600 ; la copie `id_ed25519` du NAS a la même empreinte que la clé courante. Reste : test GitHub avec la **secondaire** seule.
5. [ ] **FIDO2 principale** : l'enregistrer comme seconde clé de sécurité sur GitHub, Microsoft, AWS (×2), Bitwarden, puis Stripe et OpenAI.
6. [ ] **`id_ed25519` dans KeePassXC** (agent SSH), test truenas/pfsense coffre ouvert/verrouillé, puis retrait du fichier privé de `~/.ssh` (garder le `.pub`).
7. [ ] **Mots de passe** : rapport *Santé* de KeePassXC, rotation des réutilisés en commençant par les comptes de récupération (e-mail, GitHub, banque, Vaultwarden, registrar).
8. [ ] **Appui obligatoire** sur le slot 2 de la secondaire (`ykman otp chalresp --touch 2`, même secret) une fois l'étape 1 attestée.
9. [ ] **`YUBIKEY_ROLES`** déclaré localement le 31/10 (`~/.config/environment.d/50-yubikey-roles.conf`, la sonde affiche `principale`) ; décisions séparées sur OTP USB, NFC et KDF OpenPGP ([inventaire](runbooks/inventaire-applets.md)). **OTP USB constaté le 31/10** : un effleurement a tapé un code Yubico OTP dans un terminal ; Vaultwarden utilisant Yubico OTP, ne pas désactiver sans le remplacer (ex. `ykman otp swap` pour un appui long, ou WebAuthn dans Vaultwarden).

## Séquence locale sans effet matériel

```bash
# Dans le dépôt dédié, branche PR #1 :
just test
just dependencies-readonly
just ssh-fido2-readonly
just applets-readonly

# Dans nabla-compose actualisé, comparer l'inventaire
# sans déplacer ou nettoyer de fichiers :
python3 scripts/ops/plan-repository-split.py
python3 -m unittest discover -s tests -p 'test_repository_split_plan.py' -v
git grep -n -E 'yubikey-|age-escrow|sops' -- justfile scripts tests docs
```

**GO pour le transfert d'un lot :** provenance/licence revues, scripts et tests migrés ensemble, aucun secret/dump/identifiant matériel, sorties et codes identiques, vérifications offline PASS, anciens points d'entrée maintenus. **NO-GO matériel :** pas de changement PIN/PUK/OTP2, PIV9A/PIV82/F9, GPG, SSH authorized_keys, PAM ou provisioning sans décision séparée et preuves de restauration indépendantes.

**DONE extraction :** `nabla-yubikey` détient les commandes client et les runbooks opérationnels ; `nabla-compose` garde exclusivement les interfaces serveur/stockage et wrappers transitoires explicites, puis retire les doublons après revue ; aucun secret dans Git et PRA de récupération attesté sur copies indépendantes.

Références : [plan de migration](migration.md) ; [ADR de séparation Compose](https://github.com/AlbanAndrieu/nabla-compose/blob/master/docs/adr/adr-repository-split-workstation-yubikey-20261030.md).
