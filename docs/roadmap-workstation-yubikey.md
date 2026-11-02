# Roadmap nabla-compose — YubiKey et intégrations workstation

> **Mise à jour d'autorité (30/10/2026) :** le dépôt [nabla-yubikey](https://github.com/AlbanAndrieu/nabla-yubikey) existe, sa PR #1 est Draft ; le lot des dépendances readonly y est importé. La cible des runbooks matériels/escrow est maintenant ce dépôt ; Compose garde temporairement les 84 recettes historiques jusqu'à parité des tests. Le tableau ci-dessous documente **l'état historique avant cutover**. Suivi opérationnel transversal : [roadmap OpenClaw/YubiKey](https://github.com/AlbanAndrieu/nabla-compose/blob/master/docs/roadmap-openclaw-yubikey-extraction-20261030.md).

> **30 octobre — extraction non encore réalisée :** le dépôt
> [`nabla-yubikey`](https://github.com/AlbanAndrieu/nabla-yubikey) existe ;
> sa PR #1 reste **Draft** et ne contient qu'un premier lot de diagnostics
> de dépendances. Les 84 recettes historiques Compose restent accessibles
> jusqu'à validation de la parité. Ne transférer aucun secret, PIN, PIV,
> archive age ni données SOPS. [Plan et ADR](migrations/workstation-yubikey-extraction-20261030.md).



**Date : 27 octobre 2026**. Ceci est le volet de la roadmap **propre à Compose**, sans recopier les actions système ou shell d'autres dépôts. Décision : [ADR Option A](adr/adr-workstation-option-a.md). Références déjà existantes : [inventaire des capacités](workstation-yubikey-full-capabilities.md), [runbook secondaire cinq chantiers](runbooks/yubikey-backup-five-execution.md) et [roadmap PIV/GPG](workstation-yubikey-gpg-vault-roadmap.md).

| Priorité | Action | Validation / gate | État |
| --- | --- | --- | --- |
| P0 | Maintenir **un seul owner** pour les diagnostics OTP2, FIDO2, SSH-sk, PIV, GPG/OpenPGP, age, escrow | Tous les scripts matériels restent sous `scripts/workstation/` ; aucun write automatique | Déjà centralisé ; intégration Ansible à retirer |
| P0 | Distinguer l'escrow age **validé** du provisioning PIV82 et du PRA restant | Deux archives chiffrées sur supports distincts, chacune restaurée et identité historique confirmée ; phrase secrète accessible hors SanDisk/workstation/NAS **non attestée** | **Sauvegarde/restauration DONE ; PIV82/PRA NO-GO**, aucune mutation matériel |
| P0 | Contrat inter-dépôts pour PAM / dépendances YubiKey | Compose ne touche pas `/etc/pam.d` ; Ansible audite PAM sans muter | Documentation acceptée |
| P1 | Harmoniser les commandes de préflight YubiKey dans les runbooks actifs | Un seul chemin `--readonly` sans SCD, PIN, PUK ni mutation de slots | À consolider |
| P1 | Proposer à Ansible la liste minimale de prérequis OS sans les installer automatiquement | Matrice versions/dépendances (pcscd, libfido2, opensc, ykman) expurgée | À faire |
| P1 | Définir sauvegarde indépendante des artefacts de récupération sensibles | Restic chiffré ou coffre chiffré validé, copie hors NAS, restauration prouvée | À faire sans sauvegarder les secrets sur Git |
| P2 | Débloquer éventuellement PIV82 après les gates et décision humaine explicite | Génération supervisée 0x82 seulement ; OTP2/PIV9A inchangés | **NO-GO** jusqu'aux preuves |
| P2 | Intégrer les preuves autorisées au catalogue sécurité | Métadonnées de conformité seulement, aucune identité unique de carte | À faire |

**Propriétaires des autres étapes :** `dotfiles` pour shell/terminal et `ansible-workstation` pour OS, système PAM, paquets, réseau, snapshots et sauvegarde Restic. Les runbooks hardware de Compose ne deviennent pas des rôles Ansible.

**P1 NFS actuel (preuves 30/10, sans mutation) :** l'export de
sauvegarde est actif et accessible en écriture, sans filtres `hosts`
ou `networks` au niveau partage, avec `security=DEFAULT_UNVERIFIED`.
Les trois flags sont documentés dans la
[roadmap transversale](https://github.com/AlbanAndrieu/nabla-compose/blob/master/docs/roadmap-openclaw-yubikey-extraction-20261030.md).
La sonde clients TCP/2049 a initialement retourné
`SS_RESPONSE_UNVERIFIED` ; la correction du parseur `ss` a été **revalidée**
sur TrueNAS depuis un worktree PR #300 au SHA `245bd928` : **8/8 tests PASS**,
`TCP_SNAPSHOT_OBSERVED`, **1 session TCP et 1 pair distinct** sur tous les
exports NFS. Ce n'est ni un inventaire spécifique de l'export `lab` ni une
liste exhaustive : `all_clients_enumerated=false` et
`consumer_allowlist_verified=false`. La suite reste read-only ; une
allowlist ne doit pas être construite depuis les seules connexions
du moment. [Matrice d'extraction](migrations/workstation-yubikey-extraction-20261030.md).

**Sans consentement :** aucune rotation de PIN/PUK, clé PIV AES256, changement OTP2, reset PIV, export de clés GPG ou activation PAM. Pas d'automerge ni de CI payante, tests offline avant manipulation supervisée.
