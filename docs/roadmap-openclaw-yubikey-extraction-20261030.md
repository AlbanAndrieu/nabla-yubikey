# Migration inter-dépôts — OpenClaw et YubiKey (30 octobre 2026)

> **Point d'entrée de coordination pour `nabla-compose`**. Le détail des tâches et les commandes propres à chaque outil appartiennent à ses roadmaps dédiées : [OpenClaw](https://github.com/AlbanAndrieu/nabla-openclaw/blob/master/docs/migration.md) et [YubiKey](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1). Les PRs Draft de consolidation peuvent précéder leur fusion : [OpenClaw #2](https://github.com/AlbanAndrieu/nabla-openclaw/pull/2), [YubiKey #1](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1). Les docs historiques restent consultables mais ne priment pas sur ce tableau.

## Réception locale du plan d'extraction — 30 octobre 2026

**Preuve fournie depuis la Workstation, sur un worktree isolé de
la branche de la PR #300 (`HEAD=a05a5ec2`)** :
`python3 scripts/ops/plan-repository-split.py` a réussi et
retourné `schema=nabla-repository-extraction-plan/v1`,
`tracked_paths=1770`, `read_only=true`,
`copy_or_delete_authorized=false`, et
`destination_access=not_checked_offline`.
`test_repository_split_plan.py` : **3/3 PASS** ;
`test_openclaw_policy_relocation.py` : **5/5 PASS**.
**Total : 8/8 tests locaux ciblés PASS.** Ce résultat ne
constitue ni gate global ni diagnostic TrueNAS, et ne prouve
aucune disponibilité d'un dépôt de destination.

| Groupe d'inventaire | Nombre au HEAD testé |
| --- | ---: |
| Fichiers Git suivis | 1 770 |
| Candidats YubiKey à revoir | 106 |
| Candidats OpenClaw à revoir | 84 |
| Candidats Workstation/Ansible à revoir | 36 |
| Fichiers serveur Compose conservés | 187 |
| Fichiers `apps/openclaw/` sandbox conservés | 4 |
| Fichiers exclus par motif sensible/crypto | 2 |
| Autres, conservés ou à revoir | 1 351 |
| **Recettes Just totales** | **375** |
| Recettes `yubikey-*` / `openclaw-*` / `workstation-*` | **87 / 98 / 15** |

Les groupes de chemins décrivent des **candidats identifiés
par motifs**, jamais une autorisation de copie. Les **87**
recettes YubiKey et **375** recettes totales remplacent
uniquement les comptages opérationnels **84/370** de l'ADR
historique ; ils n'impliquent pas que trois fonctions ont
été migrées ou qu'une recette correspond à un service.

**Gate de suite :** sur TrueNAS, exécuter en lecture seule
`python3 scripts/truenas/check-openclaw-sandbox-binding.py
--all-apps` depuis un checkout vérifié. Cette commande
retourne **2 volontairement** : inspecter le champ
`sandbox_relocation` et les compteurs, sans publier les
configurations brutes. Même une inspection complète sans
référence ne lève pas à elle seule le **NO-GO** du sandbox :
`build.sh`, catalogue et topologie pointent encore vers
l'ancien `compose.yml`. Préserver Gateway Workstation
et tous les secrets.

## Avancement vérifié dans les dépôts

| Dépôt | Propriété pérenne | Git / statut | Runtime |
| --- | --- | --- | --- |
| `nabla-compose` | LiteLLM TrueNAS, volumes ZFS, NFS, réseau, interfaces cross-host et futur gitlink | PR #295 **fusionnée** ; 14 artefacts Workstation sous `ops/openclaw-workstation/`, 4 fichiers sandbox sous `apps/openclaw/` | **Aucune migration Gateway attestée** |
| `nabla-openclaw` | Gateway Docker cible TrueNAS, heartbeat et cron déclaratifs, tests, runbooks | PR #1 **fusionnée**, PR #2 de consolidation Draft ; politiques candidates et contrat cible | **Non déployé**, automations inactives |
| `nabla-yubikey` | Diagnostics YubiKey client, FIDO2/SSH-sk/OpenPGP/PIV, age/SOPS/USB escrow, recovery | PR #1 **Draft** ; lot 1 dépendances readonly seulement | Aucun matériel modifié |
| `ansible-workstation` | Pré-requis OS, audits source systemd/Node/mise/DNS, sécurité Ubuntu | PR #16 **fusionnée** ; audit YubiKey sans PAM | Audit OS déjà attesté, pas de provisionnement matériel |
| `dotfiles` | Shell, Terminator, Starship, configuration utilisateur interactive | Hors transfert | Inchangé |

## Dépendance P0 — LiteLLM, Vaultwarden et frontières des identités

**État vérifié par les sorties opérateur, 28–30 octobre :**

| Saut | Identité | Preuve disponible | Verdict |
| --- | --- | --- | --- |
| FastAPI Sample → LiteLLM TrueNAS | `fastapi-sample-staging` ; `LITELLM_API_KEY`, modèle `fastapi-qwen` | Tentative de génération sur TrueNAS : `BLOCKED` ; résultat en base non inspecté | **UNVERIFIED** ; pas de nouvelle tentative sans inventaire d'alias |
| LiteLLM TrueNAS → LiteLLM Workstation | `fastapi-sample-upstream` ; `LITELLM_FASTAPI_WORKSTATION_API_KEY`, modèle `qwen` | 12/12 tests inventaire PASS ; alias absent avant émission ; `status=created target=workstation model=qwen` ; fichier privé `0600` attesté | **ISSUED_LOCAL**, pas encore `READY` |
| Coffre Vaultwarden → runtime TrueNAS | Champ masqué dans `nabla/prod/litellm` → `/mnt/cpool/secrets/runtime/litellm/.env.secrets` | Dernier audit fichier TrueNAS : déclaration absente ; import CLI interrompu avant `bw edit` | **NOT_VERIFIED** |
| OpenClaw main / cron → LiteLLM | Clés dédiées main/cron, distinctes de FastAPI | Attribution 429/401, budgets, modèles et identité effective à valider séparément | **NO-GO cutover** tant que les preuves manquent |

**Incident sécurité, avant tout nouvel accès au coffre :** le CLI `bw unlock` a affiché dans une sortie partagée un **jeton de session**. Le second `bw unlock --raw` a échoué au déchiffrement avant toute écriture connue. **Invalider la session exposée** (verrouillage/déconnexion locale puis révocation des sessions depuis les paramètres Vaultwarden), puis vérifier le coffre en **lecture seule** dans une session renouvelée et privée. Ne publier ni `BW_SESSION`, ni JSON d'item, ni valeurs de clés ; ne pas supprimer le cache CLI ou modifier les mots de passe sur une cause non attribuée.

**Responsabilités pérennes :** les serveurs/proxys LiteLLM, les modèles, les budgets, les fichiers runtime TrueNAS, les contrats de transit et la conservation Vaultwarden restent sous **Compose**. Le modèle de sécurité Ubuntu du poste relève de **Ansible** ; les routines Gateway et cron relèvent de **nabla-openclaw**. La logique de provisionnement du couple FastAPI → LiteLLM et les diagnostics cross-host ne sont **pas** des composants Gateway à migrer dans `nabla-openclaw`, ni de simples audits OS à déplacer dans `ansible-workstation`. Les chemins `scripts/workstation/provision-fastapi-litellm-keys.py`, `scripts/workstation/diagnose-fastapi-litellm-workstation-key.py` et `scripts/secrets/*bitwarden*` sont à revoir **explicitement** avant tout transfert.

**Prochaine unité finissable, sans activation :** vérifier que le jeton exposé a été révoqué, confirmer par lecture seulement l'accès Vaultwarden, puis attester **la présence et le format masqué du champ** avec `just litellm-fastapi-upstream-source-check` ; ce contrôle ne prouve pas l'égalité de la valeur avec le fichier `workstation.key`. L'installation du fichier runtime existant requiert une comparaison non destructive de **toutes** ses autres variables, un rollback et un `GO` opérateur. Ne pas réémettre `fastapi-sample-upstream`, réutiliser la master/IDE, déclencher des appels aux modèles ou relancer le gateway pour « réparer » l'absence du champ.

**Sources :** [PR Compose #289 fusionnée](https://github.com/AlbanAndrieu/nabla-compose/pull/289), [runbook FastAPI/LiteLLM](runbooks/fastapi-sample-litellm.md) et [incident déverrouillage](https://github.com/AlbanAndrieu/nabla-compose/pull/289#issuecomment-6457346739). **La création locale de la clé n'atteste pas les permissions/budgets réellement appliqués par `/key/info`, ni un parcours bout en bout.**

### Livraison P0 en PR #300 : preuve d'égalité coffre / clé locale

- **CODED, non encore exécuté sur la Workstation :**
  `scripts/secrets/inspect-fastapi-workstation-key-vaultwarden.py --check`,
  recette `just litellm-fastapi-upstream-vaultwarden-compare`
  et tests hermétiques
  `tests/test_fastapi_workstation_vaultwarden_compare.py`.
- Le contrôle est exclusivement **read-only** : vérification du
  fichier local émis `workstation.key` (fichier unique, régulier,
  non symlink, propriétaire courant, permissions `0600` et chemin
  privé), serveur HTTPS / dossier / item canonique Vaultwarden,
  unicité du champ et comparaison `hmac.compare_digest` en mémoire.
- Il distingue `field_absent`,
  `field_matches_private_key`,
  `field_mismatch_no_overwrite` et les états de sessions,
  permissions ou schémas non vérifiés ; ne divulgue aucune valeur,
  session ni réponse brute du coffre. Un `bw sync` peut actualiser
  le cache **local** du CLI, pas la donnée serveur.
- **Aucune session n'a été révoquée depuis GitHub.**
  Révocation de la session exposée et connexion saine en shell privé
  à faire sur Workstation ; `bw list folders >/dev/null` doit
  réussir avant le nouveau check. L'ajout du champ reste une
  opération distincte après le résultat `field_absent`.
- **NO-GO restant :** tout import automatique du fichier
  complet `litellm/.env.secrets`, toute nouvelle clé LiteLLM,
  modification de master/salt/IDE/Redis/Langfuse, redémarrage,
  activation heartbeat ou cutover tant qu'un résultat
  `field_matches_private_key` et les gates runtime ne sont
  pas attestés.

## P0 — tâches immédiates, dans cet ordre

| Ordre | Responsable | Action restante | Preuve pour DONE |
| --- | --- | --- | --- |
| 0 | **Compose + Vaultwarden** | Révoquer la session CLI exposée, rétablir l'accès readonly, puis attester le champ upstream FastAPI sans régénérer la clé Workstation | Session exposée invalidée, `bw list` readonly valide, contrôle ciblé du champ masqué, aucun runtime changé |
| 1 | **OpenClaw + Compose** | Attribuer les erreurs 429 (budget vs RPM/TPM vs upstream), 401/403 et modèles ; diagnostiquer **les deux** LiteLLM et les clés scoped **sans nouvelle génération** | Rapports Workstation/TrueNAS datés, aucun faux PASS, clés main/cron distinctes, modèle réellement disponible |
| 2 | **OpenClaw** | Importer les scripts/contrats Gateway/cron pertinents par lots et leurs tests, en maintenant les wrappers Compose | Parité des interfaces, sorties, exit codes et redaction ; `just test` et tests Compose ciblés PASS |
| 3 | **OpenClaw** | Réconcilier heartbeat candidat avec CLI native effectivement installée, mettre sous contrôle cadence/coût/session, séparer digest et tâches privées | `plan → sauvegarde privée → apply explicite → verify → rollback` ; 14 capacités non réactivées par défaut |
| 4 | **YubiKey** | Migrer les collecteurs strictement readonly avec tests (host/GPG/PCSC puis FIDO2/PIV), vérifier provenance/licences et imports | Commandes `just` équivalentes sur Workstation ; aucun PIN, PUK, OTP, PIV ou données de carte dans Git |
| 5 | **YubiKey + Compose** | Transférer par lots les contrats client age/SOPS/USB, en conservant le diagnostic de l'export/dataset NFS côté Compose | Deux **supports distincts** contenant la même identité age chiffrée, restauration de chaque copie déjà prouvée ; phrase secrète disponible **hors SanDisk/workstation/NAS non attestée** ; parité des recettes et tests avant retrait ; **NO-GO matériel** |

## P0 — réception NFS/escrow et passation Compose ↔ YubiKey (30/10)

**Preuves déjà reçues ; ne pas recommencer les sauvegardes :**
- Deux copies chiffrées identiques de **la même identité age** sur deux supports distincts (workstation et NFS TrueNAS), chacune réellement déchiffrée ; 14/14 tests de sauvegarde et 13/13 de restauration PASS. Ce ne sont pas deux méthodes cryptographiques indépendantes.
- Contrôle NFS4 quatre niveaux : 11/11 tests PASS ; une autorisation non propriétaire *potentielle* sur la racine de l'export, aucune sur les deux répertoires sensibles et le fichier.
- Contrôle des modes côté TrueNAS : 9/9 tests PASS ; répertoires `0700/0700`, archive `0600`, propriétaire uniforme. Cela **ne prouve pas** le mapping d'identité ni les droits effectifs d'un client privilégié.
- Audit `sharing.nfs.query` : 10/10 tests PASS sur workstation, `EXPORT_MATCHED` en lecture seule ; export actif, accessible en écriture, **sans filtre** `hosts` ou `networks`, `maproot/mapall=UNSET`, `security=DEFAULT_UNVERIFIED`. Trois avertissements attestés : `NO_NFS_HOST_OR_NETWORK_FILTER`, `NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED`, `EXPORT_WRITABLE`. Une sécurité par défaut **ne démontre pas** l'absence d'authentification `sec=sys`.
- **Inventaire TCP/2049 revalidé sur TrueNAS (30/10, worktree PR #300 au SHA `245bd928`) :** 8/8 tests hermétiques PASS (`0.272s`) ; précontrôle `BACKUP_RESTORATION_PREFLIGHT_READY` ; sonde `TCP_SNAPSHOT_OBSERVED`, **1 session TCP/2049 établie et 1 pair distinct**, toutes exportations NFS confondues, sans adresse divulguée ni écriture. Le précédent `SS_RESPONSE_UNVERIFIED` (avant correction du parseur `ss` à 4/5 colonnes) est **résolu** ; ne pas assimiler ce pair à un client de l'export `lab` ni en déduire une allowlist complète. `all_clients_enumerated=false`, `export_specific_clients_verified=false`, `consumer_allowlist_verified=false`.

**Contrat inter-dépôts :** `nabla-compose` garde l'export TrueNAS, ses ACL, le réseau, les scripts d'audit serveur et les dépendances NFS inter-hôtes ; `nabla-yubikey` reçoit progressivement les diagnostics client et les procédures de restauration age/SOPS avec les tests et garde-fous. Les wrappers Compose doivent rester fonctionnels tant que la parité n'est pas prouvée. Aucune copie de clé privée, identité PIV, PIN, archive age ou fichier SOPS n'entre dans un dépôt public.

**Consommateurs identifiés par le code** : un montage workstation `nabla:/mnt/cpool/backup/lab` → `/media/backup/lab` déjà observé ; les scripts OpenClaw (`backup-openclaw-nfs.py`, `copy-openclaw-backups-nfs.sh`) écrivent dans `infra/openclaw` ; l'escrow age écrit exceptionnellement dans `secret` ; un script de reprise heartbeat et des archives pfSense font également référence au partage. Cela ne prouve **ni** que pfSense est un client NFS, **ni** que ces jobs sont actuellement actifs.

**Gate P0 de reprise sans mutation, depuis un worktree propre de Compose :**

```bash
just yubikey-usb-identity-nfs-consumers-test
just yubikey-usb-identity-nfs-consumers-check
just yubikey-usb-identity-nfs-consumers-probe
```

Cette sonde n'est qu'un instantané des sessions TCP/2049 de **tous** les exports du NAS ; elle ne peut ni attribuer les sessions à `lab` ni découvrir les clients hors ligne ou intermittents. `all_clients_enumerated=false` et `consumer_allowlist_verified=false` doivent rester vrais. Corréler ensuite, hors automatisme, montages et automounts de chaque hôte, cron/backups, besoins d'écriture et filtrage pare-feu. **NO-GO** pour `sharing.nfs.update`, `ro=true`, une allowlist dérivée du seul `ss`, `chmod` ou une nouvelle sauvegarde tant que ces dépendances ne sont pas documentées avec un rollback.

**PRA encore ouvert :** débranchement physique de la SanDisk pendant un exercice supervisé, accès réel à la phrase secrète indépendamment **des trois systèmes** (SanDisk, workstation, TrueNAS) et test d'accès NFS négatif sous identité dédiée. Ne pas publier la phrase, le nom du coffre, les UID/GID ou les adresses clientes.

Traçabilité : [preuves et runbook USB age](runbooks/usb-age-identity-independent-backup-20261028.md), [inventaire d'extraction](migrations/workstation-yubikey-extraction-20261030.md), [PR #295 fusionnée](https://github.com/AlbanAndrieu/nabla-compose/pull/295).

## PR #300 — réception P0 OpenClaw au 30 octobre 2026

**CODED [skip ci], réception Workstation restante :** le hook `developer-tooling-contract` dispose désormais de `PyYAML==6.0.3` en environnement Pre-commit isolé ; `openclaw-migration-evidence.sh --diagnose` inclut les journaux des **deux** LiteLLM, l'inventaire de routes et les quotas de clés TrueNAS (tests de contrat adaptés). Le candidat `HEARTBEAT-RESTORED.candidate.md` limite ses alertes aux preuves fraîches, anomalies dédupliquées, trois signaux maximum, sans requête de génération, et conserve ses 14 anciennes capacités désactivées.

**Runbook opérateur complet :** [P0 logs, 429, cron, heartbeat et cutover](runbooks/openclaw-p0-truenas-heartbeat-20261030.md). Il précise les commandes indépendantes Workstation/TrueNAS, le mode `--truenas-sudo-logs` **seulement avec droit sudo préexistant**, les preuves privées `0600` et les critères de sortie.

**Dernières observations apportées par l'opérateur :** Gateway `ready` (3 endpoints 200), alignement Node/service PASS, dépenses de clés sous caps ; `docker_permission_denied` côté TrueNAS, `agent:cron:main` absent sur 21 sessions, digest `skill_template_range_int_mismatch`, source effective des 429 `unverified`. `--diagnose` initial : 5 PASS, 3 unverified (avant extension à trois sondes). Aucun de ces éléments ne démontre que `gpt-4.1` ou `gpt-4.1-mini` fonctionne sur TrueNAS.

**GO limité au diagnostic et aux tests locaux. NO-GO** sur redéploiement, clés, heartbeat actif, suppression du sandbox ou ajout de submodule tant que les modèles, le routage effectif, la disponibilité des logs et le rollback ne sont pas prouvés. L'environnement de rédaction n'a pas exécuté les tests dans le checkout Workstation ; ne pas écrire « PASS local » sur la seule base de modifications GitHub.

## P1 — construction et intégration

| Ordre | Responsable | Action restante | Condition |
| --- | --- | --- | --- |
| 6 | **OpenClaw + Compose** | Sélectionner image/digest non-root, stockage privé ZFS, ACL, réseau/egress et sauvegarde avec restauration hors prod | Contrat TrueNAS et recovery PASS ; aucune autoactivation de cron/heartbeat |
| 7 | **Compose** | Préparer le déplacement des **4** fichiers sandbox, après audit de `build.sh`, du catalogue, de la topologie et des includes TrueNAS ; [registre des consommateurs](migrations/openclaw-sandbox-consumers-go-no-go-20261030.md) | **NO-GO courant** : `build.sh` et plusieurs sources du catalogue pointent encore vers `apps/openclaw/compose.yml` ; scan TrueNAS `--all-apps` et rollback non attestés |
| 8 | **Compose** | Ajouter `nabla-openclaw` en submodule **piné** directement à `apps/openclaw` | SHA vérifié, aucune dépendance au dossier privé `~/.openclaw` |
| 9 | **OpenClaw + Compose** | Démarrer en parallèle sur TrueNAS, sans doubles automations, puis basculer `cron` et `main` un par un | End-to-end, budgets, reprise et rollback Workstation prouvés |
| 10 | **YubiKey + Compose** | Évaluer ensuite le lien `security/nabla-yubikey` et déprécier les recettes Compose | Parité des 84 recettes sélectionnées/compat wrappers ; pas de transfert opaque ni secrets |

## Gate spécifique au submodule OpenClaw — statut actuel : NO-GO

La [revue ciblée du code](migrations/openclaw-sandbox-consumers-go-no-go-20261030.md)
confirme **quatre fichiers sandbox** dans `apps/openclaw/`, mais aussi
des consommateurs actifs de l'ancien chemin :
`build.sh` exécute encore `docker compose -f apps/openclaw/compose.yml
up -d --build` sur la Workstation ; `catalog/services.json` et
`catalog/service-topology.json` exposent toujours
`sourcePath=apps/openclaw/compose.yml`, y compris des références
de provenance. `apps/openclaw/catalog-info.yaml` conserve son
annotation Backstage vers ce répertoire. Le sandbox monte des
répertoires de **Workstation** ; il ne constitue pas le Gateway
Docker TrueNAS cible.

Il existe déjà un audit TrueNAS fail-closed, à réutiliser sans
réinventer un second collecteur :
`scripts/truenas/check-openclaw-sandbox-binding.py --all-apps`.
Ce contrôle ne doit être lancé **que sur TrueNAS**, avec une
lecture `midclt` autorisée ; son exit code **2 permanent** est
intentionnel et aucun verdict n'autorise un déplacement automatique.
Les configurations `app.config` peuvent contenir des secrets :
ne pas publier les retours bruts.

En conséquence : **ne pas effectuer le `git mv` des quatre
fichiers, ni ajouter le submodule `apps/openclaw` dans la PR #300**.
La prochaine PR d'implémentation devra préparer ensemble
`build.sh`, le catalogue canonique et les artefacts générés,
l'annotation Backstage, le chemin d'include TrueNAS et son rollback,
puis valider le runtime avant un gitlink épinglé.

Autre divergence cross-repo confirmée : le contrat
`nabla-openclaw/deploy/truenas/target-contract.json` sur `master`
référence encore **18** fichiers sous `apps/openclaw` ;
cet inventaire est historique. Compose en suit désormais **4**.
Faire corriger ce décalage dans `nabla-openclaw` avant
d'utiliser le contrat comme condition d'entrée.

**Revue du 30 octobre** : code et documentation observés dans Git ;
aucun audit `midclt` LIVE, déplacement, run de modèle, test matériel
ou test de restauration attestés par cette PR.

## P2 — clôture / nettoyage

- Retirer **seulement après parité** les scripts, wrappers, politiques et docs obsolètes de Compose ; ne pas supprimer des interfaces TrueNAS ou NFS utilisées par d'autres consommateurs.
- Éviter de maintenir deux sources de vérité : roadmap Gateway dans `nabla-openclaw` ; YubiKey dans `nabla-yubikey` ; OS dans `ansible-workstation`. Compose ne conserve que l'état des dépendances et les décisions cross-host.
- Mettre à jour les liens depuis `docs/roadmap.md`, le catalogue et les runbooks, puis marquer les notes précédentes « historique ».

## Gate local (sans CI GitHub)

```bash
# nabla-compose, worktree propre :
python3 scripts/ops/plan-repository-split.py
python3 -m unittest discover -s tests -p 'test_repository_split_plan.py' -v
just openclaw-migration-evidence-tests
OPENCLAW_TRUENAS_LOG_SUDO=1 just openclaw-migration-evidence-check
just openclaw-litellm-dual-logs-check-sudo

# nabla-openclaw :
just test && just plan

# nabla-yubikey (PR #1) :
just test && just dependencies-readonly
```

Les sorties runtime ne sont pas attestées par la seule existence des scripts. Un `exit=2` faute d'observabilité reste `UNKNOWN/NOT_VERIFIED`, pas une panne certaine. L'utilisateur SSH TrueNAS n'est pas dans le groupe `docker` (`docker_permission_denied`) : l'opt-in explicite `OPENCLAW_TRUENAS_LOG_SUDO=1` utilise le `sudo -n` existant, sans changer d'ACL.

**Mesure P0 ordre 1 (31/10, fenêtre 2 h, 300 lignes par proxy, YubiKey) :** `coverage=both`, 9/11 sondes PASS. Aucun indicateur 429/budget/timeout/upstream sur les deux LiteLLM ; quotas `openclaw-main` et `openclaw-cron` `below_cap`. Les 13 lignes 401 TrueNAS sont toutes `GET /metrics` depuis le réseau Prometheus : job `litellm_hermes` sans credential, **pas OpenClaw**. Correctif à préparer : `authorization.credentials_file` comme `fastapi_sample`, après création opérateur d'une clé LiteLLM dédiée (gate clé). Les deux sondes restantes viennent de `agent:cron:main` absent du catalogue : conversation cron à recréer dans l'UI OpenClaw par l'opérateur.

**Sécurité non négociable :** aucune réutilisation de session `BW_SESSION` exposée, aucune génération ou rotation de clé FastAPI déjà émise, aucun PIN/PUK/OTP2/PIV/GPG ou manipulation carte ; aucun secret, session SQLite, fichier `~/.openclaw`, identité age, archive privée ou fichier SOPS copié dans Git public ; aucune activation de clés, hausse de quotas, heartbeat ou Gateway sans gate et application explicite. Pas de CI payante, de merge automatique, de `git submodule update --remote` ni de migration implicite sur `git pull`.

**DONE global** = deux propriétaires spécialisés réellement autonomes + tests locaux et runtime validés + Gateway TrueNAS/heartbeats sans doublons + plan de rollback éprouvé + escrow restaurable avec deux supports indépendants + Compose débarrassé des seuls doublons devenus inutiles.

Références : [ADR séparation](adr/adr-repository-split-workstation-yubikey-20261030.md), [inventaire des chemins](migrations/workstation-yubikey-extraction-20261030.md), [migration OpenClaw](runbooks/openclaw-end-to-end-migration-20261030.md), [propriété Workstation](adr/adr-workstation-option-a.md).
