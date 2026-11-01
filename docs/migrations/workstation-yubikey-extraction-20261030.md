# Inventaire de transfert Workstation / YubiKey — 30 octobre 2026

> **État Git du 30/10/2026 :** PR Compose #295 **fusionnée** ; PR nabla-openclaw #1 et PR ansible-workstation #16 **fusionnées** ; PR nabla-yubikey #1 **Draft**. Les 14 politiques Workstation sont dans `ops/openclaw-workstation/` et **4** fichiers sandbox restent dans `apps/openclaw/`. La migration du Gateway et du matériel n'est pas attestée. [Suivi actif](../roadmap-openclaw-yubikey-extraction-20261030.md).

**Lecture seule.** Cette matrice distingue emplacement actuel et
propriétaire cible, sans déplacer les fichiers. Source de décision :
[ADR](../adr/adr-repository-split-workstation-yubikey-20261030.md).

| Chemins Compose actuels | Cible proposée | État / restriction |
| --- | --- | --- |
| `scripts/workstation/diagnose-openclaw-*`, `check-openclaw-*`, `openclaw-ops.sh`, `tests/test_openclaw_*` | **nabla-openclaw** pour logique Gateway/cron cible ; **Ansible** pour audit OS de la source | Examiner les imports TrueNAS/stockage, ne pas copier le Gateway Workstation en bloc |
| `ops/openclaw-workstation/` (anciennement `apps/openclaw/workstation/`) | **nabla-openclaw `policies/`** pour heartbeat/cron ; Ansible garde l'OS | 14 artefacts relocalisés dans Compose, politiques candidates importées en PR #1 ; ne pas transférer les sessions ni les secrets |
| `apps/openclaw/compose.yml` (sandbox actuel) | **Compose, puis `apps/openclaw-sandbox/` seulement après gates** | `build.sh`, catalogue/topologie et `app.config` TrueNAS sont des consommateurs à auditer ; pas le Gateway cible ; [NO-GO documenté](openclaw-sandbox-consumers-go-no-go-20261030.md) |
| `apps/litellm/`, `scripts/truenas/*litellm*` | **Reste Compose** | Proxies, modèles TrueNAS, clés scoped, DB, quotas et NFS |
| `scripts/workstation/provision-fastapi-litellm-keys.py`, `scripts/workstation/diagnose-fastapi-litellm-workstation-key.py`, `scripts/secrets/*bitwarden*` | **Compose / frontière FastAPI–LiteLLM–Vaultwarden** | **Exception explicite : ne pas transférer à OpenClaw ni à Ansible**. Clé Workstation `fastapi-sample-upstream` émise, Vaultwarden/runtime TrueNAS encore non vérifiés ; préserver le contrôle anti-doublon et les secrets existants |
| `scripts/workstation/diagnose-*-dns*.py`, `workstation-split-dns-*` | ansible-workstation | Reprendre les audits existants, PAS de second collecteur équivalent |
| `scripts/workstation/*yubikey*`, `*age-escrow*`, `*sops*` | nabla-yubikey PR #1 | Tri manuel par effet et tests ; pas de clés, PIN ou configs chiffrées |
| `tests/test_yubikey_*` et `docs/runbooks/yubikey-*` | futur nabla-yubikey | Transférer ensemble avec scripts, fixtures et avertissements |
| `scripts/workstation/*nfs*escrow*` | YubiKey **client**, Compose **serveur TrueNAS** | Conserver une interface de sonde et les contrôles de ACL NFS |
| `docs/roadmap-workstation-yubikey.md` | roadmap YubiKey indépendante | Lien/alias d'historique dans Compose après extraction |
| `secrets.env.sops`, `.sops.yaml`, `~/.openclaw/`, fichiers `*.age` privés | **Jamais copiés dans les nouveaux dépôts** | Secrets/snapshots/profiles dans le coffre existant, usage sous autorisation |

## Lot 2 — contrat précis de l'escrow age/NFS après #295 (sans extraction)

Cette table est un **plan**, pas un déplacement de fichiers. Les commandes
continuent à être servies par Compose ; `nabla-yubikey` PR #1 est Draft.

| Fichier actuel (Compose) | Responsabilité cible | Gate avant transfert |
| --- | --- | --- |
| `scripts/workstation/backup-usb-age-identity.py`, `verify-usb-age-identity-independent-backup.py` et leurs tests | **nabla-yubikey** : client USB/age, sauvegarde/restauration explicite | Préserver les garde-fous anti-écrasement, les confirmations interactives, le schéma JSON et les deux restaurations prouvées ; ne copier aucun ciphertext |
| `scripts/workstation/inspect-usb-identity-backup-nfs4-acl.py` et `inspect-usb-identity-backup-server-modes.py` | **Compose** : preuve serveur TrueNAS ACL et modes NFS4 ; interface client possible dans YubiKey | Maintenir la compatibilité SSH et la sortie expurgée ; aucun `setacl` ou `chmod` |
| `scripts/workstation/inspect-usb-age-backup-nfs-export.py` et `inspect-usb-age-nfs-consumers.py` | **Compose** : export, service et clients NFS sur TrueNAS ; aucun fork divergent dans YubiKey | `sharing.nfs.query` et `ss` strictement read-only, sortie sans adresses/UID, état `REVIEW_REQUIRED` sans acceptation d'une allowlist |
| `scripts/workstation/backup-openclaw-nfs.py`, `copy-openclaw-backups-nfs.sh` | **Compose / OpenClaw** selon le runtime source/cible, pas YubiKey | Identifier les processus autorisés à écrire dans `infra/openclaw` ; ne jamais rendre le partage `ro` sans migration validée |
| Recettes `yubikey-usb-identity-*` dans `justfile` | **Wrappers Compose conservés** jusqu'à parité des commandes YubiKey | `just --list`, schéma, codes retour, tests hermétiques et diagnostics réels concordants, sans CI payante |

**Évidence reçue (30/10/2026) :** backups et deux restaurations cryptographiques
PASS ; modes privés serveur `0700/0700/0600` PASS ; audit de l'export
`10/10` tests PASS avec `EXPORT_MATCHED` et trois alertes
(`NO_NFS_HOST_OR_NETWORK_FILTER`, `NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED`,
`EXPORT_WRITABLE`). **Sonde clients TCP/2049 revalidée en worktree isolé PR #300** (SHA `245bd928`) : `8/8` tests PASS, préflight `BACKUP_RESTORATION_PREFLIGHT_READY`, `TCP_SNAPSHOT_OBSERVED` avec **1 session TCP établie et 1 pair réseau distinct** sur l'ensemble des exports TrueNAS. Le correctif `ss` quatre/cinq colonnes est donc accepté côté sonde réelle. **Aucune attribution à l'export `lab`**, ni recensement des clients intermittents : `all_clients_enumerated=false`, `consumer_allowlist_verified=false`. Ne pas transformer cet instantané en allowlist.

**NO-GO :** ne pas copier les archives `.age`, les secrets SOPS ou
l'historique Git sensible. Ne pas installer de submodule YubiKey,
supprimer les recettes historiques, restreindre l'export NFS ou toucher
aux YubiKeys avant les validations séparées. La conservation de la
phrase secrète hors SanDisk/workstation/TrueNAS n'est pas encore attestée.

### Frontière d'identité FastAPI/LiteLLM avant extraction

Le nom `scripts/workstation/` ne constitue **pas** une preuve de propriété
`ansible-workstation`. Le planificateur `plan-repository-split.py`
produit des **candidats nominaux** : ses catégories
`candidate_ansible_workstation_review` et
`candidate_openclaw_target_review` n'autorisent
pas le transfert automatique des identités de service.
Les deux scripts FastAPI/LiteLLM énumérés ci-dessus ont
une responsabilité **transversale Compose**, indépendamment
de l'emplacement de leur exécution sur Ubuntu.

Distinguer la clé virtuelle **émise par Workstation LiteLLM**
(`fastapi-sample-upstream`, modèle `qwen`, valeur consommée
par TrueNAS), de la clé **émise par TrueNAS LiteLLM**
(`fastapi-sample-staging`, modèle `fastapi-qwen`, valeur
consommée par FastAPI). Seule la première est attestée
générée le 28/10 ; aucune migration Git ou activation
automatique n'est une preuve de son injection TrueNAS.
[Suivi P0](../roadmap-openclaw-yubikey-extraction-20261030.md).

## Contrôle croisé vérifié dans le code — sandbox OpenClaw

Le prochain gitlink `apps/openclaw` **reste bloqué** par
quatre fichiers sandbox encore suivis, par `build.sh`
qui utilise l'ancien `compose.yml`, par les références
du catalogue `services.json` et de la topologie, ainsi
que par les configurations TrueNAS encore inconnues.
Les quatre fichiers ne doivent pas être déplacés depuis
cette PR documentaire. Détails, checks et rollback :
[registre de consommateurs OpenClaw](openclaw-sandbox-consumers-go-no-go-20261030.md).

Le contrat `nabla-openclaw/deploy/truenas/target-contract.json`
sur `master` contient encore `current_tracked_file_count: 18`
malgré les **4** fichiers restant dans Compose. Cette valeur
historique doit être corrigée dans le dépôt propriétaire du
Gateway avant de s'en servir pour valider un gitlink.

## Audit de dépendances avant tout changement

Exécuter en local depuis le checkout Compose, sans requêtes GitHub ni
opérations matérielles :

```bash
python3 scripts/ops/plan-repository-split.py
python3 -m unittest discover -s tests -p 'test_repository_split_plan.py' -v

# Références cross-repo, lire sans les modifier :
git grep -n -E 'scripts/workstation|apps/openclaw/workstation|yubikey-' \
  -- justfile docs scripts tests apps | head -n 100
```

Les comptes sont des *candidats* (patterns nominaux), pas un ordre de
copie ni une preuve de sécurité. Après extraction : mise à jour des
références, comparaison des résultats, tests locaux et parité de
découverte `just --list` avant suppression de recettes.

## Arbitrages

- Le dépôt YubiKey est **pertinent** : cycle de vie matériel,
  procédures de reprise sensibles et 84 recettes indépendantes.
  Préférer `nabla-yubikey` avec revue explicite des licences et
  de l'historique Git. Ne pas créer un repo public directement
  depuis une copie de l'ancien historique sans analyse des secrets.
- `ansible-workstation` est le bon propriétaire de l'OS, **pas**
  du runtime persistant `~/.openclaw` ni des secrets. Le modèle est
  **plan → dry-run → sauvegarde privée → apply explicite → verify/rollback**.
- Un `justfile` global court peut conserver temporairement
  `just workstation-check` et `just yubikey-check` comme
  dispatchers **non silencieux**, mais ne doit pas importer tous
  les fichiers des nouveaux dépôts.

## Dépôts réellement créés et transfert initial

- [nabla-yubikey PR #1](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1) : collecteur autonome de dépendances avec test hermétique, aucun matériel.
- [nabla-openclaw PR #1](https://github.com/AlbanAndrieu/nabla-openclaw/pull/1) : **fusionnée** (merge `dd304743`) ; politiques `HEARTBEAT` et digest inactives, contrat cible TrueNAS sans image/dataset validés.
- [ansible-workstation PR #16](https://github.com/AlbanAndrieu/ansible-workstation/pull/16) : audit `systemd --user` de la source Workstation, ancien template OpenClaw Node 25 interdit au déploiement.

**Submodules :** chemin canonique OpenClaw : `apps/openclaw` directement.
Ce chemin ne contient plus que **quatre fichiers suivis** (sandbox) :
les 14 artefacts Workstation ont déjà été relocalisés temporairement
sous `ops/openclaw-workstation/`, et leurs scripts/tests ont été adaptés.
Le déplacement des quatre fichiers restants vers `apps/openclaw-sandbox/`
reste bloqué en attendant le préflight TrueNAS global et la revue
des consommateurs. Le submodule ne sera ajouté
qu'après parité locale, avec un commit testé épinglé. Emplacement YubiKey
proposé : `security/nabla-yubikey`, séparé des applications Docker.
Pas de checkout direct dans les datasets de runtime, ni de
`git submodule update --remote` automatisé.


### Lot 1 — migration structurelle engagée (30 octobre 2026)

Les **14 fichiers de politiques/artefacts Workstation** ont été
transférés de `apps/openclaw/workstation/` vers
`ops/openclaw-workstation/` dans `nabla-compose`, avec modification
des chemins dans les scripts Python et tests associés. Les
références précédentes à l'ancien chemin décrivent désormais la
source historique, pas la localisation courante. Le dossier
`apps/openclaw` conserve **quatre fichiers du sandbox** :
`Dockerfile`, `catalog-info.yaml`, `compose.yml`, `test-docker.sh`.
Le **futur submodule direct `apps/openclaw` n'est pas encore ajouté** :
sa libération doit attendre la validation des références TrueNAS
vers le sandbox. Aucune application n'a été redéployée.
