# Roadmap — extraction YubiKey / age / SOPS (30 octobre 2026)

> **Source de vérité cible :** `nabla-yubikey`. Cette roadmap suit uniquement le code client et les procédures matérielles. L'infrastructure NFS/ZFS et les exports appartiennent à `nabla-compose` ; les dépendances Ubuntu à `ansible-workstation`. Le dépôt public ne contient aucun secret. **Aucune opération sur la carte n'est autorisée par ce document.**

## État vérifié dans Git

- Dépôt dédié créé ; PR [#1](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1) **Draft, non fusionnée** au contrôle du 30/10.
- **Lot 1 importé dans cette PR** : `inspect-yubikey-dependencies-readonly.py` et ses tests hermétiques ; aucun accès smartcard, aucune modification système. Le `justfile` contient `test` et `dependencies-readonly`.
- `nabla-compose` [PR #295](https://github.com/AlbanAndrieu/nabla-compose/pull/295) **fusionnée** : les anciennes recettes et scripts YubiKey restent la référence temporaire jusqu'à parité documentée.
- Les prérequis OS sont déjà traités par `ansible-workstation` ; ne pas réintroduire de tâches PAM globales.

## File de travail priorisée

| Priorité | Lot | Livrable | Gate / état |
| --- | --- | --- | --- |
| P0 | 1 — prérequis offline | Collecteur de dépendances + fixtures + `just test` | **Code dans PR #1 ; gate sur la branche non encore attesté ici** |
| P0 | 2 — lecture seule Workstation | Inventaire des commandes YubiKey actuellement exécutées depuis Compose ; tests host, GPG-agent, PC/SC, versions, état SSH-sk/FIDO2 **sans PIN ni données personnelles** | **À importer** avec les tests et états `UNKNOWN/NO-GO` |
| P0 | 3 — récupération age/SOPS | Vérification des métadonnées de deux copies indépendantes (USB + cible hors support commun), test synthétique et restauration isolée | **Partiel** : une récupération SOPS avec identité USB a déjà été signalée PASS ; cela ne démontre pas deux copies indépendantes ni un PRA complet |
| P0 | 4 — escrow USB/NFS | Sonde client readonly + contrats de chemin NFS ; permissions strictes et cas d'échec NFS non monté | **À importer** ; exports/ACL côté TrueNAS restent Compose |
| P1 | 5 — protocole matériel | Inventaire FIDO2, OpenPGP, OTP2, PIV et 0x82 ; NO-GO par défaut | **À importer après tests hermétiques**, aucune écriture matérielle |
| P1 | 6 — compatibilité | Parité du `just --list`, chemins/imports, statuts/codes sortie 0/2 et wrappers Compose | **À prouver sur Workstation** |
| P1 | 7 — cutover GitOps | Marquer les anciens scripts Compose comme dépréciés, transférer les liens de runbook, puis supprimer seulement les doublons sans consommateurs | **Bloqué par parité et revue** |
| P2 | 8 — intégration dans Compose | Évaluer `security/nabla-yubikey` piné, sans submodule automatique ni données runtime | **Différé** jusqu'à release/commit testé |

## Séquence locale sans effet matériel

```bash
# Dans le dépôt dédié, branche PR #1 :
just test
just dependencies-readonly

# Dans nabla-compose actualisé, comparer l'inventaire
# sans déplacer ou nettoyer de fichiers :
python3 scripts/ops/plan-repository-split.py
python3 -m unittest discover -s tests -p 'test_repository_split_plan.py' -v
git grep -n -E 'yubikey-|age-escrow|sops' -- justfile scripts tests docs
```

**GO pour le transfert d'un lot :** provenance/licence revues, scripts et tests migrés ensemble, aucun secret/dump/identifiant matériel, sorties et codes identiques, vérifications offline PASS, anciens points d'entrée maintenus. **NO-GO matériel :** pas de changement PIN/PUK/OTP2, PIV9A/PIV82/F9, GPG, SSH authorized_keys, PAM ou provisioning sans décision séparée et preuves de restauration indépendantes.

**DONE extraction :** `nabla-yubikey` détient les commandes client et les runbooks opérationnels ; `nabla-compose` garde exclusivement les interfaces serveur/stockage et wrappers transitoires explicites, puis retire les doublons après revue ; aucun secret dans Git et PRA de récupération attesté sur copies indépendantes.

Références : [plan de migration](migration.md) ; [ADR de séparation Compose](https://github.com/AlbanAndrieu/nabla-compose/blob/master/docs/adr/adr-repository-split-workstation-yubikey-20261030.md).
