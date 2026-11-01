# Première tranche — migration non destructive

> **État 30/10/2026 :** la PR Compose #295 est fusionnée ; la PR #1 de ce dépôt reste Draft. Cette page décrit la première tranche, pas un cutover. Suivi des étapes et critères DONE dans [la roadmap](roadmap.md).

Source : `AlbanAndrieu/nabla-compose`, PR #295.
Les fichiers importés en phase initiale gardent **exactement** leurs
chemins d'origine pour préserver les imports dans les tests. La
provenance Git est documentée, aucun `git filter-repo` d'un
historique susceptible de contenir des secrets n'est importé.

## Lot 1 — métadonnées de dépendances

- `scripts/workstation/inspect-yubikey-dependencies-readonly.py`
- `tests/test_yubikey_dependencies_readonly.py`

Ce contrôle ne démarre pas `pcscd`/`scdaemon`, ne consulte pas les
secrets et n'interroge pas le périphérique. Il peut renvoyer
`NO-GO` même lorsque tous les outils semblent installés : une
présence logicielle **n'est pas une preuve de restauration**.

```bash
python3 -m py_compile scripts/workstation/inspect-yubikey-dependencies-readonly.py
python3 -m unittest discover -s tests -p 'test_yubikey_dependencies_readonly.py' -v
python3 scripts/workstation/inspect-yubikey-dependencies-readonly.py
```

Les prochaines tranches sont
`readonly-host` → `FIDO2/OpenPGP/PIV` → `age/SOPS` →
`USB escrow` → `NFS/TrueNAS boundary`. Les tests
hermétiques précèdent toute interaction matérielle.

Ne pas retirer l'ancien code Compose tant que les recettes
locales, statuts, exit codes et rapports ne sont pas équivalents.
Le submodule Git dans Compose sera ajouté plus tard, sous un chemin
ne chevauchant pas une application déjà suivie.

## Comparaison des contrats avec Compose (analyse statique)

Le dépôt contient désormais `scripts/ops/compare-compose-contracts.py`, un
comparateur Python **sans import ni exécution** des scripts inspectés. Il lit
uniquement les fonctions `snapshot()` de
`scripts/workstation/inspect-yubikey-dependencies-readonly.py` dans les deux
checkouts, puis compare **les noms des champs littéraux du JSON**.

Depuis `nabla-yubikey` avec les deux checkouts côte à côte :

```bash
just compose-contract
# Si les checkouts ne sont pas frères :
COMPOSE_ROOT=~/w/nabla-compose just compose-contract
```

La recette applique `--assert-field-parity` : code de sortie 0 uniquement si
les ensembles de champs se correspondent et que les champs de base requis
existent ; code 2 si la source manque, est illisible ou si son schéma dérive.
Le rapport JSON comprend `compose_fields`, `yubikey_fields`,
`missing_fields`, `extra_fields` et `source_identical`.
Les chemins locaux absolus ne sont jamais imprimés.

**Limite impérative :** `status=SCHEMA_MATCH` atteste uniquement la forme
statique des clés, **pas** la parité des valeurs, des commandes invoquées, des
codes de sortie réels, de l'accès matériel ou des scénarios de récupération.
`runtime_parity_verified=false` est constant et aucun wrapper Compose ne
doit être supprimé sur cette seule base.

Les quatre scripts de lecture seule partagent `main_json`, notamment le
retour JSON `NO-GO` redigé en cas d'exception avec conservation du champ
`mode`. Les scripts matériels, l'accès aux secrets et les tests réels restent
hors de ce comparateur.

**État de cette PR :** code et tests écrits ; aucun test ni diagnostic lancé
pendant la présente itération, pas de CI GitHub, pas de migration définitive.
