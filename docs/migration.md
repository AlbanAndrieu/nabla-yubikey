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
retour JSON `NO-GO` expurgé en cas d'exception avec conservation du champ
`mode`. Les scripts matériels, l'accès aux secrets et les tests réels restent
hors de ce comparateur.

**État de cette PR :** code et tests écrits ; aucun test ni diagnostic lancé
pendant la présente itération, pas de CI GitHub, pas de migration définitive.

## Parité fonctionnelle simulée et valeurs JSON (code préparé)

Pour comparer les **valeurs** sans lancer les sondes, deux voies complémentaires
ont été ajoutées. Elles ne déverrouillent rien, ne contactent aucun hôte et ne
doivent recevoir **aucune archive, fichier clé ni diagnostic nominatif**.

### 1. Comparaison de rapports de scénarios synthétiques

`scripts/ops/compare-probe-fixtures.py` compare deux fichiers JSON distincts,
chacun contenant la même série de scénarios :

```json
{
  "schema": "nabla-yubikey/probe-fixtures/v1",
  "cases": [
    {"name": "invalid_args", "exit_code": 2, "report": null}
  ]
}
```

Un scénario avec `exit_code: 0` fournit un `report` complet, strictement
limité aux champs connus de `inspect-yubikey-dependencies-readonly.py` :
statut `NO-GO`, `mode: HOST_DEPENDENCIES_METADATA_ONLY`, booléens de
preuve à `false`, métadonnées des processus, et outils de récupération
(`INSTALLED_UNVERIFIED` ou `MISSING`). Aucun numéro de série, chemin
privé ou message brut d'erreur n'est accepté dans le format de comparaison.

```bash
export COMPOSE_PROBE_FIXTURES=/chemin/vers/compose-fixtures-synthetiques.json
export YUBIKEY_PROBE_FIXTURES=/chemin/vers/yubikey-fixtures-synthetiques.json
just fixture-contract
```

Les fichiers sont lus avec une taille maximale, sans suivre le lien
symbolique final. Les clés inconnues, doublons JSON, cas dupliqués,
`exit_code` différent de 0/2 et valeurs inattendues sont refusés
(`status=NO-GO`). Le rapport n'affiche **que les noms des champs**
différents, les codes fixes et les identifiants de scénarios. Une
comparaison identique donne `FIXTURES_MATCH` et un code 0 ;
l'option `--assert-fixture-parity` retourne 2 autrement.

### 2. Tests hermétiques des versions source et migrée

`tests/test_compose_runtime_parity.py` importe **uniquement** le script
de dépendances du checkout Compose de confiance et sa version extraite.
Pendant les appels `snapshot()`, les observations externes et
`shutil.which` sont remplacés par des mocks ; les scénarios synthétiques
couvrent outils absents, présence partielle, états inconnus et code
d'arguments refusés (2), ainsi que l'émission JSON normale (0).

```bash
# Avec les checkouts côte à côte, commande à réserver à une validation ultérieure :
just parity-tests

# Sinon, COMPOSE_ROOT=~/w/nabla-compose just parity-tests
```

Si le checkout Compose est absent, la recette `just` échoue au
pré-requis plutôt que d'annoncer un succès après un test `SKIP`.
Cette suite importe du Python local : **n'utiliser que des checkouts
de confiance**, même si les appels observateurs sont simulés.

**Limites strictes :** `FIXTURES_MATCH`, `SCHEMA_MATCH` et
les tests hermétiques ne sont pas des preuves de parité en conditions
réelles : `runtime_parity_verified=false` dans les rapports de
comparaison. Les anciennes recettes Compose et leurs consommateurs
restent en place jusqu'à la preuve d'exécution et de retour arrière
sur les deux environnements.

**État de cette itération :** scripts, tests et documentation écrits,
aucun test/diagnostic/CI réellement exécuté, aucune modification
matérielle, aucune fusion.
