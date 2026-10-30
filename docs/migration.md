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
