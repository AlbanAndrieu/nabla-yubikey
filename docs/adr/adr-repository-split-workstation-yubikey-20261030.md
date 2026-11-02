# ADR — Séparer Workstation, YubiKey et Gateway OpenClaw cible TrueNAS (proposé)

**Statut : PROPOSED — 30 octobre 2026.** Ne déplace encore aucun fichier ni ne modifie le runtime.

> **Note de synchronisation Git de la PR Compose #300 :** le
> document ci-dessous conserve les motifs et statuts historiques
> de la décision. Depuis sa rédaction, `ansible-workstation` #16
> et `nabla-openclaw` #1 ont été **fusionnées** ;
> `nabla-yubikey` #1 et `nabla-openclaw` #2 sont **Draft**.
> Dans Compose #295 fusionnée, les 14 artefacts Workstation ont
> quitté `apps/openclaw/` pour `ops/openclaw-workstation/` :
> il reste **4 fichiers sandbox**. Ni le Gateway TrueNAS ni
> le submodule `apps/openclaw` ne sont déployés. Le déplacement
> du sandbox est **NO-GO** tant que les consommateurs `build.sh`,
> catalogue/topologie et les Apps TrueNAS ne sont pas validés.
> [Registre des consommateurs](../migrations/openclaw-sandbox-consumers-go-no-go-20261030.md)
> et [roadmap transversale](https://github.com/AlbanAndrieu/nabla-compose/blob/master/docs/roadmap-openclaw-yubikey-extraction-20261030.md).


> **Réception de la PR #300 (Workstation, HEAD `a05a5ec2`) :**
> `plan-repository-split.py` a observé **1 770 fichiers suivis**,
> **375 recettes** au total, dont **87 YubiKey**, **98 OpenClaw**
> et **15 Workstation** ; deux suites hermétiques ont réussi
> (**3/3 + 5/5**). Le paragraphe « Constat vérifié » ci-dessous
> conserve les **chiffres historiques de la PR #295** (1 740,
> 370, 84) et ne décrit pas l'inventaire du HEAD testé.
> Aucun transfert n'est autorisé par l'inventaire.

## Constat vérifié

Sur la branche de la PR #295 : `justfile` compte **370 recettes**,
dont **84** `yubikey-*`, **98** `openclaw-*` et **15**
`workstation-*`, soit 197 recettes nommées explicitement pour ces
domaines. Les 84 et 98 recettes représentent à elles seules 49,2 %
du fichier ; le problème est structurel, pas seulement cosmétique.
Le dépôt contient 1 740 fichiers suivis, dont ~100 chemins liés
à YubiKey/age/escrow et plus de 300 chemins associés à la Workstation
et à OpenClaw (inventaires par nom, **pas** liste approuvée à copier).

`AlbanAndrieu/ansible-workstation` existe et comprend déjà le rôle,
les tâches mise/uv, les audits Ubuntu et les templates systemd.
Sa PR Draft #16 applique l'**Option A** : OS dans Ansible, dotfiles
utilisateur dans dotfiles, hardware YubiKey et homelab actuellement
dans Compose. La suppression du `tasks/yubikey.yml` et des templates
PAM de la PR #16 reste voulue : **ne pas les réintroduire**.

Attention au template historique
`ansible-workstation/templates/openclaw-gateway-systemd.sh-Ubuntu.j2` :
il pointe vers Node **25.4.0** et OpenClaw **2026.4.15** alors que
le runtime déclaré/observé au 30/10 utilise Node 24 et OpenClaw
2026.10.7. Ce template NE DOIT PAS être appliqué tel quel.
`ansible-workstation/workstation.yml` reste un vieux playbook global
potentiellement mutateur ; ne pas l'utiliser pour réaliser la migration.

## Décision proposée

1. **nabla-compose** : état désiré des services TrueNAS/Compose,
   LiteLLM serveur et upstreams, pfSense, Talos/Kubernetes, CSI/NFS,
   topologie, catalogues de services et règles de sécurité inter-hôtes.
   Les probes *serveur* TrueNAS restent ici.
2. **ansible-workstation** : audits OS Ubuntu, installations contrôlées,
   Node/mise, DNS et réseau locaux, et **audit** des services
   `systemd --user` OpenClaw/LiteLLM actuellement sur Workstation.
   Les services utilisateurs doivent être gérés sans `become: true`
   global, avec préflight de version et sauvegarde/rollback.
3. **dotfiles** : configuration utilisateur interactive, notamment
   Starship, Terminator, configuration shell. Ne pas la copier dans Ansible.
4. **`nabla-yubikey` (dépôt public créé ; PR #1 Draft)** :
   runbooks et contrôles matériels FIDO2/SSH-sk, OpenPGP,
   PIV/AES256, age/SOPS, escrow USB et backups, tests hermétiques.
   L'identité réelle, les clés privées et archives chiffrées restent
   hors des dépôts publics. Un rôle Ansible de **prérequis logiciels
   uniquement**, opt-in, peut fournir `pcscd`, `libfido2`,
   `ykman`, `opensc` sans PAM ni provisionnement matériel.
5. **`nabla-openclaw` (dépôt public créé ; PR #1 Draft)** :
   Gateway cible Docker/TrueNAS, politiques heartbeat, cron et
   automation versionnées, image et manifeste futurs. Ne pas
   déplacer l'état privé de `~/.openclaw` dans Git. Le sandbox
   `apps/openclaw/compose.yml` actuel n'est PAS le Gateway cible.
6. Les actions nécessitant **les deux hôtes** (ex. logs LiteLLM
   TrueNAS depuis OpenClaw Workstation, NFS escrow) gardent un
   contrat dans Compose ; le client local appartient au dépôt
   spécialisé, le serveur/dataset à Compose.

## Séquencement et critères GO/NO-GO

| Phase | Contenu | Critère pour continuer |
| --- | --- | --- |
| 0 | Inventaire des chemins, recettes, import Python, shells, docs, secrets, perms et versions | Résultats reproductibles sans accès matériel |
| 1 | `ansible-workstation` : audit de la **source** Gateway Workstation, sans activation | CLI/Node et unité observés, `changed=0`, aucune configuration cible ; template Node25 neutralisé |
| 2 | Contrats de probes et commandes locales dans `ansible-workstation`, diagnostics TrueNAS conservés Compose | Parité de sortie, mêmes exit codes et redaction, test LAN |
| 3 | Les dépôts publics `nabla-yubikey` et `nabla-openclaw` existent ; importer scripts/politiques **par lots** en PR Draft | Tests hermétiques, scanning sensible, source Workstation intacte, aucun Gateway TrueNAS lancé |
| 4 | Reconnecter via wrappers de compatibilité, migration des consommateurs externes | Pas de `command not found`, plus aucune importation vers l'ancien chemin, aucun secret Git |
| 5 | Déprécier et seulement ensuite retirer les anciennes recettes/code | Validation sur deux hôtes, plan/rollback documentés et revue manuelle |

Les **84 recettes YubiKey ne sont pas 84 services Ansible** : elles
doivent devenir un `justfile` propre au dépôt YubiKey, avec 2 à 4
points d'entrée ergonomiques. Même règle pour OpenClaw Workstation.
Ne pas créer de sous-module Git simplement pour contourner le
`justfile` volumineux : un submodule multiplie les conflits et
crée une nouvelle dépendance de synchronisation. Préférer des
checkouts frères et des wrappers explicites pendant la transition.

## Sécurité et rollback

- AUCUN reset/reconfiguration de YubiKey, PIN, PUK, PIV, OTP, PAM,
  enrolment SSH ou déchiffrement SOPS/age.
- `git mv` entre dépôts n'existe pas : reprise avec attribution
  historique, inventaire de licence et commits de provenance ; ne
  jamais déplacer les éléments cryptographiques privés.
- Ne pas faire converger un client Workstation via un playbook
  privilégié TrueNAS ou via le vieux template systemd.
- Garder les anciennes recettes et points d'entrée jusqu'à parité
  attestée ; les erreurs de bord restent UNKNOWN et non DOWN.
- Commits `[skip ci]`, tests locaux seulement, PRs Draft, jamais
  de merge automatique.

## Décision de cible confirmée le 30 octobre 2026

OpenClaw **fonctionne aujourd'hui sur Workstation** mais doit migrer
vers **TrueNAS**. Le référentiel Git cible est
[nabla-openclaw PR #1](https://github.com/AlbanAndrieu/nabla-openclaw/pull/1),
non Ansible. Ansible [PR #16](https://github.com/AlbanAndrieu/ansible-workstation/pull/16)
garde l'OS et l'audit **source**. Le dépôt
[nabla-yubikey PR #1](https://github.com/AlbanAndrieu/nabla-yubikey/pull/1)
contient un premier collecteur read-only et ses tests, sans secrets.

**Chemin canonique retenu : `apps/openclaw` directement comme submodule.**
Le dossier contient actuellement **18 fichiers suivis** : quatre fichiers
sandbox (`compose.yml`, `Dockerfile`, `catalog-info.yaml`, `test-docker.sh`)
et 14 éléments Workstation. Préalables à tout gitlink : déplacer le
sandbox vers `apps/openclaw-sandbox/` après audit des consommateurs,
migrer les politiques Workstation vers `nabla-openclaw/policies/`,
conserver les wrappers Compose et prouver leur parité, puis vérifier
`git ls-files -- apps/openclaw` vide. Le sandbox actuel monte des
volumes Workstation et n'est pas le Gateway TrueNAS. Ne pas déplacer ou
déployer immédiatement. Un seul Gateway doit exécuter automations et
heartbeat pendant le cutover ; rollback Workstation validé obligatoire.


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
