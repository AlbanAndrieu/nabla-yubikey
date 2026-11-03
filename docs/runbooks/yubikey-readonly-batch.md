# Diagnostic YubiKey consolidé — lecture seule (PR #280)

Objectif : produire **un seul rapport JSON** à partir des contrôles existants
sans mélanger observation matérielle et validation fonctionnelle.
Ce script ne déchiffre rien, ne modifie aucune carte et ne démarre pas GPG-agent.

## Point d'entrée unique

Sur le worktree actualisé de `feat/apisix-standalone-poc-20261025` :

```bash
just yubikey-diagnostics-test
just yubikey-diagnostics-secondary-readonly
```

La première recette exécute les **19 contrats synthétiques** du
coordinateur sans carte et sans réseau. La seconde exécute en une fois :
- contrôle des métadonnées de la workstation (SOPS, GPG-agent via
  `gpgconf --list-dirs agent-socket`, SSH et mapping PAM),
- contrôles des applets FIDO, OATH, OpenPGP, PIV et des slots
  9A/9C/9D/9E/83 sur la **seule** YubiKey secondaire 11110002,
- synthèse de bloqueurs et des fonctions **non vérifiées**.

**Pas de nouvelle lecture OTP2, F9 ou PIV82** dans ce parcours.
Un résultat `status=NO-GO` est attendu, même si le processus retourne 0 :
un inventaire public n'est pas une configuration complète.

Alternatives explicites :

```bash
just yubikey-diagnostics-host-readonly
# Après avoir retiré la secondaire et connecté UNIQUEMENT la principale :
just yubikey-diagnostics-primary-readonly
```

Ne pas brancher les deux cartes simultanément : l'inventaire exige
exactement le numéro de série demandé et un seul périphérique.

Si deux sauvegardes chiffrées **existantes** sont identifiées, le coordinateur
peut vérifier uniquement leurs métadonnées (chemins absolus) :

```bash
python3 scripts/workstation/diagnose-yubikey-readonly-batch.py \
  --escrow-a /CHEMIN/ABSOLU/COPIE_A.age \
  --escrow-b /CHEMIN/ABSOLU/COPIE_B.age
```

Ne pas inventer des chemins et ne pas lancer ce contrôle tant que les deux
copies n'ont pas été localisées. Aucun contenu de fichier n'est lu.
La sortie ne reproduit pas les chemins. Deux fichiers sur des filesystems
distincts ne prouvent ni leur indépendance physique ni la restauration.

Le retour du précédent diagnostic OTP2 (programmé sur 11110002)
est déjà enregistré : ne pas répéter un challenge ni une lecture.
La commande `--otp2-secondary` reste **opt-in** et n'est jamais
activée par les recettes du lot standard.

## Interprétation du rapport

| Champ | Interprétation |
| --- | --- |
| `workstation.paths.gpg_agent_socket=PRESENT_UNVERIFIED` | socket local détecté, pas de preuve de transport scdaemon |
| `device.applications.*=RESPONDS_METADATA_ONLY` | applet accessible, pas de credential/passkey fonctionnel prouvé |
| `device.piv_slots.9A=OCCUPIED_METADATA` | présence publique, préserver le certificat historique |
| `device.piv_slots.*=EMPTY_CONFIRMED` | slot vide ; aucune autorisation d'écriture |
| `otp2=NOT_CHECKED` | pas de nouvelle lecture de l'OTP2 déjà documenté |
| `escrow=NOT_CHECKED` | chemins de sauvegardes non fournis |
| `completion.*=NOT_VERIFIED` | preuves opérationnelles encore manquantes |
| `status=NO-GO` | aucune mutation autorisée, quelle que soit la sortie |

Les bloqueurs `CONVENTIONAL_SSH_FIDO_PUBLIC_HANDLE_NOT_FOUND` et
`PAM_U2F_ENROLLMENT_TOOL_MISSING` ne prouvent **pas** une absence de
toutes les identités SSH ni la nécessité de modifier PAM : ils décrivent
uniquement un chemin courant et un outil optionnel. Ne pas installer
automatiquement `pamu2fcfg`, ni modifier `/etc/pam.d` ;
l'enrôlement PAM exige un rollback, une session administrateur de secours
et un test avec les deux cartes.

## Actions restant à prouver avant configuration

1. **Récupération prioritaire** : inventorier les sauvegardes age,
   GPG et PostgreSQL ; organiser une restauration réellement isolée,
   après accord explicite, sans exposer de clés privées.
2. **GPG/scdaemon** : établir l'accès OpenPGP sans démarrer ou réinitialiser
   d'agent à l'aveugle. Le simple socket GPG détecté n'est pas une
   validation de `gpg --card-status`.
3. **FIDO2 / SSH** : inventorier les registrations existantes et les
   voies de secours, puis inscrire les deux clés séparément seulement
   après décision. Les passkeys FIDO2 ne se clonent pas entre tokens.
4. **PIV82 / age-plugin-yubikey** : le slot secondaire était vide lors
   d'un relevé précédent ; démontrer d'abord l'escrow et l'authentification
   AES256 supervisée, puis traiter génération P-256, certificat, attestation,
   roundtrip age et seconde carte comme des transactions indépendantes.
5. **PKI / 9A, OATH, 9C/9D/9E, PAM** : cartographier usages et
   dépendances. Aucun écrasement du slot 9A historique, aucune
   reprogrammation OTP2, aucune activation PAM sans rollback.

Toutes les opérations générant/modifiant une clé, demandant PIN/PUK,
challenge OTP, restauration d'escrow ou modification SOPS/PAM
sont hors périmètre de ce diagnostic et nécessitent des autorisations
distinctes.

Références internes : [plan de finition](yubikey-capabilities-completion-plan.md),
[preuves F9/PIV82/OTP2](yubikey-piv82-postmerge-diagnostics.md).


## Sonde GPG-agent active mais non intrusive (opt-in)

`just yubikey-gpg-agent-readonly` envoie uniquement `GETINFO version` à un agent GPG **déjà lancé**, par `gpg-connect-agent --no-autostart`. La réponse brute et le chemin du socket ne sont jamais imprimés. L'état `RESPONDS_GETINFO_ONLY` prouve uniquement la joignabilité du protocole Assuan, **pas** l'accès à une carte OpenPGP, une signature, un déchiffrement ni une restauration PostgreSQL. Une erreur indique `UNKNOWN` ou `TOOL_MISSING`, jamais un agent démarré implicitement. Voir la [documentation GnuPG](https://gnupg.org/documentation/manuals/gnupg-devel/Invoking-gpg_002dconnect_002dagent.html).

`just yubikey-diagnostics-all-secondary` lance aussi `just yubikey-gpg-agent-test` puis active `--gpg-agent-probe` sur le coordinateur. Ce lot exécute **16 + 28 + 12 + 13 + 19 + 7 = 95 méthodes de tests ciblés** avant l'observation publique de la secondaire. Ce compteur indique les tests versionnés, **pas des tests déjà exécutés sur le nouveau HEAD**. Aucune nouvelle lecture OTP2, F9 ou PIV82.


## Preuve du diagnostic GPG-agent par gpgconf (workstation)

Journal opérateur au snapshot `9dca0d43` (le HEAD distant de cette
PR peut avoir changé ensuite) :

- `just yubikey-workstation-test` : **13/13 PASS** en 0,023 s ;
  `py_compile` PASS ;
- `just yubikey-workstation-readonly` :
  `gpg_agent_socket_locator=GPGCONF`,
  `gpg_agent_socket=PRESENT_UNVERIFIED` ;
- identité SOPS logicielle : `PRESENT_PRIVATE_METADATA_ONLY` ;
  mapping PAM : `PRESENT_UNVERIFIED` ; `pamu2fcfg=MISSING` ;
  poignée SSH FIDO2 conventionnelle : `NOT_FOUND`.
- `gpg_card_access_verified=false`, `postgres_restore_verified=false`,
  `age_decrypt_verified=false`, `ssh_fido_auth_verified=false` et
  `hardware_mutation_authorized=false`.

**Interprétation :** le chemin de socket codé en dur était un faux
négatif. `gpgconf` localise maintenant un socket Unix existant.
Cela **ne prouve pas** que GPG-agent réponde, que scdaemon accède
à l'applet OpenPGP, ni que les sauvegardes PostgreSQL soient
déchiffrables.

### Prochaine validation groupée (sans secrets)

À partir du worktree actualisé de la PR #280, et avec **une seule
YubiKey secondaire 11110002** connectée :

`just yubikey-diagnostics-all-secondary`

Cette recette réexécute les contrats hermétiques ciblés et produit
un rapport agrégé des applications publiques ainsi qu'un contrôle
GPG-agent **GETINFO version --no-autostart**. Elle ne déclenche
ni OTP2/challenge, ni PIV82/F9, ni PIN, ni déchiffrement, ni écriture.
Une réponse `RESPONDS_GETINFO_ONLY` ne vaut pas validation
OpenPGP ou de récupération GPG/PostgreSQL. Un état `NO-GO`
est attendu même si le programme retourne 0.

Le journal opérateur du 25 octobre 2026 est disponible (voir la preuve ci-dessous).
Il ne valide pas automatiquement les commits publiés après son exécution.

## Preuve opérateur — diagnostic groupé du 25 octobre 2026

Source : sortie de `just yubikey-diagnostics-all-secondary` exécutée sur la
workstation au HEAD **`d4f1afbd`** rapporté par l'opérateur.
Le HEAD distant de #280 peut différer : revalider au SHA exact avant
acceptation de nouvelles modifications. **Aucune CI GitHub déclenchée.**

| Suite | Résultat effectivement rapporté |
| --- | --- |
| Récupération (contrats + runner) | 16/16 + 28/28 PASS |
| Applications YubiKey | 12/12 PASS |
| Workstation | 13/13 PASS |
| Coordinateur | 19/19 PASS |
| GPG-agent | 7/7 PASS |
| **Total ciblé** | **95/95 PASS** |

Rapport agrégé de la **seule** secondaire `11110002` :
`gpg_agent=RESPONDS_GETINFO_ONLY`,
`workstation.gpg_agent_socket_locator=GPGCONF`,
`device.management=AES256_PIN_PROTECTED`,
`device.piv_slots.9A=OCCUPIED_METADATA`,
`otp2=NOT_CHECKED`, `escrow=NOT_CHECKED`.
`pin_requested=false`, `decrypt_executed=false`,
`hardware_mutation_authorized=false`, `status=NO-GO`.

Cette preuve confirme **la réponse Assuan `GETINFO version` d'un agent existant**,
pas une connexion à scdaemon/OpenPGP, signature/déchiffrement, roundtrip age,
ni restauration PostgreSQL. Les gates `GPG_OPENPGP_INTEROP_NOT_VERIFIED`,
`POSTGRES_RESTORE_NOT_VERIFIED`, `ESCROW_RESTORE_NOT_VERIFIED` et
`HARDWARE_AGE_ROUNDTRIP_NOT_VERIFIED` restent ouvertes. Aucun changement
PIV82/9A, OTP2, PAM, SOPS ou escrow n'est autorisé par ce résultat.

## Préparation simultanée — sans modification des cartes

La recette `just yubikey-parallel-host-readonly` lance **en parallèle** les
cinq familles de tests hermétiques déjà existantes (récupération,
applications, workstation, coordinateur, GPG-agent). Après réussite de ces
tests, elle exécute **en parallèle** deux contrôles du poste : métadonnées
SOPS/SSH/PAM/GPG et protocole GPG-agent `GETINFO`. Elle produit un seul
JSON synthétique sans restituer les sorties privées des sous-processus.

`just yubikey-parallel-secondary-readonly` ajoute, uniquement sur option
explicite, un inventaire public de la carte secondaire 11110002 **après la
fin** des contrôles parallèles. L'accès au même périphérique n'est **jamais**
parallélisé. Aucune lecture OTP2/F9/PIV82, aucun PIN, aucune signature,
aucun déchiffrement, aucune écriture matérielle, aucune modification SOPS/PAM.

```bash
just yubikey-parallel-test
just yubikey-parallel-host-readonly
# Avec une seule YubiKey secondaire connectée :
just yubikey-parallel-secondary-readonly
```

En cas d'échec ou d'expiration d'un seul contrôle, l'inventaire matériel
est bloqué (exit 3). **`status=NO-GO` reste invariable**, même lorsque les
contrôles réussissent et que le programme renvoie 0. Une suite de tests
n'est jamais une validation des futures configurations.

### Chantiers préparables en parallèle

| Chantier | Travail possible immédiatement | Condition avant configuration réelle |
| --- | --- | --- |
| GPG/scdaemon/OpenPGP | Probe du transport Assuan, inventaire du chemin PC/SC et des dépendances | Ne pas redémarrer scdaemon, manipuler les sous-clés ni effectuer de signature sans validation séparée |
| Sauvegardes GPG/PostgreSQL | Identifier les fichiers existants et préparer un environnement de restauration jetable | Autorisation explicite avant tout accès à une clé privée ou déchiffrement |
| age/SOPS/escrow | Identifier deux supports distincts et préparer le plan de reprise | Vérification de restauration et accès aux secrets autorisés séparément |
| FIDO2/SSH/KeePassXC | Cartographier les comptes, destinations et voies de secours, sans enregistrer de credential | Enrôlements et challenges approuvés individuellement |
| PIV82/AES256, PKI/9A | Préparer le plan d'intégration age et inventorier les dépendances du certificat 9A | Escrow fonctionnel, approbation distincte de chaque opération matérielle |

Une configuration réelle peut suivre plusieurs chantiers **indépendants** en
parallèle, mais **pas** les écritures concurrentes sur une même YubiKey.
La clé de gestion PIV AES256, OTP2, PIV9A, PAM et SOPS restent protégés
par leurs gates respectives. Le statut général de récupération est NO-GO.

**Validation du nouveau code :** tests hermétiques versionnés dans
`tests/test_yubikey_parallel_readonly.py` ; **NOT_RUN sur la workstation**
au moment de la publication de cette extension. Exécuter la recette
`just yubikey-parallel-test` au SHA exact de la branche.

## Diagnostic complémentaire des dépendances (sans contact matériel)

Commande indépendante :

```bash
just yubikey-dependencies-test
just yubikey-dependencies-readonly
```

Le nouveau `inspect-yubikey-dependencies-readonly.py` observe uniquement :
- l'existence de processus `scdaemon` **de l'utilisateur courant** et
  `pcscd` (via `pgrep`, sans lire arguments, PID ou journaux) ;
- le socket SSH-agent : refus des chemins relatifs, liens symboliques et
  sockets dont le propriétaire ne correspond pas à l'utilisateur ; si
  autorisé, `ssh-add -l` ne transmet que l'**état de présence d'identités
  publiques**, stdout/stderr éliminés ;
- la disponibilité des binaires `pg_restore`, `pg_dump`, `psql`,
  `initdb`, `pg_ctl`, `age`, `sops`, `gpg`, `ssh-add` ;
  la version, l'accès et la fonction ne sont pas démontrés.

Aucun `gpg --card-status`, `SCD GETINFO`, démarrage ou arrêt de
`scdaemon`/GPG-agent/PCSC, requête sur la YubiKey, PIN/PUK, extraction de
clé, lecture de sauvegarde, signature, déchiffrement ou commande PAM/SOPS.
**Un processus `scdaemon` présent ne prouve PAS le transport PC/SC ni
l'accès à OpenPGP.** `ssh-add -l` ne prouve PAS une connexion SSH FIDO2.

La recette `just yubikey-parallel-host-readonly` exécute désormais six
familles de tests hermétiques **en parallèle**, dont les 11 tests du
nouveau collecteur, puis trois contrôles indépendants du poste **en
parallèle** (workstation, GPG-agent, dépendances). La variante
`just yubikey-parallel-secondary-readonly` maintient l'inventaire
matériel *après* ces contrôles et jamais en concurrence avec eux.
Le coordinateur exige maintenant une réponse `PASS` de **chaque** job
attendu ; aucune absence d'une clé JSON ne peut autoriser la suite.

**Preuve locale hors matériel :** 11/11 tests hermétiques du nouveau
collecteur PASS (Python 3.13), `py_compile` PASS. Correspondance des
empreintes entre copie testée et GitHub :
`inspect-yubikey-dependencies-readonly.py@eaf2d752` ;
`test_yubikey_dependencies_readonly.py@bdcfd2bf`.
Les 13 tests du coordinateur parallèle *modifié* et la recette complète
sont encore **NOT_RUN sur la workstation**. Le résultat opérateur antérieur
11/11 sur `5bd112f0` ne valide pas ce nouveau lot.

**Interprétation :** `status=NO-GO` reste systématique ; présence des
processus et binaires n'implique aucune preuve fonctionnelle de
restauration, signature, SSH ou chiffrement. Les sauvegardes existantes
sont à inventorier explicitement, sans découvrir ou publier leurs chemins
dans les logs du dépôt.

## Validations workstation — transport scdaemon et outils PostgreSQL versionnés

**Nouvelle preuve opérateur au SHA `aa2bdedd01a2d3dd93405d704c39934e21a7747c`** :
`just yubikey-dependencies-test` **11/11 PASS**,
`just yubikey-parallel-test` **13/13 PASS** ;
`just yubikey-parallel-host-readonly` et
`just yubikey-parallel-secondary-readonly` terminés avec toutes les
suites/sondes `PASS`. La secondaire `11110002` était seule interrogée.
Dépendances : `scdaemon=PROCESS_PRESENT_UNVERIFIED`,
`pcscd=PROCESS_PRESENT_UNVERIFIED`,
`ssh_agent=PUBLIC_IDENTITIES_PRESENT_UNVERIFIED`.
PostgreSQL : `pg_restore`, `pg_dump` et `psql` dans `PATH` ;
`initdb` et `pg_ctl` **absents de `PATH`**, installation globale inconnue.
`status=NO-GO`, `recovery=NOT_VERIFIED`,
`configuration=NOT_AUTHORIZED` et
`hardware_mutation_authorized=false` maintenus.

### Nouveaux diagnostics préparés dans la PR

`just yubikey-dependencies-readonly` ajoute deux champs de statut :

- `agent_scdaemon` interroge uniquement **l'agent GPG existant**
  (`gpg-connect-agent --no-autostart "GETINFO scd_running" /bye`).
  `AGENT_REPORTS_SCD_RUNNING_UNVERIFIED` signifie que l'agent connaît
  déjà un scdaemon actif. Tout refus, erreur ou réponse incomplète
  n'est pas une preuve d'accès à l'applet OpenPGP. **Aucune commande
  `SCD` n'est envoyée** : l'ouverture d'une session `SCD` peut démarrer
  scdaemon si celui-ci est absent. Ni signature, ni carte, ni clé privée,
  ni PIN n'est touché.
- `postgres_versioned_server_tools` examine uniquement les métadonnées
  des exécutables `initdb` et `pg_ctl` sous
  `/usr/lib/postgresql/<version>/bin` (disposition Debian/Ubuntu).
  Les liens symboliques et exécutables non détenus par root sont
  refusés. `VERSIONED_SERVER_BINARIES_PRESENT_UNVERIFIED` n'est
  **pas** une preuve de leur fonctionnement ou d'une restauration.
  Une absence à cet emplacement n'exclut pas une installation
  PostgreSQL différente (container, Nix, autre distribution).

Les deux observations se déroulent avec le diagnostic du poste et la
sonde GPG-agent : **trois sondes indépendantes en parallèle**, sans lancer
`initdb`, `pg_ctl`, `gpg --card-status`, `SCD GETINFO` ni accéder aux
sauvegardes.

Le collecteur de dépendances possède désormais **17 tests hermétiques**
(11 initiaux et 6 nouveaux). **Preuve locale isolée du 25 octobre :**
`py_compile` PASS, **17/17 tests PASS** sous Python 3.13 ; les blobs
effectivement exécutés correspondent aux fichiers publiés dans #280 :
`inspect-yubikey-dependencies-readonly.py@18545ba46b26e2a735162056437b810f1942edd5`
et `test_yubikey_dependencies_readonly.py@86fc35e484cf29f064abfb7d996886f2bbd684d5`.
Ce test local ne prouve aucun état matériel de la workstation :
**validation des nouvelles sondes réelles encore NOT_RUN**. Exécuter
depuis un HEAD à jour :

```bash
git rev-parse HEAD
just yubikey-dependencies-test
just yubikey-parallel-test
just yubikey-dependencies-readonly
just yubikey-parallel-host-readonly
# Facultatif : un seul token secondaire, jamais simultanément à un autre inventaire
just yubikey-parallel-secondary-readonly
```

**Interprétation de sortie** : aucune réussite de sonde ni présence
de binaires n'autorise une écriture de clé, un changement PAM/SOPS, un
déchiffrement age/GPG ou la restauration des bases. Avant une restauration
isolée, inventorier séparément les archives existantes et leur format,
puis approuver le déchiffrement et l'utilisation des secrets concernés.

Références externes :
[GnuPG gpg-agent](https://gnupg.org/documentation/manuals/gnupg26/gpg-agent.1.html),
[PostgreSQL pg_config](https://www.postgresql.org/docs/current/app-pgconfig.html),
[PostgreSQL sous Debian](https://wiki.debian.org/PostgreSql).

## Suite opérateur après validation du SHA dfb2b850 (25 octobre 2026)

Exécution réellement fournie sur workstation :

- `just yubikey-dependencies-test` **17/17 PASS** et `just yubikey-parallel-test` **13/13 PASS**, compilation Python réussie.
- Les six familles de tests du diagnostic parallèle et trois sondes du poste ont renvoyé `PASS`. **Aucun inventaire matériel demandé dans cette dernière exécution** ; l'inventaire de la secondaire avait été validé au SHA opérateur précédent.
- `scdaemon=PROCESS_PRESENT_UNVERIFIED`, `pcscd=PROCESS_PRESENT_UNVERIFIED`, mais `agent_scdaemon=NOT_CONFIRMED`. Ces deux preuves ne sont pas contradictoires : un processus scdaemon peut exister sans qu'il soit connu de l'agent GPG connecté, ou la sonde peut recevoir une réponse non conforme. Il n'est pas autorisé de démarrer, redémarrer ou tuer des agents à titre de correction automatique.
- Les commandes clientes `psql`, `pg_dump`, `pg_restore` sont présentes. `initdb`/`pg_ctl` manquent dans `PATH` et la disposition Debian/Ubuntu `/usr/lib/postgresql/<version>/bin` n'a pas fourni de binaires serveur vérifiés. Cela ne suffit pas à exclure une installation PostgreSQL différente, un conteneur ou un serveur distant.

### Extension du diagnostic PostgreSQL, en lecture seule

La nouvelle sortie `postgres_pg_config_server_tools` interroge exclusivement
`pg_config --bindir` avec entrée standard fermée, durée bornée et sortie
masquée ; elle contrôle ensuite seulement les métadonnées des deux
exécutables serveur `initdb`/`pg_ctl` à cet emplacement. Refus des
liens symboliques et des exécutables dont le propriétaire est inconnu.

- `PG_CONFIG_SERVER_BINARIES_PRESENT_UNVERIFIED` : deux binaires trouvés ; ni version compatible ni restauration démontrée.
- `PG_CONFIG_BINDIR_HAS_NO_SERVER_BINARIES` : `pg_config` peut décrire une installation cliente seulement.
- `PG_CONFIG_SERVER_BINARIES_PARTIAL` : un des deux binaires admissibles seulement.
- `PG_CONFIG_MISSING`, `BINDIR_UNAVAILABLE`, `UNKNOWN` : constat insuffisant.

`pg_config --bindir` fournit le répertoire des exécutables *de son installation*, sans prouver la présence d'un serveur complet ; source :
[PostgreSQL, pg_config](https://www.postgresql.org/docs/current/app-pgconfig.html).

**Nouveau code publié, NON TESTÉ sur la workstation** : quatre tests hermétiques
supplémentaires, soit **21 tests** de dépendances attendus. Aucun service,
conteneur ni token n'est démarré. La récupération GPG/PostgreSQL reste
`NOT_VERIFIED`. Valider les commandes :

```bash
git pull --ff-only
git rev-parse HEAD
just yubikey-dependencies-test
just yubikey-parallel-test
just yubikey-dependencies-readonly
just yubikey-parallel-host-readonly
```

Ces commandes n'effectuent ni restauration, ni accès PIV, ni signature OpenPGP.
Les tests de contrat `PASS` n'équivalent pas à un `GO` fonctionnel.

## Diagnostic GPG renforcé et restauration PostgreSQL synthétique — 25/10/2026

**Dernière preuve opérateur** : `32209b385b3bdc974a6cdcf5d3ec0c609ea69d76`,
`just yubikey-dependencies-test` **21/21 PASS**,
`just yubikey-parallel-test` **13/13 PASS**, six familles de tests et trois
sondes du poste PASS. `agent_scdaemon=NOT_CONFIRMED`,
`scdaemon=PROCESS_PRESENT_UNVERIFIED` et
`pcscd=PROCESS_PRESENT_UNVERIFIED`.
`postgres_pg_config_server_tools=PG_CONFIG_BINDIR_HAS_NO_SERVER_BINARIES` ;
les clients `pg_dump`, `pg_restore` et `psql` sont installés. La dernière
recette `host-readonly` n'a pas interrogé la YubiKey.

### 1. GPG-agent ↔ scdaemon : diagnostic, pas remédiation

Le classifieur Assuan accepte désormais les deux réponses positives
`OK / OK closing connection` et
`OK Pleased to meet you / OK / OK closing connection`.
Il distingue une réponse `ERR <code>` (`AGENT_SCD_STATUS_REJECTED_UNVERIFIED`)
d'une réponse malformée (`NOT_CONFIRMED`).
Ni code, ni message d'erreur brut, ni PID ni chemin ne sont affichés.
`gpg-connect-agent --no-autostart "GETINFO scd_running" /bye` reste
l'unique requête ; aucune commande `SCD` n'est envoyée.
**Un succès n'autorise ni l'accès à la carte OpenPGP, ni un PIN ni une signature.**
`NOT_CONFIRMED` ne prouve pas l'absence de scdaemon ; ne pas redémarrer les
agents sans un diagnostic et une autorisation séparés.

### 2. PostgreSQL : smoke de récupération avec des données synthétiques

Le manque de `initdb` et `pg_ctl` sur la workstation ne justifie pas
l'installation d'un serveur dans le système hôte.
Le script `scripts/workstation/verify-postgres-fixture-recovery.sh`
vérifie séparément `pg_dump -Fc` → `pg_restore -1` → résultat SQL
dans **un conteneur jetable contenant seulement une fixture synthétique**.

Prérequis : image PostgreSQL approuvée déjà présente dans Docker local ;
choisir une version majeure cohérente avec la source de la future restauration.
Exporter son identifiant **immutable** `sha256:<64 hex>` via
`NABLA_POSTGRES_FIXTURE_IMAGE_SHA256` ; la recette refuse les tags, ne
télécharge aucune image et refuse les contextes Docker distants
(`ssh://`, `tcp://`, y compris un contexte TrueNAS).

```bash
just yubikey-postgres-fixture-test
# Image SHA256 déjà choisie et installée localement :
export NABLA_POSTGRES_FIXTURE_IMAGE_SHA256='sha256:REMPLACER_PAR_ID_LOCAL_64_HEX'
just yubikey-postgres-fixture-check
# Action explicitement autorisée : crée puis détruit un conteneur local jetable
just yubikey-postgres-fixture-run
```

La recette `--check` ne crée ni conteneur ni base. La recette `--run`
exige `--acknowledge SYNTHETIC_ONLY`, Docker Unix local, `--pull=never`,
`--network none`, `--read-only`, tmpfs seulement, sans ports ni volumes
hôtes. Elle s'arrête si la fixture SQL restaurée ne correspond pas à la
source. Le conteneur est supprimé à la sortie. **Le SHA doit appartenir
à une image PostgreSQL de confiance** ; aucune nouvelle image n'est
récupérée automatiquement.

**Preuve hors Docker** : `bash -n` PASS, 5/5 tests hermétiques PASS
sur les blobs Git exacts `verify-postgres-fixture-recovery.sh@ddb6a5c8`
et `test_yubikey_postgres_fixture_recovery.py@5153dc79`.
**Smoke Docker réel : NOT_RUN** dans l'environnement agent dépourvu
de Docker. Une fixture réussie ne valide pas un backup GPG/age,
une restauration d'escrow ni une base PostgreSQL de production.
Ces récupérations nécessitent une autorisation distincte et un
environnement isolé, sans accès aux bases existantes.
