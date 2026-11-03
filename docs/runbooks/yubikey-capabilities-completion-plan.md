# YubiKeys — plan de finition, preuves et décisions

**Owner :** nabla-compose. **Branche de travail :** PR #280.
**Périmètre :** secondaire 11110002 puis principale 11110001.
**Principe :** un diagnostic en lecture seule n'autorise aucune configuration.

## État établi / état non établi

| Domaine | Preuve acquise | Ce qui manque pour considérer terminé |
| --- | --- | --- |
| KeePassXC / OTP2 | Sur la secondaire, OTP2 est PROGRAMMED_TYPE_UNVERIFIED (25/10/2026) ; historique de challenge équivalent sur les deux cartes | Test KeePassXC supervisé après validation du plan de récupération ; ne jamais reprogrammer le slot 2 |
| PIV / F9 | Certificat F9 secondaire validé avec racine Yubico épinglée | Ne constitue pas une attestation de clé PIV82 |
| PIV / 9A | RSA2048 importé et certificat Nabla Root CA historiquement expiré (22/01/2025) | Dépendances PKI/Vault et usages du certificat réellement prouvés, sans écrasement |
| PIV / 82-83 | 82 confirmé vide sur la secondaire ; 83 vide selon inventaire antérieur | Deux sauvegardes récupérables, authentification AES256 autorisée, certificat interop age, roundtrip sur documents synthétiques |
| SOPS / age | Identité logicielle et procédures de récupération documentées | Deux supports de secours effectivement distincts et restauration indépendante testée |
| GnuPG / PostgreSQL | GPG utilisé pour signatures et sauvegardes ; incident scdaemon / pcsc historique | Correspondance des sous-clés, correction du transport, déchiffrement et restauration PostgreSQL isolée |
| FIDO2 / passkeys | PIN FIDO2 historiquement actif sur la secondaire | Inventaire d'état public, authentification/inscription indépendante sur les deux cartes, codes de récupération |
| SSH FIDO2 | Chemin recommandé, non considéré comme enrôlé | Deux clés distinctes, tests ssh, voie d'accès de secours avant durcissement |
| OpenPGP | Application présente historiquement ; gpg --card-status a échoué | Diagnostic PC/SC, présence des sous-clés, sauvegarde hors ligne et test GPG |
| OATH | Applet présent historiquement, protection désactivée | Politique de protection et inventaire de récupération, sans publier comptes ni TOTP |
| PIV 9C/9D/9E | Slots historiquement vides sur la secondaire | Décider des usages S/MIME/PDF/PKCS#11 avant toute génération |
| PAM U2F / GNOME keyring | Non provisionné en tant que gate du poste | Deux tokens testés + session de secours ; PAM/keyring seulement après procédure de rollback |

Ce tableau distingue une **observation ponctuelle** d'une recette validée. Une clé
fournissant des métadonnées n'est pas une identité SSH/GPG utilisable.

## Diagnostic applicatif additionnel — sans PIN ni secret

Exécuter les deux YubiKeys **séparément** depuis un worktree de la PR :

- `just yubikey-applications-secondary-readonly` : carte 11110002 seule.
- `just yubikey-applications-primary-readonly` : carte 11110001 seule.
- `just yubikey-applications-test` : tests synthétiques, sans matériel.

Le diagnostic `inspect-yubikey-applications-readonly.py` vérifie d'abord
l'unicité du token, son numéro de série et le firmware 5.4.3 ; puis lit
uniquement `ykman fido info`, `ykman oath info`,
`ykman openpgp info`, `ykman piv info` et
`ykman piv keys info` pour 9A, 9C, 9D, 9E et 83.
Il n'interroge **pas** OTP2, F9 ou PIV82 déjà observés. Il n'utilise ni
commandes de compte OATH/FIDO, ni credential list, ni certificat brut,
ni GPG privé, ni challenge OTP. Entrée standard fermée et timeout.

Le JSON n'imprime jamais les sorties `ykman` brutes. Une applet
`RESPONDS_METADATA_ONLY` n'est pas configurée/validée par ce seul fait.
Un slot `EMPTY_CONFIRMED` ne peut pas être provisionné sans accord ;
`OCCUPIED_METADATA` ne prouve pas qu'une clé privée est utilisable ;
`UNKNOWN` bloque. La clé de gestion PIV doit rester
`AES256_PIN_PROTECTED` et 9A doit conserver des métadonnées de clé.
Même un diagnostic code 0 retourne toujours `status=NO-GO` et
`hardware_mutation_authorized=false`. Les réponses personnelles
et certificats ne sont pas recopiés dans les logs publics.

## Ordre d'exécution des configurations futures

1. **P0 — Sauvegardes et perte de carte.** Identifier les deux copies
   chiffrées d'escrow et leurs supports physiques. Inspecter seulement
   leurs métadonnées avec le script existant ; effectuer une restauration
   dans un environnement isolé lors d'une séance autorisée. Prouver
   l'accès GPG aux anciennes sauvegardes et restaurer un PostgreSQL jetable.
   Ne pas déplacer de sous-clés avant ce résultat.
2. **P0 — PKI / 9A.** Cartographier la confiance actuellement utilisée.
   Ne pas remplacer le certificat historique expiré : définir root
   hors ligne et intermédiaire Vault/OpenBao, politique de révocation
   et récupération, puis approuver séparément l'architecture.
3. **P1 — AES256 et PIV82 secondaire.** Contrôler publiquement la
   politique du slot ; obtenir l'autorisation d'une seule authentification
   supervisée. Planifier distinctement génération P-256, certificat
   compatible avec le plugin age, import, attestation et roundtrip
   sur fixture. Aucune exécution implicite ni récupération PIN automatique.
4. **P1 — PIV82 principale.** Seulement après roundtrip secondaire
   réussi et restauration logicielle prouvée. Chaque token a une clé
   privée différente ; chiffrer pour les deux destinataires avant
   changement SOPS.
5. **P1 — OpenPGP et FIDO2.** Réparer d'abord la visibilité GPG/PCSC,
   préserver la clé de signature et le chiffrement PostgreSQL.
   Choisir SSH FIDO2 ou PIV après inspection des dépendances ;
   inscrire les deux clés séparément, tester et prévoir les secours.
   Les passkeys sont à enregistrer par relying party, sur chaque clé.
6. **P2 — OATH, 9C/9D/9E, PAM et keyring.** Examiner les usages
   réels avant d'activer une protection OATH ou une signature PDF/S/MIME.
   Tester les deux tokens et un compte secours avant toute modification
   de `/etc/pam.d`. Le trousseau GNOME n'est pas automatiquement
   débloqué par FIDO2.

## Critères de sortie

- `L1` : diagnostics en lecture seule, tests hermétiques et gate locale PASS.
- `L2` : état de **chaque** carte observé (pas inféré du modèle voisin).
- `L3` : restauration age/SOPS **et** PostgreSQL/GPG validées isolément.
- `L4` : transaction PIV82 secondaire approuvée étape par étape et
  véritable roundtrip age. Recontrôler OTP2 et 9A **après** transaction.
- `L5` : principale validée indépendamment, destinataires de secours
  documentés, SSH/FIDO2/OpenPGP acceptés séparément, plan de rollback PAM.

Chaque phase mutante demande une approbation explicite. Les résultats
actuels ne satisfont pas les critères L3-L5.

## Références et runbooks

- [Inventaire YubiKey existant](../workstation-yubikey-full-capabilities.md)
- [GPG, PostgreSQL et Vault](../workstation-yubikey-gpg-vault-roadmap.md)
- [Diagnostic F9, PIV82 et escrow](yubikey-piv82-postmerge-diagnostics.md)
- [Reprise AES256](yubikey-piv82-aes256-handoff.md)
- [Yubico ykman commandes](https://docs.yubico.com/software/yubikey/tools/ykman/)


## Diagnostic du poste (sans aucune commande YubiKey)

`just yubikey-workstation-readonly` examine exclusivement la présence
des outils locaux (`gpg`, `gpgconf`, `age`, `sops`,
`age-plugin-yubikey`, `ykman`, `pcsc_scan`, `ssh-keygen`,
`pamu2fcfg`, `keepassxc`, `cryptsetup`, `lsblk`).
Il inspecte uniquement les métadonnées de quatre emplacements
conventionnels : identité age SOPS (mode 0600, utilisateur courant),
socket gpg-agent, poignée publique SSH FIDO2 et mapping PAM U2F.
Il **n'ouvre aucun fichier**, n'énumère aucun compte, ne lance pas
`gpg --card-status`, ne demande aucun PIN ni mot de passe et
n'interroge pas la carte. Les chemins et contenus ne sont pas imprimés.

`just yubikey-workstation-test` valide ces règles hors matériel.
La présence d'une commande, d'un socket ou d'un fichier public n'est
**jamais** une preuve d'authentification, de déchiffrement, ni de
restauration de sauvegardes. Le JSON reste `status=NO-GO`.


## Diagnostic agrégé du poste et des applications

Exécuter `just yubikey-diagnostics-test` puis `just yubikey-diagnostics-secondary-readonly` pour une seule observation sans mutation. Les étapes GPG/scdaemon, escrow, PostgreSQL, PIV82, FIDO2/SSH et PAM conservent `NOT_VERIFIED`. L'OTP2 n'est pas revérifié par défaut. [Runbook](yubikey-readonly-batch.md).


La cible `just yubikey-diagnostics-all-secondary` inclut une sonde GPG-agent `GETINFO version` avec `--no-autostart`, sans PIN et sans toucher à scdaemon ni aux clés. Un agent joignable ne suffit pas à valider OpenPGP ou la restauration des sauvegardes PostgreSQL. Elle comprend 95 méthodes de test au total. **Preuve opérateur du 25/10/2026 : 95/95 PASS** depuis le HEAD local `d4f1afbd`, avec `gpg_agent=RESPONDS_GETINFO_ONLY`. Le HEAD distant peut avoir évolué : ces résultats ne valent pas validation d'un commit ultérieur. **Statut de récupération : NO-GO** (scdaemon/OpenPGP, PostgreSQL/GPG, escrow age, PIV82 et PAM non validés). Voir le [rapport de diagnostic groupé](yubikey-readonly-batch.md#preuve-opérateur--diagnostic-groupé-du-25-octobre-2026).

## Exécution parallèle des préparations (PR #280)

Pour réduire le chemin critique, les chantiers P0/P1 sont préparés en
**quatre flux simultanés** : (A) GPG-agent/scdaemon/OpenPGP,
(B) sauvegardes GPG/PostgreSQL et escrow age/SOPS, (C) FIDO2/SSH/KeePassXC,
(D) PKI/9A et plan PIV82/AES256. Aucun flux ne doit attendre la fin des autres
pour préparer ses contrats, runbooks, preuves et tests hermétiques.

- `just yubikey-parallel-test` : 13 tests (dont 2 nouveaux contrats de complétude),
  vérifiant la concurrence, toutes les réponses attendues et l'absence de mutation.
- `just yubikey-dependencies-test` : 11 tests hermétiques indépendants sur
  les états GPG/scdaemon/PCSC, SSH-agent public et outils PostgreSQL/age/SOPS.
- `just yubikey-dependencies-readonly` : métadonnées locales uniquement,
  sans démarrage de daemon, sans secrets ni inventaire matériel.
- `just yubikey-parallel-host-readonly` : six familles de tests en parallèle,
  puis vérifications workstation/GPG-agent/dépendances en parallèle.
- `just yubikey-parallel-secondary-readonly` : même lot, puis **un seul**
  inventaire public de la secondaire, sans concurrence sur le périphérique.

**Barrière transversale conservée** : les configurations qui écrivent ou qui
utilisent des secrets ne sont pas incluses dans l'orchestrateur. Les opérations
OpenPGP, PIV82, PIN/AES256, OTP2, PAM et SOPS ne sont jamais déclenchées
implicitement. Avant configuration réelle, démontrer restauration indépendante,
préservation 9A/OTP2, moyens de secours et approbation de l'opération ciblée.
La présence d'une carte, le succès d'un test ou une réponse Assuan ne suffit pas.

**Preuve locale hors matériel** : au 25/10/2026, compilation Python et **11/11
nouveaux tests PASS** sur copies strictement identiques aux blobs Git publiés :
`run-yubikey-parallel-readonly.py@823111e8` et
`test_yubikey_parallel_readonly.py@4b6ebd29`. Ce résultat ne teste ni
la recette réelle `just` du worktree, ni le périphérique de la workstation.
Le statut de récupération et de configuration reste **NO-GO**.

**Point d'avancement P0 (25/10/2026)** : diagnostic du poste étendu,
sans toucher aux clés. Les 11 tests du collecteur de dépendances ont réussi
sur copie locale strictement identique à GitHub ; la recette parallèle
élargie (13 tests de contrat, six suites puis trois sondes) reste à exécuter
sur la workstation. Les étapes mutantes restent soumises à des accords
séparés ; aucune vérification GPG/OpenPGP, escrow ou restauration PostgreSQL
ne peut être déclarée terminée par simple présence d'un daemon.

### Validation suivante — agent scdaemon et récupération PostgreSQL

La workstation au SHA `aa2bdedd` confirme les processus
`scdaemon`/`pcscd` et les identités publiques SSH, mais pas l'accès
OpenPGP. `initdb` et `pg_ctl` sont absents du `PATH` seulement.

Le collecteur de dépendances étendu teste désormais, sans démarrage :
`GETINFO scd_running` via GPG-agent existant `--no-autostart`, puis
les métadonnées des binaires PostgreSQL versionnés standards. **17/17
contrats PASS en local sur blobs Git exacts** ; lecture sur workstation
du nouvel état encore `NOT_RUN`. Éviter d'installer un nouveau serveur
PostgreSQL avant d'avoir qualifié l'installation actuelle et défini un
espace de restauration isolé. Les deux copies d'escrow et les archives
GPG/PostgreSQL restent non inventoriées ou non restaurées dans ces
preuves : aucun changement du statut `NO-GO`.


### Prochaine étape concrète : première preuve PostgreSQL fonctionnelle isolée

- **Contexte validé (`32209b38`)** : 21/21 dépendances, 13/13 contrats
  parallèle PASS sur la workstation. `GETINFO scd_running` reste
  `NOT_CONFIRMED`; les clients PostgreSQL sont présents mais pas les
  exécutables serveur locaux. Les anciennes sauvegardes restent intactes.
- **Correctif GPG** : classifieur Assuan plus robuste pour un message
  d'accueil et distinction explicite de `ERR`, sans requête `SCD`.
  Les 3 nouveaux contrats GitHub attendent validation sur workstation.
- **Récupération PostgreSQL sur fixture** : le nouveau script
  `verify-postgres-fixture-recovery.sh` peut prouver le roundtrip
  `pg_dump` → `pg_restore` **sans aucune sauvegarde personnelle**,
  avec un conteneur local isolé, opt-in, SHA image imposé et cleanup.
  **5/5 tests hermétiques PASS en local sur blobs exacts** ; test Docker
  fonctionnel réel `NOT_RUN`. Un succès éventuel ne satisfait pas L3
  avant une restauration d'archive réelle explicitement autorisée.
- **En parallèle** : conserver l'inventaire des dépendances PKI/9A,
  FIDO2/SSH, escrow age et GPG/OpenPGP. Ne pas déduire un `GO`
  matériel du smoke PostgreSQL.

Voir [runbook des diagnostics](yubikey-readonly-batch.md#diagnostic-gpg-renforcé-et-restauration-postgresql-synthétique--25102026).

## Cinq opérations demandées — exécution conjointe (25 octobre 2026)

La demande opérateur couvre **PIV82/age, OpenPGP/GPG, FIDO2/SSH,
KeePassXC/OTP2 et SOPS/escrow/PostgreSQL**. Leur préparation peut
être menée en parallèle, mais les opérations sur matériel réel ne
peuvent pas être lancées depuis l'agent sans lecteur ni secrets locaux.

Livré en #280 : `scripts/workstation/prepare-yubikey-backup-five.py`,
`tests/test_yubikey_backup_five_workstreams.py` et recettes
`just yubikey-backup-five-{test,readonly,secondary-readonly}`.
Le collecteur réutilise les outils existants, refuse de reproduire
les sorties brutes et conserve `status=NO-GO`. Il ne configure
pas automatiquement PIV, FIDO, OpenPGP, OTP2 ni SOPS.

| Piste | Prochaine preuve d'acceptation |
| --- | --- |
| PIV82/age | attestation P-256, certificat interopérable, roundtrip réel sur la secondaire |
| OpenPGP/GPG | accès réel à la carte et test de signature/déchiffrement supervisé |
| FIDO2/SSH | création locale d'une identité backup distincte puis login vérifié et secours |
| KeePassXC/OTP2 | ouverture d'une copie de base KDBX avec les deux clés, sans reprogrammer OTP2 |
| SOPS/age/escrow | deux voies indépendantes de récupération, déchiffrement et restauration PostgreSQL isolée |

**Contrats :** 10 tests hermétiques de l'orchestrateur exécutés
sur une copie locale avant publication ; la validation des nouvelles
recettes sur workstation reste `NOT_RUN`. L'inventaire
matériel et les étapes mutantes doivent rester séparés.
Ne pas interpréter le code de sortie 0 d'un diagnostic comme une
autorisation d'opération irréversible.

[Runbook détaillé des cinq chantiers](yubikey-backup-five-execution.md).

## Mise à jour : OTP2 secondaire programmé — KeePassXC en attente (26/10/2026)

La commande opérateur `just yubikey-otp2-secondary-readonly` a confirmé
`otp2=PROGRAMMED_TYPE_UNVERIFIED` pour la YubiKey de secours
`11110002`. `keepassxc_verified=false`,
`otp2_hmac_sha1_verified=false`, `escrow=NOT_CHECKED`,
`status=NO-GO`. **Ne pas reprogrammer OTP2** : `ykman otp info`
ne révèle pas le type ou le secret HMAC existant.

**Jalon KeePassXC à exécuter localement** : ouvrir la même **copie
chiffrée KDBX**, sans jamais enregistrer, une fois avec la principale
`11110001` seule, puis une fois avec la secondaire `11110002`
seule, en conservant les mêmes autres facteurs.
Conditions de clôture : `PRIMARY_UNLOCK=PASS` et
`SECONDARY_UNLOCK=PASS`, plus moyen de récupération disponible.
Si aucune base existante n'utilise HMAC-SHA1 challenge-response,
le jalon reste `NOT_CONFIGURED`, sans changer la protection
de la base principale.

[Procédure OTP2/KeePassXC](yubikey-backup-keepassxc-otp2-verification.md).

**Autres chantiers à ne pas confondre** : signature SSH/FIDO2 locale
déjà démontrée (SSHSIG), login SSH distant non testé ; OpenPGP
répond publiquement mais pas de preuve de clé privée ; PIV82 non
provisionné ; récupération SOPS/GPG/PostgreSQL réelle et escrows non
vérifiés. Ces chantiers gardent leurs critères de validation propres.

## Transfert vers PR #285 — récupération age/SOPS validée, escrows à inventorier (26/10/2026)

Le test KeePassXC/OTP2 est **reporté à la demande de l'opérateur** ;
la seule observation actuelle reste `PROGRAMMED_TYPE_UNVERIFIED`.
Pas de nouveau challenge, aucune reprogrammation.

**Validation opérateur déjà obtenue** sur `feat/yubikey-software-recovery-20261026` :
`just yubikey-software-recovery-test` **9/9 PASS** ;
`just yubikey-software-recovery-check` :
`SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED` ;
`just yubikey-software-recovery-run` :
`AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS`, avec
`synthetic_software_roundtrip_verified=true`.
Cela démontre le roundtrip synthétique avec des binaires réels du
poste, **pas** la récupération d'une sauvegarde personnelle.

**Consolidation demandée dans PR #285** : reprise des mêmes blobs
de script et de 9 tests age/SOPS depuis #287, en préservant les
corrections secrètes de la PR #285. Ajout d'un collecteur facultatif
`yubikey-escrow-pair-inspect` à saisie masquée, sans chemins en
arguments ou logs, ni accès aux contenus. Les 8 contrats hermétiques
de cet outil sont **PASS en environnement agent** ; une exécution
de métadonnées sur les deux vrais escrows reste **NOT_RUN**.

**Prochaines preuves séparées :**
- Sélectionner deux archives `.age` déjà existantes sur la workstation.
- Observer `TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED` (stat-only),
  sans confondre plusieurs filesystems avec deux supports physiques.
- Vérifier la récupération indépendante de chaque copie dans un
  environnement isolé, sans publication des secrets.
- Lancer une restauration isolée GPG/PostgreSQL seulement après
  validation des prérequis, avec preuve expurgée.
- Autoriser ensuite, phase par phase, PIV82/age (génération, attestation,
  certificat et roundtrip matériel), en préservant PIV9A et OTP2.

Voir [runbook de récupération synthétique et escrows](yubikey-software-recovery-20261026.md).

## Deux emplacements age connus — preuve opérateur et recherche automatique (26/10/2026)

Le logiciel a désormais un mode `--discover` qui examine uniquement
les deux répertoires suivants (sans récursion et sans ouverture du contenu) :

- `~/.local/share/nabla/age-backups/`
- `/media/backup/lab/secret/`

La découverte fait correspondre les fichiers `.age` **par nom
identique** dans les deux répertoires. Elle refuse de choisir une paire
si plusieurs noms correspondent et ne suit aucun lien symbolique.
`just yubikey-escrow-pair-discover` renvoie seulement un statut
JSON, sans afficher les noms ni chemins.
`just yubikey-escrow-pair-inspect` propose la paire unique après
confirmation `[o/N]`, sinon conserve la saisie manuelle masquée.
Les tests hermétiques de cette interface sont passés de **8 à 17**
et attendent une validation sur la workstation.

**Preuve utilisateur** : même chemin fourni deux fois
→ `SAME_FILE`, refus correct. Après copie `cp` vers le support monté,
deux inspections des deux chemins ont renvoyé
`TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED`.
La copie destination apparaît en `-rw-------+` et contient
389 octets. Cela ne prouve ni identité des contenus, ni supports
physiquement indépendants, ni déchiffrement/restore.
L'ACL `+` devra être contrôlée localement.

**Suite** : vérifier l'identité binaire de la copie puis restaurer en
environnement isolé à partir du support de sauvegarde, sans exposer
la clé age ou le texte déchiffré. Aucune génération PIV82 ou mutation
SOPS autorisée à ce stade. Test KeePassXC/OTP2 toujours reporté.

## Escrow chiffré — deux copies repérées et comparaison de contenu à faire (26/10/2026)

**Preuve opérateur au HEAD `41e2b099` :** découverte de la
copie locale et de la copie sur support monté
`TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED` par
`just yubikey-escrow-pair-discover`, puis la même classification
confirmée après réponse `o` à `just yubikey-escrow-pair-inspect`.
**17/17 tests de la découverte PASS sur workstation.**

La prochaine preuve est l'égalité **octet par octet** des deux
archives `.age` chiffrées, sans clé, sans déchiffrement ni
publication de hash. Nouveau programme :
`compare-yubikey-escrow-pair-readonly.py`, recette explicite
`just yubikey-escrow-compare-run`, avec contrôle et
**11/11 tests hermétiques PASS en environnement agent**.
Le test des **vraies copies** reste `NOT_RUN`.

Une réponse `ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED` permettra
de considérer la copie chiffrée comme identique au moment du contrôle,
mais **pas** comme récupérable, indépendante physiquement ou source
d'une seconde identité age. L'ACL `+` sur la destination et la
restauration réelle doivent encore être vérifiées.

La génération PIV82 et les changements de destinataires SOPS restent
**NO-GO**. Le test KeePassXC/OTP2 demeure reporté.

[Procédure](yubikey-software-recovery-20261026.md).

## Escrows — diagnostic de découverte et comparaison manuelle (26/10/2026)

La suite du comparateur a **11/11 PASS sur la workstation**, et son
précontrôle `--check` confirme qu'aucun contenu n'est lu. Mais le
premier `just yubikey-escrow-compare-run` réel a renvoyé
`DISCOVERY_NO_MATCHING_PAIR`, avec
`encrypted_content_read_attempted=false`.
Ce résultat ne signifie pas que les archives diffèrent ou sont
indéchiffrables : aucune comparaison de contenu n'a eu lieu.

Le collecteur et le comparateur partagent l'inventaire des répertoires
`~/.local/share/nabla/age-backups` et `/media/backup/lab/secret`.
Pour distinguer HOME incohérent, dossier manquant, absence de fichier
ou absence de nom commun, exécuter le nouveau
`just yubikey-escrow-pair-diagnose`. Il produit uniquement les
états des deux répertoires, les compteurs bornés de fichiers `.age`
et le nombre de noms correspondants. Aucun chemin n'est publié.

Si la découverte reste absente malgré l'existence des fichiers,
`just yubikey-escrow-compare-manual` permet une sélection par
saisie terminale masquée, sous le même contrôle de métadonnées,
avec autorisation explicite. La comparaison **lit les contenus
chiffrés**, sans déchiffrer, écrire ou afficher les fichiers.
Les contrats ont été étendus à **22 tests d'inventaire** et
**18 tests de comparaison** ; la validation complète de ces nouveaux
contrats sur workstation est `NOT_RUN`.

**Toujours NO-GO** pour la restauration réelle, l'identité d'un
second moyen de récupération age, toute écriture PIV82 et toute
modification du SOPS de production. KeePassXC/OTP2 reste reporté.

[Diagnostic et procédure](yubikey-software-recovery-20261026.md).

## Escrow NFS — copie absente côté serveur, snapshots à examiner (26/10/2026)

La workstation a validé **12/12 contrats** du probe NFS/TrueNAS ;
`SERVER_EXPECTED_COPY_MISSING` a été observé depuis le serveur
dans `/mnt/cpool/backup/lab/secret`. Le fichier est également absent
de la vue cliente NFS, tandis que la source locale `.age`
reste identifiable. **La disparition permanente n'est pas démontrée.**

Nouveau jalon non destructif : `just yubikey-escrow-history-test`,
`just yubikey-escrow-history-check`, puis
`just yubikey-escrow-history-probe` supervisé.
Le programme examine les métadonnées de trois racines de snapshots
ZFS candidates, **au plus 32 entrées par racine**, sans scan récursif
général, contenu privé ou commande ZFS à privilèges.
**10 tests hermétiques PASS dans l'environnement agent** ;
preuve workstation réelle `NOT_RUN`.

L'ordre des opérations reste : identifier la copie/snapshot
historique éventuel → confirmer intégrité → restaurer
dans un espace isolé → vérifier les moyens de récupération.
Aucun rollback ZFS, copie, changement de destinataire SOPS ni
provisionnement PIV82 autorisé. KeePassXC/OTP2 reste différé.

Voir [runbook](yubikey-software-recovery-20261026.md).

## Suite au probe des snapshots ZFS — pagination contrôlée (27/10/2026)

**Résultat opérateur (version initiale) :** `just
yubikey-escrow-history-test` **10/10 PASS** ;
`just yubikey-escrow-history-probe` :
`roots_accessible=3`, `snapshots_checked=96`,
`candidate_copies=0`, `SNAPSHOT_HISTORY_INCOMPLETE`.
Le programme a atteint son plafond de 32 snapshots dans
chacune des trois racines ; il n'a pas prouvé l'absence
des sauvegardes au-delà des entrées vérifiées.

**Correctif livré** : pages de 32 snapshots par racine, en
ordre lexicographique inverse des noms (pas nécessairement
chronologique), jusqu'à 32 pages/1 024 entrées inventoriées
par racine. `just yubikey-escrow-history-page 1` permet
d'avancer explicitement. Suivre `next_page` seulement
si la réponse l'autorise ; ne pas lancer de boucle non bornée.
Un répertoire qui dépasse 1 024 entrées garde
`inventory_truncated=true` : rien n'est déclaré complet.
**14/14 tests PASS dans l'environnement agent** ;
exécution paginée sur workstation encore `NOT_RUN`.

**Étape suivante :** valider la pagination sur workstation,
inspecter les pages suivantes si nécessaire, puis seulement
préparer une récupération autorisée depuis un snapshot candidat
dans un espace isolé. Aucune lecture des archives, copie,
restauration ou modification matérielle n'est intégrée au
probe. Maintenir `NO-GO` pour PIV82 et la restauration réelle ;
KeePassXC/OTP2 reste reporté.

[Procédure détaillée](yubikey-software-recovery-20261026.md).

## Escrow age — 120 snapshots sans candidat, copie NFS contrôlée préparée (27/10/2026)

**Preuve workstation** : `just yubikey-escrow-history-test`
**14/14 PASS**. Page 0 : 96 snapshots, 0 candidat, page suivante
disponible. Page 1 : 24 snapshots, 0 candidat,
`more_pages=false`, `next_page=null`,
`inventory_truncated=false`. **120 entrées examinées dans les trois
racines connues** ; la recherche a terminé ses pages sans retrouver
le nom de l'archive attendu. Cela n'exclut pas d'autres datasets,
supports ni une variation des snapshots entre les probes.

**Priorité suivante : créer une copie chiffrée NFS**, mais
uniquement après précontrôle. Le script
`create-yubikey-escrow-nfs-copy.py` est ajouté à #285 avec
`just yubikey-escrow-copy-test` et
`just yubikey-escrow-copy-check`. **9/9 contrats synthétiques
PASS local agent** ; workstation encore `NOT_RUN`.
Il vérifie la source, le montage NFS et l'absence de destination.
La copie réelle reste une commande Python **séparée, facultative
et opt-in**, avec nom temporaire 0600, publication atomique sans
écrasement, `fsync` et comparaison octet par octet. Aucune
écriture n'a été effectuée par l'agent.

**Conditions d'acceptation** : copie chiffrée créée et identique,
puis visibilité depuis le client et TrueNAS, ACL contrôlées,
déchiffrement age et récupération SOPS réels séparément démontrés.
Une simple copie binaire **n'est pas un escrow récupérable prouvé**.
Pas de changement des destinataires SOPS ou de PIV82. Le test
KeePassXC/OTP2 reste reporté.

[Procédure](yubikey-software-recovery-20261026.md).

## NFS age — nouvelle copie chiffrée effectivement créée (27/10/2026)

**Preuve opérateur** : après **12/12 tests de précontrôle PASS**
sur workstation, l'exécution volontaire et supervisée
`create-yubikey-escrow-nfs-copy.py --copy` a retourné
`ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED`,
`new_copy_verified=true`, `existing_destination_overwritten=false`,
`source_decryption_performed=false`, `restore_verified=false`.
La duplication **des octets chiffrés** sur l'export NFS
est donc **DONE** pour ce jalon. Ne pas réexécuter `--copy`.

**Priorité suivante dans PR #289** : contrôle post-copie
indépendant avec `just yubikey-escrow-postcopy-test`,
`just yubikey-escrow-postcopy-check`, puis
`just yubikey-escrow-postcopy-verify` en lecture seule.
Ce contrôle compare une nouvelle fois les octets chiffrés,
vérifie la visibilité côté TrueNAS et refuse de qualifier
les ACL NFSv4 ou la restauration de validées sans preuve.
Tests du nouvel outil sur workstation : **NOT_RUN**.

**Toujours NO-GO** : indépendance réelle des supports et
identités de récupération, ACL natives NFSv4, déchiffrement
age, restauration SOPS, génération PIV82 et rotation de
destinataires. KeePassXC/OTP2 demeure différé.

[Runbook](yubikey-software-recovery-20261026.md).

## Post-copie NFS / TrueNAS confirmé ; ACL natif prochain gate (27/10/2026)

**Preuve reçue depuis la workstation :**
`just yubikey-escrow-postcopy-test` **10/10 PASS** ;
`just yubikey-escrow-postcopy-check` a validé le mode
POSIX `0600` et la paire de fichiers. Le contrôle explicite
`just yubikey-escrow-postcopy-verify` a confirmé
`ciphertext_identical=true`, `server_visibility_verified=true`,
`server_state=SERVER_EXPECTED_COPY_REGULAR_NONEMPTY`
et `POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED`.
La duplication et la vérification binaire sont donc **DONE**.
**Ne pas relancer la création NFS.**

**Prochain jalon : audit des ACL natives côté TrueNAS**.
Le script `inspect-yubikey-escrow-truenas-acl.py` de la PR #289
interroge `filesystem.getacl` via un SSH autorisé, en lecture
seule, et retourne uniquement des compteurs/états anonymisés.
Il distingue ACL NFS4 / POSIX, relevé disponible / indisponible
et ACE candidates de lecture hors propriétaire. Le résultat
ne calcule pas les droits effectifs ; `nfs4_acl_verified=false`
reste toujours le défaut. `just yubikey-escrow-acl-test`,
`just yubikey-escrow-acl-check`, puis
`just yubikey-escrow-acl-probe` après validation des contrats.
**10 tests hermétiques ajoutés, NOT_RUN sur workstation**.

**NO-GO toujours** pour déchiffrement/restauration age/SOPS réelle,
preuve de moyen de récupération indépendant, modification PIV82,
PIV9A, OTP2 et destinataires SOPS. KeePassXC reste reporté.

[Runbook de récupération](yubikey-software-recovery-20261026.md).

## Audit ACL NFS4 natif — 10/10 PASS, restauration isolée prochaine étape (27/10/2026)

**Résultat workstation :**
`just yubikey-escrow-acl-test` **10/10 PASS** et
`just yubikey-escrow-acl-probe` :
`acltype=NFS4`, `trivial=true`, `ace_count=3`,
`potential_nonowner_read_allow_count=0`,
`ACL_NATIVE_REVIEW_REQUIRED`.
Il s'agit d'une preuve favorable **d'inventaire du fichier**,
pas de l'accès effectif : `nfs4_acl_verified=false`.
La politique ACL du répertoire et de ses parents reste
à revoir pour les identités NFS autorisées.

**État du chantier :**
copie chiffrée NFS créée sans remplacement, comparaison binaire
positive à deux reprises, présence serveur TrueNAS et mode
POSIX `0600` prouvés. **DONE pour duplication et readback**.

**Jalon suivant à haut levier :** préparer **un plan
de restauration réelle age/SOPS isolée**, sans aucune
transmission de secret. Confirmer d'abord en privé le
mécanisme réel de déchiffrement de l'archive age
(identité/destinataire ou mot de passe), puis prévoir
`umask 077`, espace local `0700`, jamais de
plaintext sur stdout/terminal/log/CI, aucune mutation
d'archive ou de fichier SOPS original.
Ne pas exécuter de déchiffrement réel sans approbation
distincte. Pour la procédure détaillée, voir
[yubikey-software-recovery-20261026.md](yubikey-software-recovery-20261026.md).

**NO-GO** toujours pour récupération réelle,
identités de récupération indépendantes,
PIV82/PIV9A/OTP2 et rotation des destinataires SOPS.
KeePassXC reporté. Pas de nouvelle copie NFS.

## Gate age / SOPS — logiciel présent, en-tête à classifier (27/10/2026)

**Nouvelle preuve workstation :**
`just yubikey-software-recovery-check` retourne
`SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED`,
`synthetic_software_roundtrip_verified=false`,
`real_escrow_restoration_verified=false`,
`status=NO-GO`.
Le mode de contrôle n'exécute aucun binaire age/SOPS
autre que sa recherche dans `PATH`. Le roundtrip synthétique
PASS plus ancien reste distinct de ce contrôle.

**Étape P1 de préparation :** déterminer la catégorie de
destinataire dans l'en-tête age, **sans déchiffrement**,
à l'aide de `just yubikey-escrow-age-header-{test,check,inspect}`
ajouté dans PR #289. Le mode `--inspect` exige un acquittement
et lit au maximum 8 Kio de l'archive locale, sans imprimer
les arguments ou identifiants des destinataires. Familles
de sortie : `PASSPHRASE_SCRYPT`, `X25519_IDENTITY`,
`SSH_IDENTITY`, `PLUGIN_OR_OTHER_IDENTITY` ou
`MIXED_OR_MULTIPLE_METHODS`. Cette classification
ne prouve pas que le MAC age est valide ou que le moyen
de déchiffrement correspondant est disponible.

**13/13 tests hermétiques PASS localement dans
l'environnement agent**, publication des blobs identiques
à la version testée, validation sur workstation encore
`NOT_RUN`. Après classification, préparer séparément
une restauration age/SOPS réelle avec secrets strictement
hors stdout/historique GitHub/CI et répertoire isolé `0700`.

**NO-GO** pour restauration effective, preuve de récupération
indépendante, PIV82/PIV9A/OTP2 et changement de destinataires
SOPS ; KeePassXC reste reporté. Ne plus relancer la copie
NFS déjà vérifiée.

[Procédure](yubikey-software-recovery-20261026.md).

## X25519 confirmé ; PRA USB historique réutilisable (27/10/2026)

**Validation workstation au 27/10** : test de l'en-tête age
**13/13 PASS**, `HEADER_INSPECTION_READY`,
puis `AGE_V1_HEADER_TYPE_HINT_ONLY` avec
`recipient_family_hint=X25519_IDENTITY` et
`stanza_count=1`. Aucune tentative de
déchiffrement n'a eu lieu avec ce nouveau diagnostic.

**Réconciliation nécessaire avec le PRA existant :**
[`sops-age-usb-disaster-recovery.md`](sops-age-usb-disaster-recovery.md)
consigne une **restauration age réussie le 17 octobre 2026** :
une archive chiffrée de l'identité SOPS a été déchiffrée
avec l'identité de récupération age X25519 stockée sur
USB SanDisk LUKS2, puis un test de fixture SOPS a réussi.
Il serait inexact de résumer **tout** le projet comme
n'ayant jamais eu de restauration réelle ; l'état
`NO-GO` porte désormais sur la **nouvelle copie NFS**
du 27/10 (non retestée en restauration) et sur
l'indépendance non prouvée de la **clé privée de
récupération USB**.

**Prochaine étape unique, sans déchiffrement :
`just yubikey-escrow-usb-status`.**
La commande réutilise `manage-age-escrow-usb.sh --check`
en lecture seule, n'ouvre aucun support chiffré,
ne génère aucun secret et retourne l'état verrouillé
ou monté de la SanDisk connue. Validation réelle sur
workstation : `NOT_RUN`.

Si USB déjà monté, préparer et autoriser séparément
la reprise des scripts existants
`verify-sops-age-escrow.sh` et
`test-sops-usb-recovery.sh` sur la nouvelle
copie chiffrée, après vérification des accès,
du stockage `/dev/shm` et de l'absence
de divulgation de clé dans les logs.
**Ne pas inventer un nouveau mécanisme de déchiffrement.**

**Reste NO-GO** : support de récupération
indépendant de la SanDisk, test de restauration de
la **nouvelle** copie NFS, preuve de l'accès effectif
aux dossiers NFS4, toute mutation PIV82/PIV9A/OTP2
ou rotation SOPS. KeePassXC reporté ; ne jamais
réexécuter `--copy`.

## USB de récupération — lien UUID LUKS absent, inventaire lsblk nécessaire (27/10/2026)

**Dernier résultat réel :** `just yubikey-escrow-usb-status`
sur workstation a donné `LUKS UUID device not found`
(ancien script basé uniquement sur le lien
`/dev/disk/by-uuid`, exit 1). **Ce n'est pas une preuve
de perte matérielle** du support SanDisk : la présence
dans `lsblk` et l'état `udev` n'avaient pas été
contrôlés séparément.

**Prochaine action unique, lecture seule :**
`just yubikey-escrow-usb-test` puis
`just yubikey-escrow-usb-status` après mise à jour
de la branche #289. La nouvelle recette réalise un
inventaire `lsblk` redacted pour distinguer
partition LUKS non énumérée, UUID visible sans
lien udev, volume verrouillé, mapper ouvert ou
volume monté. Aucun `sudo`, déverrouillage,
clé privée, PIV ou montage. Le script historique
reste disponible dans
`just yubikey-escrow-usb-legacy-check`.

**13 tests hermétiques écrits, exécution workstation
`NOT_RUN`** ; aucune CI payante déclenchée.
La restauration depuis la nouvelle copie NFS reste
suspendue jusqu'à identification de l'identité USB.
Ne jamais régénérer une identité X25519 incompatible
avec l'ancien destinataire et ne pas reformater le
seul support de récupération connu.

**Maintenir :** duplication ciphertext et contrôle
TrueNAS déjà `DONE`, PRA USB historique du 17/10
conservé comme preuve, restauration depuis la copie
du 27/10 `NO-GO`, indépendance de l'identité USB
non prouvée, PIV82/PIV9A/OTP2 et changements
SOPS non autorisés. KeePassXC reporté.

[Procédure](yubikey-software-recovery-20261026.md).

## Validation USB : 12/13 PASS, faux positif test corrigé, UUID non énuméré (27/10/2026)

**Preuve workstation** : première exécution de
`just yubikey-escrow-usb-test` **12/13 PASS**.
L'unique échec provenait de la chaîne générique
`private` contenue dans le **nom du champ**
`private_age_identity_read=false` du JSON.
**Aucune clé privée n'a été exposée.** Le test a été
corrigé dans PR #289 et renforcé par une fixture
de chemins de montage sensibles. **Revalidation
workstation le 27/10 : 14/14 PASS** ; le test
des chemins de montage privés est positif.

**État du support réel** :
`ESCROW_UUID_NOT_ENUMERATED`,
`luks_uuid_link_present=false`. L'UUID attendu
n'est pas visible dans la vue `lsblk` actuelle,
sans preuve que la SanDisk soit perdue.
**Bloquant avant une restauration** : vérifier
la connexion physique et le support détecté,
sans déverrouillage ni génération d'identité.

**Action suivante** : vérifier localement
la connexion physique de la SanDisk et sa
détection par le noyau Linux, sans exposer
les détails du périphérique. Après éventuelle
reconnexion, relancer **uniquement**
`just yubikey-escrow-usb-status` en lecture seule.
Le résultat réel reste
`ESCROW_UUID_NOT_ENUMERATED` avec
`luks_uuid_link_present=false` (sortie 3 attendue).
Maintenir `NO-GO` pour la restauration de la
copie NFS du 27/10, les mutations PIV/SOPS
et toute duplication supplémentaire de l'archive.


## SanDisk USB reconnectée — contrôle de métadonnées à suivre

Le 27 octobre, l'opérateur a reconnecté physiquement le support de
récupération d'origine. Le diagnostic lecture seule confirme
`ESCROW_LUKS_UNLOCKED_MOUNTED` et la présence du lien UUID attendu.
Rappeler systématiquement de **brancher le support USB physique**
avant de rechercher son UUID.

Prochain gate de la PR #289 :
`just yubikey-escrow-usb-identity-test`, puis
`just yubikey-escrow-usb-identity-check`.
Ces commandes vérifient les métadonnées du support et
de l'identité de récupération sans lire la clé ni déchiffrer
l'archive. Treize tests nouveaux sont à valider sur workstation.

Les copies chiffrées restent vérifiées. La restauration depuis
la nouvelle copie NFS, les modifications matérielles et toute
rotation des destinataires restent suspendues.


## Destinataire X25519 historique attesté sur USB (27/10/2026)

**Preuve workstation :** `USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL`,
`public_recipient_matches_historical=true` ;
la clé privée a été lue localement par `age-keygen -y`
mais n'a été ni publiée ni utilisée pour déchiffrer.
Aucune mutation du support, de SOPS ou des YubiKeys.

**DONE** : détection et montage SanDisk, métadonnées
de l'identité age, correspondance du destinataire
public X25519 historique.

**P0 restant** : tester avec autorisation distincte
la restauration réelle de l'identité SOPS à partir
de la **nouvelle copie NFS** (et non l'ancien
fichier du dossier `keepass`), sous `/dev/shm`
privé, puis la fixture SOPS synthétique.
Réutiliser les scripts du PRA existant ; vérifier
leurs sorties d'erreur et le nettoyage des
fichiers temporaires avant exécution.
**P1 restant** : sauvegarde indépendante de la
clé privée USB et revue effective ACL NFS.
PIV82, OTP2, PIV9A, rotations SOPS, KeePassXC
et copie NFS supplémentaire demeurent suspendus.

[Preuve et procédure](yubikey-software-recovery-20261026.md).


## Restauration de l'identité SOPS depuis la nouvelle copie NFS : DONE (27/10/2026)

**Nouvelle preuve workstation, réussite effective** :
le script historique `verify-sops-age-escrow.sh`
a déchiffré l'unique archive age créée à la
racine du partage NFS. L'identité X25519
provenait de la SanDisk originale
**physiquement branchée et déjà montée**.
La sortie confirme :
`PASS: TrueNAS encrypted backup decrypted with USB key and recovered original SOPS public recipient.`
L'identité SOPS retrouvée correspond au
destinataire public historique. Ce jalon de
restauration **est DONE**, pas un simple contrôle
de métadonnées. Il ne prouve pas une récupération
avec perte du support USB.

**Étape P0 — DONE le 27/10/2026** :
`test-sops-usb-recovery.sh` a été exécuté
sur **la même nouvelle archive NFS** et
la SanDisk d'origine déjà branchée/montée.
Résultat opérateur : `PASS: SOPS recovery
with USB-backed escrow`. Le script a récupéré
l'identité SOPS puis réussi un chiffrement et
un déchiffrement **SOPS synthétiques**.
Ce PASS ne valide pas un document SOPS de
production ni une récupération sans SanDisk.

**Étapes différées** : attester une copie
réellement indépendante de l'identité privée
de récupération USB, revoir l'accès effectif
des dossiers NFS4, et maintenir les gels
PIV82/PIV9A/OTP2, rotation des destinataires
SOPS et KeePassXC. Ne pas relancer `--copy`.

[Procédure et preuve](yubikey-software-recovery-20261026.md).


## Bilan de clôture — récupération age/SOPS validée (27/10/2026)

- **DONE :** duplication NFS chiffrée, comparaison binaire, présence TrueNAS et inventaire NFS4 du fichier.
- **DONE :** SanDisk physique reconnectée, LUKS2/ext4 monté, métadonnées de l'identité X25519 et correspondance du destinataire historique.
- **DONE :** déchiffrement réel de la nouvelle copie NFS dans le tmpfs privé ; identité SOPS historique restaurée et destinataire public confirmé.
- **DONE :** `PASS: SOPS recovery with USB-backed escrow` avec une fixture synthétique chiffrée et déchiffrée depuis l'identité restaurée.
- **P0 ouvert :** protéger le principal point de défaillance, l'unique identité privée de récupération sur SanDisk, par un plan de copie **indépendante** et une preuve de récupération séparément autorisées. Aucune copie de clé privée n'a été exécutée ici.
- **P1 ouvert :** attester les ACL NFS4 **effectives** du fichier et de ses répertoires parents, pas seulement les ACE de fichier.

**Différé :** restauration d'un document SOPS de production, provisioning PIV82/PIV9A/OTP2, rotation de destinataires SOPS, KeePassXC et toute nouvelle copie NFS. Ne pas relancer `--copy`.

[Runbook détaillé](yubikey-software-recovery-20261026.md).


## Sauvegardes chiffrées de la clé age USB : implémentation livrée, exécution en attente

**Autorisation opérateur accordée :** protéger l'identité
de récupération X25519 d'origine avec `age -p`
(phrase secrète externe), puis conserver le même
ciphertext sur **workstation et TrueNAS**.
Ne jamais copier la clé privée en clair sur ces supports.

**Livré dans #289 [skip ci]** :
`backup-usb-age-identity.py`,
`test_usb_age_identity_independent_backup.py`
et les recettes
`just yubikey-usb-identity-backup-test`,
`just yubikey-usb-identity-backup-check`
et `just yubikey-usb-identity-backup`.

Le contrôle de montage vérifie le NFS attendu.
Le script refuse les fichiers préexistants,
les symlinks, les répertoires non privés,
les deux copies sur le même système de fichiers
et les lancements non interactifs. La source
USB reste inchangée, les fichiers publiés sont
chiffrés et vérifiés identiques, sans écrasement.

**État réel : BACKUP_NOT_EXECUTED sur workstation.**
Le test hermétique a été validé dans un
environnement local isolé ; l'exécution sur
le montage TrueNAS réel est à effectuer par
l'opérateur avec la SanDisk **physiquement
branchée, déverrouillée et montée**.

**Done intermédiaire :** copies chiffrées sur
workstation et TrueNAS byte-identiques,
passphrase indépendante conservée hors de
la SanDisk. **Done PRA final :** déchiffrement
d'une copie en RAM dans un scénario de perte
de la SanDisk, destinataire public X25519
retrouvé et restauration testée ; non validé
par la seule égalité de fichiers.

**Reste ouvert :** preuve ACL NFS4 effective,
snapshots/rétention et un emplacement offsite.
Ne pas modifier PIV82/OTP2, les destinataires
SOPS ni la précédente archive `--copy`.

[Procédure](yubikey-software-recovery-20261026.md).
