# YubiKey — reprise récupération logicielle age/SOPS (26 octobre 2026)

**Périmètre** : `nabla-compose`, suite de la PR #280 fusionnée.
**KeePassXC / OTP2** : **DIFFÉRÉ à la demande de l'opérateur** ;
secondaire `11110002` avec `PROGRAMMED_TYPE_UNVERIFIED` (slot 2 programmé),
aucun challenge HMAC, aucune base KDBX ouverte, aucune modification OTP.
Il ne s'agit ni d'un test `PASS`, ni d'un test `FAIL`.

## État des cinq chantiers

| Voie | Preuve acquise | Reste |
| --- | --- | --- |
| PIV82/age | F9 public contrôlé, AES256 PIN-protected connu, slot 82 vide au dernier inventaire | Deux restaurations d'escrow et certificat âge/P-256 interopérable, attestation de la clé, véritable roundtrip matériel, aucune génération avant |
| OpenPGP/GPG | `gpg --card-status` a répondu publiquement sur la secondaire après échec intermittent | Correspondance des sous-clés, signature/déchiffrement fonctionnels, stabilité du transport |
| SSH/FIDO2 | Clé de secours ED25519-SK créée, fingerprint et `ssh-keygen -Y sign/verify` **PASS** ; 14/14 contrats sur workstation | Login SSH distant, inscription passkeys par service |
| KeePassXC/OTP2 | Slot 2 **programmé** sur secondaire | **DIFFÉRÉ** : test de déverrouillage de la même copie KDBX avec les deux cartes |
| SOPS/age/escrow | Outils logiciels age et sops présents au dernier inventaire workstation | Roundtrip logiciel synthétique, deux vrais escrows récupérables indépendamment et restauration GPG/PostgreSQL isolée |

**Aucun état PASS synthétique n'est une preuve de récupération réelle.**
Conserver les destinataires SOPS actuels, PIV9A historique, OTP2 et les clés
GPG ; aucune modification matérielle automatique.

## Test logiciel synthétique — aucun secret personnel

Nouveau script `verify-yubikey-software-age-sops-fixture.py` :
- `--check` n'exécute aucun outil ni accès au matériel : vérifie seulement
  que `age`, `age-keygen` et `sops` existent.
- `--run` crée un répertoire temporaire 0700, une **nouvelle clé age
  éphémère**, et une fixture JSON **publique synthétique** ;
  chiffrement/déchiffrement age, puis chiffrement/déchiffrement SOPS
  avec **uniquement** cette clé temporaire.
- Le sous-processus reçoit un environnement isolé avec `HOME`,
  `XDG_CONFIG_HOME`, `GNUPGHOME` et `SOPS_AGE_KEY_FILE` temporaires.
  Les variables de secrets du shell, les identités réelles,
  `.sops.yaml` du dépôt et les profils cloud ne sont pas propagés.
- Les erreurs brutes, clés et contenus ne sont pas imprimés. Le
  répertoire et l'identité synthétiques sont détruits à la sortie.
  En cas d'erreur, la classification retourne un **état borné**,
  sans tentative automatique ni fallback vers une vraie identité.

### Procédure workstation

```bash
cd ~/w/nabla-compose
git fetch origin
git switch feat/yubikey-software-recovery-20261026
git pull --ff-only
git rev-parse HEAD

just yubikey-software-recovery-test
just yubikey-software-recovery-check

# Seulement si les binaires sont présents et si l'opérateur autorise
# un test cryptographique logiciel utilisant une clé jetable :
just yubikey-software-recovery-run
```

La sortie attendue pour le test logiciel effectif est
`AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS`, avec
`synthetic_software_roundtrip_verified=true`, mais **toujours**
`status=NO-GO`, `real_escrow_restoration_verified=false` et
`piv82_decrypt_verified=false`.

Le script possède **9 tests hermétiques PASS** en environnement agent
sur copies correspondant bit-à-bit aux blobs Git publiés.

**Preuve opérateur workstation reçue** : `just yubikey-software-recovery-test`
**9/9 PASS**. Le contrôle `-check` a renvoyé
`SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED`.
L'exécution réelle `just yubikey-software-recovery-run` a ensuite
renvoyé **`AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS`** et
`synthetic_software_roundtrip_verified=true` avec les vrais
binaires du poste. Aucun secret utilisateur ni YubiKey n'a été utilisé.
**Deux véritables archives d'escrow : toujours NOT_VERIFIED.**

## Deux escrows age réels — contrôle de métadonnées uniquement

Une alternative interactive évite de placer les chemins privés dans
l'historique du shell ou la ligne de commande d'un processus :

```bash
just yubikey-escrow-pair-test
just yubikey-escrow-pair-check
# Recherche automatique locale de deux fichiers *.age de même nom :
just yubikey-escrow-pair-discover
# Pour utiliser la paire détectée après confirmation (ou saisie masquée
# manuelle si la découverte ne trouve pas exactement une paire) :
just yubikey-escrow-pair-inspect
```

Le script recherche désormais les fichiers `.age` non récursivement dans
les deux répertoires connus de la workstation :

- `~/.local/share/nabla/age-backups/` (origine locale)
- `/media/backup/lab/secret/` (copie du support monté)

`--discover` vérifie uniquement les noms et métadonnées accessibles, puis
retourne un état sans publier le nom des fichiers ni leurs chemins.
Il sélectionne automatiquement **une seule** paire de noms identiques.
Deux paires possibles donnent `DISCOVERY_MULTIPLE_MATCHING_PAIRS` :
aucun choix arbitraire n'est effectué. Les répertoires et fichiers
symboliques sont rejetés, et le nombre d'entrées parcourues est limité.

`--inspect` exige un terminal interactif. Quand une paire est reconnue,
il propose son inspection avec une confirmation `[o/N]`, sans montrer le
chemin des fichiers. Si l'opérateur refuse ou si la découverte échoue,
il demande les deux chemins absolus en **saisie masquée** comme auparavant.
Les sorties JSON ne contiennent jamais ces chemins. L'outil délègue à
`inspect-yubikey-recovery-readonly.py`, qui vérifie uniquement
les métadonnées (type de fichier, taille non nulle, inode,
filesystem, liens symboliques) ; il n'ouvre et ne déchiffre pas les
archives. L'état
`TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED` n'atteste **pas**
l'indépendance physique des supports ni leur récupérabilité.
Les tests de cette nouvelle recette doivent être validés sur workstation.

Avec les **deux vrais chemins absolus** choisis localement par l'opérateur,
le script déjà présent permet un inventaire de fichiers sans ouvrir
ni déchiffrer les sauvegardes :

```bash
python3 scripts/workstation/inspect-yubikey-recovery-readonly.py \
  --escrow-a '/SUPPORT_A/backup.age' \
  --escrow-b '/SUPPORT_B/backup.age'
```

Seule la sortie `TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED` indique
deux fichiers distincts sur deux systèmes de fichiers distincts ;
**ce n'est pas une preuve de deux supports physiques ni de leur
restauration**. Si les fichiers n'existent pas, ou si les chemins sont
des liens symboliques, conserver `UNKNOWN` et ne pas créer de faux
fichiers pour réussir le contrôle. Ne pas mettre ces chemins en clair
dans un ticket public ou une PR.

**Preuves opérateur du 26/10/2026** : le premier essai avait fourni
deux fois le même chemin : `SAME_FILE`, refus normal. L'opérateur a
ensuite copié une archive `.age` de l'origine locale vers le support
monté avec `cp` et utilisé un chemin dans chaque répertoire. Deux
exécutions ont produit `TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED`.
La copie du support apparaît comme fichier de 389 octets,
`-rw-------+` : le signe `+` indique une ACL à examiner séparément.
Ces observations **ne prouvent pas** que les contenus sont identiques,
que le support est physiquement indépendant ou que la clé de
déchiffrement est récupérable. Il s'agit de deux copies d'une même
archive chiffrée, non de deux identités de récupération distinctes.

Pour vérifier ensuite uniquement l'identité binaire des deux copies,
l'opérateur peut utiliser `cmp -s --` localement, avec les chemins
réels, sans afficher le contenu. Ce test **lit** les deux fichiers
(à la différence de l'inventaire stat-only) mais n'écrit rien.
Une égalité binaire ne valide toujours pas le déchiffrement.

Après un contrôle de métadonnées réussi, le prochain jalon est
une récupération supervisée de chacune des deux archives sur un espace
isolé, dans le respect des accès et des supports originaux. Aucune
restauration réelle ni aucun changement de destinataire SOPS n'est
initié par ce chantier.

## Préconditions avant toute écriture PIV82

1. Vérifier deux moyens de récupération logiciels réellement
   fonctionnels **et indépendants du token secondaire**.
2. Vérifier un déchiffrement d'archive GPG existante et une
   restauration PostgreSQL isolée, sans changer les originaux.
3. Refaire l'inventaire public PIV82/9A/AES256 avec **une seule carte**
   pour confirmer que 82 est toujours vide et 9A inchangé.
4. Suivre les sept phases de `plan-age-yubikey-piv82-transaction.py`
   en séance supervisée, avec autorisation par opération et
   pas de nouvelle tentative PIN automatique.
5. Tester un roundtrip age **réel sur PIV82**, puis l'autre YubiKey
   séparément, avant toute modification des destinataires SOPS.

Références : [SOPS age](https://getsops.io/docs/usage/identities/age/),
[age-keygen](https://manpages.debian.org/testing/age/age-keygen.1.en.html),
[plan YubiKey](yubikey-capabilities-completion-plan.md),
[runbook de 5 chantiers](yubikey-backup-five-execution.md).

## Contrôle supplémentaire — identité binaire des deux escrows chiffrés

**Preuve workstation acquise au HEAD `41e2b099` (26/10/2026)** :
`just yubikey-escrow-pair-test` **17/17 PASS**,
`just yubikey-escrow-pair-discover` et
`just yubikey-escrow-pair-inspect` avec confirmation `o`
ont tous deux renvoyé
`TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED`.
L'inventaire ne lit jamais le contenu des archives : ce résultat
ne prouve donc pas leur identité binaire.

Pour comparer leurs **octets chiffrés uniquement**, exécuter une commande
**distincte** : elle lit les fichiers, contrairement à l'inventaire
précédent. Elle exige une autorisation explicite. Aucune clé age,
carte YubiKey ni passphrase n'est utilisée.

```bash
just yubikey-escrow-compare-test
just yubikey-escrow-compare-check
# Après validation des tests et de la présence des deux fichiers :
just yubikey-escrow-compare-run
```

Le programme `compare-yubikey-escrow-pair-readonly.py` réutilise la
découverte d'**une seule paire** de noms identiques dans les deux
répertoires connus. Il vérifie l'appartenance des fichiers à
l'utilisateur, les tailles non nulles (maximum 16 Mio), le type
regular, les liens multiples et les identifiants de fichiers. Il ouvre
les deux fichiers avec `O_NOFOLLOW`, puis compare les octets par
blocs de 64 Kio en mémoire. Il détecte un changement de
métadonnées pendant la lecture, refuse les fichiers sur un même
filesystem et nettoie les descripteurs ouverts.

Le résultat JSON ne contient jamais de chemin, de hash, de contenu,
de clé ou de secret. Les états principaux sont :

| État | Interprétation |
| --- | --- |
| `ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED` | Les deux fichiers chiffrés ont été lus et les octets comparés sont identiques, sans changement détecté pendant la lecture |
| `ENCRYPTED_COPIES_DIFFER` | Contenu ou taille différents : ne pas utiliser la copie comme preuve de redondance identique |
| `ENCRYPTED_COPY_CHANGED_DURING_READ` | Source ou copie modifiée pendant le contrôle : arrêt, pas de conclusion |
| `ENCRYPTED_COPY_UNVERIFIED` | Permissions, type, métadonnées ou accès non conformes |
| `DISCOVERY_MULTIPLE_MATCHING_PAIRS` | Plusieurs noms correspondants : il faut traiter l'ambiguïté avant de lire |
| `COPIES_NOT_ON_DISTINCT_FILESYSTEMS` | Le test exige deux systèmes de fichiers différents |

Même si les octets sont identiques, les deux fichiers représentent
**la même archive chiffrée recopiée**, et non deux clés de récupération
distinctes. Ce test ne démontre ni le déchiffrement de l'identité
`age`, ni un stockage sur deux supports physiques indépendants,
ni la récupération réelle d'un secret SOPS, ni l'autorisation de créer
une clé PIV82.

Le nouveau comparateur et **11 tests hermétiques ont été exécutés en
local par l'agent** sur des fichiers synthétiques. L'exécution
sur les deux vraies archives de workstation n'est **pas encore faite**.
Les tests existants du collecteur ont été validés par l'opérateur
(**17/17 PASS**).

**Suite** : vérifier localement l'ACL du fichier de destination
(`getfacl` ; ne pas publier les chemins si confidentiels), puis
préparer une restauration isolée de la sauvegarde à partir de la copie
sur support, avec ses moyens de déchiffrement réels et une preuve
expurgée, avant toute transaction PIV82.

## Investigation d'une découverte intermittente — 26/10/2026

**Preuve opérateur :** `just yubikey-escrow-compare-test` **11/11 PASS**
et `just yubikey-escrow-compare-check` =
`ENCRYPTED_CONTENT_NOT_READ`. Cependant
`just yubikey-escrow-compare-run` a renvoyé
`DISCOVERY_NO_MATCHING_PAIR`, avec
`encrypted_content_read_attempted=false`. Aucune archive n'a été lue
par cette dernière commande.

Les deux outils (inventaire et comparateur) réutilisent la **même**
fonction `discover_pair(Path.home())`, qui exige **un unique nom
de fichier .age commun** entre les répertoires source et backup.
Les relevés antérieurs avaient réussi ; la cause du désaccord actuel
n'est pas démontrée. Possibilités à vérifier : répertoire `HOME`
différent, montage de backup indisponible, copie déplacée ou renommée,
absence momentanée de fichier, ou changement de son type.
Le code ne doit pas assimiler l'absence de paire à un échec de
déchiffrement.

### Diagnostic sans divulguer de chemin

```bash
just yubikey-escrow-pair-test
just yubikey-escrow-compare-test
just yubikey-escrow-pair-diagnose
just yubikey-escrow-pair-discover
```

La nouvelle recette `yubikey-escrow-pair-diagnose` n'ouvre aucun
fichier chiffré. Elle renvoie un nombre borné de fichiers `.age`
et l'état d'accès à chaque répertoire connu (`ACCESSIBLE`,
`DIRECTORY_MISSING`, `PERMISSION_DENIED`, `DIRECTORY_UNAVAILABLE`,
`TOO_MANY_ENTRIES`, `SYMLINK_DIRECTORY_UNTRUSTED`), ainsi que
`matching_age_filenames` et
`home_location_consistent_with_account`.
Aucun nom, chemin, octet chiffré ou contenu de clé n'est affiché.
Une valeur `matching_age_filenames=0` explique le refus
`DISCOVERY_NO_MATCHING_PAIR` à l'instant du contrôle, sans en prouver
la cause historique.

Pour vérifier la disponibilité du support monté sans modifier les
données, un opérateur peut aussi exécuter localement :
```bash
findmnt -T /media/backup/lab/secret -o TARGET,FSTYPE
```

### Comparaison manuelle en lecture seule

Si la découverte automatique échoue **mais que les deux archives
existent**, utiliser **une commande distincte**, avec une session
terminale interactive et l'autorisation explicite :

```bash
just yubikey-escrow-compare-manual
```

Les deux chemins absolus sont demandés en **saisie masquée**
(sans argument en ligne de commande ni historique shell).
Le programme vérifie d'abord avec l'inspecteur existant que les
deux fichiers sont réguliers, non symboliques, distincts et
sur des systèmes de fichiers différents, puis applique le même
contrôle d'octets chiffrés avec `O_NOFOLLOW`, owner/métadonnées
et limites de taille. **Il lit les données chiffrées**, mais
ne déchiffre rien, ne modifie aucun fichier et ne publie
ni chemin ni empreinte.

Un `ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED` prouvera
seulement l'égalité des deux copies au moment de la lecture.
Un `NO-GO` de comparaison doit conduire au diagnostic,
pas à une copie `cp` supplémentaire ni à une rotation de clé.
Deux copies identiques de la même archive ne constituent toujours
pas deux identités indépendantes de récupération.
Le test KeePassXC/OTP2 reste reporté, et la génération PIV82
reste bloquée.

## Diagnostic confirmé — destination accessible sans fichier .age (26/10/2026)

**Logs opérateur :** les deux suites récentes sont vertes :
`just yubikey-escrow-pair-test` **22/22 PASS**,
`just yubikey-escrow-compare-test` **18/18 PASS**.
Le dernier contrôle `just yubikey-escrow-pair-diagnose` a retourné :

- `source_directory.state=ACCESSIBLE`, `age_files=1`.
- `backup_directory.state=ACCESSIBLE`, `age_files=0`.
- `matching_age_filenames=0`.
- `home_location_consistent_with_account=true`.
- `files_opened=false` et `restoration_verified=false`.

`just yubikey-escrow-pair-discover` a renvoyé
`DISCOVERY_NO_MATCHING_PAIR`. La tentative
`just yubikey-escrow-compare-manual` a renvoyé `UNKNOWN`
avant d'ouvrir le contenu chiffré
(`encrypted_content_read_attempted=false`).
**Aucune preuve que les deux archives aient été comparées ou restaurées.**

Le répertoire `/media/backup/lab/secret` est donc **accessible**,
mais aucune entrée régulière se terminant par `.age` n'a été
recensée au moment du test. Cela peut correspondre à un fichier
absent, renommé, à un lien symbolique ignoré ou à une cible de
montage devenue inaccessible à son contenu habituel.
Le diagnostic ne prouve pas à lui seul un démontage du disque.

### Prochaine vérification — aucun changement de fichiers

```bash
# Vérifier le filesystem effectif associé au chemin sauvegarde :
findmnt -T /media/backup/lab/secret -o TARGET,FSTYPE

# Diagnostiquer les entrées attendues SANS lire le contenu age :
just yubikey-escrow-pair-diagnose
```

Attention : `findmnt -T` peut identifier simplement le filesystem
parent (par exemple `/`) même si le disque de sauvegarde n'est plus
monté. Comparer la valeur de `TARGET` au point de montage attendu.

Le champ `diagnostic.expected_backup_copy_state` classe désormais,
en lecture de métadonnées uniquement, le fichier de même nom que
l'unique archive `.age` locale :

| Valeur | Interprétation |
| --- | --- |
| `EXPECTED_COPY_MISSING` | Aucun fichier de ce nom au chemin de sauvegarde |
| `EXPECTED_COPY_IS_SYMLINK` | Entrée présente, mais lien symbolique refusé |
| `EXPECTED_COPY_EMPTY` | Entrée régulière vide ; copie non valide |
| `EXPECTED_COPY_NOT_REGULAR` | Objet autre qu'un fichier régulier |
| `EXPECTED_COPY_REGULAR_NONEMPTY` | Entrée régulière non vide présente ; **pas** une preuve d'intégrité |
| `EXPECTED_COPY_ACCESS_DENIED` | Métadonnées inaccessibles |
| `NO_UNIQUE_SOURCE_FILE` | Plusieurs fichiers locaux possibles ; ne pas choisir arbitrairement |
| `NOT_EVALUATED` | Un des répertoires n'a pas passé l'inventaire |

Le champ ne présente ni nom ni chemin, ne calcule aucun hash
et n'ouvre aucun contenu. Les tests du nouveau champ sont publiés
dans la PR ; leur exécution complète sur workstation est `NOT_RUN`.

**Ne pas répéter `cp` avant d'avoir vérifié le montage attendu.**
Écrire dans le répertoire sous-jacent d'un disque non monté risquerait
de donner l'impression d'une sauvegarde externe alors que les données
sont restées sur le disque local.

Une fois le support et l'archive attendus retrouvés, relancer
l'inventaire, puis seulement la comparaison chiffrée. Cela ne vaut
toujours pas restauration indépendante. Pas de modification des
destinataires SOPS, d'OTP2, de PIV9A ni de génération PIV82.
KeePassXC reste reporté.

## NFSv4 confirmé ; archive attendue manquante — suite (26/10/2026)

**Preuve opérateur sur checkout PR #285** : `just yubikey-escrow-pair-test`
**26/26 PASS**, `just yubikey-escrow-pair-diagnose` :
`source_directory.age_files=1`,
`backup_directory.state=ACCESSIBLE`,
`backup_directory.age_files=0`,
`expected_backup_copy_state=EXPECTED_COPY_MISSING`,
`matching_age_filenames=0`. La commande
`findmnt -T /media/backup/lab/secret -o TARGET,FSTYPE` a retourné
**`/media/backup/lab nfs4`**.

Ceci confirme que **le chemin de sauvegarde est actuellement situé
sous un montage NFSv4 actif**. Il ne s'agit pas d'une simple écriture
sous `/` causée par un montage absent. Le diagnostic ne prouve pas
que l'export NFS actuel soit le même qu'au moment où le fichier
`.age` de 389 octets avait été observé, ni la présence du fichier
sur le serveur à un autre emplacement.

**Ajout PR** : `backup_mount_state` dans la commande
`just yubikey-escrow-pair-diagnose`, via `findmnt` sans exposer
`SOURCE`, options, adresse du serveur ou chemin de l'export. État
attendu : `EXPECTED_NFS4_MOUNT_PRESENT`.
4 tests hermétiques supplémentaires vérifient le format de la
réponse, le refus d'un point de montage parent et l'absence de
succès trompeur si `findmnt` est indisponible. Les tests doivent
être validés sur la workstation après récupération de la PR.

### Investigation locale de l'export (sans écriture)

```bash
# Afficher ces informations uniquement localement : ne pas coller
# la source/export, les ACL complètes ou la liste des secrets en PR.
findmnt -T /media/backup/lab/secret -o TARGET,FSTYPE,SOURCE,OPTIONS

# Vérifier la visibilité du répertoire, sans lecture d'archive chiffrée :
stat -c 'directory_type=%F mode=%a uid=%u gid=%g' /media/backup/lab/secret

# Relever les métadonnées et ACL du répertoire :
getfacl -cp /media/backup/lab/secret

# Comparer localement l'export indiqué par findmnt à l'export
# attendu côté serveur NFS (aucun remount automatique).
```

Si la source de montage est inattendue, corriger **l'identification
de l'export** d'abord ; ne pas recopier la sauvegarde vers un export
qui pourrait être incorrect. Si la source est la bonne, rechercher
sur le serveur NFS une suppression, un déplacement, un snapshot
antérieur ou un changement de dataset/ACL. Ne pas recréer
automatiquement l'archive avant d'avoir confirmé son sort.

**Critère de reprise** : le montage correct est identifié, l'archive
régulière `.age` attendue redevient visible, puis la comparaison
réelle des deux fichiers chiffrés renvoie
`ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED`. Même cette preuve
n'autorise pas de mutation PIV82 ou de secrets SOPS : le déchiffrement
et la restauration restent des étapes séparées. KeePassXC/OTP2
reste reporté.

## Preuve NFS client et comparaison avec le serveur TrueNAS — 26/10/2026

**Preuve workstation au HEAD `1be4d5b2`** : la suite
`just yubikey-escrow-pair-test` a réussi **30/30 tests**.
Le diagnostic renvoie simultanément :
`backup_mount_state=EXPECTED_NFS4_MOUNT_PRESENT`,
`expected_backup_copy_state=EXPECTED_COPY_MISSING`,
`source_directory.age_files=1`,
`backup_directory.age_files=0`,
`matching_age_filenames=0`.
La commande `findmnt` sur la workstation identifie
`/media/backup/lab` comme point de montage `nfs4`
de `nabla:/mnt/cpool/backup/lab`, avec NFS version 4.2.
Cette preuve correspond à **un export NFS actif**, mais ne démontre
pas que la cible serveur correspond au dataset attendu ni qu'un
fichier a été effectivement supprimé : la visibilité côté serveur
n'a pas encore été interrogée.

### Nouvelle sonde à preuve séparée côté TrueNAS

Un contrôle non destructif a été ajouté sous
`scripts/workstation/inspect-yubikey-escrow-nfs-server.py`.
Il exige le montage `/media/backup/lab`, l'export
`nabla:/mnt/cpool/backup/lab` et un **unique nom `.age`**
dans l'emplacement local. Le nom attendu est transmis uniquement dans
le programme Python envoyé sur **stdin SSH**, jamais en argument ou
dans la sortie JSON. L'archive chiffrée n'est ni ouverte, ni copiée,
ni déchiffrée.

```bash
# Mode passif : identifie l'export et la source locale. Aucun SSH.
just yubikey-escrow-nfs-test
just yubikey-escrow-nfs-check

# Session volontaire : métadonnées uniquement côté TrueNAS.
# Utilise un hôte SSH connu, BatchMode=yes, pas de prompt mot de passe.
just yubikey-escrow-nfs-probe
```

Le probe exécute un Python fixe en lecture seule sur TrueNAS
(`/mnt/cpool/backup/lab/secret`) via
`albandrieu@172.17.0.24`. Il inspecte le répertoire, le nombre
borné d'archives `.age` et les métadonnées du **nom attendu**.
Il interdit les liens symboliques, n'ouvre aucun contenu et n'effectue
aucune modification NFS/TrueNAS. Aucune authentification SSH
interactive ni nouvelle clé d'hôte n'est acceptée automatiquement.
En cas de refus SSH, d'hôte inconnu ou d'absence de Python, il
renvoie un état borné de non-vérification, sans tentative en boucle.

| `server_state` | Suite |
| --- | --- |
| `SERVER_EXPECTED_COPY_MISSING` | Confirmer la disparition/rotation/migration/snapshot côté serveur ; ne pas recopier automatiquement |
| `SERVER_EXPECTED_COPY_REGULAR_NONEMPTY` | Fichier visible côté serveur mais pas côté NFS : analyser permissions UID/GID, export, cache et ACL |
| `SERVER_DIRECTORY_MISSING` | Investiguer dataset ou répertoire côté serveur |
| `SERVER_DIRECTORY_ACCESS_DENIED` | Vérifier les ACL côté TrueNAS avec accès autorisé |
| `SERVER_EXPECTED_COPY_SYMLINK` | Ne pas suivre ni utiliser le lien pour la preuve |
| `SSH_READONLY_PROBE_UNAVAILABLE` | Vérifier SSH/known_hosts/compte, sans redémarrage ni réessai automatique |

Les sorties conservent **`status=NO-GO`**,
`archive_opened=false`, `remote_write_performed=false`,
`restoration_verified=false` et `decryption_attempted=false`.
**12 tests hermétiques PASS en environnement agent**, dont un
qui exécute réellement le Python distant sur un répertoire
synthétique pour vérifier les réponses `MISSING` et `REGULAR_NONEMPTY`, mais le
probe SSH réel et la suite sur la workstation restent
**NOT_RUN** au moment de la création.
Ne pas traiter une réponse `SERVER_EXPECTED_COPY_MISSING` comme
une preuve de suppression définitive : d'autres datasets, snapshots
ou exports peuvent contenir la copie historique.

La vérification des copies et de leur déchiffrement est un jalon
distinct, prérequis avant toute écriture PIV82. KeePassXC/OTP2
reste différé à la demande de l'opérateur.

## Absence côté NFS et serveur — inspection bornée des snapshots ZFS

**Preuve opérateur confirmée (26/10/2026)**, HEAD workstation
`72bf9956` : `just yubikey-escrow-nfs-test` **12/12 PASS** ;
`just yubikey-escrow-nfs-check` :
`mount_state=EXPECTED_NFS_EXPORT_MOUNTED`,
`source_state=SOURCE_UNIQUE_AGE_FOUND`.
Le probe SSH autorisé a renvoyé
`server_state=SERVER_EXPECTED_COPY_MISSING`,
`server_age_files=0`, `archive_opened=false`,
`remote_write_performed=false`.

La copie attendue n'est donc pas visible dans
`/mnt/cpool/backup/lab/secret` sur le serveur au moment du probe.
Cette réponse n'exclut pas un autre dataset ou un snapshot historique.
Aucune preuve de suppression définitive, aucune restauration.

### Recherche limitée aux emplacements ZFS connus

Nouveau programme :
`scripts/workstation/inspect-yubikey-escrow-nfs-history.py`.
Il vérifie d'abord le montage NFS et **l'unique nom `.age`** de
l'origine locale. En mode opt-in, il passe un script Python via
l'entrée standard de SSH vers TrueNAS. Le script vérifie exclusivement
les métadonnées du même nom dans ces chemins de snapshots :

- snapshots du dataset `/mnt/cpool/backup/lab`,
  sous-répertoire `secret` ;
- snapshots du parent `/mnt/cpool/backup`,
  sous-répertoire `lab/secret` ;
- snapshots du pool `/mnt/cpool`,
  sous-répertoire `backup/lab/secret`.

Il ne descend pas dans d'autres datasets, ne recherche pas
récursivement toutes les archives et n'inspecte **au maximum
que 32 entrées par racine de snapshots**. Il refuse les chemins de
snapshot symboliques. Il n'ouvre aucune archive, n'exécute pas
`zfs rollback`, `zfs list`, `zfs send`, `cp` ou `sudo`.
Il ne modifie ni le serveur ni les YubiKeys.

```bash
cd ~/w/nabla-compose
git fetch origin fix/code-password-dotenv-fixture-20261026
# Dans le worktree de PR #285 déjà sélectionné :
git merge --ff-only origin/fix/code-password-dotenv-fixture-20261026

just yubikey-escrow-history-test
just yubikey-escrow-history-check

# Si le check confirme le montage et l'unique source locale :
just yubikey-escrow-history-probe
```

Les seuls résultats retournés concernent le nombre de snapshots
examinés, le nombre de copies candidates et la disponibilité des
trois racines : **aucun nom de snapshot, nom d'archive, chemin
individuel, clé age ou sortie SSH brute n'est révélé**.

| `state` | Interprétation |
| --- | --- |
| `SNAPSHOT_CANDIDATE_FOUND` | Au moins un fichier régulier non vide portant le nom attendu a été repéré dans les snapshots examinés, **sans preuve d'intégrité ni de déchiffrement** |
| `NO_CANDIDATE_IN_CHECKED_SNAPSHOTS` | Aucun candidat dans les chemins examinés ; **ne prouve pas** l'absence de copies ailleurs |
| `SNAPSHOT_HISTORY_INCOMPLETE` | Analyse partielle (permissions, limite de 32 entrées, erreur de parcours) ; ne pas conclure à l'absence |
| `SNAPSHOT_HISTORY_UNAVAILABLE` | Aucun dossier de snapshot connu accessible ; examiner le dataset et la visibilité `.zfs` |
| `SSH_HISTORY_UNAVAILABLE` | SSH ou sortie distante non validés ; aucun résultat historique fiable |

Même `SNAPSHOT_CANDIDATE_FOUND` maintient
`status=NO-GO`, `archive_opened=false`,
`restore_verified=false` et
`hardware_mutation_authorized=false`.
Un résultat positif conduira à un plan de récupération supervisée
**dans une nouvelle destination protégée**, sans rollback ZFS.
Ne pas publier les secrets ni tenter de restauration automatique.

**Qualité :** **10/10 tests hermétiques PASS en environnement agent**,
y compris simulation des snapshots présents/absents et refus des
liens symboliques. Exécution sur workstation et interrogation des
snapshots réels encore `NOT_RUN`.

**Maintien des contraintes** : ne pas reprogrammer OTP2/KeePassXC
(reporté), ne pas modifier PIV9A, PIV82, les destinataires SOPS ou
les bases existantes. Le logiciel age/SOPS synthétique a déjà
fait son roundtrip ; les vrais escrows restent non restaurés.

## Pagination de l'historique ZFS après 96 snapshots (27/10/2026)

**Preuve fournie par l'opérateur :**

- `just yubikey-escrow-history-test` : **10/10 PASS** sur la
  version d'origine (sans pagination).
- `just yubikey-escrow-history-check` :
  `EXPECTED_NFS_EXPORT_MOUNTED`,
  `SOURCE_UNIQUE_AGE_FOUND`, `state=NOT_PROBED`.
- `just yubikey-escrow-history-probe` :
  `roots_accessible=3`, `roots_missing=0`,
  `snapshots_checked=96`, `candidate_copies=0`,
  `state=SNAPSHOT_HISTORY_INCOMPLETE`.
  Les trois racines ont atteint la limite initiale de 32 entrées ;
  **ce résultat ne démontre pas l'absence de l'archive ailleurs ou
  au-delà de cette première fenêtre**.

### Pagination bornée implémentée dans PR #285

- Une page examine au maximum **32 répertoires de snapshots par racine**,
  soit 96 au total pour les trois racines autorisées.
- Le programme inventorie au plus **1 024 entrées par racine**. Les
  résultats sont classés selon **l'ordre lexicographique inverse des
  noms de snapshots**, *pas* forcément selon la date de création.
- Le champ `page` vaut 0 à 31.
  `next_page` indique la page suivante lorsqu'elle existe ;
  `more_pages` indique que certaines racines possèdent plus
  de noms au-delà de cette page.
- Si une racine contient plus de 1 024 entrées,
  `inventory_truncated=true` et le résultat reste incomplet,
  **même sur la page 31**. Une recherche ciblée supplémentaire,
  fondée sur l'inventaire ZFS autorisé, sera alors nécessaire.
- Les inventaires sont effectués séparément à chaque exécution.
  Un ajout/suppression de snapshots entre deux pages peut modifier
  leur ordre et faire manquer ou répéter une entrée. Ne jamais
  interpréter une succession de pages comme un snapshot atomique.
- Les sorties restent limitées à des comptes et des états bornés,
  sans nom de snapshot, fichier, chemin privé, hash ni secret.

```bash
# Dans le worktree propre à la PR #285 :
git fetch origin fix/code-password-dotenv-fixture-20261026
git merge --ff-only origin/fix/code-password-dotenv-fixture-20261026

just yubikey-escrow-history-test
just yubikey-escrow-history-check

# Refaire la première page avec le nouveau format.
just yubikey-escrow-history-probe

# Seulement si next_page=1 :
just yubikey-escrow-history-page 1

# Suivre next_page, sans lancer de boucle illimitée.
# Par exemple, seulement si next_page=2 :
just yubikey-escrow-history-page 2
```

**Validation du correctif** : **14/14 tests hermétiques PASS
dans l'environnement agent**, dont un scénario où un fichier
n'apparaît que dans la page 1, la validation d'une réponse SSH paginée
malformée et le refus de considérer un inventaire tronqué comme
une recherche complète. Les versions publiées sont identiques
octet par octet aux versions testées. Le probe réel paginé sur
la workstation est **NOT_RUN**.

`SNAPSHOT_CANDIDATE_FOUND` signale une présence de métadonnées
pour le nom attendu dans une page. Ce résultat **ne démontre ni
l'intégrité du fichier ni sa récupérabilité**. La génération PIV82,
les modifications de destinataires SOPS et les opérations de
récupération restent bloquées. KeePassXC/OTP2 demeure reporté.

## Fin de la recherche paginée — préparation contrôlée d'une copie NFS (27/10/2026)

**Preuves opérateur (HEAD workstation `5f2537af`) :**

- `just yubikey-escrow-history-test` : **14/14 PASS**.
- Page `0` : 96 snapshots examinés, aucune archive candidate,
  `next_page=1`, `inventory_truncated=false`.
- Page `1` : 24 snapshots examinés, aucune archive candidate,
  `next_page=null`, `more_pages=false`,
  `inventory_truncated=false`,
  `state=NO_CANDIDATE_IN_CHECKED_SNAPSHOTS`.
- Au total, **120 entrées inspectées**, réparties entre les trois
  racines connues, sans candidat. La pagination n'est **pas un
  instantané atomique** de l'historique : les snapshots pourraient
  avoir changé entre les deux commandes. D'autres datasets ou
  supports ne sont pas couverts.

Les contrôles antérieurs ont également établi que l'archive attendue
est absente du répertoire NFS actuellement exporté, **côté client et
côté serveur TrueNAS**. Une sauvegarde age chiffrée reste présente sur
la workstation. **Cela ne signifie pas qu'une restauration réelle
est possible** ; le contenu de cette archive locale n'a pas été
déchiffré dans le cadre de cette investigation.

### Préparer une nouvelle copie chiffrée, sans écraser de fichier

Le nouveau programme
`scripts/workstation/create-yubikey-escrow-nfs-copy.py`
sépare explicitement deux opérations :

```bash
# Exécutable maintenant, aucun fichier ouvert en lecture de contenu :
just yubikey-escrow-copy-test
just yubikey-escrow-copy-check
```

La vérification `--check` exige :

- le montage exact NFS attendu `nabla:/mnt/cpool/backup/lab` ;
- **un unique fichier `.age` source** dans
  `~/.local/share/nabla/age-backups` ;
- un fichier source régulier, unique, appartenant à l'utilisateur,
  avec permissions non accessibles au groupe/autres et taille de
  1 octet à 16 Mio ;
- une destination `/media/backup/lab/secret` qui existe et ne
  contient **pas encore** le nom de fichier attendu ;
- aucun lien symbolique dans les composants des chemins.

**État de précontrôle attendu** :
`READY_TO_CREATE_ENCRYPTED_COPY`.
Si la destination existe (même sous forme de lien), le contrôle
retourne `TARGET_ALREADY_EXISTS_NO_OVERWRITE`.

Après validation du précontrôle et inspection du partage NFS,
la commande d'écriture **facultative, supervisée et distincte**
est la suivante. **Ne l'exécuter qu'avec autorisation explicite
de créer une nouvelle copie** :

```bash
python3 scripts/workstation/create-yubikey-escrow-nfs-copy.py \
  --copy --acknowledge CREATE_NEW_ENCRYPTED_AGE_ESCROW_NFS_COPY
```

Cette commande exige un terminal interactif. Elle ouvre le fichier
`.age` **chiffré**, copie ses octets vers un nom temporaire sur le
partage NFS avec le mode `0600`, synchronise le contenu, puis publie
un nouveau nom final **par lien matériel atomique refusant tout
écrasement**. Elle supprime le lien temporaire, effectue un
`fsync` de répertoire si disponible, puis rouvre la source et la
copie pour les comparer intégralement. Un échec de vérification après
publication **ne supprime jamais automatiquement la destination**.
Ne pas relancer l'opération en boucle après un résultat partiel.

Résultat fort attendu :
`ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED`.
Il prouve la création et l'égalité binaire de la copie avec la
source lors de ce contrôle ; il ne prouve pas la pérennité NFS,
l'indépendance physique du support, l'absence d'ACL inattendue,
le déchiffrement age ni la restauration d'un secret SOPS.
Un échec de `fsync` du répertoire donne
`PUBLISHED_COPY_DIRECTORY_SYNC_UNVERIFIED`, même si
la comparaison des octets a réussi.
L'outil n'imprime aucun chemin, contenu, hash ou clé privée.

**Qualité** : **9/9 tests locaux synthétiques PASS** pour l'outil,
dont contrôle du montage, refus d'écraser des fichiers et liens
symboliques, publication atomique, vérification et nettoyage du
fichier de transit. Les sources GitHub correspondent exactement
aux versions testées. **Le vrai précontrôle et l'écriture NFS sur
workstation sont encore NOT_RUN**.

### Après la copie

1. Vérifier les ACL du répertoire et du nouveau fichier avec
   `getfacl` localement, sans publier de contenu sensible.
2. Vérifier que la copie reste visible côté TrueNAS et depuis NFS.
3. Tester séparément sa récupération avec la méthode age disponible
   dans un espace isolé.
4. Vérifier deux moyens d'accès ou de récupération indépendants
   avant tout provisionnement PIV82.

**Statut inchangé : `NO-GO` global**, KeePassXC/OTP2 reporté,
OpenPGP privé non prouvé, restauration réelle age/SOPS non effectuée.

## Transfert de suivi dans PR #289 — précontrôle NFS validé (27/10/2026)

La PR **#285 a été fusionnée dans `master`**. Les scripts YubiKey
font donc déjà partie de la branche de base. À la demande de
l'opérateur, les améliorations suivantes sont poursuivies dans la
PR de suivi **#289** sans déplacer, supprimer ni réécrire ses
modifications existantes concernant pfSense, HAProxy et Nexus.

**Preuve opérateur sur workstation :**
`git fetch origin fix/code-password-dotenv-fixture-20261026`,
`git merge --ff-only`, puis :

- `just yubikey-escrow-copy-test` : **9/9 PASS** ;
- `just yubikey-escrow-copy-check` :
  `state=READY_TO_CREATE_ENCRYPTED_COPY`,
  `new_copy_verified=false`, `restore_verified=false`,
  `independent_age_identity_verified=false`,
  `source_decryption_performed=false`,
  `existing_destination_overwritten=false`, `status=NO-GO`.

Ces résultats sont des preuves de **préparation**, pas de copie.
**Aucune écriture NFS ni restauration age/SOPS réelle** n'a été
effectuée par cette exécution.

### Durcissement du fichier NFS temporaire

Le programme `create-yubikey-escrow-nfs-copy.py` exige désormais,
**avant toute écriture des octets chiffrés**, `os.fchmod(stage_fd, 0o600)`
et une vérification via `os.fstat`. Une deuxième vérification est
effectuée **après l'écriture, avant de publier le nom final** :

- fichier temporaire régulier appartenant à l'utilisateur ;
- mode POSIX strictement `0600` à chaque étape ;
- un seul lien matériel et une taille initialement nulle ;
- taille finale égale à celle de la source ;
- si ce contrôle échoue, aucune destination finale n'est publiée.

Trois tests supplémentaires couvrent l'échec de `fchmod`,
les permissions temporaires non conformes et l'ordre des opérations
(`chmod` avant le premier `write`).
La suite étendue compte **12 tests**, mais son exécution sur
workstation est encore `NOT_RUN` pour ces changements.

**Limite :** NFSv4 peut comporter des ACL additionnelles ;
un mode POSIX `0600` ne prouve pas à lui seul l'absence de droits
définis par une ACL. Contrôler localement les ACL côté client
et TrueNAS après publication ; ne pas publier leurs détails sensibles.

### Validation à effectuer avant toute copie

Dans un worktree propre de **PR #289**, sans toucher au checkout
actif qui contient peut-être d'autres modifications :

```bash
git fetch origin fix/nexus-wan-haproxy-acl-evidence-20261027
git merge --ff-only origin/fix/nexus-wan-haproxy-acl-evidence-20261027

just yubikey-escrow-copy-test
just yubikey-escrow-copy-check
```

Si `READY_TO_CREATE_ENCRYPTED_COPY` est confirmé, la commande
`--copy` **reste facultative et distincte**, documentée plus haut.
Ne l'exécuter qu'après décision explicite de créer la copie
chiffrée sur l'export NFS attendu. **Ne jamais relancer à
l'aveugle après un résultat partiel** : l'archive peut déjà
exister sous son nom final, et l'outil doit alors refuser
tout écrasement.

Le jalon suivant sera la validation d'égalité binaire, de
visibilité côté TrueNAS et des ACL, puis une restauration age/SOPS
isolée et prouvée. Les autres restrictions sont maintenues :
aucune écriture PIV82, PIV9A, OTP2 ou modification de destinataires
SOPS ; le test KeePassXC reste reporté.

## Preuve de validation workstation #289 — gate de copie chiffrée (27/10/2026)

**Preuve opérateur au worktree détaché HEAD `124b23ef`** :
`just yubikey-escrow-copy-test` a réussi **12/12 tests**,
y compris les trois contrats ajoutés dans #289
(`fchmod` en erreur, refus du mode temporaire non conforme,
`fchmod` avant la première écriture). Le
`just yubikey-escrow-copy-check` a renvoyé
`state=READY_TO_CREATE_ENCRYPTED_COPY`,
`new_copy_verified=false`, `restore_verified=false`,
`independent_age_identity_verified=false`,
`existing_destination_overwritten=false` et `status=NO-GO`.

**Clôture :** les gates de préparation, de non-écrasement et de
permission POSIX sont validés sur la workstation. Ce statut
**ne confirme pas** qu'une seconde copie chiffrée existe ;
le script a seulement examiné les métadonnées et aucun contenu
`.age` n'a encore été copié ou déchiffré dans ce jalon.

**Étape opérateur distincte, uniquement après décision d'écrire
sur le partage NFS attendu** (dans le worktree #289) :

```bash
python3 scripts/workstation/create-yubikey-escrow-nfs-copy.py \
  --copy --acknowledge CREATE_NEW_ENCRYPTED_AGE_ESCROW_NFS_COPY
```

État attendu en cas de réussite complète :
`ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED`.
En cas d'échec ou d'état partiel, **ne pas répéter la création** :
inspecter d'abord la destination et les éventuels fichiers de transit,
sans jamais effacer une copie publiée susceptible d'être utile.

Après copie, valider le fichier côté NFS et TrueNAS,
les ACL POSIX/NFSv4, puis le déchiffrement et la restauration
`age/SOPS` dans un emplacement isolé. L'indépendance de
récupération reste à prouver. PIV82, modifications SOPS,
PIV9A et OTP2 restent non autorisés ; KeePassXC demeure reporté.

## Création effective de la copie age sur NFS et contrôle post-copie (#289)

**Preuve d'exécution réelle fournie par l'opérateur le 27/10/2026 :**
le programme `create-yubikey-escrow-nfs-copy.py --copy` avec
l'acquittement explicite a retourné :

- `state=ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED`
- `new_copy_verified=true`
- `existing_destination_overwritten=false`
- `source_decryption_performed=false`
- `independent_age_identity_verified=false`
- `restore_verified=false`
- `status=NO-GO`

**Conclusion :** une nouvelle copie NFS des *octets chiffrés* a été
publiée sans écraser l'ancien fichier et vérifiée identique à la
source au moment de l'opération. Cette preuve n'atteste pas
l'indépendance physique du support, les ACL NFSv4, la possibilité
de déchiffrer le fichier ni la récupération d'un secret SOPS.
**Ne pas lancer une deuxième fois `--copy`** : le nom final est
désormais censé exister.

### Contrôle post-copie, exclusivement en lecture seule

Ajout dans PR #289 :
`scripts/workstation/verify-yubikey-escrow-nfs-postcopy.py`.

```bash
# Dans le worktree de la PR #289 mis à jour :
just yubikey-escrow-postcopy-test
just yubikey-escrow-postcopy-check
```

Le `--check` confirme **uniquement les métadonnées** :
montage NFS attendu, paire `.age` non ambiguë, fichiers réguliers
et uniques (un lien matériel chacun), propriétaire local et mode
POSIX strictement `0600`. Il n'ouvre pas les octets du fichier,
ne contacte pas TrueNAS et ne modifie rien.
État attendu : `PAIR_METADATA_READY_ACL_UNVERIFIED`.

Si ce précontrôle passe, l'exécution suivante est une
**vérification indépendante et explicite en lecture seule** :

```bash
just yubikey-escrow-postcopy-verify
```

La commande compare les octets chiffrés à nouveau, puis interroge
par SSH la présence d'un fichier régulier non vide **du même nom**
dans le répertoire TrueNAS correspondant. La connexion impose
l'authentification non interactive et une clé SSH hôte connue.
La sortie ne contient ni nom privé, ni chemin, ni contenu
chiffré ni empreinte.

**État positif attendu** :
`POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED`.
Il confirme la concordance des copies et leur visibilité via les
deux accès. **Il ne valide pas les ACL NFSv4 ni la restauration**.
Si le test échoue, ne pas supprimer ni recréer l'archive : examiner
le résultat, l'export et les permissions.

### ACL et récupération réelle — jalons séparés

- Contrôler les ACL du fichier et du répertoire côté TrueNAS via
  l'outil local approprié au dataset (ACL NFSv4/native ZFS) ;
  `getfacl` du client POSIX ne suffit pas nécessairement.
  Ne publier ni ACE privées ni chemins complets.
- Vérifier que le support de sauvegarde dispose d'un mécanisme
  indépendant de récupération et de rétention.
- Préparer ensuite **une restauration supervisée age/SOPS dans un
  emplacement privé et isolé**, en gardant la clé age et tout
  contenu déchiffré hors des journaux, arguments de commande et PR.
- Ne pas modifier PIV82, PIV9A, OTP2 ni les destinataires SOPS.
  KeePassXC reste reporté.

**Validation logiciel en cours :** les tests du nouvel outil
post-copie ont été ajoutés dans #289. Ils doivent encore être
exécutés sur la workstation ; ne pas les compter comme PASS
avant de recevoir leurs résultats. Aucune action de restauration
ni de changement de secret n'a été effectuée par cet outil.

## Validation post-copie indépendante — résultat workstation et gate ACL TrueNAS (27/10/2026)

**Nouvelles preuves workstation sur PR #289 :**
`just yubikey-escrow-postcopy-test` **10/10 PASS** ;
`just yubikey-escrow-postcopy-check` :
`PAIR_METADATA_READY_ACL_UNVERIFIED`,
`posix_0600_verified=true`, sans lire de contenu.
Le `just yubikey-escrow-postcopy-verify`, avec acquittement
explicite, a renvoyé :

- `state=POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED`
- `ciphertext_identical=true` ;
- `server_state=SERVER_EXPECTED_COPY_REGULAR_NONEMPTY`,
  `server_visibility_verified=true` ;
- `posix_0600_verified=true` ;
- `nfs4_acl_verified=false`, `restore_verified=false`,
  `independent_recovery_verified=false`, `status=NO-GO`.

**Jalon DONE :** le fichier chiffré a été copié vers NFS,
la relecture binaire sur deux systèmes de fichiers a réussi et
TrueNAS voit le fichier correspondant. Aucun troisième fichier
ni nouvelle identité age n'a été créé. **Ne pas relancer `--copy`.**

### Nouveau gate ACL natif TrueNAS : audit sans exposition des ACE

La méthode de lecture seule
`filesystem.getacl` de TrueNAS retourne le type d'ACL (`NFS4`,
`POSIX1E` ou `DISABLED`), le caractère trivial et les ACE.
Le script `scripts/workstation/inspect-yubikey-escrow-truenas-acl.py`
appelle `midclt call filesystem.getacl` **directement sur TrueNAS**
via le SSH préalablement configuré, sans `sudo`.
Il ne publie **aucune ACE brute**, identité d'utilisateur ou groupe,
nom d'archive, chemin, permission détaillée ou sortie d'erreur.

Source : [documentation de l'API TrueNAS 25.10, `filesystem.getacl`](https://api.truenas.com/v25.10/api_methods_filesystem.getacl.html).

```bash
# Tests synthétiques ; aucune connexion TrueNAS :
just yubikey-escrow-acl-test

# Précontrôle montage/source locale, sans ouvrir les archives ni SSH :
just yubikey-escrow-acl-check

# Inventaire ACL natif côté serveur via SSH, en lecture seule :
just yubikey-escrow-acl-probe
```

Le résultat se limite à `acltype`, `trivial`, `ace_count`
et `potential_nonowner_read_allow_count`, avec états bornés :

| État | Signification et suite |
| --- | --- |
| `ACL_NATIVE_REVIEW_REQUIRED` | ACL NFS4 lisible ; aucune règle non-propriétaire avec lecture de données repérée par ce filtre simple ; **pas une preuve d'absence d'accès indirect** |
| `ACL_POTENTIAL_NONOWNER_DATA_ALLOW` | Au moins une ACE `ALLOW` non-propriétaire candidate donne potentiellement lecture ; demander une revue ACL avec ordre, DENY et héritage |
| `ACL_TYPE_NOT_NFS4` | ACL non NFS4 ; analyser le type effectivement configuré sur le dataset |
| `ACL_READ_UNAVAILABLE` / `SSH_ACL_UNAVAILABLE` | Méthode/permissions/SSH non accessibles, aucune conclusion ACL |
| `ACL_RESPONSE_UNVERIFIED` | Structure renvoyée inattendue, refus de conclure |

Le compteur d'ACE candidates **n'est pas un calcul d'accès effectif**.
Il ne résout pas les DENY, l'héritage complet, les ACL de répertoire,
les comptes ou les droits du serveur NFS.
Même si la collecte réussit, l'outil retourne toujours
`nfs4_acl_verified=false`, `restore_verified=false`,
`status=NO-GO`. La conformité ACL doit être évaluée
manuellement à partir de la politique du dataset et des identités
autorisées ; les détails ne doivent pas être copiés dans la PR.

**Qualité :** dix tests hermétiques ajoutés, dont des exemples
synthétiques d'ACL NFS4 avec `owner@` et `everyone@`.
Ces nouveaux contrats et la sonde réelle sur workstation sont
encore **NOT_RUN**. Aucune mutation TrueNAS, chmod distant,
écriture NFS, lecture du contenu age ou opération YubiKey
n'est prévue.

### Prochaine clôture

1. Vérifier les ACL réelles du fichier et du répertoire, puis
   confirmer les identités NFS autorisées.
2. Préparer une restauration age/SOPS avec une procédure
   supervisée et un espace isolé, sans afficher la clé privée.
3. Démontrer un accès de récupération indépendant avant PIV82.

Aucune écriture PIV82/PIV9A/OTP2, ni changement de destinataire
SOPS. KeePassXC reste reporté.

## Preuve ACL NFS4 triviale et préparation de récupération isolée (27/10/2026)

**Preuve réelle fournie par la workstation au commit de PR
`7300e891`** :

- `just yubikey-escrow-acl-test` : compilation OK,
  **10/10 tests PASS**.
- `just yubikey-escrow-acl-check` :
  `EXPECTED_NFS_EXPORT_MOUNTED`,
  `SOURCE_UNIQUE_AGE_FOUND`, `state=NOT_PROBED`.
- `just yubikey-escrow-acl-probe` :
  `acltype=NFS4`, `trivial=true`,
  `ace_count=3`,
  `potential_nonowner_read_allow_count=0`,
  `state=ACL_NATIVE_REVIEW_REQUIRED`,
  `nfs4_acl_verified=false`, `status=NO-GO`.

**Conclusion permise :** TrueNAS a fourni une ACL native NFS4
`trivial` comportant trois ACE. Le filtre du script n'a
trouvé aucune ACE `ALLOW` explicite accordant la lecture
de données hors propriétaire. Ce relevé est **favorable**, mais
ne prouve pas à lui seul la politique d'accès effective :
l'ordre et les `DENY`, les ACL des répertoires parents,
l'identité des comptes/NFS et les autorisations indirectes
restent à apprécier. Ne pas modifier l'ACL automatiquement et
ne pas interpréter `trivial=true` comme une certification.

### Préparer la preuve de récupération réelle age/SOPS

Les deux copies du **même ciphertext** ont été comparées
et vues côté TrueNAS. Le prochain jalon est la récupération
**supervisée et isolée** d'une identité de déchiffrement utilisable,
puis le contrôle d'un objet SOPS représentatif mais autorisé.
Il ne faut pas essayer de deviner la méthode de chiffrement de
l'archive `.age` : présence d'une identité, d'un mot de passe
ou d'un destinataire spécifique **non vérifiée** à ce stade.

**Gate de préparation, sans lire ni déchiffrer de secret :**

1. Confirmer localement `just yubikey-software-recovery-check`
   et `just yubikey-escrow-postcopy-check` ; ne pas réexécuter
   `--copy`.
2. Confirmer les ACL natives du **répertoire `secret` et de
   ses parents** sur TrueNAS et les identités autorisées,
   sans copier les ACE ou UID/GID dans GitHub.
3. Choisir en privé la méthode et les justificatifs réels de
   déchiffrement de l'archive `.age`. Ne transmettre **ni clé,
   ni mot de passe, ni contenu déchiffré** à l'agent ou à la PR.
4. Prévoir un répertoire de travail local temporaire, privé
   (`umask 077`, mode `0700`), sur un support non exporté,
   avec sortie de déchiffrement redirigée **vers un fichier
   protégé, jamais stdout, logs, arguments de processus,
   shell tracing ou historique**.
5. Définir un contrôle de restauration qui n'expose que des
   booléens bornés (identité age utilisable, fichier SOPS
   autorisé récupérable) ; inspecter et détruire proprement
   les copies temporaires sous supervision après validation.

**Aucune opération de récupération réelle n'a été exécutée
dans ce suivi.** La restauration doit être autorisée séparément,
avec le mécanisme age exact et les protections de ses sorties
confirmés ; l'ancien roundtrip de clés SOPS jetables n'atteste pas
la restauration du secret utilisateur. Deux copies d'un même
ciphertext n'équivalent pas à deux identités de récupération
indépendantes.

**NO-GO maintenu** pour validation de restauration réelle,
provisionnement PIV82, modification des destinataires SOPS,
PIV9A, OTP2 ; KeePassXC demeure reporté.

## Preflight de restauration réelle — outils présents et inspection age limitée (27/10/2026)

**Dernière preuve opérateur sur workstation :**

```
just yubikey-software-recovery-check
state=SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED
synthetic_software_roundtrip_verified=false
real_escrow_restoration_verified=false
piv82_decrypt_verified=false
status=NO-GO
```

Cela **prouve seulement** que `age`, `age-keygen` et
`sops` sont disponibles à l'emplacement attendu par le
script. Cette invocation n'a exécuté ni roundtrip logiciel
synthétique ni déchiffrement de l'archive réelle.
Un précédent roundtrip synthétique PASS reste une preuve distincte
et historique, **pas** une restauration du secret utilisateur.

### Classifier sans déchiffrer les stanzas age

La spécification `age-encryption.org/v1` dispose d'un en-tête
texte avec stanzas de destinataires avant le contenu chiffré.
Le nouveau `scripts/workstation/inspect-yubikey-escrow-age-header.py`
examine uniquement ce type d'en-tête. Il ne doit pas être
interprété comme validant son MAC, l'identité effective ou
la récupération du contenu.
Source : https://c2sp.org/age@main

```bash
# Dans un worktree à jour de PR #289 :
just yubikey-escrow-age-header-test
just yubikey-escrow-age-header-check

# Lecture optionnelle de 8 Kio maximum de ciphertext, aucun déchiffrement :
just yubikey-escrow-age-header-inspect
```

Le contrôle `--check` inspecte **uniquement les métadonnées**
de l'archive locale et du montage NFS connu. Le mode
`--inspect` exige l'acquittement
`INSPECT_EXISTING_ENCRYPTED_AGE_HEADER_ONLY`, puis réutilise
`secure_open` (propriétaire local, fichier régulier 0600
ou plus restrictif, absence de lien symbolique, métadonnées stables).
Il lit au plus **8 192 octets** depuis l'archive locale,
sans copie, écriture ou déchiffrement.

Les sorties ne contiennent **aucun identifiant de destinataire,
sel scrypt, argument de stanza, nom de fichier, chemin,
contenu d'en-tête brut ou donnée chiffrée**.
Elles peuvent inclure ces seuls états/familles :

| `recipient_family_hint` | Interprétation limitée |
| --- | --- |
| `PASSPHRASE_SCRYPT` | En-tête suggérant une archive chiffrée avec une phrase secrète |
| `X25519_IDENTITY` | En-tête suggérant une identité age X25519 |
| `SSH_IDENTITY` | En-tête suggérant un destinataire SSH |
| `PLUGIN_OR_OTHER_IDENTITY` | Stanza spécialisée ou inconnue : ne pas supposer qu'une YubiKey est nécessaire |
| `MIXED_OR_MULTIPLE_METHODS` | Plusieurs catégories de destinataires : déterminer les exigences hors logs |
| `null` | En-tête non identifié, incomplet ou armuré non analysé |

**État attendu pour un fichier v1 binaire reconnu** :
`AGE_V1_HEADER_TYPE_HINT_ONLY`. Un fichier armuré est
signalé `ARMORED_AGE_UNINSPECTED`, sans décodage.
`status=NO-GO`, `recovery_method_verified=false` et
`real_escrow_restoration_verified=false` restent toujours
maintenus : le contrôle d'en-tête n'effectue **aucune authentification
cryptographique** du MAC ni aucune récupération.

**Qualité : 13/13 tests synthétiques PASS en environnement agent**,
dont scrypt, X25519, SSH/multiple, plugin inconnu, en-tête
incomplet/armuré, présence d'un seul fichier, permissions,
acquittement, lecture bornée et absence de données privées en
sortie. Les deux blobs GitHub correspondent aux fichiers
testés localement. Exécution sur archive réelle workstation :
**NOT_RUN** à la publication.

**Étape suivante :** selon l'indication de famille, identifier
**en privé** l'identité, le plugin ou la passphrase réellement
disponible. La prochaine preuve de restauration doit disposer
d'une autorisation spécifique, d'un support temporaire local
`0700`/`umask 077`, d'une sortie déchiffrée dans un
fichier protégé, et d'un nettoyage sous supervision.
Ne jamais publier de plaintext, de clé age ou de passphrase.
Ne pas modifier les originaux, les destinataires SOPS,
les slots YubiKey ou l'escrow NFS existant.

## Preuve X25519 du 27 octobre et reprise du PRA USB du 17 octobre

**Résultat opérateur du 27/10/2026 dans #289** :

- `just yubikey-escrow-age-header-test` : **13/13 PASS**.
- `just yubikey-escrow-age-header-check` :
  `HEADER_INSPECTION_READY`, aucun octet lu.
- `just yubikey-escrow-age-header-inspect` :
  `AGE_V1_HEADER_TYPE_HINT_ONLY`,
  `recipient_family_hint=X25519_IDENTITY`,
  `stanza_count=1`,
  `archive_decryption_attempted=false`,
  `real_escrow_restoration_verified=false`, `status=NO-GO`.

**Découverte de preuve historique à conserver :** le runbook
[`sops-age-usb-disaster-recovery.md`](sops-age-usb-disaster-recovery.md)
documente, au **17/10/2026**, le déchiffrement réussi de
l'archive `sops-age-identity-20261017T183615Z.age` depuis
l'ancien emplacement TrueNAS `secret/keepass/`, avec l'identité
age X25519 de récupération **indépendante de l'identité SOPS**,
conservée sur une SanDisk LUKS2. Un second script a utilisé
l'identité SOPS ainsi récupérée pour réussir un roundtrip
**SOPS synthétique isolé** (`PASS: SOPS recovery with
USB-backed escrow`). Ce sont de vraies preuves de récupération
de l'identité age SOPS **à cette date** ; ce n'est pas un
déchiffrement d'un document SOPS de production.

La **copie NFS du 27/10** a été créée et relue dans
`/media/backup/lab/secret/` (sans le sous-dossier
`keepass` du PRA historique). Le contenu chiffré concorde
avec la source locale et la présence TrueNAS est confirmée,
mais **aucune restauration n'a encore été rejouée depuis
cette nouvelle copie**. Une stanza `X25519` ne permet
pas d'affirmer à elle seule qu'elle correspond à la même
identité USB ; ne pas afficher l'identifiant de la stanza.

### P0 — vérifier l'état du support USB, sans déchiffrement

```bash
# Depuis le worktree PR #289 actualisé, lecture seule :
just yubikey-escrow-usb-status
```

Cette recette réutilise **le script préexistant**
`manage-age-escrow-usb.sh --check` avec l'UUID de
partition LUKS déjà documenté. Elle identifie le support
et indique `Locked`, `Unlocked but not mounted`
ou `Unlocked and mounted`. Aucun `cryptsetup open`,
formatage, montage, création de clé, YubiKey ni
déchiffrement n'est exécuté. Ne pas publier le
`lsblk` détaillé si des identifiants privés figurent
dans la sortie ; communiquer seulement l'état du support.

Si la clé USB n'est pas présente, **ne pas déduire que
la récupération est impossible** : signaler `USB_ABSENT`
et reporter le test réel. Si elle est déjà déverrouillée et
montée, vérifier localement sa clé de récupération
`age-escrow/recovery-identity.txt` en mode `0600`,
sans l'ouvrir dans un éditeur ou imprimer sa valeur.
La présence d'un fichier ne prouve pas sa compatibilité
avec cette archive.

### P1 — rejouer le PRA historique sur la copie actuelle (autorisation séparée)

**Il existe déjà deux scripts :**

1. `scripts/workstation/verify-sops-age-escrow.sh` :
   déchiffre une archive age à l'aide de l'identité USB
   dans un répertoire `/dev/shm` privé et compare le
   destinataire public de l'identité SOPS récupérée au
   destinataire SOPS attendu. Ce script réalise un
   **véritable déchiffrement de l'archive**.
2. `scripts/workstation/test-sops-usb-recovery.sh` :
   restaure à nouveau l'identité SOPS dans `/dev/shm`,
   chiffre puis déchiffre **une fixture SOPS synthétique**
   avec cette identité, sans écraser la configuration
   réelle.

Avant utilisation, contrôler avec l'opérateur le bon
fichier de backup (nouvel emplacement à la racine
`secret/`, pas l'ancien `secret/keepass/`),
le bon montage USB et l'état du `tmpfs`. N'exécuter
ces scripts **qu'après autorisation explicite d'un
déchiffrement réel**, en vérifiant leurs protections de
journalisation et leur nettoyage. Ne jamais insérer
de clé ou mot de passe dans Git, la conversation,
les arguments de processus ou les logs.

**Critère DONE de ce nouveau jalon** : le même test
d'identité X25519 USB / archive NFS créée le 27/10
réussit et la fixture SOPS se déchiffre dans
l'environnement isolé. Même alors, il reste à vérifier
une seconde copie **de l'identité de récupération USB**
et les ACL NFS4 effectives des répertoires. Deux
copies du même ciphertext ne remplacent pas la
sauvegarde de la clé privée de récupération.

**Maintien NO-GO** : aucune écriture PIV82, PIV9A,
OTP2, aucune rotation des destinataires SOPS, aucun
`luksFormat` ni `init-identity`. KeePassXC
demeure reporté. **Ne pas relancer `--copy`.**

## Support SanDisk non résolu par /dev/disk/by-uuid — preuve workstation du 27/10

**Preuve fournie par l'opérateur** après récupération de la branche
#289 : `just yubikey-escrow-usb-status` a exécuté la commande
`manage-age-escrow-usb.sh --check`, puis répondu
**`LUKS UUID device not found`**, avec **code de retour 1**.
Ce résultat signifie strictement que
`/dev/disk/by-uuid/<UUID_LUKS_ATTENDU>` n'a pas été résolu
comme périphérique bloc. Il **ne prouve pas** que la
SanDisk est physiquement absente ou définitivement perdue :
la partition, le lien `udev` ou les métadonnées
de l'inventaire peuvent être indisponibles.

**Action décidée :** ne pas tenter `--open`, `--close`,
`--init-identity`, `cryptsetup`, `mkfs`, un reset
ou une nouvelle identité age. Maintenir en l'état les
deux copies de ciphertext précédemment vérifiées sur
workstation et NFS.

### Diagnostic de découverte redacted, exclusivement lecture seule

La recette `just yubikey-escrow-usb-status` pointe désormais
sur `scripts/workstation/diagnose-age-escrow-usb-presence.py --check`.
Elle effectue **un inventaire `lsblk -J` borné**
et vérifie l'existence du lien `udev` correspondant à
l'UUID LUKS historique, sans ouvrir le périphérique,
sans `sudo`, sans monter/déverrouiller et sans lire
l'identité age. Elle n'imprime **aucun UUID, chemin
de périphérique, nom de mapper, point de montage, clé ni secret**.
Le script historique reste accessible en lecture seule via
`just yubikey-escrow-usb-legacy-check` si nécessaire ;
celui-ci peut imprimer des données `lsblk` locales.

```bash
# Dans le worktree de la PR #289 actualisé :
just yubikey-escrow-usb-test
just yubikey-escrow-usb-status
```

Les états possibles incluent :

| `state` | Interprétation et suite |
| --- | --- |
| `ESCROW_UUID_NOT_ENUMERATED` | Aucun UUID correspondant dans la vue `lsblk` actuelle ; vérifier en privé si la SanDisk est connectée et reconnue, sans conclure à une perte |
| `ESCROW_LUKS_PRESENT_UDEV_LINK_MISSING` | Partition LUKS attendue visible par `lsblk` mais lien `/dev/disk/by-uuid` absent ; examiner `udev` en lecture seule |
| `ESCROW_LUKS_LOCKED` | Périphérique identifié et verrouillé ; **ne pas déverrouiller automatiquement** |
| `ESCROW_LUKS_UNLOCKED_NOT_MOUNTED` | Mapper ouvert, volume non monté ; aucune modification automatique |
| `ESCROW_LUKS_UNLOCKED_MOUNTED` | Mapper ouvert et volume monté ; la présence/validité de la clé privée age reste à vérifier séparément |
| `ESCROW_UUID_UNEXPECTED_FSTYPE` ou `ESCROW_UUID_AMBIGUOUS` | Métadonnées contradictoires ; diagnostic manuel nécessaire |
| `LSBLK_INVENTORY_UNAVAILABLE` | Commande `lsblk` indisponible, sortie malformée ou inventaire trop grand |

**Qualité :** 13 contrats synthétiques ajoutés
(`tests/test_age_escrow_usb_presence.py`). Leur
exécution complète sur workstation et la nouvelle
lecture `lsblk` réelle restent **NOT_RUN** lors de
la publication du correctif ; aucun CI payant exécuté.

**Gate inchangé :** en l'absence de disponibilité
vérifiée de l'identité privée de récupération,
aucun nouvel essai `age -d`, aucune restauration
SOPS, aucune modification PIV82/PIV9A/OTP2 et
aucune nouvelle copie `--copy`. KeePassXC reporté.

## Relevé workstation : USB non énuméré et faux positif de test corrigé (27/10/2026)

**Nouveau retour opérateur après `just yubikey-escrow-usb-test` et
`just yubikey-escrow-usb-status` :**

- Suite initiale : **12/13 tests PASS**, un seul échec :
  `test_invocation_is_single_redacted_lsblk_read`.
  L'assertion `assertNotIn("private", output)` détectait
  **le nom de champ JSON** `private_age_identity_read`
  (avec la valeur `false`), sans qu'aucune donnée privée
  ait été divulguée. Il s'agissait d'un **faux positif du test**,
  pas d'un échec de la protection ni d'une lecture de clé.
- Diagnostic réel : `state=ESCROW_UUID_NOT_ENUMERATED`,
  `luks_uuid_link_present=false`,
  `private_age_identity_read=false`,
  `luks_unlock_attempted=false`,
  `disk_mutation_performed=false`,
  `status=NO-GO`. L'UUID LUKS attendu n'apparaît
  **pas dans l'inventaire `lsblk` actuel**, et le lien
  `udev` correspondant n'est pas disponible.
  **Aucune preuve de perte matérielle définitive.**

**Correction dans PR #289 :**
l'assertion de non-divulgation compare désormais des
valeurs d'UUID et de chemins réels, et non le terme
générique `private` utilisé par la structure du rapport.
Un nouveau test utilise un point de montage et un mapper
**synthétiques** pour vérifier qu'ils ne sont jamais
repris dans la sortie.

**Revalidation workstation effectuée le 27 octobre 2026 :**
`just yubikey-escrow-usb-test` : **14/14 PASS**,
compilation Python PASS, y compris le test de
masquage du mapper et du chemin de montage privés.
`just yubikey-escrow-usb-status` :
`state=ESCROW_UUID_NOT_ENUMERATED`,
`luks_uuid_link_present=false`,
`private_age_identity_read=false`,
`luks_unlock_attempted=false`,
`disk_mutation_performed=false`,
`status=NO-GO`, code de sortie 3 **attendu**.
La correction du faux positif est donc validée ;
le support reste non identifié par UUID dans la vue
`lsblk` de cette exécution.

```bash
# Dans le worktree PR #289 mis à jour :
just yubikey-escrow-usb-test
just yubikey-escrow-usb-status
```

Si `ESCROW_UUID_NOT_ENUMERATED` reste inchangé,
vérifier **en privé et localement** la connexion physique
de la SanDisk et la détection par le noyau.
Après reconnexion éventuelle, relancer uniquement
le diagnostic read-only. **Ne pas exécuter**
`--open`, `--init-identity`, `cryptsetup`,
`luksFormat` ou `--copy` pour corriger une absence
de périphérique. La restauration age/SOPS depuis
la nouvelle sauvegarde NFS reste bloquée en l'absence
de l'identité USB réellement disponible.

## SanDisk reconnectée, montée et identité USB à contrôler (27/10/2026)

**Preuve opérateur après reconnexion physique de la SanDisk d'escrow** :

- Le support d'origine a été **rebranché physiquement à la workstation**.
  Il s'agissait bien du prérequis absent des premiers essais.
- `just yubikey-escrow-usb-status` :
  `state=ESCROW_LUKS_UNLOCKED_MOUNTED`,
  `luks_uuid_link_present=true`,
  `private_age_identity_read=false`,
  `luks_unlock_attempted=false`,
  `disk_mutation_performed=false`, `status=NO-GO`.
- **Point de montage déclaré par l'opérateur :**
  `/run/media/albandrieu/NABLA_ESCROW`.
  Le diagnostic antérieur confirme le montage du volume LUKS,
  **pas encore** l'existence ou la compatibilité de son identité age.

**Instruction à répéter dans toute future procédure USB** :
**brancher physiquement la SanDisk d'escrow d'origine avant
d'exécuter les commandes de contrôle.** Si le diagnostic ne
voit pas l'UUID attendu, vérifier d'abord la connexion du support ;
ne pas interpréter immédiatement ce résultat comme une perte
d'identité ou une panne `udev`.

### Précontrôle de l'identité de récupération, sans lire sa valeur

Le nouveau programme
`scripts/workstation/inspect-age-escrow-usb-identity.py`
corrobore l'UUID LUKS de la partition connue avec son unique
enfant `crypt` monté sur ext4 à l'emplacement attendu ;
il vérifie ensuite **uniquement les métadonnées** du fichier
`age-escrow/recovery-identity.txt` du support monté.
Le contrôle refuse un lien symbolique, un mauvais propriétaire,
un mode différent de `0600`, un nombre de liens autre que 1,
une taille vide ou démesurée. Aucun octet du fichier n'est ouvert.

```bash
# 1. Brancher physiquement la SanDisk d'origine.
# 2. Vérifier qu'elle est déjà déverrouillée et montée.
just yubikey-escrow-usb-status

# 3. Tests synthétiques, sans accès à la clé privée USB.
just yubikey-escrow-usb-identity-test

# 4. Métadonnées locales uniquement, sans déchiffrement :
just yubikey-escrow-usb-identity-check
```

Résultats positifs attendus :
`usb_state=USB_LUKS_MOUNT_MATCHED`,
`mount_state=USB_EXPECTED_EXT4_MOUNT_PRESENT`,
`identity_state=USB_IDENTITY_METADATA_PRESENT`.
Même après succès,
`identity_private_content_read=false`,
`identity_recipient_derived=false`,
`restore_verified=false` et `status=NO-GO`
restent exacts.

**13 nouveaux contrats hermétiques sont ajoutés dans PR #289 ;
leur exécution réelle sur workstation reste NOT_RUN.**
La revue des permissions est une étape de préparation ;
elle ne démontre pas que la clé X25519 présente est
celle permettant le déchiffrement de l'archive NFS.
Ne pas afficher de contenu de clé, de destinataire privé,
d'argument age ni de trace de déchiffrement dans la PR.

**Après succès du contrôle de métadonnées :** préparer
séparément, avec approbation explicite, la validation
de l'identité de récupération existante en comparant
son destinataire public au destinataire historique.
Le déchiffrement réel de la nouvelle copie NFS via
les scripts de PRA existants reste un jalon indépendant.
Aucune écriture, aucun `cryptsetup open`,
`--init-identity`, `--copy`, modification YubiKey,
rotation SOPS ou test KeePassXC n'est nécessaire.

## Preuve du contrôle X25519 USB : 12/12 tests PASS (27 octobre 2026)

**Dernière exécution workstation** : compilation de
`verify-age-escrow-usb-recipient.py` et de sa suite
de tests **PASS** ; `12/12` tests synthétiques
**PASS**. Le contrôle `--check` a retourné
`USB_IDENTITY_READY_FOR_RECIPIENT_CHECK`,
`private_identity_read_attempted=false`,
`public_recipient_compared_to_historical=false`,
`public_recipient_matches_historical=null`,
`decryption_attempted=false`,
`restore_verified=false`, `status=NO-GO`.

Cette preuve valide seulement la préparation de
l'attestation : **le destinataire public de l'identité
USB n'a pas encore été calculé ni comparé**.
La SanDisk originale doit être **physiquement branchée**,
déverrouillée et montée avant les prochaines étapes.

La commande distincte ci-dessous est **facultative
et nécessite l'autorisation explicite de l'opérateur**.
Elle lit localement la clé privée age depuis le support
USB, sans l'imprimer ; elle demande à `age-keygen -y`
d'en dériver uniquement le destinataire public, puis
compare le résultat à la référence historique en
mémoire, sans imprimer le destinataire public non plus.

```bash
python3 scripts/workstation/verify-age-escrow-usb-recipient.py \
  --verify \
  --acknowledge DERIVE_EXISTING_USB_AGE_PUBLIC_RECIPIENT_ONLY
```

Résultat positif attendu :
`USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL`,
`public_recipient_matches_historical=true`.
Même si cette attestation passe, elle **ne prouve pas**
que la copie chiffrée NFS du 27/10 est déchiffrable ;
aucun déchiffrement age/SOPS ni opération PIV n'est
réalisé. Le contrôle de récupération depuis la nouvelle
copie NFS nécessitera une autorisation et une
procédure isolée séparées.

**Ne pas réexécuter `--copy`, ne pas régénérer la
clé USB et ne pas modifier PIV82, OTP2 ou SOPS.**


## Attestation USB X25519 confirmée et prochain gate de restauration (27/10/2026)

**Preuve réellement exécutée sur la workstation :**
`verify-age-escrow-usb-recipient.py --verify` avec acquittement
`DERIVE_EXISTING_USB_AGE_PUBLIC_RECIPIENT_ONLY` retourne :

- `state=USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL` ;
- `private_identity_read_attempted=true` ;
- `public_recipient_compared_to_historical=true` ;
- `public_recipient_matches_historical=true` ;
- `private_identity_disclosed=false`,
  `public_recipient_disclosed=false` ;
- `decryption_attempted=false`, `restore_verified=false`,
  `sops_configuration_changed=false`,
  `usb_mount_or_unlock_performed=false`, `status=NO-GO`.

**DONE** : le moyen de récupération historique sur la SanDisk
physiquement rebranchée et montée a été identifié ;
son destinataire public correspond à la référence déjà documentée.
Ne pas confondre cette preuve avec l'aptitude à déchiffrer la
**nouvelle copie NFS** : la stanza X25519 de son en-tête
n'a pas été comparée cryptographiquement à cette identité.

### Prochain jalon — restauration depuis la nouvelle copie NFS

Les scripts existants
`scripts/workstation/verify-sops-age-escrow.sh` et
`scripts/workstation/test-sops-usb-recovery.sh`
sont réutilisables **après autorisation distincte du
déchiffrement réel**. Ne pas les exécuter automatiquement.

1. **Brancher physiquement la SanDisk de récupération d'origine**,
   puis vérifier qu'elle est déjà déverrouillée et montée.
2. Vérifier que l'unique copie chiffrée créée dans le dossier
   NFS courant est accessible, et non confondue avec
   l'ancienne archive `secret/keepass/`.
   Réutiliser l'inventaire et le comparateur déjà validés ;
   ne pas relancer `--copy`.
3. Vérifier que `/dev/shm` est réellement en `tmpfs` ;
   que les commandes `age`, `age-keygen` et `sops`
   sont disponibles ; que `umask 077` est appliqué.
4. Seulement après approbation de restauration : utiliser
   `verify-sops-age-escrow.sh` sur la **nouvelle** archive
   et la **clé USB déjà attestée**. Ce script écrit
   temporairement l'identité SOPS déchiffrée sur `/dev/shm`,
   compare son seul destinataire public attendu, et
   élimine son fichier temporaire au départ normal du script.
   Son succès prouve la récupération de l'identité SOPS
   mais pas un document SOPS de production.
5. Après cette preuve, exécuter séparément le test
   `test-sops-usb-recovery.sh` avec une fixture SOPS
   synthétique isolée ; ne pas utiliser un document
   confidentiel de production pour la première répétition.

**Point de vigilance sur les scripts historiques** : des
erreurs de `age` ou `sops` peuvent apparaître sur stderr ;
ne pas utiliser `set -x`, CI, capture de terminal
partagée ou envoi automatique des sorties brutes.
Les scripts réalisent un déchiffrement réel et créent
temporairement une **clé privée** dans `tmpfs`.
Ils doivent être revus avant leur prochaine exécution.

**Restent NO-GO :** restauration depuis la nouvelle NFS
(non encore essayée), indépendance de la clé privée de
récupération USB, validation effective des ACL natives
des répertoires NFS, toute écriture PIV82/PIV9A/OTP2,
rotation des destinataires SOPS et copie NFS supplémentaire.


## Restauration age du nouveau ciphertext NFS : PASS (27 octobre 2026)

**Preuve réelle fournie par l'opérateur sur la workstation :**

- La SanDisk de récupération d'origine est **physiquement branchée**,
  déverrouillée et montée au chemin confirmé.
- Le script shell de contrôle a sélectionné **une seule** archive
  `*.age` située à la racine du partage NFS
  `/media/backup/lab/secret/` (pas le fichier historique
  du sous-dossier `keepass/`).
- La condition `findmnt ... /dev/shm == tmpfs` a été franchie.
- `scripts/workstation/verify-sops-age-escrow.sh` a produit :

```text
PASS: TrueNAS encrypted backup decrypted with USB key and recovered original SOPS public recipient.
NOTE: this verifies identity recovery, not full SOPS decrypt; test fixture separately.
```

**Conclusion DONE :** la **nouvelle copie chiffrée NFS
du 27 octobre 2026**, déjà vérifiée octet par octet
et vue sur TrueNAS, a réellement été déchiffrée par
l'identité USB age X25519 ; le destinataire public de
l'identité SOPS récupérée correspond à la référence
historique attendue. La copie NFS est donc récupérable
**avec le support et l'identité USB actuellement disponibles**.
Ce succès ne prouve pas que l'identité USB dispose
d'une sauvegarde privée indépendante.

### Validation exécutée de la chaîne SOPS : fixture synthétique — PASS (27/10/2026)

**Preuve opérateur sur la nouvelle archive NFS :**
après le PASS de `verify-sops-age-escrow.sh`, le
contrôle `test-sops-usb-recovery.sh` a été exécuté
avec la **même archive NFS** et l'identité de la SanDisk
d'origine, physiquement branchée, déverrouillée et montée.
Le shell a vérifié l'unicité de l'archive et `/dev/shm`
en `tmpfs`, puis le script a retourné :

```text
✅ PASS: SOPS recovery with USB-backed escrow
```

**DONE :** le script a déchiffré l'archive age,
retrouvé l'identité privée SOPS en mémoire temporaire,
chiffré un YAML synthétique et déchiffré cette fixture
avec `SOPS_AGE_KEY_FILE` fixé à l'identité restaurée.
Il ne s'agit **pas** d'une preuve de déchiffrement
d'un document SOPS de production. Le script ne vise
pas à modifier la configuration SOPS de la workstation.

**Commande d'acceptation historique (déjà exécutée,
ne pas répéter sans nécessité) :**

```bash
# Prérequis : brancher physiquement la SanDisk d'origine,
# déjà déverrouillée et montée ; ne pas utiliser set -x.
bash <<'SOPS_FIXTURE_CHECK'
set -Eeuo pipefail
umask 077
shopt -s nullglob
archives=(/media/backup/lab/secret/*.age)
(( ${#archives[@]} == 1 )) || {
  echo "Archive NFS absente ou ambiguë : arrêt"
  exit 2
}
[[ "$(findmnt -n -o FSTYPE -T /dev/shm)" == tmpfs ]] || {
  echo "tmpfs requis : arrêt"
  exit 2
}
bash scripts/workstation/test-sops-usb-recovery.sh \
  --backup "${archives[0]}" \
  --usb-identity "/run/media/albandrieu/NABLA_ESCROW/age-escrow/recovery-identity.txt"
SOPS_FIXTURE_CHECK
```

**Critère DONE satisfait :** la sortie du test SOPS
sur la nouvelle archive NFS est `PASS: SOPS recovery
with USB-backed escrow`. Chaîne de récupération
age → identité SOPS → fixture SOPS **PASS**.
Aucun plaintext ni identité privée n'a été transmis
dans le résultat communiqué. Le test est isolé et
synthétique ; il ne simule pas la perte de la SanDisk
ou de la workstation.

**Risques restant ouverts :** la clé privée de
récupération X25519 sur SanDisk est un point
unique de défaillance tant que sa seconde copie
indépendante n'est pas vérifiée ; les ACL effectives
des répertoires NFS4 ne sont pas entièrement
attestées. PIV82/PIV9A/OTP2, destinataires SOPS,
KeePassXC et création d'une nouvelle copie NFS
restent hors périmètre.


## Sauvegarde indépendante de l'identité privée age USB — mise en œuvre

**Autorisation opérateur :** créer une sauvegarde **chiffrée avec
une phrase secrète indépendante** de l'identité age privée X25519
présente sur la SanDisk originale, puis conserver le ciphertext
sur la workstation et TrueNAS.

**Prérequis obligatoires :**
- **Brancher physiquement la SanDisk de récupération d'origine**
  sur la workstation, déjà déverrouillée et montée.
- L'identité age USB a déjà passé ses contrôles LUKS2, ext4,
  propriétaire, taille et mode `0600`.
- Vérifier que le partage NFS attendu est monté et accessible.
  **Ne pas créer une sauvegarde sur le disque local** en pensant
  qu'il s'agit du partage TrueNAS.
- Utiliser une phrase secrète **forte, nouvelle et indépendante**
  de la SanDisk et du mot de passe LUKS ; la conserver dans
  un coffre de mots de passe **récupérable sans cette SanDisk**.
  Si `age -p` propose une phrase secrète aléatoire,
  l'enregistrer immédiatement dans ce coffre.
  Ne jamais la transmettre dans GitHub, ChatGPT, les logs
  ou un argument de commande.

**Protection apportée par le nouveau script :**
`scripts/workstation/backup-usb-age-identity.py` n'ouvre
le fichier d'identité USB qu'au moment de lancer
`age -p` avec la source transmise via un descripteur
de lecture seule. Il crée des **fichiers chiffrés**
dans deux sous-dossiers privés distincts :

- Workstation : `~/.local/share/nabla/usb-recovery-backups/`.
- TrueNAS, via le NFS vérifié :
  `/media/backup/lab/secret/usb-recovery-backups/`.

Ces répertoires sont nouveaux, mode `0700`, fichiers
mode `0600`, nom commun horodaté. Le script exige
le NFS attendu, des fichiers réguliers sans symlink,
deux systèmes de fichiers différents, une exécution
**interactive** et l'acquittement explicite.
Il chiffre **avant** de copier sur NFS ;
il n'écrit jamais de clé en clair sur workstation/TrueNAS.
Il contrôle égalité binaire et SHA-256 de **ces seuls
ciphertexts**, puis publie sans écrasement.
Un exemplaire existant ou un transfert incomplet
requiert revue avant relance (aucun overwrite).

```bash
# 1. SanDisk d'origine PHYSIQUEMENT BRANCHÉE et montée.
# 2. Contrôles synthétiques sans aucune identité privée :
just yubikey-usb-identity-backup-test

# 3. Préflight metadata-only, aucune création :
just yubikey-usb-identity-backup-check

# 4. Autorisation déjà donnée par l'opérateur pour la sauvegarde.
#    Exécuter en terminal interactif ; age -p demande la phrase secrète.
just yubikey-usb-identity-backup
```

**Critère d'écriture DONE, à vérifier avec la sortie opérateur :**
`state=ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL`,
`encrypted_copy_local_and_nfs_verified=true`.
La copie est **NOT_RUN** sur la workstation à la date
de publication de cette procédure : seuls le script
et les tests hermétiques sont livrés.

**Critère de PRA définitif non encore satisfait :**
tester la **restauration d'une copie chiffrée**
avec la phrase secrète en l'absence de la SanDisk,
dans un `/dev/shm` privé, comparer le destinataire
age public restauré à la référence X25519,
nettoyer le temporaire, puis vérifier une archive
SOPS existante sans altérer les clés originales.
Le contrôle de copie binaire seul ne prouve pas
la capacité à retrouver la phrase secrète.

**Ne pas confondre** les deux exemplaires identiques
du ciphertext avec deux méthodes de récupération
cryptographiquement indépendantes : ils nécessitent
la **même phrase secrète externe**. Planifier des
snapshots TrueNAS, puis une copie hors-ligne/offsite
quand le stockage et le PRA sont validés.
Ne pas relancer `--copy` de l'archive SOPS NFS
existante. Aucun formatage, provisionnement PIV/OTP
ou rotation SOPS n'est nécessaire ici.

## ✅ Acceptation des sauvegardes indépendantes de la SanDisk — 28/10/2026

La preuve workstation du 28/10 **remplace l'état NOT_RUN** de la section
historique « Sauvegarde indépendante de l'identité privée USB » :

- `just yubikey-usb-identity-backup-test` : **14/14 PASS**.
- `just yubikey-usb-identity-restore-test` : **13/13 PASS**.
- Précontrôle de sauvegarde : `BACKUP_PREFLIGHT_READY`.
- Écriture supervisée : `ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL`
  et `encrypted_copy_local_and_nfs_verified=true`.
- Précontrôle de restauration : `BACKUP_RESTORATION_PREFLIGHT_READY`.
- Restauration de **chaque copie chiffrée** :
  `BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT`,
  `two_encrypted_backups_restored=true` et
  `historical_public_recipient_matched=true`.

**DONE :** deux copies chiffrées cohérentes sur workstation et NFS TrueNAS,
deux restaurations cryptographiques réussies ; la clé USB d'origine n'est
pas utilisée par l'outil de restauration.

**Toujours à attester :** SanDisk physiquement débranchée pendant un
exercice PRA ; conservation de la phrase secrète accessible sans SanDisk ;
ACL NFS4 effectives des fichiers et des répertoires parents. Ce résultat ne
prouve pas le déchiffrement d'un document SOPS de production.

Le détail des commandes et de leurs limites est conservé dans
[`usb-age-identity-independent-backup-20261028.md`](usb-age-identity-independent-backup-20261028.md).
Ne pas recommencer la sauvegarde : l'opération initiale est terminée et
la protection anti-écrasement doit rester active. Aucun `--copy`, aucune
rotation SOPS, aucune mutation PIV/OTP.
