# Sauvegarde indépendante de l'identité privée age sur SanDisk — PR #289

**Objectif P0 :** conserver une copie chiffrée sur la workstation et une copie
chiffrée sur TrueNAS. Ces deux copies sont des supports distincts d'un
**même** secret, pas deux identités age indépendantes.

## Conditions de sécurité

- Brancher **physiquement la SanDisk originale** et déverrouiller son LUKS2
  avant le précontrôle ou la sauvegarde USB. Ne jamais écrire sur ce support.
- Requiert une session terminal locale interactive, `age`, `age-keygen`,
  `findmnt`, Python 3 et le montage NFS `nabla:/mnt/cpool/backup/lab`
  sur `/media/backup/lab`.
- La phrase secrète `age -p` doit être indépendante de la SanDisk, des clés
  SOPS et des autres identifiants. Ne pas la mettre dans la commande, une
  variable d'environnement, un fichier texte ou les journaux. La stocker
  séparément dans un support de récupération approuvé.
- Seules les archives `*.age` chiffrées sont sauvegardées. Les répertoires
  de destination doivent appartenir à l'UID opérateur et être en `0700`,
  les archives en `0600`. Le répertoire local parent ne doit pas être
  accessible en écriture par le groupe ou les autres.
- Les ACL NFS4 effectives du fichier et des parents restent un contrôle
  distinct, non démontré par les seuls bits POSIX.

## Étapes opérateur (workstation, pas GitHub Actions)

1. Mettre à jour la branche de PR #289 en avance rapide, sans écraser
   les modifications locales.
2. Préparer si besoin le répertoire local privé :
   `install -d -m 0700 "$HOME/.local/share/nabla"`.
   Vérifier **manuellement** que `/media/backup/lab/secret` est le
   répertoire NFS prévu, privé et propriétaire UID correct. Ne pas modifier
   les permissions du NFS à l'aveugle.
3. Exécuter `just yubikey-usb-identity-backup-test` et
   `just yubikey-usb-identity-restore-test`. Les suites utilisent uniquement
   des fixtures et mocks.
4. SanDisk physiquement présente, déverrouillée et montée : exécuter
   `just yubikey-usb-identity-backup-check`. Exiger
   `BACKUP_PREFLIGHT_READY`. Tout autre état est un **NO-GO**.
5. Lancer **une seule fois** `just yubikey-usb-identity-backup`.
   Choisir/saisir la phrase secrète indépendante au prompt TTY.
   Exiger `ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL`.
   Ne jamais réexécuter l'ancienne commande NFS `--copy`.
6. Déconnecter la SanDisk originale **après** la sauvegarde.
   Exécuter `just yubikey-usb-identity-restore-check` et exiger
   `BACKUP_RESTORATION_PREFLIGHT_READY`.
7. Exécuter `just yubikey-usb-identity-restore-verify` depuis un TTY privé.
   Fournir la phrase secrète aux prompts `age` pour chacune des copies.
   Exiger `BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT` et
   `two_encrypted_backups_restored=true`.

## Portée exacte des preuves

`backup-check` ne lit pas la clé. `backup` lit l'identité USB uniquement
depuis son descripteur ouvert en lecture et produit deux fichiers chiffrés.
`restore-check` vérifie les métadonnées sans lire les archives.
`restore-verify` compare les octets chiffrés, déchiffre chaque copie
séparément dans la mémoire des processus et dérive le destinataire public
historique avec `age-keygen -y`. La clé privée n'est ni publiée ni écrite
dans un fichier par cet outil. Ne pas activer le tracing shell, les core dumps,
la capture de session ou des outils de débogage de processus pendant l'opération.
La mémoire de processus reste soumise aux politiques de swap du système.

Un PASS prouve que **les deux copies ont pu être déchiffrées** et que leur
identité correspond au destinataire age historique. Il ne constitue pas un
nouveau test de déchiffrement SOPS de production ni un audit des ACL NFS4.
Il ne démontre pas une indépendance géographique ou une restauration après
perte du NFS.

Si une étape échoue : arrêter. Ne pas supprimer les archives, les réécrire,
faire tourner les clés, modifier PIV9A/PIV82/OTP2 ou relancer la sauvegarde.
Conserver l'état `NO-GO` et diagnostiquer uniquement en lecture seule.

## ✅ Preuve d'acceptation workstation — 28/10/2026

L'opérateur a transmis la sortie des commandes après `git pull --ff-only`
sur la branche de la PR #289 :

| Contrôle | Preuve | État |
| --- | --- | --- |
| `just yubikey-usb-identity-backup-test` | 14 tests, `OK` | **PASS** |
| `just yubikey-usb-identity-restore-test` | 13 tests, `OK` | **PASS** |
| `just yubikey-usb-identity-backup-check` | `BACKUP_PREFLIGHT_READY` | **PASS** |
| `just yubikey-usb-identity-backup` | `ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL`, copie vérifiée `true` | **PASS** |
| `just yubikey-usb-identity-restore-check` | `BACKUP_RESTORATION_PREFLIGHT_READY` | **PASS** |
| `just yubikey-usb-identity-restore-verify` | `BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT`, restauration `true` | **PASS** |

**DONE :** création d'une archive chiffrée localement et d'une copie chiffrée
identique sur le montage NFS TrueNAS ; restauration cryptographique séparée
des deux copies ; conformité du destinataire public historique.
**27/27 tests hermétiques PASS**, sans CI GitHub. Aucun secret n'a été fourni
dans les sorties. Le script de restauration ne dépend pas de l'USB.

**Limites non attestées :**
- Le transcript ne confirme pas le **débranchement physique** de la SanDisk
  avant l'essai de restauration ; ne pas revendiquer un exercice PRA complet
  « sans SanDisk » au niveau opérateur.
- La **conservation durable de la phrase secrète** dans un support accessible
  indépendamment de la SanDisk n'est pas prouvée. Ne jamais publier sa valeur.
- Les droits NFS4 effectifs du fichier et de ses répertoires parents restent
  à auditer séparément.
- Aucune restauration d'un document SOPS de production, ni simulation de
  perte de workstation/NFS, n'a été effectuée dans cette séquence.

## Contrôle suivant — phrase secrète indépendante et ACL NFS4

### Phrase secrète — attestation humaine, sans saisir de secret

**État : À ATTESTER.** Les restaurations prouvent que la phrase secrète
était disponible pendant la vérification, **pas** qu'elle survivra à la perte
de la SanDisk, de la workstation ou de TrueNAS.

Contrôles à confirmer localement, sans afficher de valeur ni nom de coffre :

1. La phrase secrète `age -p` est enregistrée **hors de la SanDisk**.
2. L'accès au stockage de cette phrase ne dépend ni de la clé privée
   sauvegardée, ni de la workstation, ni du LUKS de la SanDisk.
3. Une panne du NAS TrueNAS n'empêche pas **à elle seule** d'accéder à la
   phrase : un Vaultwarden hébergé uniquement sur ce TrueNAS ne garantit
   pas l'indépendance recherchée.
4. Une consultation depuis un support indépendant a effectivement été
   testée, sans copier la valeur dans des logs, GitHub ou ChatGPT.

**Seule confirmation exploitable dans la PR :** quatre booléens
`true/false` et la date du contrôle ; aucune phrase secrète, identifiant,
URL de coffre ou emplacement physique.

### ACL NFS4 — inventaire en lecture seule de la nouvelle archive

La précédente recette `yubikey-escrow-acl-probe` porte sur **l'ancienne**
archive à la racine du partage NFS. Pour **la nouvelle** archive
`usb-recovery-identity-*.age`, utiliser :

```bash
# Aucun USB requis. 11 tests hermétiques locaux, sans SSH.
just yubikey-usb-identity-nfs4-acl-test

# Vérifie le montage NFS et les deux fichiers chiffrés par métadonnées.
just yubikey-usb-identity-nfs4-acl-check

# Opt-in en lecture seule : SSH existant + TrueNAS filesystem.getacl.
just yubikey-usb-identity-nfs4-acl-probe
```

Le programme parcourt **quatre niveaux fixes** sur TrueNAS :
`nfs_export`, `secret_directory`, `backup_directory`,
`encrypted_archive`. Pour chacun : type d'ACL, bit `trivial`,
nombre d'ACE et nombre d'autorisations **non propriétaires
potentielles** (sans révéler les identités des principaux ou les ACE).

- `NFS4_REVIEW_REQUIRED` : métadonnées NFS4 valides, aucun
  `ALLOW` non propriétaire détecté par l'heuristique ; il faut
  quand même une revue effective.
- `POTENTIAL_NONOWNER_ALLOW` : un droit de lecture/traversée
  non propriétaire potentiel a été détecté ; **ne pas modifier
  automatiquement** les ACL.
- `NON_NFS4_ACL`, `ACL_SCHEMA_UNVERIFIED`,
  `ACL_READ_UNAVAILABLE` et `UNTRUSTED_PATH` :
  constat insuffisant, arrêt en échec contrôlé.

Même avec code retour 0, `status=REVIEW_REQUIRED` et
`effective_nfs4_authorization_verified=false` : pour une
**preuve effective**, il faut corréler l'identité NFS réelle,
les groupes, l'ordre `ALLOW` / `DENY`, les chemins traversés
et, si autorisé, un test d'accès négatif avec identité de test
dédiée. Cette sonde ne réalise aucun test d'accès, ne lit aucune
archive et ne contacte pas le support USB.

### Preuve réelle TrueNAS du 28/10 — inventaire PASS, politique à revoir

**Workstation, après mise à jour de la PR #289 :**
- `just yubikey-usb-identity-nfs4-acl-test` : **11/11 PASS**.
- `just yubikey-usb-identity-nfs4-acl-check` : `BACKUP_RESTORATION_PREFLIGHT_READY`.
- `just yubikey-usb-identity-nfs4-acl-probe` :
  `acl_probe_state=ACL_INVENTORY_RECORDED`, SSH et les quatre
  `filesystem.getacl` TrueNAS répondent ; aucune écriture ni lecture age.
- `nfs_export` : `NFS4`, `trivial=true`, 3 ACE,
  `POTENTIAL_NONOWNER_ALLOW`, compteur **1**.
- `secret_directory`, `backup_directory`, `encrypted_archive` :
  `NFS4`, `trivial=true`, 3 ACE chacun,
  `NFS4_REVIEW_REQUIRED`, compteur non propriétaire **0**.

**Interprétation correcte du code retour 3 :** la sonde a **réussi
son inventaire**, mais le contrôle strict échoue dès qu'une autorisation
non propriétaire potentielle est détectée, même au niveau export.
Ce n'est ni un échec de connexion SSH ni une preuve d'exfiltration.
Une ACE au niveau `nfs_export` ne donne pas automatiquement accès à
l'archive si les répertoires sensibles interdisent la traversée.
Un `trivial=true` signifie que la politique ACL peut être représentée
sans perte par les bits de mode, mais ne prouve pas à lui seul la
résistance à un mauvais mappage d'identités NFS.

**Disposition : REVIEW_REQUIRED, pas de correction ACL autorisée.**
La prochaine vérification doit seulement confirmer sur le **serveur**
les modes `0700` des deux répertoires sensibles et `0600` de
l'archive, ainsi que la cohérence des propriétaires, sans imprimer
leurs valeurs. L'identité NFS effective et un test d'accès négatif
restent nécessaires pour une garantie d'autorisation effective.
Aucun `chmod`, `chown`, `setacl`, `midclt filesystem.setacl`,
changement ZFS ou restauration de secret n'est autorisé.

### ✅ Vérification complémentaire des modes sur le serveur — PASS opérateur 28/10

Un contrôle dédié, sans relancer la sauvegarde, vérifie la barrière des
**modes Unix effectifs sur TrueNAS**. Il interroge uniquement `lstat`
sur des chemins fixes, par SSH strict, sans extraire d'ACE :

```bash
cd ~/w/nabla-compose
git pull --ff-only
just yubikey-usb-identity-server-modes-test
just yubikey-usb-identity-server-modes-check
just yubikey-usb-identity-server-modes-probe
```

Conditions attendues côté **serveur** :
- `nfs_export` : répertoire présent ;
- `secret_directory` : mode `0700` ;
- `backup_directory` : mode `0700` ;
- `encrypted_archive` : mode `0600`, fichier régulier non lié ;
- même propriétaire numérique pour les **trois éléments sensibles**,
  sans afficher UID/GID.

Le contrôle ne lit pas les octets de l'archive, ni la clé USB, ni la
phrase secrète. Résultat attendu : `MODE_BOUNDARY_OBSERVED` et
`private_mode_boundary_observed=true`. Dans tous les cas,
`effective_nfs4_authorization_verified=false` et
`nfs_identity_mapping_verified=false`. Un échec ne déclenche aucune
correction automatique des ACL.

**Preuve opérateur reçue le 28/10/2026 :** `git pull --ff-only`
(`Already up to date`), compilation Python PASS, **9/9 tests hermétiques PASS**,
`--check` : `BACKUP_RESTORATION_PREFLIGHT_READY` et
`server_probe_state=NOT_PROBED` ; `--probe` :
`server_probe_state=MODE_INVENTORY_RECORDED`,
`status=MODE_BOUNDARY_OBSERVED`, `private_mode_boundary_observed=true`,
`sensitive_owner_uniform=true`. Les quatre niveaux TrueNAS confirment :

| Niveau | Métadonnée serveur | Statut |
| --- | --- | --- |
| `nfs_export` | Répertoire présent | **PASS** |
| `secret_directory` | Mode exact `0700` | **PASS** |
| `backup_directory` | Mode exact `0700` | **PASS** |
| `encrypted_archive` | Mode exact `0600`, fichier régulier | **PASS** |

**DONE : barrière de modes privés côté serveur.** Les trois éléments
sensibles appartiennent au même UID, dont la valeur n'a pas été divulguée.
L'avertissement ACL sur la racine NFS reste consigné : il **n'impose pas**
un changement de droits sur cette racine. Le programme n'a ni lu les
archives ni modifié les fichiers.

**Limites maintenues :** `effective_nfs4_authorization_verified=false`,
`nfs_identity_mapping_verified=false` et
`passphrase_access_verified=false`. Les bits `0700/0600` ne
prouvent pas à eux seuls les droits effectifs d'un client NFS privilégié,
le mappage UID/GID sur l'export, ni les restrictions `maproot/mapall`
et `root_squash`. Aucun test d'accès négatif avec une identité de test
n'a été effectué. Ces derniers contrôles requièrent une procédure distincte
et **lecture seule**, sans exposer le fichier chiffré.


Référence : [TrueNAS SCALE 26 — ACL](https://www.truenas.com/docs/scale/26/datasets/permissions/configuringacls/).

**Ne pas relancer `--backup` :** les archives existent et le script refuse
de les écraser. Garder `--copy`, la rotation SOPS, OTP2 et PIV9A/PIV82
hors périmètre. PR #289 fusionnée ; continuation en PR #295 Draft, sans automerge.

## P1 — Vérifier l'export NFS et les identités (PR #295, 30/10/2026)

**Contexte :** après les preuves réelles `0700/0700/0600` et
`MODE_BOUNDARY_OBSERVED`, les permissions locales serveur sont validées.
Le contrôle ACL sur la racine de l'export a détecté **une autorisation
non propriétaire potentielle** ; cela n'implique pas la capacité de lire
les dossiers `secret` privés.

**Contrôle en lecture seule ajouté dans la PR #295 :**

```bash
cd ~/w/nabla-compose
git pull --ff-only
just yubikey-usb-identity-nfs-export-test
just yubikey-usb-identity-nfs-export-check
just yubikey-usb-identity-nfs-export-probe
```

La SanDisk d'origine **n'est pas nécessaire**. Ne pas relancer
`--backup`, `--copy` ou le déchiffrement : ce contrôle ne lit ni
l'archive chiffrée ni la phrase secrète. Les tests sont hermétiques,
sans contact réseau réel ; le `--probe` interroge une seule fois
`sharing.nfs.query` via SSH non interactif et vérification stricte
de la clé hôte existante. Aucun changement de partage, de dataset,
de propriétaire ou d'ACL.

**Éléments examinés**, sans publier leur contenu :
- Correspondance **exacte** d'un unique export avec le chemin monté
  attendu sur la workstation ; l'absence ou l'ambiguïté échoue.
- Export actif, verrouillage du dataset, partage en lecture seule ou non.
- Présence de filtres `hosts` et `networks` sans publier
  adresses IP, noms DNS ou listes complètes. L'absence des deux filtres
  déclenche `NO_NFS_HOST_OR_NETWORK_FILTER`.
- Types de sécurité `SYS`, `KRB5`, `KRB5I`, `KRB5P`.
  `SYS` utilise l'identité UID/GID déclarée par le client ; ce
  protocole ne constitue pas une authentification forte du client.
  Une liste vide est notée `DEFAULT_UNVERIFIED`, sans inférence.
- Présence de `maproot` et `mapall`. L'analyse compare les
  comptes de mappage à l'UID du fichier **sur le serveur**, puis
  ne transmet que `SENSITIVE_OWNER`, `DIFFERENT_OWNER`,
  `UNSET` ou `ACCOUNT_NOT_RESOLVED`. Aucune identité n'est divulguée.

Un retour `configuration_inventory_verified=true` signifie
**uniquement** que la configuration NFS a été lue et validée.
`status=REVIEW_REQUIRED` reste volontaire ; un code retour 0
ne constitue **pas** une validation des accès effectifs.
`effective_nfs4_authorization_verified=false` et
`nfs_identity_mapping_verified=false` ne doivent pas être modifiés
par cette sonde. Les restrictions client et le traitement de l'identité
root restent des éléments d'analyse ; aucun correctif automatique.

**Critère de clôture partielle :** retour opérateur expurgé du
`--probe`, analyse des éventuels `review_flags` et de
`configuration.client_filter`, `root_mapping`, `all_mapping`
et `security`. Une preuve d'accès négatif exige une identité
de test distincte et une procédure explicitement autorisée ;
ne pas employer `sudo` ou l'UID propriétaire pour la simuler.

**État à la publication :** scripts et tests versionnés, exécution
sur workstation/TrueNAS **NOT_RUN**. La phrase secrète conservée hors
SanDisk, workstation et NAS reste **NOT_ATTESTED** ; aucune valeur
secrète ne doit être communiquée.

**Référence :**
[TrueNAS API – partage NFS](https://api.truenas.com/v26.0/api_methods_sharing.nfs.update.html).


### ✅ Preuve de lecture réelle de l'export NFS — 30 octobre 2026, PR #295

**Workstation :**
- Mise à jour en avance rapide, sans réinitialiser les sous-modules locaux `n8n` / `sentry` déjà modifiés.
- `just yubikey-usb-identity-nfs-export-test` : **8 tests PASS, 1 FAIL**. Échec de la fixture `test_synthetic_remote_export_filters_and_user_mapping` : elle déclarait encore le chemin d'export de production alors que le programme distant simulé cherchait son chemin temporaire. **Aucun échec NFS réel.**
- `just yubikey-usb-identity-nfs-export-check` : `BACKUP_RESTORATION_PREFLIGHT_READY`.
- `just yubikey-usb-identity-nfs-export-probe` : **`EXPORT_MATCHED`, `configuration_inventory_verified=true`**, sans lecture d'archive ni mutation.

**Configuration réelle observée, expurgée :**

| Propriété | État | Interprétation |
| --- | --- | --- |
| `enabled` | `true` | Export actif |
| `locked` | `false` | Dataset non verrouillé |
| `hosts_restricted` | `false` | Aucune restriction `hosts` définie dans le partage |
| `networks_restricted` | `false` | Aucune restriction `networks` définie dans le partage |
| `read_only` | `false` | Export autorisant l'écriture sous réserve des permissions et contrôles supplémentaires |
| `root_mapping` / `all_mapping` | `UNSET` | Aucun compte explicite mappé ; comportement effectif non testé |
| `security` | `DEFAULT_UNVERIFIED` | Liste de sécurité vide ; **ne prouve pas** que `AUTH_SYS` est désactivé |

**Alertes réellement émises :** `NO_NFS_HOST_OR_NETWORK_FILTER`,
`EXPORT_WRITABLE`. La version corrigée signale aussi
`NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED` lorsqu'une liste `security`
vide est observée ; **cette alerte supplémentaire n'a pas encore été
réexécutée sur TrueNAS**.

Les deux premières alertes constituent des écarts de durcissement de la
configuration du partage, **pas** la preuve qu'un client non autorisé a
monté l'export ou lu l'identité privée. La documentation de l'API TrueNAS
indique qu'une liste `hosts` ou `networks` vide n'applique pas
de restriction à ce niveau ; les éventuelles restrictions au niveau
pare-feu et service NFS restent à inventorier.
[Référence : API TrueNAS NFS](https://api.truenas.com/v25.10/api_methods_sharing.nfs.query.html).

**Correctifs de code publiés dans la PR #295 :** alignement de la
fixture sur son chemin temporaire, test de non-correspondance d'un
export différent et test explicite pour la sécurité NFS par défaut.
**Nouvelle suite : 10 tests définis ; exécution après correctif NOT_RUN.**
Aucun changement de comportement sur le NAS.

**Plan de durcissement à valider avant toute mutation :**
1. Inventorier les clients réellement dépendants de cet export,
   y compris les jobs de sauvegarde et de restauration.
2. Préparer une liste `hosts` ou `networks` minimale couvrant
   uniquement ces clients ; vérifier séparément le filtrage réseau NFS.
3. Conserver l'export en lecture-écriture tant qu'un processus légitime
   doit déposer des sauvegardes. Une transition `ro=true`
   ou un export de lecture séparé nécessite une migration planifiée.
4. Déterminer la sécurité NFS effectivement négociée et les
   mappings/squash UID/GID. L'absence de `maproot`/`mapall`
   explicite ne constitue pas une preuve d'authentification forte.
5. Préparer un plan de retour arrière et des tests d'accès
   depuis chaque client autorisé puis depuis un client de test
   non autorisé, **sans lire le ciphertext privé**.

**Décision : pas de `sharing.nfs.update`, `chmod`, `chown`,
`setacl`, changement de permissions, déchiffrement ou sauvegarde
supplémentaire** tant que l'inventaire des clients n'est pas réalisé.
`effective_nfs4_authorization_verified=false` et
`nfs_identity_mapping_verified=false` restent exacts.


### ✅ Acceptation de l'audit export NFS — preuve workstation du 30/10/2026

La deuxième exécution après correction a réellement produit :

- `just yubikey-usb-identity-nfs-export-test` : **10 tests PASS / 10** (`0.552 s`).
- `just yubikey-usb-identity-nfs-export-check` :
  `BACKUP_RESTORATION_PREFLIGHT_READY`.
- `just yubikey-usb-identity-nfs-export-probe` :
  `probe_state=EXPORT_MATCHED`,
  `configuration_inventory_verified=true`,
  `status=REVIEW_REQUIRED`.

Les trois alertes **réellement observées**, après déploiement du correctif,
sont `NO_NFS_HOST_OR_NETWORK_FILTER`,
`NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED` et `EXPORT_WRITABLE`.

**Signification :** l'export est actif, non verrouillé, sans restriction
`hosts` ou `networks` déclarée, ouvert aux écritures NFS selon les droits
effectifs ; les mappings explicites `maproot` et `mapall` ne sont pas
configurés. La liste `security=[]` ne démontre pas que `AUTH_SYS` est
désactivé. Les contrôles antérieurs `0700/0600` du serveur restent PASS,
mais il faut analyser l'authentification des clients et leur accès effectif.

**Décision :** garder l'export tel quel tant que la liste des consommateurs
et leurs besoins en écriture sont inconnus. Un `ro=true` global ou une
allowlist improvisée risque de casser les sauvegardes légitimes.
Préparer une liste de clients et un rollback avant toute mutation.

Cette preuve **remplace** les mentions `NOT_RUN` et `8 PASS / 1 FAIL`
ci-dessus pour la version corrigée. Les diagnostics ne lisent pas l'archive,
ne modifient ni NFS ni les secrets. La phrase secrète de récupération
indépendante demeure **NON ATTESTÉE**.


## P1 — Recenser les consommateurs avant une allowlist NFS (PR #295)

**Objectif :** réduire l'exposition de l'export partagé, sans interrompre
les écritures de sauvegarde. Le passage `read_only=true` et toute
modification `hosts`/`networks` sont **NO-GO** à ce stade.

### Dépendances déclarées dans le code

| Usage | Preuve versionnée | Nature | État d'exécution |
| --- | --- | --- | --- |
| Workstation Ubuntu | Montage `nabla:/mnt/cpool/backup/lab` vers `/media/backup/lab`, déjà confirmé par les contrôles précédents | Client NFS **confirmé** | Montage observé |
| OpenClaw : archive et bases | [`scripts/workstation/backup-openclaw-nfs.py`](../../scripts/workstation/backup-openclaw-nfs.py) | **Écriture** dans `infra/openclaw` | Dépendance de code, exécution planifiée non vérifiée |
| OpenClaw : transfert local → NFS | [`scripts/workstation/copy-openclaw-backups-nfs.sh`](../../scripts/workstation/copy-openclaw-backups-nfs.sh) | **Écriture** dans le même export | Exécution courante non vérifiée |
| YubiKey / age / escrow | [`scripts/workstation/backup-usb-age-identity.py`](../../scripts/workstation/backup-usb-age-identity.py) | **Écriture exceptionnelle** dans `secret` | Sauvegarde exécutée et restaurée |
| OpenClaw heartbeat | [`scripts/workstation/apply-openclaw-heartbeat-scratch.py`](../../scripts/workstation/apply-openclaw-heartbeat-scratch.py) | Restauration/écriture potentielle dans `infra/openclaw` | Ne pas exécuter pour cet audit |
| Sauvegardes de configuration pfSense | [`docs/dns-ingress-ownership.md`](../dns-ingress-ownership.md) | Archives historiques sur le même export | Client NFS d'origine **non déterminé** |

**Important :** plusieurs applications qui écrivent dans le partage
depuis la même workstation représentent **un seul client NFS**.
L'existence d'un script ou d'une archive sur TrueNAS ne prouve pas
qu'une autre machine monte cet export. Aucun client supplémentaire
n'est inventé pour construire une allowlist.

### Sonde de connexions NFS, sans fuite d'adresses

```bash
cd ~/w/nabla-compose
git pull --ff-only
just yubikey-usb-identity-nfs-consumers-test
just yubikey-usb-identity-nfs-consumers-check
just yubikey-usb-identity-nfs-consumers-probe
```

- Le test est hermétique et ne contacte pas TrueNAS.
- Le `--check` vérifie uniquement les métadonnées des deux backups
  chiffrés existants ; aucune SanDisk ni phrase secrète nécessaire.
- Le `--probe` utilise SSH non interactif avec
  `StrictHostKeyChecking=yes` pour lancer **`ss` en lecture seule**
  sur TrueNAS. Il compte les connexions TCP établies dont le port
  serveur local est **2049**, et les adresses clientes distinctes,
  **sans imprimer leurs valeurs**.
- `tcp_sessions` et `unique_tcp_peers` concernent **tous les exports
  NFS du serveur**, pas spécifiquement `lab`. Un client absent de
  cet instantané peut être intermittent, utiliser un autre protocole,
  avoir une session expirée ou être hors ligne.
- Même sur PASS, `consumer_allowlist_verified=false`,
  `all_clients_enumerated=false` et
  `export_specific_clients_verified=false`.

**État :** les nouveaux scripts et 8 tests hermétiques sont publiés,
mais leur exécution sur la workstation et la sonde TrueNAS restent
**NOT_RUN**. Aucun `sharing.nfs.update` ou `exportfs -r` n'est
inclus. Cette sonde **n'autorise pas** la création automatique
d'une allowlist à partir du seul instantané.

### Conditions avant un changement d'export

1. Identifier les points de montage réels et les automounts de **tous**
   les hôtes pouvant accéder à cet export, pas seulement les sessions
   TCP au moment du test.
2. Relier chaque hôte à ses jobs d'écriture et à ses propriétaires ;
   vérifier la disponibilité des restaurations et le besoin d'accès
   après incident.
3. Qualifier la politique `security=[]` et le mécanisme réellement
   négocié (dont `sec=sys`), puis vérifier le traitement des UID/GID
   et du superutilisateur sur le NAS.
4. Préparer un changement séparé de `hosts`/`networks`, ainsi
   qu'un plan de retour arrière hors NFS et une fenêtre de test.
5. Effectuer un contrôle positif depuis chaque client autorisé et un
   contrôle négatif avec identité de test indépendante, sans lire
   les archives sensibles.

**Décision GO :** seulement après inventaire exhaustif validé par
l'opérateur et test de restauration des usages critiques. Les
permissions `0700/0600` des dossiers privés restent intactes et
les sauvegardes de l'identité USB ne sont pas régénérées.


### ✅ Preuve workstation — sonde TCP NFS, 30/10/2026

L'opérateur a exécuté les recettes de cartographie des consommateurs :
- `just yubikey-usb-identity-nfs-consumers-test` : **8/8 PASS**,
  compilation Python comprise.
- `just yubikey-usb-identity-nfs-consumers-check` :
  `BACKUP_RESTORATION_PREFLIGHT_READY`, `NOT_PROBED`, sans SSH.
- `just yubikey-usb-identity-nfs-consumers-probe` :
  `SS_RESPONSE_UNVERIFIED`, code retour **3** ; aucun compte de
  sessions ou de clients n'a été communiqué.

**Cause probable du code retour :** la version initiale du parseur
exigeait au moins cinq colonnes par ligne de `ss`, alors que
`ss -H -tn state established` peut retourner quatre colonnes
(`Recv-Q Send-Q Local:Port Peer:Port`) lorsque l'état `ESTAB`
est omis. Le format **4 colonnes** a été reproduit sur une connexion
TCP de laboratoire local, sans utiliser le NAS et sans afficher
les adresses. Cette reproduction n'atteste pas les octets réels
retournés par `ss` sur TrueNAS.

**Correctif livré dans PR #295 :** parseur strict acceptant
`4` colonnes (sans état) ou `5` colonnes (avec `ESTAB`),
validation numérique des files et des ports, contrôle de la
structure des IP et déduplication IPv4 / IPv4-mappé IPv6.
Les tests de sortie simulée couvrent les deux formats ainsi que
des lignes malformées. Le contrôle reste fail-closed et ne renvoie
aucune adresse cliente.

**État :** tests du nouveau correctif sur workstation **NOT_RUN**,
sonde réelle post-correctif **NOT_RUN** ; inventaire client NFS
**NON ÉTABLI**. Même après un succès, un instantané `ss` ne
constitue pas la liste exhaustive des clients autorisés et
n'est pas spécifique à l'export `lab`.

**Reprise strictement en lecture seule :**

```bash
cd ~/w/nabla-compose
git pull --ff-only
just yubikey-usb-identity-nfs-consumers-test
just yubikey-usb-identity-nfs-consumers-check
just yubikey-usb-identity-nfs-consumers-probe
```

Ne pas utiliser `sharing.nfs.update`, `ro=true`, une allowlist
dérivée des sessions TCP, `chmod`, `--copy` ou `--backup`
avant l'inventaire complet des consommateurs.

## ✅ Acceptation réelle du correctif ss — worktree PR #300, 30/10/2026

**Preuve opérateur**, depuis un worktree détaché propre créé à partir de
`origin/docs/consolidate-openclaw-yubikey-handoff-20261030` au commit
`245bd928` :

| Commande | Résultat constaté |
| --- | --- |
| `just yubikey-usb-identity-nfs-consumers-test` | **8/8 tests PASS** en 0,272 s ; compilation Python PASS |
| `just yubikey-usb-identity-nfs-consumers-check` | `BACKUP_RESTORATION_PREFLIGHT_READY` ; `NOT_PROBED` |
| `just yubikey-usb-identity-nfs-consumers-probe` | **`TCP_SNAPSHOT_OBSERVED`**, sortie JSON expurgée ; aucun secret ni adresse publié |

**Instantané serveur :** `tcp_sessions=1` et
`unique_tcp_peers=1`, TCP/2049, tous exports NFS TrueNAS confondus.
Le code retour est maintenant réussi : le précédent
`SS_RESPONSE_UNVERIFIED` (parseur `ss` pré-correctif)
est **résolu à ce point d'observation**.

**Limites inchangées :** `scope=ALL_NFS_EXPORTS_TCP2049_ONLY`,
`all_clients_enumerated=false`,
`export_specific_clients_verified=false` et
`consumer_allowlist_verified=false`. Le pair observé ne peut pas
être attribué à l'export `lab` sur ce seul relevé. Les montages
intermittents, les clients hors ligne, les jobs planifiés et la
configuration pare-feu restent hors de ce contrôle. Les trois
avertissements précédents sur le partage
(`NO_NFS_HOST_OR_NETWORK_FILTER`,
`NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED`,
`EXPORT_WRITABLE`) demeurent **ouverts**.

**Décision :** preuve de fonctionnement de la sonde clôturée,
**pas** preuve de sécurité effective de l'export. Ne pas modifier
`sharing.nfs.update`, `ro`, `hosts`, `networks`,
`chmod`, `setacl`, les archives age ou les clés SOPS.
La prochaine étape sûre est l'inventaire des montages/autofs et des
écritures légitimes sur tous les hôtes, puis une proposition
d'allowlist et rollback. L'attestation d'accès indépendant à la
phrase secrète demeure **NON ATTESTÉE**.

Cette section **remplace les statuts `NOT_RUN` des sections antérieures**
pour la sonde NFS TCP *après correction*. Les observations antérieures
restent conservées comme historique d'incident.
