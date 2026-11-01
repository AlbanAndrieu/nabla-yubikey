# Roadmap YubiKey : GnuPG, signatures Git, sauvegardes PostgreSQL, Vault

## Situation vérifiée (2026-10-16)

- Les deux YubiKeys ont leur OTP slot 2 HMAC-SHA1 fonctionnel pour KeePassXC.
- La clé GPG prioritaire pour Git et git-crypt est `F4C4B79A80826A5E5ADAD2C8B12DECD437E9E1C8`.
- La clé GPG FlowCrypt n'est plus utilisée, mais doit être conservée pour lire d'anciennes données si nécessaire.
- Les sous-clés GPG semblent locales (GnuPG `sec`/`ssb`); rien ne prouve leur présence sur la carte.
- Sur le poste Linux, GnuPG 2.4.8 et pcscd sont actifs. `ykman openpgp info` fonctionne,
  mais `gpg --card-status` renvoie `No such device` même après activation de `disable-ccid`.
- Le journal scdaemon rapporte `ccid open error: skip`. Le diagnostic doit distinguer
  conflit PCSC, sélection du lecteur, permissions et régression GnuPG; ne pas attribuer
  une cause unique sans preuve.
- Le certificat PIV Nabla Root CA dans slot 9A est autosigné, RSA2048,
  `CA:TRUE,pathlen:0`, `keyCertSign/cRLSign`, et expiré le 2025-01-22.
  Il ne permet pas une CA intermédiaire classique pour Vault; ne pas le réutiliser
  comme racine du futur chemin intermédiaire.

## Ordre d'exécution, sans mutation automatique

### P0 — Stabiliser GnuPG/PCSC et protéger les clés

- [x] Créer `scripts/workstation/diagnose-gpg-smartcard.sh --check`, lecture seule, sortie colorée.
- [ ] Comparer le résultat avec chacune des deux clés, une à la fois.
- [ ] Inspecter `systemctl status pcscd.service`, `journalctl --user -u gpg-agent`
      et les périphériques lecteurs. Les logs doivent être nettoyés avant partage.
- [ ] Après sauvegarde de `scdaemon.conf`, tester sur poste une seule variable
      à la fois : sélection du lecteur, puis option CCID/PCSC. Ne jamais désactiver
      un service système utilisé par d'autres applications sans étude d'impact.
- [ ] Définir un rollback local documenté et retester `gpg --card-status`.

**Critère de fin :** la carte répond depuis GnuPG sur les deux YubiKeys;
les logs ne contiennent plus d'erreur bloquante. Pas de rotation de PINs.

### P0 — Signature Git et déchiffrement des sauvegardes PostgreSQL

- [ ] Identifier les sous-clés de signature, de chiffrement et les destinataires
      exacts de Git-crypt et des sauvegardes PostgreSQL.
- [ ] Réaliser une sauvegarde privée hors ligne de GPG et une restauration contrôlée,
      avant tout `keytocard`.
- [ ] Confirmer `git commit -S` et `git verify-commit`, `git-crypt unlock`
      depuis une copie et déchiffrer/restaurer une sauvegarde PostgreSQL isolée.
- [ ] Concevoir deux identités matérielles utilisables après panne d'une seule clé.
      Une clé privée déjà installée sur la carte ne s'exporte pas; des clés de secours
      doivent provenir d'un escrow hors ligne ou d'une architecture de destinataires multiples.

**Critère de fin :** signature Git et restauration PostgreSQL opérationnelles
avec preuve de récupération indépendante du matériel.

### P1 — PKI Nabla Root CA et futur Vault / OpenBao

- [ ] Recenser les consommateurs historiques de la CA PIV expirée.
- [ ] Vérifier si un fichier CA historique existe et correspond à la clé publique
      PIV; sa présence n'est pas une preuve de sauvegarde valide.
- [ ] Concevoir une **nouvelle** CA racine hors ligne avec `pathlen` compatible
      avec la CA intermédiaire de Vault et rotation/révocation documentées.
- [ ] Concevoir des sauvegardes chiffrées et un test de signature hors ligne.
- [ ] Mettre en place une CA intermédiaire Vault/OpenBao séparée,
      sans dépendance circulaire au déverrouillage de Vault.

**Critère de fin :** test d'émission, chaîne complète validée,
récupération hors ligne démontrée; ancien slot 9A conservé jusqu'à décision.

### P2 — SSH, PAM, age, keyring

- [ ] SSH FIDO2/PIV : identités distinctes par clé et recovery.
- [ ] PAM U2F : enregistrer deux clés avant de rendre la vérification obligatoire.
- [ ] age-plugin-yubikey : identifier les slots PIV libres, tester des destinataires multiples.
- [ ] GNOME Keyring : étudier l'auto-unlock sans dépendance circulaire au login FIDO2.

## Procédure manuelle et retour arrière pour scdaemon

Le diagnostic n'effectue aucune correction automatique :

```bash
bash scripts/workstation/diagnose-gpg-smartcard.sh --check
```

Pour revenir à l'état antérieur de la modification déjà effectuée
sur `~/.gnupg/scdaemon.conf`, **inspecter d'abord** `scdaemon.conf.bak`
et le fichier actuel; si la sauvegarde correspond réellement au bon état
antérieur, la restauration se fait manuellement après décision explicite.
Le redémarrage de scdaemon affecte les sessions GPG en cours, donc doit
être fait en dehors des opérations Git/backup. Ne pas exécuter de
`gpg --edit-key`, `keytocard`, `ykman piv reset`, ni d'édition PAM
comme diagnostic.

Documentation : https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Options.html
et https://developer.hashicorp.com/vault/docs/secrets/pki

## TrueNAS : exécution sans YubiKey locale (retour opérateur)

Sur TrueNAS, GnuPG 2.4.7 est installé et GNUPGHOME pointe vers
`/mnt/cpool/home/albandrieu/.gnupg`. `ykman` est absent, `pcscd`
est inactif et le contexte systemd utilisateur n'a pas répondu.
Aucun accès matériel YubiKey n'est confirmé. Dans cet environnement,
`gpg --card-status` échoue normalement s'il n'y a ni lecteur connecté,
ni passthrough CCID. Cela **ne prouve pas** une panne GPG du serveur.

Exécuter le mode hôte (aucun appel matériel) :

```bash
bash scripts/workstation/diagnose-gpg-smartcard.sh --host-only
```

Ne pas installer `ykman` ni activer `pcscd` sur TrueNAS uniquement
pour faire réussir ce test. Réserver l'audit matériel au poste Linux
ayant la clé branchée. Pour les sauvegardes PostgreSQL, TrueNAS
devrait normalement pouvoir chiffrer vers une clé **publique**,
sans héberger la clé privée GPG ni avoir besoin de la YubiKey.
Vérifier l'architecture réelle avant de changer les jobs de backup.

## Workstation 11110002 — second diagnostic (2026-10-16)

Operator output: `pcscd.socket` and `pcscd.service` active,
`gpg-agent` active, GnuPG 2.4.8, `disable-ccid` configured,
`ykman openpgp info` succeeds, `SCD GETINFO version` succeeds,
but `gpg --card-status` still reports `No such device`.
This narrows the problem to the **selection/use of a smartcard reader**,
not to the existence of the OpenPGP applet.

Next steps, keeping the OTP HMAC slot 2 and PIV 9A untouched:

1. Run the updated read-only diagnostic, which probes
   `SCD GETINFO reader_list`, `SCD SERIALNO`, and `pcsc_scan` if
   installed. No card numbers or raw ATR are printed.
2. Check for unrelated processes holding the PC/SC reader (browser,
   SSH-agent alternatives, smartcard middleware), ideally with all
   browser and certificate UI clients closed before retrying.
3. If there is an identified reader name, evaluate a *manual,
   reversible* `reader-port` configuration on the workstation; test
   a single variable per run and retain the previous config.
4. Investigate GnuPG 2.4.x specific CCID/PCSC behavior and the
   GnuPG upstream issue T4998. Do not enable `pcsc-shared` blindly;
   concurrent clients could invalidate scdaemon's cached state.
5. Do not attempt `keytocard` until `gpg --card-status` works,
   GPG escrow is validated, and PostgreSQL backup restore passes.

Known relevant upstream reports:
- https://dev.gnupg.org/T4998
- https://github.com/LudovicRousseau/PCSC/issues/215
- https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Options.html

## P0 — Test réversible du choix du lecteur PC/SC (17 octobre 2026)

Constat confirmé sur la workstation : `pcsc_scan` voit un lecteur
`Yubico YubiKey OTP+FIDO+CCID 00 00` avec carte insérée ; `ykman`
lit l'applet OpenPGP ; `gpg-connect-agent 'SCD GETINFO version'`
réussit, mais `SCD SERIALNO` et `gpg --card-status` renvoient
`No such device`. Un processus `scdaemon` tourne ; `disable-ccid`
est déjà activé. L'erreur de sélection n'est **pas** encore expliquée.

**Ne pas confondre** `SCD GETINFO reader_list` terminé par `OK`
avec une preuve que l'applet OpenPGP est sélectionnée. Ne pas
automatiser une correction non vérifiée sur le serveur TrueNAS.

### Préparation sur Linux (lecture seule)

```bash
gpgconf --list-dirs homedir
gpg-connect-agent 'SCD GETINFO app_list' /bye
gpg-connect-agent 'SCD GETINFO reader_list' /bye
timeout 5 pcsc_scan -n
grep -nE '^[[:space:]]*(disable-ccid|reader-port|pcsc-driver)' \
  ~/.gnupg/scdaemon.conf
```

La liste de lecteurs peut révéler un identifiant matériel ; ne pas
transmettre la sortie brute. Le lecteur PC/SC observé est
`Yubico YubiKey OTP+FIDO+CCID 00 00` ; vérifier le nom **exact**
localement avant tout essai de `reader-port`. D'après le manuel GnuPG,
`reader-port` accepte un nom de lecteur pour PC/SC ; son absence
n'est pas intrinsèquement une erreur, car le lecteur par défaut est
normalement le premier trouvé.

### Correction du runbook interactif (2026-10-17)

**Attention :** le bloc d'essai précédent commençait par `set -e`
dans le shell interactif. Si `test ! -e "$BACKUP"` échoue parce
que le fichier existe, Bash peut fermer le terminal. De même,
`gpg --card-status` renvoie un code non nul tant que la carte
n'est pas sélectionnée. **Ne pas lancer `set -e` directement dans
le terminal.** Pour désactiver ce mode dans la session :
`set +e`.

Une sauvegarde `scdaemon.conf.before-reader-port` existe déjà
sur la workstation. Ne pas l'écraser ni présumer de son contenu.
La restauration opérateur a réussi; contrôler les directives
actuelles en lecture seule avant un nouvel essai :

```bash
bash scripts/workstation/plan-gpg-reader-port.sh --check
grep -nE '^[[:space:]]*(disable-ccid|reader-port|pcsc-driver)' \
  "$(gpgconf --list-dirs homedir)/scdaemon.conf" || true
```

Pour éviter toute sortie intempestive d'une session interactive,
effectuer le diagnostic de la carte en conditionnelle :

```bash
if gpg --card-status; then
  echo '✅ Carte accessible'
else
  printf '⚠️ Carte inaccessible (code %s)\n' "$?"
fi
```

Le `dmesg` partagé comporte **quatre segfaults dans
`libpcsclite_real.so.1` le 16 octobre**. Leur nom de thread
(`pool-0`, `pool-1`, `pool-3`) ne permet pas
d'attribuer l'incident à `scdaemon` sans identification du
processus via `coredumpctl` et les événements système.
Ces erreurs sont antérieures aux manipulations USB volontaires
du 17 octobre. Priorité à une identification non destructive :

```bash
coredumpctl list --since '2026-10-16 00:00:00' --no-pager \
  2>/dev/null | grep -E 'libpcsclite|pool-|gpg|scdaemon' || true
journalctl -k --since '2026-10-16 00:00:00' --until '2026-10-17 00:00:00' \
  --no-pager | grep -F 'libpcsclite_real.so.1' || true
```

Ne pas transmettre de dump mémoire ni lancer `coredumpctl dump` :
un processus lié à GPG peut contenir des informations sensibles.

### Essai supervisé (modifie uniquement scdaemon.conf local)

Ce test est à exécuter seulement après avoir terminé les opérations
Git signées ou les sauvegardes qui utilisent GPG :

```bash
umask 077
# Stopper manuellement si le backup existe, sans activer set -e dans le shell.
if [[ -e ~/.gnupg/scdaemon.conf.before-reader-port ]]; then
  echo '⚠️ Sauvegarde existante : interrompre et vérifier avant toute modification.'
else
  cp -p ~/.gnupg/scdaemon.conf ~/.gnupg/scdaemon.conf.before-reader-port
  echo '✅ Sauvegarde créée ; les étapes suivantes sont à lancer séparément.'
fi
# Vérifier que le nom du lecteur correspond exactement à pcsc_scan.
printf '%s\n' 'reader-port Yubico YubiKey OTP+FIDO+CCID 00 00' \
  >> ~/.gnupg/scdaemon.conf
gpgconf --kill scdaemon
gpg --card-status
```

Si le test échoue, **rollback** après vérification que le fichier
`.before-reader-port` est bien la sauvegarde de cet essai :

```bash
cp -p ~/.gnupg/scdaemon.conf.before-reader-port ~/.gnupg/scdaemon.conf
gpgconf --kill scdaemon
gpg --card-status
```

Ne pas utiliser `gpgconf --kill all`, `systemctl restart pcscd`,
`keytocard`, ni reprogrammer la carte dans le cadre de cet essai.
Ne pas répéter ce test si la configuration contient déjà un
`reader-port` ou si une sauvegarde du même nom existe : préserver
les modifications précédentes et arbitrer manuellement.

Source : https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Options.html

### Observation PC/SC du 17 octobre à 12:33

`timeout 5 pcsc_scan -n` détecte `Yubico YubiKey OTP+FIDO+CCID 00 00`
et un ATR identique lors de deux lectures. Le scanner affiche
successivement `Card inserted, Shared Mode`, puis `Waiting for the
first reader` avant de retrouver la carte. **L'opérateur a explicitement débranché et rebranché la clé** pour
vérifier la détection : cette réénumération USB est attendue et
**ne constitue pas un indice d'instabilité matérielle**.

Prochain contrôle en lecture seule : relevé ciblé des événements
`journalctl -k --since '-10 min' --no-pager` et
`journalctl -u pcscd.service --since '-10 min' --no-pager` autour
d'une seule tentative `gpg --card-status`. Inspecter localement
les identifiants et chemins avant de partager les journaux.
Ne pas redémarrer PC/SC et ne pas changer de slot.

### Clarification opérateur — 17 octobre 2026, 12:36

Les déconnexions/reconnexions USB de 12:33 sont **volontaires**.
Les erreurs PC/SC `SCardConnect ... Not Found` à 12:33:28
correspondent à la période de réénumération et ne prouvent
aucune panne persistante du lecteur. Une nouvelle tentative
`gpg --card-status` à 12:36:31 échoue toujours par
`No such device` alors que la carte est connectée.

**Priorité corrigée :** investiguer la sélection de l'applet par
`scdaemon` et la configuration GnuPG/PCSC, plutôt que l'USB.
Ne pas demander d'autres cycles de débranchement ni redémarrer
`pcscd` sans justification. La procédure réversible `reader-port`
reste une hypothèse à tester, non une correction confirmée.

### Préflight automatisé, strictement en lecture seule

Avant l'essai manuel de `reader-port`, exécuter sur la workstation :

```bash
bash scripts/workstation/plan-gpg-reader-port.sh --check
```

Ce préflight vérifie `disable-ccid`, l'absence de `reader-port` déjà
configuré, l'absence de sauvegarde homonyme et la visibilité du lecteur
YubiKey avec carte insérée. Il **ne modifie rien**, n'émet aucun
identifiant de carte et ne lance pas `gpgconf --kill`. Il refuse
également d'agir comme root ou de remplacer une ancienne sauvegarde.

Le journal USB observé à 12:33 correspond à une reconnexion volontaire,
pas à une panne USB prouvée. Une réussite du préflight ne garantit
pas la correction de `SCD SERIALNO`; elle autorise seulement la
préparation d'un essai supervisé et réversible.

### Corrélation coredump — 17 octobre 2026

L'opérateur confirme `errexit` inactif après restauration de la
configuration et présence du backup `scdaemon.conf.before-reader-port`.
Ne pas recommencer un essai de configuration avant examen du backup.

`coredumpctl list --since '2026-10-16 00:00:00'` identifie :
- Seahorse (`/usr/bin/seahorse`) SIGSEGV à 00:23:19, 09:02:49, 09:12:17 ;
- Nemo SIGSEGV à 02:39:18 et VS Code SIGSEGV à 18:40:09.

Le `dmesg` observait un segfault dans `libpcsclite_real.so.1`
**exactement à 00:23:19** : le processus correspondant est Seahorse.
Cette corrélation suggère un défaut ou usage problématique de la
bibliothèque PC/SC côté client GNOME. Elle ne démontre pas
que Seahorse bloque scdaemon lors des échecs GnuPG du 17 octobre.

Investigation non intrusive :
```bash
pgrep -a -u "$(id -u)" -f 'seahorse|scdaemon|gpg-agent' || true
coredumpctl info 2655324 --no-pager | grep -E 'Executable:|Signal:|Stack trace|libpcsclite' || true
```
Ne pas lancer `coredumpctl dump` ni partager la mémoire du processus.
Éviter `killall`, `gpgconf --kill all` et les redémarrages systemd
avant d'avoir identifié les clients concurrents.

### Résultat 17 octobre, 13:18 — Seahorse non actif

`pgrep` ne trouve que `scdaemon --multi-server` et
`gpg-agent --supervised`. Aucun processus Seahorse actif.
`coredumpctl info 2655324` confirme le crash de Seahorse dans
`libpcsclite_real.so.1`, fonction `SCardGetStatusChange`.
Les plantages antérieurs du client Seahorse sont avérés, mais ne
constituent pas une explication établie du `No such device` actuel.

Le diagnostic GPG a toujours les résultats suivants :
`ykman openpgp info` OK, `pcsc_scan` OK, `SCD SERIALNO` échoue.
Prochaine étape : contrôler les options applicables de `scdaemon`
et, si l'opérateur le souhaite, un essai contrôlé du seul `reader-port`
après inspection du backup préexistant. Ne pas lancer `set -e`
dans le terminal interactif. Éviter les opérations sur les clés
et les modifications PAM/USB.

### Validation opérateur : configuration restaurée (17 octobre 2026)

`cmp -s scdaemon.conf scdaemon.conf.before-reader-port` : **identiques**.
`gpgconf --check-options scdaemon` : entrée
`scdaemon:Smartcards:/usr/lib/gnupg/scdaemon:1:1:` (pas de
message d'erreur explicite). Le rollback précédent a restauré les
octets du fichier ; cela ne valide pas l'accès matériel OpenPGP.

Pour éviter qu'une erreur n'interrompe le terminal interactif,
**ne jamais coller `set -e` dans le shell de l'opérateur**. Utiliser
un script dédié en sous-processus avec contrôle des préconditions,
pas une séquence interactive qui continue après l'échec d'un
`test`. La sauvegarde existante est à conserver ; aucune routine
ne doit l'écraser. Avant un essai réel, confirmer que le poste
n'effectue ni signature Git ni déchiffrement GPG.

## Architecture PC/SC et hypothèse reader-port — décision P0 (17 octobre 2026)

### À quoi sert PC/SC ?

**PC/SC** (Personal Computer/Smart Card) est l'interface standard
permettant aux logiciels Linux d'utiliser les lecteurs de cartes à puce.
Sur Ubuntu, `pcscd` expose les lecteurs CCID et arbitre leur accès via
`libpcsclite`. `pcsc_scan` **énumère le lecteur et voit la carte** :
il ne démontre pas que GnuPG a sélectionné l'application OpenPGP.

Le chemin recherché est :
`gpg --card-status` → `gpg-agent` → `scdaemon` →
bibliothèque PC/SC → `pcscd` → interface USB CCID →
applet OpenPGP de la YubiKey.

`ykman openpgp info` constitue un contrôle **indépendant** : son
succès confirme que le périphérique et l'applet répondent par le
chemin choisi par ykman, pas nécessairement que `scdaemon` sait
utiliser le même lecteur.

### Que fait reader-port ?

Dans `~/.gnupg/scdaemon.conf`, `reader-port` indique **quel
lecteur** scdaemon doit sélectionner. En mode PC/SC, la valeur
peut correspondre au nom du lecteur (à confirmer sur la machine).
Ce n'est ni un port TCP, ni un port USB physique, ni un secret,
et ce n'est **pas une modification sur la YubiKey**.

`disable-ccid` demande à scdaemon de ne pas employer son
pilote CCID intégré et de privilégier la pile PC/SC. L'absence
de `reader-port` est normalement valide : scdaemon sait
chercher un lecteur. L'essai d'une sélection explicite est donc
**un test d'hypothèse, pas un correctif présumé**.

### Pourquoi le tester dans notre cas ?

Observations confirmées sur workstation : lecteur
`Yubico YubiKey OTP+FIDO+CCID 00 00` et carte visibles par
`pcsc_scan`, applet visible par `ykman`, `scdaemon`
répond à `GETINFO version`, mais `SCD SERIALNO` et
`gpg --card-status` répondent `No such device`.
Un `SCD GETINFO reader_list` terminé par `OK` ne confirme
pas la sélection de l'applet. Seahorse n'était pas actif lors du
dernier échec ; ses SIGSEGV PC/SC antérieurs ne prouvent
pas qu'il soit la cause du blocage actuel.

### Protocole, garde-fous et critères d'acceptation

1. **Préflight déjà réussi :** `scdaemon.conf` et
   `scdaemon.conf.before-reader-port` sont strictement identiques ;
   aucun `reader-port` actif ; `pcsc_scan` voit la carte.
   Préserver la sauvegarde préexistante sans jamais l'écraser.
2. **Essai supervisé uniquement sur workstation :** terminer les
   opérations utilisant GPG ; vérifier le nom PC/SC exact ; appliquer
   *une seule* directive `reader-port` dans une procédure isolée
   qui contrôle toutes les erreurs. **Ne jamais activer `set -e`
   dans le terminal interactif de l'opérateur.**
3. **Rafraîchir seulement scdaemon** si et seulement si l'essai est
   autorisé ; comparer `SCD SERIALNO` et `gpg --card-status`
   avant/après, avec délai borné. Ne toucher ni à `pcscd`, ni
   aux PIN, ni aux slots OpenPGP/PIV/OTP.
4. **Succès :** la carte OpenPGP est affichée par
   `gpg --card-status`; vérifier séparément les deux YubiKeys
   sans transférer ou supprimer de sous-clé.
5. **Échec :** restaurer la sauvegarde octet pour octet, rafraîchir
   uniquement scdaemon, vérifier `cmp`, consigner les résultats
   et investiguer les traces PC/SC/GnuPG sans exfiltrer les dumps.

La continuité **Git signing, git-crypt et restauration des sauvegardes
PostgreSQL** est une condition préalable à tout futur transfert de
clé via `keytocard` ; ce chantier ne réalise aucun transfert.

Documentation de référence :
https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Options.html

### P0 — Essai transactionnel de reader-port (agent, 17 octobre)

Le script `scripts/workstation/test-gpg-reader-port.sh` sépare
`--check` (lecture seule) de `--apply` (essai supervisé).
Il contrôle l'égalité byte-à-byte du `scdaemon.conf` courant avec
`scdaemon.conf.before-reader-port`, la présence du lecteur,
`disable-ccid`, et l'absence de directive `reader-port`.
Il refuse root, ne remplace jamais la sauvegarde et ne modifie
aucune clé, certificat ou PIN.

`--apply` utilise un fichier temporaire dans le même répertoire
avec permissions préservées, sélectionne temporairement le lecteur
`Yubico YubiKey OTP+FIDO+CCID 00 00`, rafraîchit uniquement
`scdaemon` et teste `gpg --card-status` avec un délai borné.
Un trap restaure ensuite la sauvegarde et rafraîchit `scdaemon`,
même si le test réussit. Le script est exécuté dans un processus Bash
séparé : il ne change jamais `errexit` dans le terminal parent.
Les terminaisons brutales non interceptables (SIGKILL, coupure secteur)
ne permettent pas un rollback automatique : dans ce cas utiliser la
sauvegarde préexistante avant tout nouvel essai.

**Gates :** `bash -n`, test de contrat Python et mode Git 100755
dans l'environnement agent ; `--check` et `--apply` à exécuter
uniquement sur workstation une fois les opérations GPG terminées.
Si `--apply` annonce le succès, une décision explicite distincte
sera nécessaire avant toute configuration persistante.

### P0 — Résultat de l'essai transactionnel reader-port (17 octobre 2026)

Résultats de la workstation :
- `test-gpg-reader-port.sh --check` : préflight PASS ;
- `test-gpg-reader-port.sh --apply` : PC/SC PASS, mais
  `gpg --card-status` ne sélectionne pas la carte avec
  `reader-port Yubico YubiKey OTP+FIDO+CCID 00 00` ;
- le script annonce la **restauration réussie** de
  `scdaemon.conf` original. Ne pas répéter le même test.

**Conclusion :** la sélection explicite du lecteur ne suffit pas.
La cause reste non identifiée. Prochaines pistes : vérifier la
bibliothèque PC/SC réellement chargée par `scdaemon`, examiner
les journaux bornés `scdaemon` lors d'une seule tentative,
et tester séparément (sur un profil GnuPG isolé, sans clés privées)
le chemin CCID intégré versus PC/SC, avec contrôle de retour arrière.
Ne pas redémarrer `pcscd` arbitrairement ni modifier les clés,
les PIN, KeePassXC OTP, PIV ou Git-crypt.

### P0 — Liaison dynamique scdaemon / PC/SC (17 octobre, 14:19)

Le `ldd /usr/lib/gnupg/scdaemon` de la workstation retourne
`libgcrypt.so.20`, `libassuan.so.9` et `libusb-1.0.so.0`,
mais pas `libpcsclite.so.1`. Ce n'est **pas une preuve d'absence
de PC/SC** : scdaemon peut charger ce pilote dynamiquement.

`gpgconf --list-options scdaemon` confirme :
- `reader-port` (lecteur sélectionné explicitement, déjà essayé sans succès),
- `pcsc-driver` (valeur par défaut `libpcsclite.so.1`),
- `disable-ccid` (déjà présent dans la configuration),
- `disable-pinpad` (sans rapport démontré avec la sélection).

**Nouvelle hypothèse vérifiable :** pilote PC/SC mal résolu ou échec
lors du chargement dynamique ou de l'appel PC/SC par scdaemon.
Contrôles en lecture seule sur la workstation :

```bash
ldconfig -p | grep -F libpcsclite.so.1 || true
readlink -f /usr/lib/x86_64-linux-gnu/libpcsclite.so.1
pgrep -a -u "$(id -u)" -x scdaemon || true
# En cas de processus scdaemon actif, confirmer le pilote chargé
for pid in $(pgrep -u "$(id -u)" -x scdaemon); do
  grep -F libpcsclite /proc/"$pid"/maps || true
done
```

La présence de la bibliothèque sur disque confirme sa disponibilité
pour le chargeur ; son absence dans `/proc/PID/maps` **à cet instant**
ne prouve pas qu'elle n'a jamais été chargée. L'essai `reader-port`
a échoué avec rollback réussi ; ne pas le répéter à l'identique.
Aucune réinitialisation ou transfert de clés.

### P0 — Vérification bibliothèque disponible, processus absent (17 octobre)

`ldconfig -p` résout `libpcsclite.so.1` vers
`/usr/lib/x86_64-linux-gnu/libpcsclite.so.1`, et
`readlink -f` confirme le même chemin. La boucle
`pgrep -u "$(id -u)" -x scdaemon` n'a affiché aucun PID au
moment du contrôle : impossible de consulter `/proc/PID/maps`.
Ne pas conclure à une bibliothèque manquante ou non chargée.

Prochain diagnostic : interroger l'état de scdaemon immédiatement
après une tentative OpenPGP, dans **une seule session de commandes**
sans `set -e` interactif. Interroger `gpg-connect-agent` avec un
timeout, puis regarder les PIDs et mappings. Ne pas utiliser
`gpgconf --kill all`, ne pas créer de profil avec des secrets
et ne pas modifier `scdaemon.conf`.

### P0 — Scdaemon vivant, /proc/PID/maps restreint (17 octobre 2026)

L'opérateur a exécuté `SCD GETINFO version` : `D 2.4.8`,
`OK`. `gpg --card-status` échoue `No such device`. Un
`scdaemon --multi-server` PID 1053989 reste actif. Lire
`/proc/1053989/maps` comme l'utilisateur produit `Permission denied`.
Cela **ne prouve pas** que `libpcsclite` manque : accès `/proc`
potentiellement limité par les protections noyau/ptrace.
L'essai root `pgrep -u "$(id -u)"` cherchait UID 0, pas
l'instance UID 1000 : aucune conclusion possible de sa sortie vide.

Prochain contrôle sans privilèges : `gpgconf --list-options scdaemon`,
`ldconfig -p` et statut `pcscd` sont déjà validés. Si un contrôle
de mapping est indispensable, cibler le bon UID/PID, sans désactiver
les protections du noyau. Préférer ensuite un diagnostic isolé
`GNUPGHOME` temporaire pour comparer transport CCID intégré et
PC/SC, sans importer de clés privées, sans toucher aux slots, et
sans interrompre le profil GnuPG utilisateur.

### P0 — Comparatif isolé PC/SC / CCID intégré

`scripts/workstation/compare-gpg-card-transports.sh` compare deux
profils GnuPG temporaires (`GNUPGHOME`) sans clé importée :
- `pcsc` avec `disable-ccid` ;
- `ccid` sans `disable-ccid` (pilote CCID intégré).

`--check` valide les prérequis ; `--run` effectue deux lectures
`gpg --batch --card-status` bornées à 18 secondes chacune.
Les résultats masquent les identifiants de carte. À la fin,
les agents des **profils temporaires uniquement** sont arrêtés,
les répertoires temporaires supprimés, et le vrai profil
`~/.gnupg` reste inchangé. Ce test ne touche pas aux clés ni
aux PIN ; il accède cependant à la même interface USB physique,
donc ne pas effectuer en parallèle de signature ou déchiffrement.

```bash
./scripts/workstation/compare-gpg-card-transports.sh --check
./scripts/workstation/compare-gpg-card-transports.sh --run
```

Résultats à interpréter :
- PC/SC OK, CCID KO : défaut plutôt côté accès CCID intégré ;
- PC/SC KO, CCID OK : défaut probablement dans le chemin PC/SC ;
- tous deux KO : examiner contention, permissions du lecteur,
  configuration GnuPG, journal des erreurs scdaemon ;
- tous deux OK : défaut propre au profil utilisateur.

Le succès de `--run` ne migre aucune clé GPG. Ne pas
exécuter `keytocard`. En cas d'arrêt non interceptable, des
agents temporaires peuvent nécessiter une inspection avant nettoyage.

### P0 — Résultat comparatif transports, 17 octobre 2026

L'opérateur a exécuté `compare-gpg-card-transports.sh --check` :
PASS. L'essai `--run` sur deux homes GnuPG isolés a retourné
`No such device` avec **PC/SC** (`disable-ccid`) **et CCID
intégré** (sans `disable-ccid`). Le script a terminé avec le
nettoyage des profils temporaires. La configuration originale
et les clés privées restent inchangées.

**Décision :** ne pas reproduire l'essai `reader-port` et
ne pas refaire à l'identique le comparatif. Les deux pilotes
ont échoué dans le même environnement matériel/logiciel ;
cela oriente vers une cause commune (accès au périphérique,
contention de client, état USB, règles udev, journal scdaemon)
mais ne prouve pas une cause déterminée.

**Prochaine investigation P0, lecture seule :**
1. Contrôler les processus détenteurs d'une interface USB CCID :
   `lsusb` et `lsusb -t` (sans dump de descripteur privé),
   `fuser` ou `lsof` sur le périphérique USB sélectionné,
   ne pas déconnecter arbitrairement la clé.
2. Examiner `journalctl -u pcscd --since '10 minutes ago'`
   et les éventuelles erreurs CCID/scdaemon associées à
   une seule tentative **bornée**. Filtrer et anonymiser tout
   identifiant de carte avant publication.
3. Distinguer problème de droits (udev, groupe, ACL)
   d'une contention active ; ne pas désactiver la sécurité
   du système, ne pas réinitialiser PC/SC.
4. Si nécessaire, préparer une capture de debug scdaemon
   **isolée et expurgée** sans carte privée, jamais en mode
   `set -x`, avant toute autre action matérielle.

Ne pas modifier YubiKey OTP/HMAC KeePassXC, OpenPGP, PIV,
ni perturber signature Git, git-crypt ou restaurations.

### P0 — USB visible et client GUI YubiKey actif (17 octobre)

L'opérateur observe `1050:0407` (YubiKey 4/5 composite) sur
Bus 001, Device 044 ; interface 2 `Chip/SmartCard` utilisant
`usbfs` — comportement normal pour l'interface CCID pilotée en
espace utilisateur, pas une panne. `pcscd.socket` et
`pcscd.service` sont actifs. Aucun événement dans
`journalctl -u pcscd --since '20 minutes ago'` : ce silence
ne démontre ni fonctionnement parfait ni panne.

**Nouvel élément important :** `ykman-gui` est actif
(PID 2114157), simultanément à `scdaemon` (PID 1053989).
Il s'agit d'un **concurrent potentiel**, pas d'une preuve
de verrouillage. Le diagnostic détecte désormais ce client.

**Prochain test discriminant P0 :** terminer normalement
`ykman-gui` via son interface (ne pas `kill -9`) ;
attendre qu'il n'apparaisse plus dans `pgrep`, puis exécuter
une seule fois `gpg --card-status`. Ne pas débrancher la clé,
ne pas redémarrer `pcscd`, ne pas modifier les PIN ni
répéter les essais `reader-port`. Si toujours KO, investiguer
les journaux scdaemon et permissions USB, avec collecte expurgée.

### P0 — ykman-gui fermé, échec GnuPG persistant (17 octobre 2026)

Après fermeture normale de `ykman-gui`, `pgrep -a -u "$(id -u)" -f '[y]kman-gui'` est vide ; une nouvelle exécution de `timeout 15 gpg --card-status` retourne toujours :
`selecting card failed: No such device` et
`OpenPGP card not available: No such device`.

**Conclusion :** `ykman-gui` actif n'est pas une condition nécessaire de l'échec. Ne pas le désigner comme cause démontrée. Les hypothèses `reader-port`, comparatif PC/SC/CCID et fermeture GUI ont été testées sans résolution.

**Prochaines observations sûres :**
- Droits et type du nœud USB : `stat -c '%A %U:%G %n' /dev/bus/usb/001/044` (numéro de device susceptible de changer).
- Identité des clients actifs via `pgrep`, et messages `journalctl -u pcscd` (sans assurance que le journal soit rempli).
- Journal du démon GnuPG à capturer de manière bornée et expurgée, de préférence avec un homedir GnuPG isolé ; ne pas activer un niveau de trace qui expose les APDU, PIN, numéros de série ou secrets.
- Ne pas exécuter de nouvelle manipulation des slots, réinitialisation, redémarrage `pcscd`, ou changement de permissions globales.

### P0 — ACL USB validées, pas de concurrent identifié (17 octobre 2026)

`lsusb -d 1050:0407` : YubiKey détectée sur bus 001 device 044.
Nœud `/dev/bus/usb/001/044` : `crw-rw-r-- root:pcscd` et
ACL explicite `user:albandrieu:rw-` (masque `rw-`).
`pgrep` : seulement `pcscd` PID 4605 et `scdaemon`
PID 1053989 parmi les clients recherchés.

Les permissions DAC/ACL du nœud USB sont suffisantes pour
l'utilisateur ; ne pas modifier les ACL, groupes ou règles udev
sans autre indice. Cette constatation ne prouve pas l'absence
d'un éventuel blocage LSM ou protocolaire.

**Prochaine étape discriminante :** déployer un diagnostic
`scdaemon` sur home GnuPG isolé, journaux de statut minimaux,
sans `debug-level guru`, `debug-ccid-driver`, `log-file`
contenant des APDU ni traces d'authentification. Tester
`SCD SERIALNO` et sa valeur de retour dans une session bornée
sans divulguer le numéro de série. Prioriser la vérification
de la pile GnuPG/pcsc-lite et des anomalies du processus,
pas de changements aux clés ou à l'interface USB.

### P0 — GETINFO reader_list retourne un identifiant CCID (17 octobre)

L'opérateur obtient `SCD GETINFO version` → `D 2.4.8`, `OK`,
et `SCD GETINFO reader_list` → `D 1050:0407:X:0%0A`,
`OK`. Aucune entrée USB/CCID/AppArmor n'est visible dans
`journalctl -k` filtré sur les 30 dernières minutes.

La chaîne `1050:0407:X:0` ressemble à l'identifiant de
lecteur USB CCID exposé par scdaemon ; elle prouve que le lecteur
est **énuméré**, mais pas que l'application OpenPGP a été
sélectionnée. Le suffixe `%0A` est l'encodage Assuan du
saut de ligne. Ne pas interpréter `X:0` comme un code d'erreur
sans preuve. Documentation GnuPG :
https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Options.html

**Contrôle suivant :** distinguer lecteur énuméré et session
applicative en demandant les statuts GnuPG à faible verbosité
et en examinant uniquement le **code** `SCD SERIALNO`.
Ne pas exposer les numéros de série ni utiliser de trace APDU,
`debug-level guru`, dump mémoire, ou opération `keytocard`.

### P0 — Code d'erreur SCD confirmé ; comparaison amont GnuPG (17 octobre)

`gpg-connect-agent 'SCD SERIALNO' /bye` retourne
`ERR 100696144 No such device <SCD>` (numéro de carte non
divulgué). Il s'agit de l'erreur de **scdaemon**, et non d'une
erreur d'accès du shell à `/dev/bus/usb`.

Documentation amont pertinente :
- https://lists.gnupg.org/pipermail/gnupg-users/2024-April/067055.html :
  un utilisateur observe **le même code 100696144** avec
  GnuPG 2.3/2.4, mais un fonctionnement avec 2.2 ; cela établit
  un précédent, **pas la cause de notre panne**.
- https://lists.gnupg.org/pipermail/gnupg-users/2022-January/065855.html :
  `1050:0407:X:0` est une chaîne typique d'énumération
  de lecteur CCID. Un seul lecteur n'exige pas forcément
  `reader-port`.
- https://dev.gnupg.org/T5632.html : pas de fallback
  automatique CCID vers PC/SC depuis GnuPG 2.3 ;
  notre comparatif isolé a déjà testé les deux chemins.

**Prochaine action prioritaire :** capturer uniquement les lignes
de diagnostic non sensibles de `scdaemon` sur un profil
temporaire, ou comparer une version GnuPG distribuée et
supportée dans un environnement totalement isolé sans modifier
les binaires système. Ne pas conseiller downgrade global, compilation
non contrôlée ou `debug-level guru`.

### P0 — Proposition de mise à niveau scdaemon, YubiKey débranchée

L'utilisateur autorise la préparation d'une mise à niveau `scdaemon`
et peut débrancher la YubiKey. **Aucune intervention sur son poste
n'a été exécutée à distance.** Version runtime actuelle
`scdaemon` / `gpg` : 2.4.8.

Ubuntu 26.04 (`resolute-updates`) publie le paquet `scdaemon`
`2.4.8-4ubuntu3.1` (même version GnuPG amont 2.4.8).
Ne pas promettre que ce rafraîchissement corrigera
`ERR 100696144 No such device <SCD>`.
Sources : https://packages.ubuntu.com/resolute-updates/scdaemon
et https://ubuntu.com/security/notices/USN-8720-1 .

**Gate de préinstallation sur workstation, clé retirée, sans modifier :**
```bash
. /etc/os-release
printf 'OS: %s (%s)\n' "$PRETTY_NAME" "$VERSION_CODENAME"
dpkg-query -W -f='${Package} ${Version}\n' scdaemon gpg-agent gnupg gpg 2>/dev/null || true
apt-cache policy scdaemon gpg-agent gnupg gpg
sudo apt-get -s --only-upgrade install scdaemon gpg-agent
```
Vérifier que le solveur ne planifie ni suppression ni changement
de distribution, et que `scdaemon` et `gpg-agent` ont des
versions compatibles. Si aucune version candidate supérieure,
**STOP** : ne pas forcer un downgrade/upgrade externe.

Après validation explicite de la simulation uniquement, procéder
à une mise à jour via paquets officiels Ubuntu :
`sudo apt-get --only-upgrade install scdaemon gpg-agent`.
Reporter toute signature/déchiffrement GPG pendant
l'opération. Ne pas remplacer manuellement le binaire,
ne pas changer PIN, slots OpenPGP, OTP HMAC ou PIV.
Une fois les paquets installés, redémarrer seulement
`scdaemon` si nécessaire (`gpgconf --kill scdaemon`)
après fermeture des sessions GPG, reconnecter la YubiKey
et comparer `gpg --card-status`. Conserver les résultats
et les versions installées. Toute mise à niveau majeure de
GnuPG requiert un test séparé en environnement isolé.

### P0 — Mise à niveau Ubuntu indisponible (17 octobre 2026)

L'opérateur a confirmé Ubuntu **26.04.1 LTS resolute**.
`gnupg`, `gpg`, `gpg-agent` et `scdaemon` sont déjà installés
en **2.4.8-4ubuntu3.1**. `apt-cache policy` montre la même version
comme candidate depuis `resolute-updates`/`resolute-security`.
La simulation puis la commande effective
`apt-get --only-upgrade install scdaemon gpg-agent` retournent
`0 upgraded, 0 newly installed, 0 to remove` ;
**aucun paquet GnuPG n'a été changé**.

**Décision :** fermer l'action « mettre à niveau scdaemon via apt »
comme *sans objet* sur ce poste. Ne pas répéter l'installation,
ne pas rétrograder globalement GnuPG, ni installer un paquet/ppa non
validé. Garder 19 autres mises à jour en attente hors périmètre P0.
Continuer par une investigation scdaemon à faible exposition
des données ; envisager une version alternative uniquement dans
un environnement isolé et vérifié.

### P0 — Nouvelle session scdaemon sans effet (17 octobre 2026)

Après la vérification que tous les paquets GnuPG et scdaemon sont
à jour sur Ubuntu 26.04.1 (`2.4.8-4ubuntu3.1`), l'opérateur a
exécuté `gpgconf --kill scdaemon` puis
`timeout 15 gpg --card-status`. La nouvelle session répond encore
`gpg: selecting card failed: No such device` et
`gpg: OpenPGP card not available: No such device`.

**Conclusion :** redémarrer scdaemon ne corrige pas la sélection
OpenPGP. Ne pas recommander une répétition des tests
`reader-port`, PC/SC contre CCID, fermeture GUI, mise à niveau APT
ou simple relance du démon sans nouvelle hypothèse.

**Prochaine piste :** comparer de façon contrôlée les capacités
de découverte / ouverture de l'applet OpenPGP de `ykman` avec
celles de GnuPG, en évitant toute écriture, APDU sensible, PIN,
dumps ou journalisation de secrets. Si une trace scdaemon est
nécessaire, configurer un home temporaire avec une journalisation
minimale et des résultats filtrés, sans toucher aux fichiers du
profil utilisateur. Ne pas conclure à une régression 2.4.8 sans
preuve expérimentale.

### P0 — RESTART scdaemon accepté, SERIALNO échoue (17 octobre 2026)

Sur la workstation, `ykman openpgp info` confirme que l'applet
OpenPGP 3.4 répond (firmware/app 5.4.3, compteurs PIN et Admin
PIN à 3). Dans la même session,
`gpg-connect-agent 'SCD RESTART' 'SCD SERIALNO' /bye`
retourne `OK`, puis
`ERR 100696144 No such device <SCD>`.

Il s'agit d'un différentiel confirmé entre deux clients :
`ykman` dialogue avec l'application OpenPGP mais
`scdaemon` ne parvient pas à la sélectionner.
`SCD RESTART OK` indique que la commande a été acceptée,
non que la sélection a réussi.

**Décision :** arrêter les essais redondants de redémarrage,
`reader-port`, basculement PC/SC/CCID et mise à niveau apt.
Ne pas changer les PIN ni réinitialiser l'applet. Préparer une
instrumentation minimale et isolée de `scdaemon` avant
toute nouvelle manipulation de la carte, sans logs APDU
ni extraction de secrets.

## Recherche amont approfondie — piste pcsc-shared (17 octobre 2026)

**Priorité P0 suivante :** tester `disable-ccid` **avec**
`pcsc-shared` dans un `GNUPGHOME` jetable et isolé.
Les essais déjà réalisés n'incluaient pas `pcsc-shared`.
Il ne s'agit pas de répéter le comparatif PC/SC/CCID :
le nouveau facteur expérimental est **le mode d'ouverture PC/SC**.

### Éléments amont et limites des preuves

- https://dev.gnupg.org/T5712 — un cas YubiKey 5 NFC a été
  amélioré en activant `pcsc-shared`.
- https://lists.gnupg.org/pipermail/gnupg-users/2022-January/065739.html —
  un utilisateur YubiKey 5 confirme le retour de `gpg --card-status`
  après `pcsc-shared`.
- https://dev.gnupg.org/T5436.html — un autre utilisateur avait
  besoin de `pcsc-shared` pour contourner `No such device`,
  mais a rencontré des problèmes de cache PIN.
- https://lists.gnupg.org/pipermail/gnupg-users/2024-April/067055.html —
  GnuPG 2.4.5 échouait dans un cas alors que 2.2.42 fonctionnait ;
  **l'auteur indique que `pcsc-shared` ne corrigeait pas son cas**.
- https://dev.gnupg.org/T6383.html — le même `ERR 100696144`
  peut aussi masquer `LIBUSB_ERROR_ACCESS` ; le code n'identifie
  pas à lui seul le défaut.
- https://gnupg.org/documentation/manuals/gnupg26/scdaemon.1.html —
  `pcsc-shared` est un mode **explicitement déconseillé par défaut**
  par GnuPG : sélection d'applet et état du PIN peuvent devenir
  incohérents lorsqu'il y a d'autres clients.
- https://dev.gnupg.org/T5484 — détails sur interférence des
  clients PC/SC et invalidation des états OpenPGP/PIV.

### Protocole proposé, sans intervention sur les clés

1. Préflight côté agent : vérifier l'existence de l'option dans
   `scdaemon --dump-options` (ou `gpgconf --list-options scdaemon`).
2. Dans un dossier temporaire `GNUPGHOME` mode 0700, écrire
   uniquement `disable-ccid` et `pcsc-shared`.
   Ne copier aucun `gpg-agent.conf`, trousseau ou secret de
   `~/.gnupg`. Ne pas stopper le daemon utilisateur principal.
3. Demander une unique lecture `gpg --batch --card-status`
   à délai borné, en supprimant l'affichage de l'identifiant de
   carte. Fermer uniquement l'agent temporaire, supprimer ses
   fichiers et vérifier que le profil principal est inchangé.
4. **Si succès :** `pcsc-shared` est un contournement possible,
   pas une résolution prouvée de la cause racine. Réévaluer le
   risque de concurrence et de PIN avant toute activation durable.
5. **Si échec :** ne pas persister l'option. Préparer des logs
   `scdaemon` filtrés (sans APDU, PIN ou secrets) et comparer
   les versions GnuPG dans un espace isolé, pas en remplaçant
   les paquets Ubuntu.

**Ne pas** modifier OpenPGP/PIV/OTP, installer de PPA,
changer les ACL USB, tenter un PIN, activer `debug-level guru`
ou désactiver les mécanismes de protection.

### P0 — Correction du contrôle de disponibilité pcsc-shared

La commande initiale `scdaemon --dump-options | grep -E
'^pcsc-shared$|^disable-ccid$'` a retourné une sortie vide.
**Ce résultat ne permet pas de conclure que l'option est absente :**
`--dump-options` peut afficher le préfixe `--` que le filtre
rejetait. La source GnuPG documente explicitement
`--pcsc-shared` et `--disable-ccid` :
https://gnupg.org/documentation/manuals/gnupg26/scdaemon.1.html

Contrôles corrigés **lecture seule**, compatibles avec les deux
formes de sortie et sans risquer `set -e` interactif :

```bash
/usr/lib/gnupg/scdaemon --dump-options 2>&1 |
  grep -E -- '(^|[[:space:]])--?(pcsc-shared|disable-ccid)([[:space:]]|$)'
gpgconf --list-options scdaemon | grep -E '^(pcsc-shared|disable-ccid):'
```

Ne lancer aucun essai `pcsc-shared` avant d'avoir vérifié la
disponibilité sur le binaire installé. Sa documentation signale
des risques d'incohérence d'état et de cache PIN en mode partagé :
préférer, si applicable, un `GNUPGHOME` jetable sans clé.

### P0 — Validation options pcsc-shared (17 octobre 2026)

La workstation confirme via `scdaemon --dump-options` les deux directives `--pcsc-shared` et `--disable-ccid`. L'absence de `pcsc-shared` dans `gpgconf --list-options scdaemon` ne suffit pas à contredire le binaire.

Un mode **`--pcsc-shared`** est ajouté à `scripts/workstation/compare-gpg-card-transports.sh`. Il crée un seul `GNUPGHOME` temporaire, contenant seulement `disable-ccid` et `pcsc-shared`, tente une lecture `gpg --batch --card-status` bornée, ne publie pas les données de la carte, puis ferme uniquement l'agent temporaire et nettoie. Ne pas utiliser de profil ou de clés privées réels. Le mode partagé est expérimental et peut affecter l'état de sélection et de PIN si d'autres clients sont actifs ; n'envisager aucune activation permanente sans analyse de risque.

```bash
./scripts/workstation/compare-gpg-card-transports.sh --check
./scripts/workstation/compare-gpg-card-transports.sh --pcsc-shared
```

### P0 — Succès expérimental confirmé avec pcsc-shared (17 octobre 2026)

**Résultat réel workstation :**
`./scripts/workstation/compare-gpg-card-transports.sh --pcsc-shared`
→ `✅ pcsc-shared: OpenPGP card detected`, suivi du nettoyage du
`GNUPGHOME` temporaire. Les deux essais précédents sans
`pcsc-shared` (PC/SC exclusif et CCID intégré) retournaient
`No such device`. Cela identifie le mode d'accès partagé PC/SC
comme **contournement fonctionnel pour la détection**, et non
comme résolution démontrée de la cause racine.

**Phase P0b — Acceptation avant activation durable :**
1. Conserver le profil habituel intact. Vérifier après l'essai :
   `cmp -s ~/.gnupg/scdaemon.conf
   ~/.gnupg/scdaemon.conf.before-reader-port` (si sauvegarde
   toujours présente), puis noter le résultat sans publier de
   données de carte.
2. Tester les deux YubiKeys séparément avec le profil temporaire
   si l'opérateur souhaite les utiliser pour OpenPGP. Ne copier
   aucune clé dans le profil de test.
3. Examiner les avertissements amont de `pcsc-shared` : une
   autre application PC/SC peut modifier la sélection de l'applet
   et l'état de vérification du PIN. Préférer l'absence de clients
   concurrents lors des opérations cryptographiques sensibles.
4. Ne **pas** conclure que la signature Git, la récupération
   `git-crypt` ou les sauvegardes chiffrées fonctionneront :
   la carte a été détectée mais ces opérations n'ont pas été
   validées ; en outre elles peuvent dépendre de clés différentes.
5. Une activation durable doit être une décision explicite,
   avec sauvegarde préservée, préflight, rollback automatisé,
   et tests de non-régression adaptés, sans `keytocard`,
   sans PIN ni changement de slots.

État : **P0 détection dans profil isolé = PASS** ;
**P0 intégration au profil principal et acceptation sécurité =
EN ATTENTE**. Aucun changement sur l'utilisateur réel.

### P0 — Contrôle final de non-régression du profil principal (17 octobre 2026)

Après la réussite de l'essai `--pcsc-shared` dans un
`GNUPGHOME` temporaire, l'opérateur a confirmé :

```text
cmp -s ~/.gnupg/scdaemon.conf \
  ~/.gnupg/scdaemon.conf.before-reader-port
✅ Configuration GnuPG principale inchangée
```

**Résultat validé :** le contournement `pcsc-shared` permet
à GnuPG de détecter l'applet OpenPGP 3.4 de la YubiKey en
mode PC/SC partagé, tandis que le profil GnuPG principal
reste identique à sa sauvegarde de référence.

**Statut opérationnel exact :**
- ✅ `ykman openpgp info` : applet accessible ;
- ❌ `gpg --card-status` sur le profil habituel : erreur
  `ERR 100696144 No such device <SCD>` constatée avant l'essai ;
- ❌ profil isolé PC/SC exclusif et pilote CCID intégré :
  `No such device` ;
- ✅ profil isolé `disable-ccid` + `pcsc-shared` :
  carte OpenPGP détectée ;
- ✅ configuration utilisateur d'origine préservée, comparaison
  binaire avec la sauvegarde réussie.

**Décision :** conserver ce contournement comme candidat
documenté, sans le présenter comme une correction persistante.
La cause racine du rejet de l'accès exclusif PC/SC reste
indéterminée. `pcsc-shared` peut exposer des risques d'état
de sélection d'applet / cache de PIN avec d'autres clients PC/SC.
Avant de modifier `~/.gnupg/scdaemon.conf`, préparer une
procédure transactionnelle réversible, identifier les clients
concurrents, confirmer le fonctionnement du lecteur sans prompt
PIN, puis faire accepter les impacts sur Git signing,
`git-crypt` et sauvegardes PostgreSQL. Ne pas lancer
`keytocard`, changer les PIN, ni altérer OTP HMAC/PIV.

### P0b — Essai d'intégration au profil principal, réversible (17 octobre)

Le script `scripts/workstation/trial-gpg-pcsc-shared.sh`
prépare un test du **profil GnuPG principal** :
- `--check` : préflight en lecture seule (non-root, sauvegarde
  historique existante et identique aux octets du fichier actif,
  présence `disable-ccid`, absence de `reader-port` et
  `pcsc-shared`, prise en charge binaire de `pcsc-shared`) ;
- `--trial` : créer un fichier de configuration provisoire dans
  le même répertoire et avec les permissions de l'original, ajouter
  `pcsc-shared`, rafraîchir **seulement** `scdaemon`,
  exécuter `gpg --batch --card-status` avec délai borné
  et **restaurer systématiquement** la configuration sauvegardée,
  même lorsque le test réussit.

Le script ne touche ni aux sous-clés, ni aux PIN, ni aux applets
OpenPGP/PIV/OTP. Il ne doit pas être exécuté pendant une
signature, un déchiffrement, ou lorsqu'une application concurrente
utilise la YubiKey. `SIGKILL`/panne électrique ne déclenchent pas
de trap ; le backup historique permet alors une restauration
manuelle. L'activation durable **n'est pas incluse** et
demandera une décision distincte après le retour d'expérience.

```bash
cd ~/w/nabla-compose && git pull --ff-only
./scripts/workstation/trial-gpg-pcsc-shared.sh --check
./scripts/workstation/trial-gpg-pcsc-shared.sh --trial
cmp -s ~/.gnupg/scdaemon.conf ~/.gnupg/scdaemon.conf.before-reader-port \
  && echo 'Configuration restaurée'
```

**Acceptation P0b :** succès de détection dans le profil utilisateur
et restauration du fichier, sans intervention sur les clés.
La disponibilité cryptographique de la signature Git et de
`git-crypt` reste à établir indépendamment ; ne pas introduire
de PIN pendant ce test.

### P0b — Validation opérateur du profil GnuPG principal (17 octobre)

Le script `trial-gpg-pcsc-shared.sh --check` a confirmé le
préflight et la prise en charge binaire de `pcsc-shared`.
Le mode `--trial` a ensuite produit :
`✅ Main GnuPG profile detects OpenPGP with pcsc-shared enabled temporarily`.
Le trap a indiqué `✅ Historical configuration restored byte-for-byte`.
Un contrôle `cmp -s ~/.gnupg/scdaemon.conf
~/.gnupg/scdaemon.conf.before-reader-port` indépendant a
également confirmé `✅ Configuration d'origine restaurée`.

**P0b validé :** mode partagé PC/SC efficace dans le profil
GnuPG usuel pour l'énumération de la carte, sans persistance.
**État du système :** `pcsc-shared` reste désactivé dans la
configuration réelle après rollback. Ne pas affirmer que
les signatures Git ou déchiffrements sont vérifiés.

**Prochain jalon P0c :** préparer une activation durable
idempotente et réversible avec sauvegarde immuable,
contrôles `gpg --card-status` et procédure
`--rollback` explicite. Analyser le risque
d'état PC/SC partagé ; validation des usages Git et
git-crypt distincte, sans transférer de clés ou dévoiler
de secrets. L'opérateur doit lancer volontairement
l'activation sur sa workstation.

### P0c — Activation persistante contrôlée et retour arrière (17 octobre)

Nouveau script : `scripts/workstation/manage-gpg-pcsc-shared.sh`
avec `--check`, `--apply` et `--rollback`. Il **ne touche
pas aux clés privées, PIN ou slots**. Avant toute écriture il
vérifie la sauvegarde historique immuable
`scdaemon.conf.before-reader-port`, puis compare le fichier
courant soit avec les octets de cette référence, soit avec la
version exactement dérivée par l'ajout de `pcsc-shared`.
Toute autre modification déclenche un arrêt (drift guard).
Le script ne remplace pas la sauvegarde historique.

`--apply` ajoute l'option au profil usuel, rafraîchit seulement
`scdaemon`, puis teste `gpg --batch --card-status` avec timeout ;
un échec de détection entraîne un rollback automatique vers la
sauvegarde. `--rollback` restaure la version originale vérifiée.
Les deux actions sont idempotentes lorsque l'état est déjà cible.
Une extinction brutale peut interrompre la transaction : la copie
historique reste disponible pour la restauration.

**Exécution supervisée, workstation uniquement**, après avoir
arrêté toute opération utilisant GPG et tout autre client CCID :
```bash
cd ~/w/nabla-compose && git pull --ff-only
./scripts/workstation/manage-gpg-pcsc-shared.sh --check
./scripts/workstation/manage-gpg-pcsc-shared.sh --apply
./scripts/workstation/manage-gpg-pcsc-shared.sh --check
# Retour arrière sur demande :
./scripts/workstation/manage-gpg-pcsc-shared.sh --rollback
```

**Point de vigilance sécurité :** le mode PC/SC partagé laisse
d'autres clients communiquer avec la carte et potentiellement
modifier la sélection d'applet ou l'état de validation du PIN.
Éviter les clients simultanés pendant les opérations sensibles.
Le PASS de `gpg --card-status` ne valide pas les opérations de
signature Git, `git-crypt` ou les restaurations PostgreSQL.
P1 doit les valider sans migration de clés. L'activation réelle
n'a pas été effectuée par l'agent.

### P0c — Activation persistante validée par l'opérateur (17 octobre 2026)

Après un `git pull --ff-only`, l'opérateur a exécuté :
- `manage-gpg-pcsc-shared.sh --check` → `Current managed state: original`, contrôle PASS ;
- `manage-gpg-pcsc-shared.sh --apply` → `Persistent pcsc-shared enabled and OpenPGP detected` ;
- `manage-gpg-pcsc-shared.sh --check` → `Current managed state: shared`, contrôle PASS.

**P0c PASS :** configuration principale désormais en
`disable-ccid` + `pcsc-shared`, carte détectée, état persistant
confirmé. La sauvegarde `scdaemon.conf.before-reader-port`
n'a pas été réécrite. En cas de régression :
`./scripts/workstation/manage-gpg-pcsc-shared.sh --rollback`.

**P1 à faire :** ne pas assimiler l'énumération OpenPGP à une
signature ou un déchiffrement réussi. Commencer par
`gpg --card-status`, puis relever les empreintes de sous-clés
disponibles et vérifier la configuration de signature Git
sans divulguer de clés privées. Toute signature de challenge
doit être explicitement supervisée et peut déclencher un PIN ;
vérifier l'identité du bon jeton avant d'autoriser une opération.
`git-crypt` et restauration PostgreSQL sont des validations
séparées. Ne pas essayer `keytocard`.

### P1 — Régression après activation persistante (17 octobre 2026)

Le profil principal annonce toujours `Current managed state: shared`
après `--apply` et `--check`, mais un test ultérieur
`timeout 15 gpg --card-status` retourne de nouveau
`No such device`. La configuration Git est
`commit.gpgsign=true`, avec une clé de signature déclarée.
**L'intégration P1 n'est donc pas validée ; la configuration
persistante n'implique pas une disponibilité persistante.**

Une explication plausible est une interaction PC/SC après le premier
succès : GnuPG avertit que `pcsc-shared` peut laisser un autre
client modifier la sélection d'applet ou l'état de la carte.
Un rapport de développement de juin 2026 signale un état
incohérent après passage de KeePassXC sur un Nitrokey 3 ;
**cela ne démontre pas le même défaut sur YubiKey**.
Sources :
https://gnupg.org/documentation/manuals/gnupg26/scdaemon.1.html
https://lists.gnupg.org/pipermail/gnupg-devel/2026-June/036307.html

Le script `manage-gpg-pcsc-shared.sh` offre désormais
`--verify` pour tester **l'accès réel** sans modifier la config.
`--check` reste uniquement une comparaison du fichier avec
le modèle attendu ; `--apply` sur configuration déjà active
valide désormais le fonctionnement au lieu d'annoncer un succès
sur la seule présence de l'option.

Investigation recommandée, sans redémarrage :
```bash
./scripts/workstation/manage-gpg-pcsc-shared.sh --check
./scripts/workstation/manage-gpg-pcsc-shared.sh --verify
pgrep -a -f '[p]cscd|[s]cdaemon|[y]kman|[s]eahorse|[k]eepassxc' || true
```
Ne pas utiliser `keytocard`, ne pas déclencher de signature
ni de saisie de PIN. Si la disponibilité n'est pas stable,
réexaminer le contournement avant toute validation Git.

### P0c — Clarification finale : carte volontairement retirée (17 octobre 2026)

**Correction d'interprétation :** l'opérateur explique avoir
volontairement retiré la YubiKey pour raisons de sécurité lors du
précédent `gpg --card-status` négatif. Le retour
`No such device` à ce moment **n'est pas une régression démontrée**
de `pcsc-shared` ; il est cohérent avec l'absence de carte.

Après réinsertion de la YubiKey de secours (numéro masqué dans
les sorties publiables), les contrôles sont tous positifs :
- `gpg --card-status` détecte un lecteur Yubico, applet
  OpenPGP 3.4 ;
- `manage-gpg-pcsc-shared.sh --check` annonce `shared` ;
- `manage-gpg-pcsc-shared.sh --verify` annonce
  `Live OpenPGP selection operational` ;
- `pcscd`, `scdaemon` et KeePassXC sont actifs.
  Ceci établit la coexistence pendant ce contrôle ponctuel,
  sans prouver la sécurité de toutes leurs opérations simultanées.

**Point de sécurité :** les trois emplacements OpenPGP
(signature, encryption, authentication) de cette carte sont
`[none]`. Ne pas confondre carte détectée et sous-clé GPG
stockée dessus. Le compte Git a `commit.gpgsign=true` et
`user.signingkey` configuré, mais l'usage de cette identité
sur carte n'est pas démontré. Aucune commande `keytocard`,
aucun changement de PIN, aucune écriture sur carte.

**Statut :** P0 accès OpenPGP **PASS pour la carte connectée** ;
P1 signature Git, récupération git-crypt et chiffrement/
restauration PostgreSQL **non validés**.

### P1 — Inventaire clés GnuPG et disponibilité de la carte (17 octobre 2026)

Sur la workstation, `gpg --list-secret-keys --keyid-format LONG`
pour l'identité Git configurée renvoie une clé principale
`sec rsa4096` de capacité `[SC]` (créée en avril 2022),
et une sous-clé `ssb rsa4096` de capacité `[E]`.
**Les marqueurs `sec` et `ssb` (sans `#` ni `>`)
indiquent la présence des composants secrets dans le trousseau
GnuPG habituel**, non un stub exclusif de smartcard.
`manage-gpg-pcsc-shared.sh --verify` renvoie toujours
`Live OpenPGP selection operational`.

La carte YubiKey de secours précédemment inspectée dispose
de trois slots OpenPGP vides. La clé logicielle Git et la
détection de l'applet YubiKey sont **deux faits distincts**.

**P1 — étape suivante :** valider une signature GPG locale sur
un message de test non sensible, puis vérifier cryptographiquement
sa signature avec la clé publique (sans faire de commit Git
ni écrire dans le dépôt). Cette opération peut exiger la
phrase de passe GPG et doit être explicitement supervisée.
Vérifier séparément la capacité à déchiffrer une fixture de test
pour la sous-clé `[E]` ; ne pas utiliser de sauvegarde
PostgreSQL de production ni de secret réel comme fixture.
Ne pas exporter les clés secrètes ni effectuer `keytocard`.

### P1 — Signature GPG logicielle : PASS (17 octobre 2026)

L'opérateur a signé une phrase de test non sensible via
`gpg --local-user <empreinte de signature Git> --armor --clearsign`,
puis validé le résultat avec `gpg --verify`.
GnuPG confirme `Good signature`, signée le 17 octobre 2026
avec la clé RSA principale `[SC]` attendue et confiance
`[ultimate]`. **P1 signature GPG logicielle = PASS.**

Ce résultat prouve la capacité à signer avec la clé privée
logicielle installée et à vérifier la signature ; il ne prouve
pas encore la signature d'un commit Git, ni la capacité à
déchiffrer via la sous-clé `[E]`, ni une récupération
`git-crypt`/PostgreSQL. Aucun slot YubiKey n'a été modifié.

Étape suivante : fixture de chiffrement éphémère et non
sensible, `gpg --encrypt --recipient <empreinte>`
puis `gpg --decrypt` et comparaison stricte de la sortie.
Utiliser un répertoire temporaire en permissions 0700
et nettoyage après contrôle ; ne pas écrire un secret réel,
ne pas inclure `--passphrase` sur la ligne de commande.

### P1 — Chiffrement GPG PASS et contrat du diagnostic enrichi (17 octobre)

L'opérateur a exécuté une fixture temporaire avec
`gpg --encrypt --recipient <identité Git>`, suivie de
`gpg --decrypt` et d'un `cmp` strict. GnuPG a confirmé
l'emploi de la sous-clé `rsa4096/87E6B8E5021D2E36`
datée du 22 avril 2022 ; le test affiche
`✅ P1 chiffrement/déchiffrement GPG validé`.
Ce test et la vérification précédente `Good signature`
valident l'usage **logiciel** de ces clés, pas leur présence
sur une YubiKey ni une restauration de backup de production.

**Diagnostic mis à jour :**
- `scripts/workstation/diagnose-gpg-smartcard.sh --check` :
  marque `pcsc-shared` comme directive de contournement
  attendue, précise la distinction GnuPG logiciel / carte,
  et vérifie sans export la présence de la clé secrète Git
  et d'une sous-clé secrète ;
- `scripts/workstation/audit-yubikey-capabilities.sh` :
  inventorie les slots OpenPGP de **la carte actuellement
  connectée** sans exposer les identifiants, signale le
  slot OTP 2 HMAC KeePassXC historiquement validé,
  et inspecte seulement la disponibilité de `ssh-agent`
  sans afficher les clés publiques ni leurs empreintes.

| Zone | État connu / attendu | À confirmer |
| --- | --- | --- |
| YubiKey secours | OpenPGP applet 3.4, clés Signature/Encryption/Auth vides lors de l'observation précédente | Nouvelle observation au diagnostic |
| OTP | Slot 2 HMAC-SHA1 KeePassXC testé sur les deux YubiKeys | Vérification facultative `--challenge`, attention au touch |
| GPG logiciel | Clé principale RSA4096 [SC] et sous-clé RSA4096 [E] présentes | Aucune migration `keytocard` |
| GPG signature | Signature locale cryptographiquement vérifiée | Commit Git signé encore à tester |
| GPG chiffrement | Roundtrip fixture non sensible validé avec sous-clé E | Récupération git-crypt et sauvegardes PostgreSQL |
| GPG carte | `disable-ccid` + `pcsc-shared` : `--verify` PASS si carte insérée | Test séparé de la clé principale/backup ; absence physique ≠ régression |
| SSH | `ssh-add -l` peut indiquer une identité chargée | Origine FIDO2/PIV/logicielle, usages SSH et FIDO2 non établis |
| PIV | Certificat 9A historique expiré et inapproprié pour une nouvelle CA | Inventaire par carte, sans reset |
| OATH/FIDO2 | Application accessible selon capacité matérielle | Identifiants et usages réels non inventoriés |

**Prochain gate P1 :** tester la signature Git dans un
repository jetable sans push et sans toucher à la branche
courante, puis contrôler séparément la récupération
`git-crypt` / sauvegardes à partir de fixtures non sensibles.
Ne jamais confondre clé GPG logicielle, carte OpenPGP, clé SSH
et clé PIV. Ne pas publier numéros de série, fingerprints SSH,
réponses HMAC, clés privées, PIN ou certificats non expurgés.

## P2 — Identité age matérielle YubiKey pour SOPS / fastapi-sample (étude du 17 octobre 2026)

Source consultée : `AlbanAndrieu/fastapi-sample@master:.sops.yaml`
(https://github.com/AlbanAndrieu/fastapi-sample/blob/master/.sops.yaml).
Elle définit un destinataire `age1...` **X25519 logiciel** pour
`.*\\.env\\.sops$`, YAML et JSON ; une règle
`secrets.*\\.yaml` associe age et AWS KMS dans un même groupe.
**Attention :** le nom littéral `.env.secret` ne correspond pas
à la règle `.*\\.env\\.sops$` ; vérifier les noms réellement
chiffrés et leurs métadonnées SOPS avant toute migration.

**Faisabilité : OUI, sous réserve d'un slot PIV disponible et
du support `age-plugin-yubikey`.** Une YubiKey 5 NFC peut héberger
une nouvelle clé matérielle age (clé P-256 via PIV et plugin).
Cela n'est pas une importation de l'identité X25519 existante :
elle doit rester disponible comme mécanisme de récupération.
SOPS récent peut accepter un destinataire
`age1yubikey1...` fourni par le plugin ; il faut vérifier la
version réelle `sops` et sa capacité à lire une identité
`AGE-PLUGIN-YUBIKEY-...` avant modification.

**Occupation constatée sur la YubiKey de secours :**
- OTP slots 1 et 2 **programmés** ; slot 2 HMAC KeePassXC : à préserver ;
- PIV 9A : clé RSA2048 + certificat CA historique expiré ; ne pas écraser ;
- PIV 9C / 9D / 9E : état **non connu**, ne pas présumer libres ;
- OpenPGP Sign/Enc/Auth observés vides : namespace distinct de PIV ;
- FIDO2, OATH et SSH : vérifier les usages sans provisionnement automatique.

`age-plugin-yubikey` emploie PIV (et ses emplacements supportés)
sans consommer les deux slots OTP ni les slots OpenPGP. Avant tout
provisionnement, contrôler les options de slots et leurs correspondances
dans la **version installée** du plugin. Préférer un slot PIV libre
compatible avec les usages du plugin, en évitant 9A. Un certificat
expiré sur 9A ne signifie pas que cet emplacement peut être effacé
sans conséquence.

**Séquence secure-by-design :**
1. Inventaire **lecture seule** par carte et par slot :
   `ykman piv info` (sortie à expurger),
   `command -v age-plugin-yubikey`,
   `command -v sops`, `sops --version`,
   `age-plugin-yubikey --help` si installé ; aucun `--generate`.
2. Vérifier sauvegarde/recovery de l'identité age actuelle
   **sans exporter ni divulguer la clé secrète**. Faire un test
   de déchiffrement de fixture existante sur stockage temporaire,
   jamais de dump des `.env.secret`.
3. Uniquement après décision explicite, provisionner une identité
   PIV age **nouvelle** dans un emplacement réellement libre,
   avec PIN non trivial et touch policy adaptée ; ne jamais reset PIV.
4. Ajouter son destinataire public comme **destinataire additionnel**
   (pas en remplacement de l'existant) dans les règles SOPS
   applicables. Attention aux groupes SOPS et à leur threshold.
   Tester d'abord une fixture, puis appliquer `sops updatekeys`
   aux fichiers chiffrés existants et valider le déchiffrement
   via clé logicielle **et** YubiKey séparément.
5. Stratégie de secours : seconde YubiKey avec identité distincte
   et destinataire additionnel si désiré, plus identité age
   logicielle protégée hors ligne. Documenter l'usage CI/serveurs :
   **ne pas** rendre le déchiffrement automatique dépendant
   d'une YubiKey physiquement absente.

**Ne jamais** copier `AGE-SECRET-KEY` dans Git, logs ou chat ;
ne pas écraser 9A, OTP2, PIV, OpenPGP ou SSH pour faire de la place.
Sources : https://github.com/str4d/age-plugin-yubikey ,
https://getsops.io/docs/reference/ ,
https://github.com/getsops/sops/blob/main/age/keysource.go .

### P2 — Relevé opérateur SOPS et correction du slot age (17 octobre 2026)

L'opérateur confirme `sops 3.13.3` installé via
`~/.local/share/mise/installs/sops/3.13.3/sops`,
`age-plugin-yubikey` **absent du PATH**, et
`ykman piv info` fonctionnel. Le PIN et PUK PIV affichent
3/3 essais ; la management key est AES256 et protégée par PIN.
Le slot 9A contient la clé RSA2048 et son certificat historique
expiré le 22 janvier 2025. **Ne pas modifier ce slot.**

**Correction de la première recommandation 9D :**
`age-plugin-yubikey` utilise normalement les slots PIV
*Retired Key Management* **82 à 95**, pas nécessairement 9D.
Le code du plugin accepte `--slot` en tant que slot retired.
La prochaine sélection devra donc porter sur un slot 82–95
réellement libre (par exemple 82, seulement après inventaire).
`ykman piv info` ne listant ici que 9A n'établit pas
l'absence de matériel cryptographique dans les slots retired ;
ne pas interpréter cette sortie comme une autorisation d'écrire.

**P2 phase préparatoire, lecture seule :**
1. Installer le plugin par une source/version vérifiée, idéalement
   paquet reproductible avec empreinte ou release signée ;
   ne pas lancer l'interface interactive par défaut si elle
   propose de provisionner la clé.
2. `age-plugin-yubikey --help`, puis `--list`
   pour inventorier les identités age existantes ;
   **pas de `--generate`, `--force` ou reset PIV**.
3. Vérifier le support des destinataires `age1yubikey1...`
   sous SOPS 3.13.3 via une fixture isolée, tout en conservant
   la clé X25519 actuelle comme destinataire.
4. Inventorier les slots 82–95 avant toute écriture.
   Ne pas publier CHUID, numéros de série ou certificats bruts.

Sources :
https://github.com/str4d/age-plugin-yubikey
https://github.com/str4d/age-plugin-yubikey/blob/main/src/main.rs
https://github.com/Yubico/Yubico.NET.SDK/blob/develop/docs/users-manual/application-piv/slots.md/

### Préparation outillage age-plugin-yubikey (17 octobre 2026)

Le bootstrap workstation existant `scripts/workstation/bootstrap-yubikey-manager.sh`
installe désormais **age-plugin-yubikey 0.5.1** (version épinglée)
avec `cargo install --locked`, ainsi que `libpcsclite-dev` et
`pkg-config` nécessaires à la compilation Linux. Prérequis : un
outil `cargo` approuvé et présent dans le PATH ; le script échoue
explicitement s'il manque. Le binaire Cargo est lié sous
`~/.local/bin/age-plugin-yubikey`. Mode `--check` : aucun changement.
Mode `--apply` : installation d'outillage uniquement, **aucune**
génération de clé, opération PIV ni modification OTP.

```bash
cd ~/w/nabla-compose && git pull --ff-only
bash scripts/workstation/bootstrap-yubikey-manager.sh --apply
bash scripts/workstation/bootstrap-yubikey-manager.sh --check
age-plugin-yubikey --help
age-plugin-yubikey --list
```

L'installation du plugin n'a pas été exécutée sur la workstation par
l'agent. Le résultat de `--list` doit être traité comme un inventaire,
non une autorisation de provisionner un emplacement PIV. Référence :
https://github.com/str4d/age-plugin-yubikey (prérequis PC/SC et Cargo).

### Installation age-plugin-yubikey : échec Cargo PC/SC et correction (17 octobre 2026)

L'opérateur a lancé `bootstrap-yubikey-manager.sh --apply`.
Ubuntu a confirmé `libpcsclite-dev 2.4.1-1` et
`pkg-config 2.5.1-4` déjà installés ; Cargo 1.93.1 a téléchargé
`age-plugin-yubikey 0.5.1`, puis la compilation s'est arrêtée
sur `pcsc-sys 1.2.1` : `Could not find a PCSC library`.
Le contrôle `--check` a ensuite justement signalé le plugin
absent. Le plugin **n'est pas encore installé** sur le poste.

Le bootstrap exécute désormais un contrôle préalable sur
`/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/pkgconfig/libpcsclite.pc`
et teste explicitement la résolution par `/usr/bin/pkg-config`.
Pour le sous-processus Cargo uniquement, il neutralise
`PKG_CONFIG_LIBDIR` et `PKG_CONFIG_SYSROOT_DIR`, et fournit
`PKG_CONFIG_PATH` pointant sur les répertoires pkg-config
système. Aucune variable globale de la session n'est modifiée.
Les avertissements Cargo sur les dépendances `yanked`
du lockfile ne sont **pas** la cause directe de ce build failed ;
un audit de dépendances reste recommandé.

Après récupération de la branche :
```bash
cd ~/w/nabla-compose
git pull --ff-only
bash scripts/workstation/bootstrap-yubikey-manager.sh --apply
bash scripts/workstation/bootstrap-yubikey-manager.sh --check
command -v age-plugin-yubikey
age-plugin-yubikey --version
age-plugin-yubikey --list
```

Si le préflight PC/SC échoue encore, remonter la sortie précise
du nouveau contrôle et `/usr/bin/pkg-config --modversion libpcsclite`,
sans retirer la carte, modifier les slots, réinitialiser PIV ou
fournir de PIN. Compilation locale non vérifiée par l'agent.

### P2 — Installation age-plugin-yubikey validée (17 octobre 2026)

L'opérateur confirme que la compilation Cargo de `age-plugin-yubikey
v0.5.1` s'est terminée avec succès (`Finished release`, `Installed
package`) après la correction des chemins PC/SC. Le bootstrap indique
`OK: age-plugin-yubikey 0.5.1 ready (no provisioning)` et la commande
`age-plugin-yubikey --version` affiche `0.5.1`. Le correctif du bootstrap
pour `libpcsclite` a donc été validé sur la workstation. L'avertissement
`num-bigint-dig v0.8.4` sur de futures incompatibilités Rust ne bloque
pas la version utilisée ; maintenir une tâche de suivi des dépendances.

**Étape suivante :** `age-plugin-yubikey --list` avec une YubiKey
connectée, puis cartographie des slots retired PIV 82–95. Il n'existe
aucune preuve de génération d'une identité age, et aucun changement PIV
n'a été effectué. Conserver l'identité age X25519 existante pour SOPS.

### P2 — Inventaire age-plugin-yubikey initial (17 octobre 2026)

Avec la YubiKey de secours connectée, l'opérateur rapporte que
`age-plugin-yubikey --list` ne retourne **aucune identité**. Ceci
indique qu'aucune identité reconnue par le plugin n'est listée sur
la carte à ce stade. Cela **ne prouve pas** que tous les slots
PIV retired 82–95 soient vides : d'autres usages PIV pourraient
y résider. Aucune identité age nouvelle n'a été générée.

Gate avant provisioning : inventorier les slots PIV retired, vérifier
les possibilités de restauration SOPS avec l'identité age logicielle
et tester d'abord un fichier chiffré de démonstration. Ne jamais
forcer un slot, effacer 9A ni toucher à l'OTP 2 KeePassXC.

## Répartition détaillée des slots PIV et gouvernance age (17 octobre 2026)

PIV signifie **Personal Identity Verification**. La YubiKey
héberge plusieurs applications **indépendantes** : OTP (dont
KeePassXC HMAC slot 2), OpenPGP (signature/chiffrement/auth),
FIDO2, OATH et PIV. Le numéro d'un slot PIV n'a **aucun**
rapport avec les numéros 1 et 2 des slots OTP.

### Slots PIV : terminologie exacte

| Identifiant hexadécimal | Fonction standard | Politique Nabla |
| --- | --- | --- |
| `9A` | PIV Authentication, clé/certificat pour authentification | **OCCUPÉ** : RSA2048 / ancien certificat « Nabla Root CA » expiré le 2025-01-22 ; ne pas effacer ni réutiliser |
| `9C` | Digital Signature, signature numérique, PIN normalement requis à chaque opération | Inconnu ; réserver pour signature PIV si besoin |
| `9D` | Key Management, clé d'accord/déchiffrement, PIN en général requis | Inconnu ; réserver à l'usage PIV classique |
| `9E` | Card Authentication, authentification de carte, opération normalement sans PIN | Inconnu ; préserver |
| `82`–`95` | **20 slots Retired Key Management** pour clés historiques de déchiffrement | **Candidats age-plugin-yubikey**, premier libre compatible seulement après inventaire |
| `9B` | Management Key PIV, clé symétrique, AES256 protégée par PIN constatée | Ne pas changer |
| `80`/`81` | Métadonnées PIN/PUK (pas de slots de clés asymétriques applicatives) | Ne pas changer |
| `F9` | Attestation des clés générées sur YubiKey | Réservé au constructeur/attestation ; ne pas écraser |

**Attention à l'hexadécimal :** les vingt emplacements retraités
sont `82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95`.
Sur le firmware 5.4.3, ces slots PIV sont pris en charge,
mais aucune disponibilité individuelle n'a encore été démontrée.
Il faut distinguer certificat présent, clé privée présente
et métadonnées absentes : l'absence d'un certificat visible ne
prouve pas systématiquement qu'un slot ne contient aucune clé.

### Répartition par application sur la YubiKey de secours

- **OTP 1 :** programmé, usage non documenté → préserver.
- **OTP 2 :** HMAC-SHA1 KeePassXC confirmé → préserver.
- **OpenPGP :** applet 3.4 reconnue par GnuPG avec
  `disable-ccid` + `pcsc-shared`; trois slots de clés
  Sign/Encrypt/Auth observés vides ; les clés GPG RSA4096
  (signature et déchiffrement de fixture validés) sont
  actuellement dans le trousseau **logiciel**, non dans PIV.
- **PIV 9A :** occupé (ancien certificat autosigné expiré).
  **PIV 9C/9D/9E et retired 82–95 : inconnus**, pas « libres ».
- **FIDO2 :** présent, identités SSH ou passkeys non inventoriées ;
  **OATH :** présent ; ne pas reset.
- **age/SOPS :** `age-plugin-yubikey 0.5.1` installé et
  `--list` vide sur la carte de secours : aucune identité
  reconnue trouvée, sans preuve de disponibilité de chaque slot.

### Plan d'allocation age / SOPS

| Slot proposé | Intention | Décision |
| --- | --- | --- |
| `82` | Première identité age pour SOPS | **Conditionnel** : après preuve qu'il est libre |
| `83` | Domaine cryptographique distinct / future rotation | Réserve conditionnelle |
| `84`–`95` | Rotations et déchiffrement historique | Ne pas provisionner par défaut |
| Seconde YubiKey, premier retired libre | Autre destinataire age, capacité de récupération | Identité indépendante et testée séparément |

La clé actuelle SOPS `age1...` X25519 reste destinataire
et facteur de récupération : **ne pas tenter de l'importer
dans un slot PIV**, ni modifier les règles des fichiers chiffrés
avant des tests hors production.

### Inventaire strictement en lecture seule

```bash
ykman piv keys info 9A
ykman piv keys info 82
ykman piv keys info 83
age-plugin-yubikey --list-all
```

Pour chaque slot PIV `82`–`95`, vérifier individuellement
avec `ykman piv keys info SLOT`. Cette commande expose
les métadonnées de clé si disponibles ; son échec ou la non-
présence d'un certificat n'autorise **pas** un écrasement.
Ne pas lancer `keys generate/import/move/delete`,
`certificates generate/import/delete`, `piv reset`,
`age-plugin-yubikey --generate` ou `--force`
avant la revue explicite d'un slot.

Sources officielles :
- https://docs.yubico.com/yesdk/users-manual/application-piv/slots.html
- https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html
- https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- https://github.com/str4d/age-plugin-yubikey

## Architecture cible « YubiKey full capabilities » — 17 octobre 2026

**Objectif :** couvrir avec deux YubiKeys les besoins de chiffrement,
déchiffrement, signatures, KeePassXC, SOPS/age, SSH, certificats
client, administrateurs Vault/OpenBao et sauvegardes du homelab.
**Ne pas confondre maximisation des capacités utiles avec saturation
des slots** : séparation des usages, récupération et continuité
de service priment. Aucune action d'écriture sur la carte n'est
autorisée par cette roadmap.

### Inventaire factuel du dernier contrôle

La YubiKey de secours connectée a livré :

```text
PIV 9A : RSA2048, IMPORTED, PIN ONCE, touch NEVER — OCCUPÉ
PIV 82 (RETIRED1) : ERROR No key stored — AUCUNE CLÉ
PIV 83 (RETIRED2) : ERROR No key stored — AUCUNE CLÉ
age-plugin-yubikey --list-all : aucun résultat communiqué
```

Les réponses de `ykman piv keys info 82` et `83`
sont des **observations explicites d'absence de clé**, plus
fortes que l'absence de certificat dans `piv info` ;
cela n'autorise toujours **pas** un provisionnement sans
contrôler le numéro de série, les politiques PIN/touch,
la récupération et les outils. L'occupation de `84–95`,
`9C`, `9D` et `9E` n'a pas été contrôlée. L'inventaire
n'établit rien sur la première YubiKey.

### Répartition proposée : les applications sont indépendantes

| Besoin | Interface / slots retenus | Prérequis et politique |
| --- | --- | --- |
| KeePassXC | OTP slot 2, deux YubiKeys | HMAC-SHA1 déjà programmé ; **ne jamais toucher à OTP2** ; maintenir une restauration KeePassXC |
| SOPS/age local | PIV retired **82** sur chaque clé | Deux clés P-256 indépendantes et deux destinataires publics ; **82 vide vérifié seulement sur la YubiKey de secours** ; ajouter aux destinataires X25519 actuels, sans remplacer |
| Rotation age / archives | PIV retired **83** puis 84–95 si nécessaire | **83 vide vérifié sur la clé de secours** ; réserver, pas provisionner maintenant ; préserver anciens destinataires pour déchiffrer les archives |
| Signature Git et certifications GPG | OpenPGP Signature, éventuellement sous-clé dédiée | GPG logiciel RSA4096 [SC] et tests de signature PASS ; sauvegarde/recovery + procédure Git avant tout `keytocard`, ne pas déplacer automatiquement la clé primaire |
| Chiffrement e-mails OpenPGP | OpenPGP Encryption | Sous-clé distincte, historique de déchiffrement préservé ; GPG logiciel RSA4096 [E] et fixture PASS ; deux clés physiques ne sont pas des clones |
| Signatures de documents et PDF | OpenPGP Signature ou PIV 9C + logiciel PDF compatible | Pour les **signatures PDF intégrées** et S/MIME, certificat X.509 approprié en PIV 9C ; ne pas assimiler signature GPG détachée et signature PDF PAdES |
| Chiffrement de PDF et fichiers | OpenPGP Encryption ou age PIV 82 | Envelopper le PDF dans un fichier `.gpg`/`.age` plutôt que supposer prise en charge universelle d'un PDF chiffré natif ; plusieurs destinataires de récupération |
| SSH humain | FIDO2 SSH `ed25519-sk` si compatible | Générer de **nouvelles** identités SSH par clé, enregistrer les publiques partout où nécessaire et garder un accès SSH de secours ; inventorier les passkeys et agents existants |
| PIV 9A, authentification client | **Préserver la clé RSA2048 importée** et certificat Nabla Root CA expiré | Inventorier usages avant migration, ne pas la transformer en racine PKI de confiance actuelle |
| PIV 9C et 9D | Réserver pour signature de documents / S/MIME ou identité client | Vérifier disponibilité réelle ; définir certificats, renouvellement et PIN/touch spécifiques ; ne pas réutiliser la même clé pour tous les usages |
| PIV 9E | Réserver à authentification de carte | Vérifier occupation et pertinence ; pas de déploiement automatique |
| Sites publics (bababou.com, autres domaines) | ACME automatisé côté proxy/serveur, DNS challenge si utile | **Ne pas dépendre d'une YubiKey hors ligne** pour le TLS en continu ; clés TLS privées sur le serveur avec permissions/rotation, clés d'administrateur protégées par YubiKey |
| Futur Vault / OpenBao PKI | Root CA **hors ligne**, CA intermédiaire serveur pour l'émission | Une YubiKey peut protéger une **clé d'opérateur** ou un certificat administrateur, pas servir seule de HA CA / auto-unseal ; garder séparation des rôles et rotation |
| Initialisation Vault, recovery/unseal | Initialisation en environnement contrôlé, Shamir ou auto-unseal pris en charge | Ne jamais mettre l'unique master/recovery key sur une seule YubiKey ; remettre les parts à des détenteurs distincts et les conserver sous chiffrement indépendant ; tester scénario perte de carte |
| Sauvegardes TrueNAS/PostgreSQL | age et/ou GPG avec identité de récupération hors ligne + destinataires matériels | Tests d'encrypt/decrypt puis **restauration complète isolée** ; CI et services automatiques ne dépendent pas d'un jeton physique absent |
| age / SOPS CI | Identité automatique séparée avec droits minimaux et secret manager | Ne pas exposer la clé age logicielle dans le dépôt ; éviter de rendre l'automatisation dépendante du PIN ou touch physique |
| 9B, 80, 81, F9 | Management Key, PIN, PUK et attestation | Emplacements spéciaux PIV, **pas** utilisables comme espaces libres age ; aucun reset |

### Modèle de récupération et de défaillance

Les clés générées dans une YubiKey ne sont normalement pas
exportables. Chaque YubiKey reçoit des clés **différentes** ;
on chiffre à plusieurs destinataires, ou on conserve une copie
sécurisée de la clé secrète d'origine avant migration,
plutôt que chercher à dupliquer physiquement la carte.
Tester systématiquement : YubiKey primaire perdue,
YubiKey de secours seule, PIV PIN bloqué, aucune clé connectée,
panne TrueNAS, expiration certificat, rotation des destinataires.
Pour GPG, conserver hors ligne la capacité de déchiffrer les
anciens messages et sauvegardes ; pour Vault, séparation
des parts de recovery et des politiques d'accès.

### Roadmap de réalisation graduelle

- [x] P0 GnuPG PCSC partagé opérationnel, cartes détectées.
- [x] P1 GPG logiciel RSA4096 : signature vérifiée et roundtrip
      chiffrement/déchiffrement non sensible validés.
- [x] P2 installation `age-plugin-yubikey 0.5.1` effectuée.
- [x] P2 inventaire PIV secours : 9A occupé, 82 et 83 vides.
- [ ] P2 inventaire complet des deux cartes : PIV 9C/9D/9E/82–95,
      OpenPGP, FIDO2, SSH, OTP, OATH sans exporter de secrets.
- [ ] P2 fixture SOPS X25519 : déchiffrement et récupération,
      examiner les règles réelles `fastapi-sample/.sops.yaml`.
- [ ] P2 proposition de création **explicite** d'une identité
      `age-plugin-yubikey` en PIV 82 sur chaque YubiKey,
      avec politiques PIN/touch, démonstration déchiffrement
      de fixture et récupération sans carte.
- [ ] P2 mise à jour SOPS destinataires : conserver X25519,
      ajouter les deux destinataires matériels, `sops updatekeys`
      sur un fichier de démonstration puis inventaire applicatif.
- [ ] P3 Git signed commit de test dans dépôt jetable ; audit
      git-crypt et backups chiffrés existants avant migration.
- [ ] P3 définir nouvelles sous-clés OpenPGP hardware, ou choisir
      de conserver les clés GPG logicielles si récupération fragile.
- [ ] P3 PIV client-auth, signature PDF, S/MIME : choisir un
      fournisseur de certificats et outils vérificateurs.
- [ ] P3 SSH-FIDO2 sur les deux clés avec accès de secours et
      plan de distribution de clés publiques sur GitHub/serveurs.
- [ ] P4 PKI sites et futur Vault/OpenBao : architecture root
      hors ligne, intermédiaire, ACME, bootstrap, auth et recovery
      documentés. Pas de root CA privée exposée à une app publique.
- [ ] P4 backup/DR : restauration réelle de PostgreSQL dans un
      bac à sable isolé, perte de YubiKey, révocation/rotation.

### Sources et limites

- PIV slots et rôles :
  https://docs.yubico.com/yesdk/users-manual/application-piv/slots.html
- YubiKey PIV :
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html
- `age-plugin-yubikey` :
  https://github.com/str4d/age-plugin-yubikey
- HashiCorp Vault PKCS#11 auto-unseal :
  https://developer.hashicorp.com/vault/docs/configuration/seal/pkcs11
  (Vault Enterprise requis pour seal PKCS#11).
- La compatibilité Vault/OpenBao et les options d'auto-unseal
  doivent être validées selon **édition/version déployée** ;
  une YubiKey 5 NFC n'est pas supposée être un HSM d'auto-unseal
  ou une solution PKI serveur autonome.

## Plan de récupération à deux YubiKeys et sauvegarde TrueNAS (17 octobre 2026)

### Inventaire déclaré du stockage existant

L'opérateur dispose d'un répertoire de sauvegarde monté sur
la workstation : `/media/backup/lab/secret/`.
L'extrait `ll` fourni contient `Login.xlsx.zip`,
`NETGEAR_R7000-01-02-2022.cfg`,
`expressvpn_router_3.4.1.8614_release_netgear-r7000.chk`,
les sous-répertoires `google/`, `keepass/`, `ssh/`
et deux fichiers historiques YubiKey HMAC de janvier 2023
(`yubikey-5-nabla-challenge-response-HMAC-28-01-2023` et
`yubikey-5c-nabla-challenge-responde-HMAC-28-01-2023`).
**Aucun contenu de ces fichiers n'a été consulté.**
Leur nom seul n'atteste ni du format ni de la validité d'une
copie du secret HMAC ; supposer qu'ils puissent être extrêmement
sensibles jusqu'à inventaire local sous contrôle de l'opérateur.

La liste affiche des permissions `rw-r--r--+` ou
`rwxr-xr-x+` : **ACL étendues (signe `+`)** et modes
potentiellement trop permissifs si les fichiers contiennent
des clés HMAC, mots de passe, clés SSH ou sauvegardes d'accès.
Ne pas déduire les accès effectifs du seul mode POSIX.
Le montage `/media/backup` ne prouve pas son
chemin dataset ZFS exact, sa réplication, son chiffrement au
repos ou sa protection contre une suppression accidentelle.

### Architecture cible — séparation des risques

- **YubiKey primaire :** opérations quotidiennes avec OTP2
  KeePassXC, FIDO2/SSH et nouvelles identités PIV age.
- **YubiKey de secours :** identités indépendantes,
  destinataires age et authentification testés, entreposage
  physiquement séparé ; conserver l'OTP2 HMAC existant.
- **TrueNAS :** dépôt de **sauvegardes chiffrées côté client**,
  répliquées/snapshotées, sans secret de déchiffrement
  uniquement hébergé sur la même appliance.
- **Escrow hors ligne séparé de TrueNAS :** identité age
  X25519 existante et/ou clés privées GPG pré-migration,
  clé(s) de récupération KeePassXC, codes de récupération
  MFA, matériel de révocation et parts de recovery Vault
  sous contrôles d'accès renforcés ; ne pas placer toutes
  les parts Vault au même endroit.
- **Destinataires multiples :** chiffrements SOPS/age
  pour la clé logicielle de récupération et les nouvelles
  identités matérielles indépendantes (une par YubiKey).
  Ne pas considérer une YubiKey clonable.
- **Disponibilité automatisée :** TrueNAS, CI, Vault/OpenBao
  et renouvellement TLS ne doivent pas exiger une YubiKey
  insérée à chaque tâche planifiée.

### P0 — Préflight de sécurité du répertoire (lecture seule)

Sans imprimer les contenus, les secrets ni les valeurs HMAC :

```bash
findmnt -T /media/backup/lab/secret/ -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c '%n | %a | %U:%G | %s octets' /media/backup/lab/secret/
getfacl -p /media/backup/lab/secret/ |
  sed -n '1,50p'
find /media/backup/lab/secret/ -maxdepth 1 -type f \
  -printf '%f | %m | %u:%g | %s octets\n'
```

Ne **pas** publier la sortie de `getfacl` complète sans
l'inspecter : noms de comptes/groupes internes possibles ;
les noms de fichiers eux-mêmes sont des métadonnées sensibles.
Éviter `cat`, `head`, `grep`, `strings`,
`sha256sum` des fichiers de secret dans un ticket,
CI ou historique. Ne jamais recopier un secret YubiKey dans
le dépôt. Les anciens fichiers HMAC pourraient être des
matériels de récupération critiques mais aussi un risque
de compromission si lisibles largement.

### Roadmap dédiée aux sauvegardes sécurisées

- [ ] **P0 ACL :** identifier les accès effectifs POSIX/NFSv4 et
      la chaîne TrueNAS/ZFS ; restreindre au détenteur et
      compte de backup dédié, sans casser l'accès KeePassXC.
- [ ] **P0 classification :** inventorier localement les
      types/risques de `Login.xlsx.zip`, `*.cfg`, `ssh/`,
      `keepass/`, `google/` et HMAC historiques **sans
      exporter les contenus** ; déterminer s'ils sont chiffrés.
- [ ] **P1 sauvegarde chiffrée :** paquet d'escrow chiffré
      **avant transfert à TrueNAS** (age à destinataires
      multiples, ou format équivalent), permissions 0600 et
      répertoire 0700, pas de copie plaintext durable.
- [ ] **P1 continuité :** définir un destinataire de
      récupération indépendant des deux YubiKeys (identité
      age hors ligne conservée hors du pool), politique de
      conservation et chiffrement des archives historiques.
- [ ] **P2 résilience ZFS :** dataset chiffré si compatible,
      snapshots avec durée documentée, réplication hors machine,
      tests de suppression/ransomware, monitoring de la réussite.
      Le chiffrement ZFS au repos **ne remplace pas**
      l'enveloppe chiffrée côté client.
- [ ] **P2 validation dual-key :** déchiffrer la même
      fixture avec YubiKey A seule, YubiKey B seule,
      puis sans YubiKey via clé de récupération hors ligne.
      Réaliser également un test KeePassXC sous contrôle,
      sans copier ni afficher la réponse HMAC.
- [ ] **P3 tests de restauration :** GPG/git-crypt,
      SOPS/age, SSH, Vault/OpenBao, emails/PDF et une
      sauvegarde PostgreSQL en environnement isolé ;
      vérifier intégrité et possibilité de réouvrir réellement.
- [ ] **P4 DR :** scénario perte simultanée des deux YubiKeys
      ou du TrueNAS, rotation de credentials, révocation des
      anciennes clés/certificats et preuve de restauration.

### Décision provisoire

**Ne pas déplacer, supprimer, modifier les droits ou provisionner**
des clés sur la base du seul listing. Le premier livrable est
un audit non destructif des ACL et du chiffrement existant,
suivi d'une stratégie de secrets hors ligne.

## Reprise dans la PR #258 — inventaire des deux YubiKeys (17 octobre 2026)

La PR #257 est fusionnée ; poursuivre les travaux uniquement sur
la branche de la PR #258, sans fusion automatique. Cette PR traite
également DefectDojo : les changements YubiKey restent limités
à leur documentation et aux scripts workstation dédiés.

### État matériel vérifié

| Constat | YubiKey principale | YubiKey de secours |
| --- | --- | --- |
| Numéro de série d'identification locale | 11110001 | 11110002 |
| Firmware et application PIV | 5.4.3 | 5.4.3 |
| PIV PIN / PUK | 3/3 et 3/3 | 3/3 et 3/3 |
| Management key PIV | AES256, protégée par PIN | AES256, protégée par PIN |
| PIV 9A | RSA2048, certificat « Nabla Root CA » expiré 2025-01-22 | RSA2048 importée, même certificat historique déclaré |
| PIV 9C / 9D / 9E | **Inconnus** | **Vides**, testés par `ykman piv keys info` |
| PIV retired 82–95 | **Inconnus** | **20/20 vides**, testés par `ykman piv keys info` |
| age-plugin-yubikey --list | Aucune identité listée | Aucune identité listée |
| OTP slot 2 | HMAC KeePassXC historique : préserver | HMAC KeePassXC historique : préserver |

Les deux cartes affichent les mêmes éléments de certificat
X.509 en PIV 9A, dont empreinte et numéro de certificat.
Cela **ne démontre pas** que leurs clés privées soient identiques,
ni même que le certificat corresponde à une clé privée utilisable
sur les deux cartes. Une vérification cryptographique distincte,
non destructive, serait nécessaire. Ne pas publier CHUID ni
certificats bruts.

### TrueNAS — durcissement confirmé

Dataset `cpool/backup/lab` : `acltype=nfsv4`,
`aclmode=passthrough`, `aclinherit=passthrough`.
Le répertoire `lab/` est passé de 777 à 750 ;
`secret/`, `secret/keepass/`, `secret/ssh/` sont en
700. Les ACL natives relevées via `nfs4xdr_getfacl`
pour les trois dossiers sensibles sont triviales :
`owner@` a lecture/écriture/traversée ;
`group@` et `everyone@` ne disposent pas des droits
de contenu/traversée `r/w/x`. Les ACL des fichiers et
l'export NFS `sec=sys` restent à auditer. Éviter
tout `chmod -R` destructif.

### P2 — Prochain ordre d'exécution

1. Sur la **principale uniquement**, une seule clé branchée,
   inventorier PIV 9C/9D/9E puis 82–95 avec
   `ykman piv keys info SLOT` sans générer de clé.
2. Valider une fixture de chiffrement/déchiffrement SOPS
   avec l'identité X25519 existante, indépendamment de TrueNAS ;
   aucune sortie de `.env.secret` en clair.
3. Confirmer une sauvegarde **chiffrée hors ligne** de l'identité
   de récupération existante. Ne jamais supposer que les deux
   YubiKeys, ni TrueNAS, constituent une copie de la clé X25519.
4. Une fois les deux inventaires et la récupération validés,
   proposer une identité age P-256 différente dans le
   premier slot retired libre (préférence 82) de **chaque** clé,
   avec PIN/touch et vérification d'une fixture.
5. Ajouter les deux destinataires matériels aux règles SOPS
   **sans retirer** le destinataire X25519 ni casser
   les automatisations de déploiement. Tester la lecture avec
   chacune des trois identités séparément.
6. Poursuivre ensuite SSH/FIDO2, signatures Git/OpenPGP,
   PIV X.509/PDF, e-mails, récupération Vault et backups selon
   l'architecture globale déjà documentée.

Aucune génération age, aucun `keytocard`, aucun reset PIV,
aucune modification d'un slot OTP ou de fichier secret.

### P2 — Audit PIV lié au numéro de série (PR #258)

Sur la **YubiKey principale**, l'opérateur a exécuté
`ykman piv keys info` pour chacun des 23 slots
`9C 9D 9E` et `82–95` : les **23 réponses indiquent
`No key stored`**. Cela complète l'inventaire de la
carte de secours, qui avait les mêmes 23 slots sans clé.
Les slots PIV `9A` sont historiques et **à préserver**.

Le script `scripts/workstation/audit-yubikey-capabilities.sh`
identifie maintenant l'appareil **avant** les diagnostics,
refuse zéro, plusieurs ou une YubiKey inconnue, et propose :
```bash
./scripts/workstation/audit-yubikey-capabilities.sh --primary
./scripts/workstation/audit-yubikey-capabilities.sh --backup
# ou explicitement --serial NUMERO
```
Une seule carte doit être connectée. Les commandes `ykman`
sont liées au numéro de série vérifié via `--device` ;
les 23 slots sont classés **EMPTY / OCCUPIED / UNKNOWN** sans
publier les métadonnées cryptographiques détaillées. Tout
état `UNKNOWN` interdit de déduire qu'un slot est libre.
Le mode `--challenge` reste optionnel pour l'OTP HMAC.
L'inventaire ne génère ni ne déplace de clé, et ne modifie
ni PIV ni OTP.

**Allocation P2 proposée** : slot retired `82` sur
chaque YubiKey pour deux identités age indépendantes ;
`83` réservé à la rotation. La preuve de récupération
logicielle X25519, la fixture SOPS et l'acceptation des
politiques PIN/touch restent des conditions préalables.

### Validation terrain de l'audit matériel de la YubiKey de secours

L'opérateur a exécuté `audit-yubikey-capabilities.sh --backup` dans un worktree de la PR #258 (HEAD `dc42459e`). Le contrôle de numéro de série a réussi et les 23 slots interrogés (`9C/9D/9E` et `82–95`) ont été classés EMPTY : `empty=23 occupied=0 unknown=0`. Le slot 9A reste occupé par le certificat RSA2048 expiré en janvier 2025. OpenPGP a été détecté ; les emplacements Signature, Encryption et Authentication ont chacun été observés vides. FIDO2, OATH et les outils SOPS/age sont disponibles ; l'OTP2 KeePassXC doit rester intact.

La sortie indique `OATH Password protection: disabled` : revoir le modèle de protection avant ajout de nouveaux comptes OATH, sans activer de contrôle susceptible de bloquer les comptes existants. L'identité SSH chargée dans ssh-agent n'est pas attribuée à la YubiKey. Le contrôle principal `--primary` reste à rejouer avec la clé principale effectivement connectée et une seule clé présente.

**Prochain jalon :** test de récupération d'une fixture SOPS avec le destinataire age X25519 actuel, avant génération explicite d'identités matérielles distinctes sur les deux cartes. Aucun provisionnement effectué.

### P2 SOPS — identité locale trouvée, permissions à durcir (17 octobre 2026)

L'opérateur rapporte `~/.config/sops/age/keys.txt` **présent**, propriétaire `albandrieu`, mode **0644**. Le chemin alternatif `~/.config/age/keys.txt` est absent. SOPS 3.13.3 est opérationnel. Attention : l'existence du fichier ne démontre pas à elle seule qu'il contient l'identité correspondant au destinataire `age1...` de `fastapi-sample/.sops.yaml`, ni qu'une restauration fonctionne.

**Priorité P0 confidentialité :** resserrer sans lire/exporter la clé : `chmod 600 ~/.config/sops/age/keys.txt` et `chmod 700 ~/.config/sops/age`. Vérifier ACL de fichier et accès aux éventuelles copies historiques. Le diagnostic `audit-yubikey-capabilities.sh` signale désormais les permissions de cette identité en n'inspectant que ses métadonnées, sans afficher le contenu. Il reste à valider le déchiffrement sur une fixture SOPS non sensible et la conservation d'une copie de récupération chiffrée hors ligne **avant** de créer les identités YubiKey PIV 82. Ne pas placer la clé privée sur TrueNAS en clair.

### SOPS age — correspondance de la clé logicielle confirmée

Le contrôle `age-keygen -y ~/.config/sops/age/keys.txt` a produit le destinataire public `age1t8wn2gqcpzxwvwhjwxwtdwp0tvr6k2z9j39v4q2fr55qhmqz7f2qvn25cp`, identique au destinataire de `fastapi-sample/.sops.yaml`. Le fichier contient donc une identité age correspondant à ce destinataire (vérification de correspondance publique, pas encore un test de déchiffrement SOPS). Ne jamais journaliser `AGE-SECRET-KEY-*`. Les permissions initialement constatées étaient 0644 ; la correction 0600/0700 n'a pas encore été confirmée par la workstation. Prochain contrôle : fixture SOPS synthétique en répertoire privé temporaire puis test de déchiffrement, et sauvegarde chiffrée indépendante avant génération age PIV 82 sur chacune des deux YubiKeys.

### Acceptation SOPS/age logicielle — fixture validée (17 octobre 2026)

Sur la workstation, SOPS 3.13.3 a chiffré une fixture YAML synthétique pour le destinataire age `age1t8wn2gqcpzxwvwhjwxwtdwp0tvr6k2z9j39v4q2fr55qhmqz7f2qvn25cp`, puis `sops decrypt` a produit exactement `message: yubikey-sops-recovery-test`. Résultat **PASS** : chiffrement et déchiffrement de bout en bout avec l'identité logicielle présente localement. La fixture a été supprimée après l'essai.

**Gates encore ouverts avant PIV 82 :** confirmer `stat` mode `600` sur `~/.config/sops/age/keys.txt` et mode `700` sur son dossier ; établir une copie de secours chiffrée hors workstation, vérifier sa lisibilité et son moyen de récupération indépendant. Ensuite seulement tester deux destinataires YubiKey matériels distincts (sans supprimer le destinataire age X25519, sans modifier OTP2 ou PIV 9A). Aucune identité matérielle provisionnée à cette date.

### Acceptation des permissions de la clé SOPS et coffre de secours (17 octobre 2026)

L'opérateur a confirmé sur la workstation :
```text
700 albandrieu:albandrieu ~/.config/sops/age
600 albandrieu:albandrieu ~/.config/sops/age/keys.txt
```
P0 permissions **PASS**. Le chiffrement/déchiffrement de
fixture SOPS avec le destinataire X25519 existant est également
PASS ; la sauvegarde de récupération indépendante **reste à faire**.

Nouvel utilitaire workstation
`scripts/workstation/backup-sops-age-identity.sh` :
mode `--check` implicite, `--apply` explicite.
Il vérifie la source 600/700, le destinataire age public
indépendant du destinataire de la source, un répertoire de
destination déjà monté sur un autre système de fichiers,
puis chiffre côté client avec `age -e -r` avant toute
écriture de la copie chiffrée sur le stockage de secours.
Il refuse l'écrasement et n'affiche ni clé privée ni contenu.
Aucune clé escrow n'est générée automatiquement ;
le propriétaire doit avoir **déjà créé** et mis hors machine
la clé privée de récupération associée au destinataire
public utilisé. Ne pas utiliser la même identité X25519
pour chiffrer sa propre sauvegarde : risque de circularité.
Vérifier séparément la sécurité des métadonnées/fichiers
temporaires et des exports NFS.

Exemple, seulement après validation d'un **destinataire de
récupération distinct** et de sa clé privée hors machine :
```bash
bash scripts/workstation/backup-sops-age-identity.sh \
  --destination /media/backup/lab/secret/keepass \
  --recipient 'age1DESTINATAIRE_DE_RECUPERATION'  # check only
# Recommencer avec --apply pour créer la copie chiffrée.
```
L'emplacement sous `keepass/` est une option, pas un
choix obligé : réserver de préférence un dossier spécifique
`secret/sops-escrow` avec ACL NFSv4 strictes et jamais
de fichier en clair. Éviter de partager les chemins réels
et métadonnées de récupération. L'opération n'est **pas**
une preuve de récupération : réaliser un test de déchiffrement
sur un poste isolé avec la **clé privée escrow**, comparer le
destinataire public dérivé, et confirmer l'ouverture d'une
fixture SOPS sans exfiltrer d'identité privée.
Ne pas modifier les deux YubiKeys avant cette preuve.

### Escrow SanDisk LUKS2 opérationnel — 17 octobre 2026

La SanDisk USB 3.2Gen1 (114,6 Gio, ancien support d'installation pfSense)
a été repartitionnée volontairement après vérification de son identité
USB, puis formatée en **LUKS2 + ext4**. Mapper
`nabla_escrow_usb`, ext4 label `NABLA_ESCROW`, montage temporaire
`/mnt/nabla-escrow`. Le support a été fermé proprement après création
d'une identité age indépendante sous
`age-escrow/recovery-identity.txt` (mode `600`, compte local).
La clé privée n'a pas été transmise dans ce chat ou stockée dans Git.

**Destinataire public age escrow :**
`age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938`.

**Référence de la phrase secrète LUKS :** coffre **LastPass**,
entrée intitulée **« USB SANDISK LUKS2 »**.
Ne jamais documenter la phrase elle-même. Le mot de passe LUKS
est distinct de l'identité age et **ne permet pas de régénérer**
sa clé privée : récupérer le même destinataire age requiert la
sauvegarde exacte de `recovery-identity.txt` ; toute nouvelle
exécution de `age-keygen` crée une clé différente, incapable
de déchiffrer les anciennes sauvegardes.

Script reproductible :
`scripts/workstation/manage-age-escrow-usb.sh` prend
`--luks-uuid UUID` (celui de la **partition LUKS**, pas
de l'ext4 interne), puis
`--check`, `--open`, `--close` ou `--init-identity`.
Il ne formate pas et n'écrase aucune identité existante.
Une régénération non équivalente requiert une confirmation
interactive explicite. Pour un nouveau support, reproduire
séparément, après identification physique robuste, la préparation
GPT/LUKS2/ext4 documentée ; copier/restaurer ensuite
l'identité age originale depuis son **backup indépendant**,
ou traiter toute nouvelle identité comme une rotation avec
rechiffrement de toutes les données existantes.

**Important :** le périphérique était `/dev/sdd` lors de
l'installation, mais ce nom n'est **pas stable**.
Lire son UUID après nouveau branchement :
```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,UUID,MOUNTPOINTS
sudo blkid -s UUID -o value /dev/sdX1  # vérifier sdX1 avant utilisation
bash scripts/workstation/manage-age-escrow-usb.sh --luks-uuid UUID --check
```
Aucune phrase secrète n'est transmise sur la ligne de commande.
Ne pas sauvegarder automatiquement un header LUKS sur TrueNAS en clair.

Le volume TrueNAS
`nabla:/mnt/cpool/backup/lab` est confirmé NFSv4.2
`sec=sys`, montage workstation `/media/backup/lab`.
`secret/` est en mode `700`, et ses sous-répertoires
`keepass/` et `ssh/` sont également protégés.
Le script existant de backup SOPS doit employer **le destinataire
public réel**, jamais `age1DESTINATAIRE_PUBLIC_REEL` :
```bash
bash scripts/workstation/backup-sops-age-identity.sh \
 --destination /media/backup/lab/secret/keepass \
 --recipient age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938
# Après preflight et contrôle de la rétention : répéter avec --apply
```

**Gates restants :**
- [ ] Créer la sauvegarde de l'identité age SOPS courante, chiffrée
  sous le nouveau destinataire et stockée sur TrueNAS.
- [ ] Rouvrir la SanDisk, déchiffrer la copie dans un contexte privé
  et comparer l'identité publique dérivée à la source sans
  journaliser la clé privée.
- [ ] Disposer d'une **seconde copie indépendante et chiffrée**
  de `recovery-identity.txt` ou d'une politique de
  récupération alternative. Un volume USB unique reste un SPOF.
- [ ] Tester le recovery de bout en bout, puis seulement
  provisionner les PIV 82 sur les deux YubiKeys.

### SanDisk reconnue et prévalidation SOPS passée (17 octobre 2026, suite)

Nouvelle vérification : UUID **de partition LUKS2** `3742c7b9-ccb7-4b5e-b1db-18bcf916c548`, mapper créé automatiquement par udisks `luks-3742c7b9-ccb7-4b5e-b1db-18bcf916c548`, montage `/run/media/albandrieu/NABLA_ESCROW` (ext4 UUID `82b61d3f-f921-4159-b8f3-426a3da2f1c5`). Le script de gestion du support a été corrigé pour détecter ce montage via le disque LUKS ciblé par UUID, y compris s'il a été ouvert par GNOME/udisks ; pas de seconde ouverture. Fermeture udisks par `udisksctl unmount` puis `udisksctl lock` pour son montage automatique ; les montages non reconnus restent bloqués.

Le contrôle `backup-sops-age-identity.sh --destination /media/backup/lab/secret/keepass --recipient age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938` a répondu `Escrow preflight OK`, suivi de `CHECK ONLY`: **pas encore de sauvegarde créée**. Prochaine acceptation : exécuter `--apply`, puis déchiffrer le fichier créé avec la clé privée USB sur un flux sans afficher le contenu ; comparer les destinataires publics de l'identité restaurée et de la source, puis tester une fixture SOPS. Ne pas confondre le déverrouillage LUKS avec la récupération de la clé privée age.

### Backup SOPS vers TrueNAS créé deux fois ; contrôle LUKS corrigé

Deux exécutions explicites de `backup-sops-age-identity.sh --apply`
ont chacune affiché `Encrypted backup created` après validation
des permissions et du destinataire escrow public. Ce sont deux
fichiers chiffrés distincts horodatés : ne pas supposer qu'ils
ont des noms différents sans contrôler l'inventaire. Le test
de récupération avec la SanDisk reste en attente ; **ne pas
provisionner les slots PIV 82** avant PASS.

Le contrôle `manage-age-escrow-usb.sh --check` échouait
avec `Selected partition is not LUKS`, alors que la
partition par UUID était vue comme `crypto_LUKS` dans
`lsblk`. Un `blkid` non privilégié peut retourner vide ;
la validation a été corrigée pour utiliser `lsblk`, en
comparant **type crypto_LUKS ET UUID exact**.

Nouveau test non destructif :
`scripts/workstation/verify-sops-age-escrow.sh`
avec `--backup /media/backup/lab/secret/keepass/FICHIER.age`
et `--identity /run/media/albandrieu/NABLA_ESCROW/age-escrow/recovery-identity.txt`.
Le script restaure uniquement dans un répertoire privé en
`/dev/shm` (tmpfs), valide que le destinataire public de
l'identité récupérée correspond au destinataire X25519 connu,
et efface le fichier temporaire au retour. Ne pas utiliser
avec un autre dossier temporaire sur disque ou exposer la
clé en sortie. Le test du déchiffrement SOPS de fixture reste
une étape indépendante.

### Gate SOPS USB → TrueNAS → fixture validée (17 octobre 2026)

L'opérateur a obtenu `message: sops-recovery-ok` puis
`PASS: SOPS recovery with USB-backed escrow` en relançant
manuellement le test avec la SanDisk déverrouillée.
Ce résultat valide le chemin de récupération de l'identité
logicielle et le déchiffrement d'une fixture SOPS. Ne pas
assimiler ce contrôle à une seconde copie de la **clé privée
d'escrow USB** : celle-ci demeure un risque de point unique
de défaillance.

La première tentative a entraîné la fermeture de la fenêtre
de terminal. Cause non démontrée : un bloc avec
`set -euo pipefail` et `trap ... EXIT` peut fermer le shell
interactif lorsqu'il est collé/exécuté dans ce contexte.
Utiliser désormais **un fichier Bash exécuté en sous-processus**
(`bash scripts/workstation/test-sops-usb-recovery.sh`),
sans `source`. Le script refuse explicitement le sourcing,
valide une fixture SOPS et n'utilise la copie déchiffrée
que sous `/dev/shm` (tmpfs).

```bash
bash scripts/workstation/test-sops-usb-recovery.sh \
  --backup /media/backup/lab/secret/keepass/sops-age-identity-20261017T183615Z.age \
  --usb-identity "/run/media/$USER/NABLA_ESCROW/age-escrow/recovery-identity.txt"
```

**Prochaines portes de sécurité matérielles :**
- [x] Sauvegarde SOPS age chiffrée sur TrueNAS ; restauration et
  fixture SOPS validées avec SanDisk.
- [ ] Deuxième copie hors ligne chiffrée de l'identité privée
  SanDisk (ne jamais la publier ni la copier en clair sur TrueNAS).
- [ ] Inventaire PIV 82 confirmé juste avant chaque écriture ;
  OTP2 KeePassXC et ancien PIV 9A intouchables.
- [ ] Une identité age PIV 82 distincte sur chaque YubiKey,
  avec preuve de déchiffrement synthétique par clé.
- [ ] Intégration multi-recipient SOPS uniquement après
  démonstration de recovery et identification des contraintes
  des environnements CI et headless.

### Runbook pérenne PRA et diagnostic PIV 82 (17 octobre 2026)

La procédure **autonome de récupération** est désormais dans [`docs/runbooks/sops-age-usb-disaster-recovery.md`](runbooks/sops-age-usb-disaster-recovery.md) : emplacements TrueNAS/workstation/USB, empreinte SHA-256 vérifiée, référence de la phrase secrète **LastPass → USB SANDISK LUKS2**, UUID LUKS, destinataires publics, restauration testée, limites de recréation d'une SanDisk perdue, contrôles de permissions et commandes de secours. Ne jamais confondre sauvegarde de la clé SOPS avec sauvegarde de la clé **escrow** de la SanDisk : la deuxième copie de celle-ci reste à réaliser.

Lors du PIV82 preflight : `Connect exactly the selected single YubiKey` sur le secours et `PIV 82 info unavailable` sur la principale. Le script a été corrigé pour traiter **uniquement** les messages explicites « no key » comme slot vide, y compris si `ykman` retourne un code non nul ; tous les autres échecs restent bloquants. Ne pas provisionner tant que les diagnostics ne renvoient pas PASS.

### Correctif PIV 82 : principale vérifiée vide (17 octobre 2026)

Avec la principale seule branchée, `ykman list --serials` a retourné `11110001` et `ykman --device 11110001 piv keys info 82` a répondu `ERROR: No key stored in slot 82 (RETIRED1).` C'est un constat direct de slot **vide** ; aucune identité n'a été créée et les slots OTP2/9A restent intouchés. Le précontrôle rejetait cette carte à cause de deux défauts logiciels : backreference `sed` échappée deux fois et message d'absence de clé non reconnu. Correctifs dans la PR #259, à vérifier sur la workstation après fetch. La YubiKey de secours devra être vérifiée séparément avec **une seule carte branchée**, sans présumer le résultat des diagnostics précédents.

### PIV 82 — les deux précontrôles matériels PASS

Les deux YubiKeys ont **PASS** au script non destructif `preflight-age-yubikey-piv82.sh`, avec chacune son numéro de série et une seule carte connectée : principale `11110001`, secours `11110002`. Les slots PIV 82 sont donc vérifiés vides au moment du contrôle ; ni génération, ni écriture, ni modification des OTP2 et PIV9A. Il reste à provisionner séparément les identités age matérielles puis à effectuer les tests de déchiffrement synthétique. Les sorties des scripts shell interactifs suivent désormais `AGENTS.md` : états colorés et icônes si TTY UTF-8, repli texte pour CI/NO_COLOR/non-TTY, sans secrets dans les sorties.

### Validation age-plugin-yubikey 0.5.1 et tests locaux (17 octobre 2026)

Sur la YubiKey secondaire, le précontrôle PIV82 a affiché **PASS** avec
icônes/couleurs. `age-plugin-yubikey --version` affiche `0.5.1` ;
l'aide confirme les options `--generate`, `--identity`,
`--list`, `--list-all`, `--name`, `--pin-policy always|once|never`,
`--serial`, `--slot`, `--touch-policy always|cached|never`.
Ne jamais employer `--force` : il écraserait une clé en slot occupé.

L'opérateur a exécuté la suite `unittest` : **17 PASS, 1 FAIL**,
uniquement l'assertion du texte ancien `Connect exactly the selected
single YubiKey` alors que le script affiche désormais `Expected exactly
one YubiKey matching requested serial`. Assertion corrigée dans la PR
#259 ; revalider les 18 tests avant provisionnement.

Commande envisagée **seulement après cette gate**, avec **une seule**
YubiKey secondaire connectée et après une seconde vérification PIV82 :
```bash
age-plugin-yubikey --generate --serial 11110002 --slot 1 \
  --pin-policy always --touch-policy always \
  --name nabla-age-backup
```
Cette commande modifie réellement le slot PIV82 (clé privée non
exportable) et pourra demander le PIN ou le toucher physique.
Collecter **uniquement** le destinataire public/identité plugin,
puis tester une fixture age synthétique séparément.
Procéder à la principale après le test de la secondaire.
Conserver OTP2, PIV9A et l'identité SOPS X25519 existants.

### Correctif de numérotation age-plugin-yubikey 0.5.1 (17 octobre 2026)

Le contrôle `ykman piv keys info 82` désigne le slot matériel PIV hexadécimal **82** (`RETIRED1`). En revanche `age-plugin-yubikey --slot` n'accepte **que l'index décimal de 1 à 20** des slots retired : `--slot 1` correspond à PIV 82, `--slot 2` à PIV 83, etc. La tentative `--generate --slot 82` a échoué en validation `Invalid slot '82' (expected number between 1 and 20)` et **n'a pas créé de clé**. Les 18 tests locaux `unittest` sont maintenant PASS.

Avant génération, vérifier que le plugin `--list` est toujours vide et que PIV82 est encore libre sur la seule carte connectée. La commande corrigée de la secondaire est :
```bash
age-plugin-yubikey --generate --serial 11110002 --slot 1 \\
  --pin-policy always --touch-policy always --name nabla-age-backup
```

ATTENTION : la clé de gestion PIV existante est **AES256 PIN-protected** ; le plugin 0.5.1 peut ne pas supporter certains formats de management key. En cas d'erreur, arrêter, documenter et rechercher une option compatible ; **ne pas** réinitialiser PIV, convertir sa clé de gestion, utiliser `--force`, ni modifier le slot 9A ou OTP2 pour contourner l'échec. Une éventuelle écriture doit être confirmée après opération avec `ykman piv keys info 82`, puis test sur fixture de chiffrement avant tout usage SOPS.

### Blocage matériel age-plugin-yubikey AES et référence PIN (17 octobre 2026)

Sur la YubiKey secondaire `11110002`, `age-plugin-yubikey 0.5.1 --generate --slot 1 --pin-policy always --touch-policy always` a échoué après demande de PIN : `Failed to authenticate with the PIN-protected management key`; le message précise explicitement **AES non supporté** (issue [str4d/age-plugin-yubikey#92](https://github.com/str4d/age-plugin-yubikey/issues/92)). La carte utilise une clé de gestion PIV **AES256 protégée par PIN**. **L'échec ne prouve pas un PIN erroné.** L'opérateur a sélectionné le PIN depuis LastPass **« yubikey-5-nabla principal »** alors que **la carte secondaire** était connectée. Cette entrée est désignée pour la principale et ne prouve pas que les PIN sont identiques. Vérifier la bonne entrée secondaire sans révéler la valeur. Éviter les essais répétés (compteur PIN limité).

**Aucune génération réussie confirmée.** Avant toute autre action, effectuer un inventaire PIV 82 et des compteurs PIN en lecture seule. Ne pas suivre automatiquement la suggestion du plugin de migrer la management key vers TDES : rétrogradation crypto pour contourner une incompatibilité logicielle, avec risques opérationnels pour le slot historique 9A. Conserver PIV 9A et OTP2. Chercher prioritairement une version/fork du plugin prenant en charge AES ou un processus compatible et contrôlé, puis tester sur fixture avec une carte uniquement. La génération de l'identité age matérielle reste **BLOCKED** tant que compatibilité et PIN de secours ne sont pas validés.

Le préflight affiche maintenant un **rappel non sensible de la référence LastPass** selon le numéro de série ; jamais la valeur du PIN.

### PIN secondaire et compatibilité AES — contrôle matériel

Le diagnostic en lecture seule de la carte secondaire indique PIN 3/3 et PUK 3/3, management key AES256 protégée par PIN, ancien certificat 9A inchangé et slot 82 vide. L'échec du plugin ne démontre pas un PIN erroné : il annonce une incompatibilité avec AES.

Références LastPass confirmées par l'opérateur : principale `yubikey-5-nabla principal` ; secondaire `yubikey-5-nabla backup`. Ne conserver que les libellés, jamais les valeurs. Ne pas migrer la management key vers TDES et ne pas réinitialiser PIV ; recherche d'un chemin AES-compatible requise avant toute génération.

### P1 — AES management-key compatibility: investigation and guard (2026-10-17)

The upstream `str4d/age-plugin-yubikey` issue [#92](https://github.com/str4d/age-plugin-yubikey/issues/92) remains open, blocked by an upstream dependency. Version `0.5.1` does **not** establish PIN-protected AES management-key compatibility. Its latest release as checked is `0.5.1`; the reported `--generate` failure on the backup card is consistent with this known blocker, not proof of wrong PIN. See [issues #238](https://github.com/str4d/age-plugin-yubikey/issues/238) and [#92](https://github.com/str4d/age-plugin-yubikey/issues/92).

Read-only guard:
```bash
bash scripts/workstation/check-age-yubikey-aes-compat.sh --serial 11110002
```
It intentionally exits **3** on incompatible AES or unapproved management-key configurations (nonzero means **blocked by policy**, not a hardware failure). Never use it as a provisioning success signal. The previous PIV82 preflight still checks slot emptiness independently.

Investigation plan before any write:
1. Check age-plugin-yubikey's current dependencies and upstream #92 fixes, with reproducible, pinned versions; test first against a disposable token if possible.
2. Research external ECC P-256 key generation directly on-card in retired PIV 82 using AES-compatible `ykman`, **plus plugin-compatible certificate encoding** and PIN/touch policy; verify that no existing PIV applet state must be reset. Building a P-256 key alone is insufficient.
3. Validate the resulting recipient and actual synthetic age decrypt against the plugin, and independently inspect PIV 9A and OTP2 afterwards.
4. Document rollback, slot 83 rotation reservation, and migration impact for unattended SOPS/CI before new production recipients.

No automatic TDES downgrade, no PIN guessing, no PIV reset, no wildcard `--force`. Existing SOPS X25519 and TrueNAS/SanDisk recovery remain operational.

### Acceptation locale AES guard — 17 octobre 2026

L'opérateur a synchronisé le worktree PR #259 au commit `9464f03d`, puis exécuté `bash -n scripts/workstation/check-age-yubikey-aes-compat.sh` et `python3 -m unittest discover -s tests -p test_yubikey_keepassxc_diagnostic_contract.py -v` : **19 tests PASS / 19**. Avec la YubiKey secondaire `11110002` connectée, `check-age-yubikey-aes-compat.sh --serial 11110002` a affiché le blocage attendu AES PIV management key et retourné **3**, par politique de sécurité. Cela valide le garde-fou local en lecture seule, pas la compatibilité age-plugin-yubikey ni le provisionnement matériel. PIV82 reste non provisionné ; ne pas convertir en TDES, ne pas saisir de PIN pour refaire ce diagnostic. Prochaine tâche : analyser les métadonnées d'un certificat compatible age-plugin-yubikey et un chemin de génération P-256 via ykman compatible AES, d'abord sans écriture.

### Investigation external P-256 via ykman (lecture seule — 17 octobre 2026)

L'aide de la version `ykman` installée confirme que
`piv keys generate SLOT PUBLIC-KEY` propose `ECCP256`,
`--pin-policy ALWAYS` et `--touch-policy ALWAYS`.
La génération de certificat utilise
`piv certificates generate SLOT PUBLIC-KEY --subject SUBJECT`.
La commande `age-plugin-yubikey --list-all` n'a produit
aucune entrée avec la carte secondaire présente : **aucune identité
age détectée** à ce stade.

Source amont importante :
[age-plugin-yubikey issue #206](https://github.com/str4d/age-plugin-yubikey/issues/206)
décrit une **méthode expérimentale de génération externe**
par `ykman` suivie d'un certificat X.509. L'auteur précise
que l'organisation de sujet `O=age-plugin-yubikey` joue
sur la découverte automatique, et que des extensions OID
peuvent porter les politiques PIN/touch. **Cette expérience
n'établit pas** que le certificat ordinaire émis par
`ykman piv certificates generate` reproduise toutes
les métadonnées attendues, ni que le plugin détecte
correctement les politiques ALWAYS. Le témoignage amont
utilise même des politiques NEVER : **ne pas copier cet
exemple** sur des cartes opérationnelles.

**Avant écriture :** analyser source/format de certificat
du plugin et préparer un test de compatibilité sur clé
jetable ou certificat simulé ; prévoir un outil de signature
et extensions conforme si nécessaire. Vérifier ensuite
`age-plugin-yubikey --list-all` et un déchiffrement
réel avec PIN/touch avant tout usage. Les cartes existantes
restent inchangées et le workflow `--generate` du plugin
est toujours bloqué par AES256. Ne pas passer en TDES.

### Offline certificate inspection gate (2026-10-17)

Added `scripts/workstation/inspect-age-yubikey-certificate.sh` with `--certificate PATH.pem`; it reads a local public X.509 certificate only, never connects to a YubiKey or requests secrets. It validates the certificate's public key curve **EC P-256** and warns when `O=age-plugin-yubikey` is absent. Exit **3** is intentional even for a matching certificate: PIN and touch policy extension semantics, token slot binding, plugin selection, and actual age decryption are **unverified**. No certificate currently exists for PIV82, so do not run an apply workflow as a shortcut. Use `--help` and run updated `unittest` contracts (expected **20** tests) on the workstation.

[Upstream external-generation issue #206](https://github.com/str4d/age-plugin-yubikey/issues/206) is **not a certified secure recipe**: its example uses `PIN=NEVER` and `touch=NEVER`. Never copy those policies; investigate supported OIDs/encoding and require `ALWAYS` for both. [Plugin README](https://github.com/str4d/age-plugin-yubikey) notes `--list-all` lists compatible retired-slot keys even if not plugin-owned, but this is a discovery check only. A successful synthetic decryption is still mandatory before any production rollout.

### Certificat compatible : exigences extraites du code amont (2026-10-17)

Analyse de `str4d/age-plugin-yubikey` (`src/builder.rs`, `src/util.rs`, `src/key.rs`) : sujet X.509 avec `O=age-plugin-yubikey`, `OU` version (ex. `0.5.1`), `CN` nom ; clé publique ECDSA P-256 dans un slot *retired*. Extension de politique **non critique** `1.3.6.1.4.1.41482.3.8` dont la valeur est constituée de deux octets : `03 02` signifie `PIN=ALWAYS` et `TOUCH=ALWAYS`. Le plugin rejette les extensions critiques inconnues. Sans organisation reconnue, `--list-all` peut découvrir une clé compatible, mais `--list` la masque.

Nouveau test de contrat OpenSSL synthétique `test_plugin_policy_oid_synthetic_certificate` : génère temporairement une clé P-256 logicielle et un certificat avec cette extension, vérifie l'encodage DER attendu et passe le certificat à notre inspecteur en lecture seule. Test du fixture OpenSSL effectué hors carte ; validation `unittest` dans le worktree opérateur encore à faire. Ce test **ne prouve ni la lecture réelle par le binaire age-plugin-yubikey, ni les politiques effectives dans le matériel, ni un déchiffrement** : il faut encore un jeton jetable ou une procédure matérielle explicitement autorisée, avec inventaire PIV avant/après et déchiffrement synthétique.

Ne jamais utiliser `age-plugin-yubikey --generate` version 0.5.1 contre une clé de gestion AES256 protégée par PIN : incompatibilité connue. Ne pas convertir en TDES, ne pas altérer OTP2 ni PIV9A.

### Acceptation locale du test X.509 synthétique (17 octobre 2026)

L'opérateur a mis à jour son worktree vers `7226a265` et exécuté `python3 -m unittest discover -s tests -p test_yubikey_keepassxc_diagnostic_contract.py -v` : **22 tests sur 22 PASS (0,470 s)**. Le test `test_plugin_policy_oid_synthetic_certificate` passe après correction de l'écriture des fins de ligne dans la configuration OpenSSL. Cette acceptation valide uniquement la fixture synthétique, le contrôle des OID et l'inspecteur hors matériel. Il reste à démontrer reconnaissance effective par `age-plugin-yubikey` et déchiffrement avec PIV 82 sur matériel AES256. Aucune saisie PIN ou écriture PIV lors de cette acceptation.

### PIV82 AES256 : procédure en deux phases — statut NO-GO matériel (2026-10-18)

**Préflight validé :** le worktree PR #259 dispose de `scripts/workstation/plan-age-yubikey-piv82-enrollment.sh --serial 11110002`, strictement en lecture seule. À lancer avec une seule carte. Le script vérifie la série, la clé de gestion AES256 protégée par PIN et l'absence de clé dans PIV82. Code 0 : préconditions vérifiées, **pas** une autorisation d'écrire.

**Étape 1 (préparation, aucune écriture) :**
```bash
bash scripts/workstation/plan-age-yubikey-piv82-enrollment.sh --serial 11110002
ykman --device 11110002 piv keys generate --help
ykman --device 11110002 piv certificates generate --help
```

**Étape 2 (NO-GO, ne pas exécuter sur les YubiKeys opérationnelles pour l'instant) :** l'instruction générique `ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 82 PUBLIC.pem` est supportée par la CLI et préserverait la clé de gestion AES256, mais créerait une clé privée permanente dans PIV82. Le plan de certificat n'est **pas encore** prouvé : `ykman piv certificates generate` offre sujet et validité, mais pas de paramètre explicite pour ajouter l'extension non critique `1.3.6.1.4.1.41482.3.8` contenant précisément `03 02`. Ne pas enchaîner ces deux commandes au hasard ; pas de `--force`, de downgrade TDES, d'effacement/recréation PIV, d'accès OTP2 ni d'écriture PIV9A.

**Critères de GO avant toute clé réelle :**
1. Construire et auditer une chaîne de certificats (signature par la clé PIV82 elle-même) avec `O=age-plugin-yubikey`, `OU=0.5.1`, `CN=nabla-age-backup`, clé publique P-256 correspondante, extension OID `1.3.6.1.4.1.41482.3.8` non critique avec deux octets `03 02`. Prouver les octets DER et absence d'extensions critiques inconnues.
2. Vérifier l'intégration de cette chaîne avec les API PIV/ykman sans exposer le PIN ni la management key et sans passer sur TDES. Tester si possible sur YubiKey de test non opérationnelle.
3. Confirmer que la carte reconnaît `PIN=ALWAYS` et `touch=ALWAYS` réellement ; le certificat n'impose pas à lui seul la politique du slot.
4. Exécuter sur une seule carte secondaire après sauvegardes et inventaires avant/après, vérifier `age-plugin-yubikey --list-all`, récupérer uniquement le destinataire public et réussir un vrai encrypt/decrypt synthétique. Ne pas re-lancer une création de clé si un incident survient après l'étape 2.
5. Même procédure indépendante pour la principale avant toute migration SOPS. Garder l'identité logicielle et le coffre USB comme voie de retour arrière.

Le contrôle X.509 de base peut désormais afficher la présence de l'OID, mais il est délibérément **non conclusif** : il ne vérifie pas complètement les octets ou les politiques effectives, et retourne le code 3. Les tests synthétiques `unittest` ne remplacent pas un essai du binaire réel ni un déchiffrement sur matériel.

**Décision :** aucun provisionnement sur les deux clés tant que le point 1 + la méthode de signature/installation ne sont pas validés. Il est acceptable de conserver durablement le blocage et de surveiller la correction amont d'age-plugin-yubikey AES.

### Exécution regroupée hors matériel — 18 octobre 2026

Le dernier résultat opérateur confirme **23/23 tests PASS** après réparation du contrat d'inscription AES256. Pour éviter des commandes répétées et les erreurs de `pytest` manquant, utiliser désormais une seule quality gate standard-library :

```bash
cd /tmp/nabla-yubikey-pr259
git fetch origin fix/quality-reviewed-deletions-defectdojo-lan-20261017
git switch --detach origin/fix/quality-reviewed-deletions-defectdojo-lan-20261017
bash scripts/workstation/verify-age-yubikey-offline.sh
```

Cette commande réalise `py_compile` puis `unittest discover` sur le contrat YubiKey, et **ne contacte aucune carte**. Son nouveau test porte le total attendu à **24** (à confirmer sur workstation). Les contrôles de préflight matériel séparés restent strictement en lecture seule. Aucun script de provisionnement `--apply` n'est proposé tant que la chaîne de signature et d'import du certificat avec l'OID `1.3.6.1.4.1.41482.3.8` et les politiques `PIN=ALWAYS` / `touch=ALWAYS` n'a pas été prouvée.

**Point de reprise :** étudier comment obtenir un certificat P-256 signé par la clé de PIV82 avec extensions personnalisées sans jamais exporter la clé privée ; démontrer l'outil sur un jeton jetable ou environnement de test avant d'utiliser les deux YubiKeys opérationnelles. Ne pas confondre validation du certificat synthétique et acceptation par le plugin matériel.

### Acceptation opérateur de la quality gate hors matériel (2026-10-18)

L'opérateur a synchronisé le worktree au commit `8f88d706` puis exécuté `bash scripts/workstation/verify-age-yubikey-offline.sh` : **24/24 tests PASS en 0,518 s**, compilation Python comprise, sans contact matériel. L'avertissement final `Not a hardware GO: AES256 compatible certificate install and real decrypt remain unverified` est le comportement attendu. Ces résultats sont une acceptation du parcours local-first, **pas** une autorisation de créer une clé en PIV82. La prochaine étape consiste à valider hors matériel la signature X.509 avec extension OID, puis la compatibilité réelle avant écriture sur la YubiKey secondaire.

### CSR → certificat P-256 : PoC hors matériel ajouté (2026-10-18)

Ajout de `scripts/workstation/test-age-yubikey-csr-offline.sh` et de son contrat `unittest` : génération d'une clé **logicielle éphémère**, d'un CSR, autosignature X.509, inclusion de l'OID de politiques `1.3.6.1.4.1.41482.3.8=DER:03:02` et vérification que la clé publique certifiée correspond à celle de la clé générée. Fichiers temporaires privés supprimés à la sortie ; aucune commande `ykman` et aucun PIN. Le modèle équivalent OpenSSL a été exécuté hors matériel ; la quality gate intégrée (désormais **25 tests attendus**) reste à confirmer sur la workstation.

**Limite essentielle :** ce PoC emploie une clé privée logicielle via `openssl x509 -signkey`. Cette commande **ne peut pas être copiée telle quelle sur une clé PIV privée non exportable**. Il manque une voie de signature depuis PIV82 (PKCS#11 provider, outil utilisant `ykman piv keys attest`/signature ou SDK), qui ajoute exactement la même extension non critique tout en préservant le certificat existant 9A, la management key AES256 et les politiques on-card. Il faut aussi vérifier les octets DER et réellement déchiffrer avec le plugin. **Pas de GO matériel** sur la base de cette seule fixture.

L'opérateur a validé le précédent lot **24/24 tests PASS** au commit `8f88d706`; aucune nouvelle intervention n'est nécessaire avant la prochaine vérification groupée.

### Acceptation opérateur de la chaîne CSR synthétique (18 octobre 2026)

L'opérateur a exécuté `bash scripts/workstation/verify-age-yubikey-offline.sh` : **25 tests PASS / 25, 0,563 s**. Le test `test_offline_csr_certificate_pipeline` est notamment PASS. Le script signale correctement `Not a hardware GO: AES256 compatible certificate install and real decrypt remain unverified`. **Conclusion :** génération CSR + certificat et vérifications synthétiques acceptées en local ; signature par clé privée non exportable en PIV82, installation compatible et déchiffrement age matériel restent à valider. Aucun provisionnement matériel autorisé par ce résultat.

### 2026-10-18 — Chemin SDK Python pour signature PIV non exportable

Recherche documentation Yubico : `ykman.piv.sign_certificate_builder(session, slot, key_type, builder, hash_algorithm)` sait signer un `cryptography.x509.CertificateBuilder` au moyen de la clé privée stockée sur PIV. Ceci ouvre une voie pour ajouter `x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.41482.3.8"), b"\\x03\\x02")` à un certificat auto-signé, contrairement au CLI standard `ykman piv certificates generate` qui ne propose pas directement ces extensions. Sources : https://developers.yubico.com/yubikey-manager/API_Documentation/autoapi/ykman/piv/index.html et https://github.com/Yubico/yubikey-manager/blob/main/ykman/piv.py .

Ajout d'un script de découverte **sans matériel** : `bash scripts/workstation/check-yubikey-piv-python-sdk.sh`. Il vérifie l'existence des modules Python `ykman`, `yubikit`, `cryptography` et de l'API `sign_certificate_builder` dans l'interpréteur sélectionné. **Exit 3** lorsque le SDK manque ou n'est pas compatible, sans tentative d'installation globale. Une nouvelle assertion de contrat porte le nombre attendu de tests `unittest` à **26** (encore à revalider sur workstation).

Chemin étudié **non exécuté** :
1. Préflight strict série + une carte + slot PIV82 vide + AES256 PIN-protected.
2. Génération sur carte de clé ECCP256 en PIV82 avec PIN et toucher `ALWAYS`, uniquement après approbation opérateur de l'étape d'écriture.
3. Construction `x509.CertificateBuilder` avec sujet `O=age-plugin-yubikey,OU=0.5.1,CN=nabla-age-backup`, public key PIV82, dates contrôlées, extension non critique `1.3.6.1.4.1.41482.3.8` = octets `03 02`. Signature par `ykman.piv.sign_certificate_builder` via PIV82 non exportable ; vérifier la signature avec sa clé publique.
4. Import explicite du certificat en PIV82 avec vérification correspondance clé/certificat ; ne pas modifier PIV9A, CHUID ni la management key AES256.
5. `age-plugin-yubikey --list-all` + lecture identité puis vrai encrypt/decrypt synthétique avec toucher/PIN, suivi inventaire slot 9A et OTP2.

**NO-GO persistant :** le script d'inscription matérielle et l'ouverture d'une session PIV authentifiée AES256 ne sont pas encore implémentés/validés ; la compatibilité réelle avec le plugin demeure inconnue. Aucun appel de signature matériel ni mutation de carte n'est autorisé par cette seule découverte de l'API. Préférer un environnement virtuel à versions épinglées et une carte jetable avant déploiement sur secondaire.

### SDK Python manquant — préparation isolée (2026-10-18)

L'opérateur a validé la quality gate **26/26 PASS**, puis `check-yubikey-piv-python-sdk.sh` a indiqué l'absence des modules Python `ykman`, `yubikit` et `cryptography` dans l'interpréteur `mise` Python 3.14.8. Il ne s'agit pas d'un échec YubiKey ni d'un défaut de PIN.

Nouveau `scripts/workstation/bootstrap-yubikey-piv-python-sdk.sh` : mode `--check` implicite (sans téléchargement), `--apply` explicite pour installer un environnement virtuel privé sous `~/.local/share/nabla/piv-sdk-venv`; dépendances top-level épinglées à `yubikey-manager==5.8.0` et `cryptography==46.0.3`, transitive lock encore à produire après résolution. L'installation nécessite un index Python fiable et l'examen de la politique d'approvisionnement logiciel. Le diagnostic SDK accepte désormais `NABLA_PIV_PYTHON` pour sélectionner cet interpréteur sans modifier Python global.

```bash
bash scripts/workstation/bootstrap-yubikey-piv-python-sdk.sh --check
# Si dépôt, sources et versions approuvés :
bash scripts/workstation/bootstrap-yubikey-piv-python-sdk.sh --apply
```

Aucune carte requise, aucun PIN et aucune commande de génération/import PIV. Un contrat ajouté porte le total attendu à **27 tests**, à confirmer localement. **Ne pas confondre capacité Python et GO matériel** ; le chemin CSR/certificat signé par PIV82 et le déchiffrement age ne sont pas encore validés.

### SDK isolé accepté par l'opérateur (2026-10-18)

Le retour workstation confirme **27/27 tests PASS**. L'opérateur a exécuté `bootstrap-yubikey-piv-python-sdk.sh --apply` avec succès : environnement isolé `~/.local/share/nabla/piv-sdk-venv` sous Python 3.14.8, `yubikey-manager==5.8.0`, `cryptography==46.0.3`, et dépendances résolues. `check-yubikey-piv-python-sdk.sh` rapporte `Python SDK imports and signing-builder capability available` puis `SDK capability gate ... available without downgrading AES`. C'est une validation d'import/API, **pas** une validation de session PIV ni de signature sur carte. Aucun PIN, aucune écriture matérielle ni altération AES256 confirmés par ces commandes. Avant opération matérielle : figer dépendances transitives, inspecter les signatures exactes de `PivSession`, du constructeur X.509 et de `sign_certificate_builder`, puis vérifier l'authentification AES256 dans un mode strictement contrôlé. Les YubiKeys restent NO-GO matériel jusqu'à procédure signée et interopérabilité age validées.

### 2026-10-18 — Validation de l'API réelle de signature avec session PIV simulée

Ajout de `scripts/workstation/test-age-yubikey-piv-signing-sdk-offline.py`. Ce test n'utilise **pas** `openssl x509 -signkey` : il appelle réellement `ykman.piv.sign_certificate_builder` (Yubico Manager 5.8.0), avec une fausse session PIV dont la méthode `sign` est exécutée par une clé P-256 éphémère en mémoire. Il vérifie la signature ECDSA du certificat final, la correspondance de la clé publique, le sujet, la présence d'une extension **non critique** `1.3.6.1.4.1.41482.3.8` valant exactement `03 02` et le slot `SLOT.RETIRED1` simulé. Le script n'ouvre aucune connexion PC/SC, ne persiste aucune clé, ne demande aucun PIN et ne modifie aucune carte.

Nouveau contrat dans `tests/test_yubikey_keepassxc_diagnostic_contract.py` : test statique systématique et exécution du PoC avec `~/.local/share/nabla/piv-sdk-venv/bin/python` lorsque cet environnement existe. **28 tests attendus**, à vérifier sur workstation. Commandes en une fois :
```bash
bash scripts/workstation/verify-age-yubikey-offline.sh
~/.local/share/nabla/piv-sdk-venv/bin/python scripts/workstation/test-age-yubikey-piv-signing-sdk-offline.py
```

**Restent NO-GO :** authentification AES256 on-card, import du certificat en PIV82 et vérification de l'identité/du déchiffrement du vrai plugin. Le test par session simulée prouve la structure du certificat et l'API de substitution de signature, **pas** la compatibilité matérielle. Refuser tout script `--apply` sur les deux clés jusqu'à validation séparée et autorisation explicite.

### Reprise dans PR #271 — 23 octobre 2026

La PR #259 étant fermée, la suite est menée **uniquement** dans [PR #271](https://github.com/AlbanAndrieu/nabla-compose/pull/271), branche `feat/fast-batch-talos-k8s-services-20261023`, sans nouvelle PR ni CI payante. Le dernier rapport opérateur a validé **28/28** tests du lot précédent, y compris le SDK de signature avec session PIV simulée.

Ajout de `scripts/workstation/verify-age-yubikey-piv82-certificate.py`, outil **strictement hors matériel** : exige un certificat PEM et une clé publique SPKI PEM obtenus séparément ; refuse les liens symboliques, valide la courbe P-256, la concordance exacte clé/certificat, la signature ECDSA SHA-256 autosignée, le sujet `O=age-plugin-yubikey, OU=0.5.1`, les dates, et l'extension non critique OID `1.3.6.1.4.1.41482.3.8` de valeur **03 02**. En cas d'échec, code 3 (NO-GO). Succès **n'autorise pas** l'installation du certificat. Nouveau contrat dans `tests/test_yubikey_keepassxc_diagnostic_contract.py` ; **29 tests attendus** lors de la prochaine exécution locale.

Exemple futur, uniquement après génération de fichiers **publics** dans une procédure vérifiée :
```bash
~/.local/share/nabla/piv-sdk-venv/bin/python scripts/workstation/verify-age-yubikey-piv82-certificate.py \
  --certificate /chemin/public/piv82.crt.pem \
  --public-key /chemin/public/piv82.spki.pem
```

**Restent bloqués :** authentification réelle AES256 protégée par PIN, preuve de liaison de la clé matérielle PIV82, import du certificat et round-trip `age-plugin-yubikey` sur YubiKey secondaire. Ne jamais modifier AES256, OTP2, PIV9A ni destinataires SOPS à ce stade.

### Validation 29/29 et tests négatifs du certificat — 23 octobre 2026

Retour opérateur : `bash scripts/workstation/verify-age-yubikey-offline.sh` **29/29 PASS en 0,913 s** au HEAD `44e1253d`. Le validateur PIV82 est maintenant couvert par le contrat statique. Dans PR #271, ajout d'un banc d'essai hors matériel `scripts/workstation/test-age-yubikey-certificate-negative-offline.py` : un certificat valide signé par une clé P-256 éphémère doit être accepté ; sept variations (mauvaise clé publique, PIN/touch différents de 03:02, extension critique, certificat expiré, mauvaise organisation, issuer différent, signature réalisée avec une autre clé) doivent être refusées. Le test est branché sur la quality gate en utilisant le Python SDK isolé s'il existe. **30 tests attendus à confirmer sur workstation.**

Rester **NO-GO matériel** : validation 30/30 n'autorise aucune inscription ni import. Priorités non résolues : session YubiKey réelle AES256 PIN-protected, import PIV82, découverte `age-plugin-yubikey` et round-trip de déchiffrement avec présence/toucher. La PR #271 reste ouverte sans CI facturée.

### Validation opérateur 30/30 — 23 octobre 2026

Après synchronisation sur le HEAD `f6480a5b`, l'opérateur a exécuté `bash scripts/workstation/verify-age-yubikey-offline.sh` : **30/30 tests PASS en 0,859 s**, notamment `test_piv82_certificate_adversarial_fixtures`. La gate reste exclusivement hors matériel. Le message `Not a hardware GO: AES256 compatible certificate install and real decrypt remain unverified` est attendu. Le jalon tests positifs/négatifs des certificats est accepté ; les prochaines vérifications doivent porter sur les interfaces de session PIV AES256 et l'interopérabilité matérielle, sans demander de PIN ni écrire sur la carte tant que le chemin n'est pas approuvé.

### 23 octobre 2026 — Préflight matériel AES256 en lecture seule (PR #271)

Script ajouté : `scripts/workstation/inspect-age-yubikey-aes256-hardware.sh --serial 11110002|11110001`. Limité aux deux numéros de série inventoriés, exige **exactement une** YubiKey connectée ; vérifie via `ykman` le stockage de la management key **AES256 protégée par PIN**, l'absence de clé dans PIV82 et la présence de métadonnées clé en PIV9A. N'effectue **aucun** essai PIN, authentification, signature, génération ou import. En cas de doute ou d'erreur d'accès, termine en **NO-GO (exit 3)**. Le contrôle de PIV9A porte sur les métadonnées de clé, **pas sur son certificat** ou une comparaison de fingerprint historique. OTP2 reste intact mais n'est pas vérifié cryptographiquement par cet inventaire. Le résultat ne démontre pas l'authentification PIN-protected AES256.

Nouveau contrat unittest correspondant : **31 tests attendus** lors de la prochaine gate. Validation précédente **30/30 PASS** au commit `f6480a5b` et enregistrée dans PR #271. Commandes à exécuter uniquement lorsque la carte secondaire peut être connectée en exclusivité :

```bash
bash scripts/workstation/verify-age-yubikey-offline.sh
bash scripts/workstation/inspect-age-yubikey-aes256-hardware.sh --serial 11110002
```

**NO-GO provisionnement maintenu** jusqu'à validation du mécanisme d'authentification matérielle AES256 et de l'inscription/certification PIV82, suivie d'un déchiffrement age réel. Aucun merge automatique ni CI facturée.

### Diagnostic PIV82 indéterminé — 23 octobre 2026 (PR #271)

L'opérateur a validé **31/31 tests PASS (0,945 s)** sur HEAD `4f5a95d7`, mais le préflight matériel sur la secondaire série `11110002` s'est arrêté avec `PIV82 is occupied or its empty state is not provable`. **Ce message ne prouve pas que PIV82 contient une clé.** Le code exigeait à tort un status `ykman piv keys info 82` égal à zéro même si certaines versions signalent explicitement un slot vide avec exit 1. La correction accepte désormais uniquement un message d'absence **explicite et reconnu** et un exit status 0 ou 1 ; toute erreur transport, message ambigu ou statut différent reste NO-GO. Un diagnostic catégorisé est imprimé sans exposer la sortie brute. Nouveau contrat : **32 tests attendus**, non encore validés sur la workstation.

Reprise en lecture seule : synchroniser la branche PR #271, lancer `bash scripts/workstation/verify-age-yubikey-offline.sh`, puis `bash scripts/workstation/inspect-age-yubikey-aes256-hardware.sh --serial 11110002` avec uniquement la secondaire branchée. Si résultat toujours indéterminé, examiner séparément la sortie `ykman` sans publier les secrets. **Aucun PIN, aucune écriture matérielle, aucune modification AES256/OTP2/PIV9A**.

### Retour opérateur 32/32 — réponse PIV82 ykman (23 octobre 2026)

Au HEAD `c97c35f3`, gate locale **32/32 PASS en 0,949 s**. L'inventaire matériel secondaire série `11110002` a donné `ykman exit=1`, catégorie `unsupported or unrecognized ykman response` : **état PIV82 inconnu**, pas occupé confirmé. La source `Yubico/yubikey-manager` tag `5.8.0`, `ykman/_cli/piv.py`, commande `piv keys info`, produit `CliFail(f"No key stored in slot {slot}.")` si le code APDU vaut `REFERENCE_DATA_NOT_FOUND`. Notre ancienne regex n'acceptait ni l'éventuel préfixe CLI `Error:` ni le nom symbolique `RETIRED1` du slot 82. Regex resserrée sur la réponse **complète** et les désignations explicites `RETIRED1`/`SLOT.RETIRED1` ou `82`/`0x82`, sans accepter d'erreur transport. Le contrat existant est ajusté. **32/32 de nouveau attendus**, pas encore confirmés après changement. L'absence de métadonnées PIV9A n'a pas été réévaluée lorsque PIV82 bloque ; une nouvelle exécution lecture seule est nécessaire. La réussite du préflight n'est pas une preuve de signature matérielle ni de déchiffrement age ; **NO-GO provisionnement** inchangé.

### 23 octobre 2026 — Capturer la réponse exacte de `ykman`

Retour opérateur : **32/32 tests PASS en 1,003 s** sur HEAD `25ece6fb`, mais le préflight série `11110002` reste `PIV82 unverified (ykman exit=1)` / `unsupported or unrecognized ykman response`. Plusieurs tentatives de correction par expressions régulières ont provoqué des erreurs Bash ; ne pas continuer à supposer la sortie CLI. Nouveau diagnostic en lecture seule `scripts/workstation/diagnose-age-yubikey-piv82-response.sh --serial 11110002` : vérifie qu'une seule carte attendue est connectée, exécute uniquement `ykman --device SERIAL piv keys info 82`, affiche le code de retour et **la réponse réelle** (métadonnées publiques ; à relire avant partage), puis affiche NO-GO. Aucun PIN et aucune écriture. Nouveau test de contrat : **33 tests attendus**. Le résultat du diagnostic conditionnera la correction suivante ; ne pas autoriser le provisionnement sur la seule interprétation d'un code de sortie `1`.

### Preuve matérielle PIV82 (23 octobre 2026)

Retour opérateur sur secondaire `11110002` : **33/33 tests PASS (0,995 s)** ; `ykman --device 11110002 piv keys info 82` retourne code **1** avec texte exact `ERROR: No key stored in slot 82 (RETIRED1).`. Cela **confirme PIV82 vide** dans le contexte de cette commande ; il n'est pas nécessaire de poursuivre les hypothèses sur la sortie CLI. L'inventaire préflight utilisait une regex qui exigeait un point immédiatement après `82` et rejetait les parenthèses `(RETIRED1)` : correction désormais fondée sur cette preuve exacte. Nouveau test vérifie acceptation de cette réponse et rejet des mauvaises désignations et messages composites. **34 tests attendus** après changement, à vérifier localement. La lecture de PIV9A via l'inventaire n'a pas encore été confirmée après cette correction ; l'authentification AES256 et le déchiffrement matériel ne sont pas validés. **NO-GO provisionnement** maintenu ; aucune mutation, aucun PIN, aucun merge et aucune CI payante.

### 23 octobre 2026 — 35 PASS et contrôle SDK AES256 sans matériel (PR #271)

Résultat opérateur : `python3 -m py_compile tests/test_yubikey_keepassxc_diagnostic_contract.py` OK et `bash scripts/workstation/verify-age-yubikey-offline.sh` **35/35 PASS en 0,928 s**, HEAD `bd146ceb`. Le préflight matériel précédent a confirmé sur la secondaire série `11110002` : management key **AES256 protégée par PIN**, PIV82 vide et métadonnées de clé en PIV9A présentes. Aucune authentification PIN/management key ni déchiffrement age n'a été tenté.

**Analyse source SDK Yubico Manager 5.8.0 :** dans `ykman/_cli/piv.py`, `_ensure_authenticated` suit le chemin `_verify_pin` quand `pivman.has_protected_key`; `_verify_pin` effectue `session.verify_pin(pin)`, récupère l'objet `get_pivman_protected_data(session)` si `has_stored_key`, puis `session.authenticate(pivman_prot.key)`. Dans `ykman/piv.py`, le type `MANAGEMENT_KEY_TYPE.AES256` possède une longueur de clé de **32 octets**. Ces faits décrivent **un chemin technique documenté**, mais ne sont pas une validation sur l'appareil. Éviter la voie historique de dérivation TDES ; ne jamais publier la clé ou le PIN et ne jamais automatiser les tentatives de PIN.

Ajout de `scripts/workstation/inspect-age-yubikey-piv-aes256-sdk-api.py` : contrôle **strictement hors matériel** des imports, interfaces et constantes (AES256 32 octets, objets Pivman, PIV82, ECCP256, PIN/touch ALWAYS). Ne construit aucune session PIV, n'appelle aucune fonction d'authentification et ne lit aucun octet secret. La nouvelle gate doit compter **36 tests**, à revalider sur workstation.

```bash
bash scripts/workstation/verify-age-yubikey-offline.sh
~/.local/share/nabla/piv-sdk-venv/bin/python \
  scripts/workstation/inspect-age-yubikey-piv-aes256-sdk-api.py
```

**NO-GO provisionnement maintenu.** Le succès SDK ne valide ni l'authentification AES256 réelle, ni la signature/certificat depuis une clé privée PIV82, ni le déchiffrement `age-plugin-yubikey`. Prochaine étape : prévoir une session opérateur explicitement approuvée, contrôler le budget d'essais PIN, puis préparer les validations matérielles sans écriture avant toute génération de clé.

### 23 octobre 2026 — 36 PASS et lot de tests comportementaux AES256/PIV82 (PR #271)

Résultat opérateur au HEAD ce9801f0 : **36/36 tests PASS en 1,066 s** ; le script inspect-age-yubikey-piv-aes256-sdk-api.py confirme les API du SDK Yubico 5.8.0, la management key AES256 (32 octets), le Pivman protégé, le slot PIV82 et PIN/touch ALWAYS. Ceci **ne démontre pas une authentification réelle sur la carte**. Le préflight réel précédent sur la secondaire 11110002 a déjà prouvé AES256 PIN-protected, PIV82 vide et métadonnées PIV9A présentes.

Pour limiter les petites itérations, deux bancs de tests **hors matériel** ont été ajoutés ensemble dans la PR #271 :

- **test-age-yubikey-piv-aes256-handshake-offline.py** : appelle les véritables parseurs PivmanData, PivmanProtectedData, get_pivman_data et get_pivman_protected_data dans une **session factice en mémoire**. Vérifie l'ordre PIN synthétique → lecture de la clé AES256 fictive → authentification simulée → vérification finale du PIN. Couvre six refus sans nouvelle tentative après échec : PIN incorrect, compteur trop bas/bloqué, management key non protégée, clé absente, longueur incorrecte. Le seuil simulé de trois tentatives est volontairement conservateur ; il ne constitue pas une autorisation matérielle.
- **test-age-yubikey-piv82-inventory-fake-offline.py** : intercepte tous les appels ykman avec un exécutable factice prioritaire dans PATH ; vérifie sept scénarios (slot vide, occupé, réponse ambiguë, erreur transport, mauvais numéro de série, algorithme non AES256, métadonnées PIV9A absentes). Aucun vrai périphérique n'est interrogé et tous les appels passent par une liste blanche lecture seule.

Les deux contrats sont intégrés à tests/test_yubikey_keepassxc_diagnostic_contract.py : **39 tests attendus** après revalidation workstation. La quality gate compile désormais explicitement les scripts Python et contrôle la syntaxe Bash avant d'exécuter les tests de comportement, afin de détecter les régressions de fichier tronqué ou mal échappé.

```bash
bash scripts/workstation/verify-age-yubikey-offline.sh
~/.local/share/nabla/piv-sdk-venv/bin/python scripts/workstation/test-age-yubikey-piv-aes256-handshake-offline.py
python3 scripts/workstation/test-age-yubikey-piv82-inventory-fake-offline.py
```

**NO-GO matériel maintenu :** aucune lecture de PIN réel ni authentification effective ; signature PIV82, import de certificat et déchiffrement age matériel restent à valider. Préserver management key AES256, OTP2 KeePassXC, PIV9A et destinataires SOPS de production.

### 23 octobre 2026 — Convergence du plan de provisionnement et de l'inventaire

Le planificateur de PIV82 avait lui aussi conservé une interprétation obsolète du code de sortie 1 de Yubico Manager. Il délègue maintenant **tous** les précontrôles matériels au script de référence inspect-age-yubikey-aes256-hardware.sh : série exacte, carte unique, management key AES256 PIN-protected, PIV82 vide et métadonnées PIV9A présentes. Plus de seconde regex ni de seconde logique d'authentification dans le planificateur.

Le faux exécutable ykman couvre désormais **les deux scripts** (inventaire et planificateur), soit **14 exécutions simulées** pour sept scénarios, avec refus systématique des erreurs. Une commande age-plugin-yubikey factice couvre la vérification de présence de l'outil ; aucune vraie carte n'est utilisée. La quality gate lance également bash -n sur le planificateur avant les tests. **39 tests unittest attendus**, validation réelle sur workstation encore en attente après ce lot. NO-GO pour toute écriture PIV82.

### 23 octobre 2026 — Lot groupé de contrôles AES256 hors matériel

La workstation a confirmé `36/36 PASS` sur HEAD `ce9801f0`. Le script `inspect-age-yubikey-piv-aes256-sdk-api.py` rapporte `PASS: SDK AES256 (32-byte), protected Pivman data, PIV82 and PIN/touch ALWAYS APIs`, sans authentification réelle. Ajout de `scripts/workstation/test-age-yubikey-aes256-auth-offline.py` : session **entièrement simulée**, clé fictive de 32 octets, séquence `verify_pin → authenticate → verify_pin` et trois rejets (PIN factice erroné, authentification factice rejetée, longueur AES256 incorrecte). Aucun périphérique PC/SC, secret ni fonction d'écriture. Contrat unittest ajouté.

**Limite de preuve :** ce test reproduit le chemin du SDK documenté, sans exercer l'API authentifiée sur matériel et sans vérifier la lecture de Pivman protégé. La première authentification réelle devra être une opération séparée avec contrôle des tentatives PIN, approbation opérateur et absence de retry automatique. Les slots 82 et 9A, OTP2, la management key AES256 et les identités SOPS restent inchangés. **Aucun GO pour le provisionnement.**

Dans la branche PR #271, le nombre de tests peut varier avec les commits concurrents : prendre `python3 -m unittest discover` comme source de vérité et ne pas présumer du décompte avant exécution.
