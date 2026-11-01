# YubiKey PIV82 / age AES256 — reprise de chantier (23 octobre 2026)

## Source de vérité et limites

- Dépôt : `AlbanAndrieu/nabla-compose`.
- **PR de travail unique : [#271](https://github.com/AlbanAndrieu/nabla-compose/pull/271)**, branche `feat/fast-batch-talos-k8s-services-20261023`. Ne pas créer de PR, merger ou lancer de GitHub Actions.
- Vérifier le dernier HEAD GitHub avant toute écriture : plusieurs agents poussent sur cette branche.
- Priorité : réutiliser les deux **YubiKey 5 NFC** sans perturber KeePassXC OTP2, l'ancien certificat PIV9A, la management key AES256 PIN-protected ou la récupération SOPS logicielle.
- Secondaire **11110002** (LastPass : `yubikey-5-nabla backup`), principale **11110001** (LastPass : `yubikey-5-nabla principal`). Ne jamais enregistrer PIN, PUK, clé privée, management key ou jeton d'authentification dans les logs/PR.
- Conserver PIV82 (`SLOT.RETIRED1`) pour age, PIV83 pour une future rotation.

## Preuves validées côté workstation

1. La dernière gate **40/40 PASS (2,576 s)** lors du retour opérateur précédent. `test-age-yubikey-aes256-auth-offline.py` affichait alors le succès du modèle simplifié à 3 échecs.
2. Le préflight matériel secondaire a confirmé la clé de gestion **AES256 protégée par PIN**, PIV82 vide, métadonnées de clé PIV9A présentes. `ykman piv keys info 82` retourne `ERROR: No key stored in slot 82 (RETIRED1).` et status 1 : c'est le message attendu d'un slot vide.
3. `yubikey-manager==5.8.0` / `cryptography==46.0.3` installés sous `~/.local/share/nabla/piv-sdk-venv` sur la workstation. La vérification hors matériel des interfaces SDK AES256 est **PASS**.
4. Prototype X.509 P-256 autosigné et OID `1.3.6.1.4.1.41482.3.8` valeur `03 02` vérifiés sur clés logicielles ou sessions simulées. Aucune clé privée sur carte n'a été générée.

## Préparatifs de la passe courante

- Renforcement du modèle `test-age-yubikey-aes256-auth-offline.py` : séquencement vérification PIN → lecture de clé protégée → authentification AES256 → revérification PIN ; refus des budgets de tentatives faibles, des clés absentes/courtes, des erreurs d'authentification, d'une politique dérivée/incorrecte et d'un échec à la revérification. **10 cas négatifs**, validés en local sans SDK ni matériel.
- `test-age-yubikey-piv-signing-sdk-offline.py` : le certificat produit par `ykman.piv.sign_certificate_builder` avec fausse session doit maintenant passer `verify-age-yubikey-piv82-certificate.py`, tandis qu'une mauvaise clé publique et une signature forgée doivent être rejetées. Ce parcours requiert le SDK Yubico pour la validation workstation.
- `verify-age-yubikey-offline.sh` précompile désormais le script de modèle AES256 avant la suite `unittest`.
- **Nombre de tests `unittest` attendu : 40**, sans nouveau test nommé ajouté. Les modifications récentes ne sont **pas encore** validées par la gate complète sur la workstation.

## Commandes de validation (sans carte, sans CI)

```bash
cd /tmp/nabla-yubikey-pr259
git fetch origin feat/fast-batch-talos-k8s-services-20261023
git switch --detach origin/feat/fast-batch-talos-k8s-services-20261023
bash scripts/workstation/verify-age-yubikey-offline.sh
python3 scripts/workstation/test-age-yubikey-aes256-auth-offline.py
~/.local/share/nabla/piv-sdk-venv/bin/python scripts/workstation/test-age-yubikey-piv-signing-sdk-offline.py
```

## Restes obligatoires avant provisionnement

1. Vérifier précisément la séquence d'authentification AES256 PIN-protected et le compteur de tentatives sur matériel, **seulement avec autorisation distincte** ; aucun retry automatique du PIN.
2. Construire une procédure transactionnelle à étapes distinctes, chacune autorisée explicitement : `generate_key` ECCP256 dans PIV82 avec politiques `ALWAYS/ALWAYS`, signature X.509 par la clé **non exportable**, contrôle de signature, import puis lecture du certificat. Prévoir le comportement si l'import échoue sans écraser PIV9A.
3. Vérifier `age-plugin-yubikey --list-all`, les identités/récipients age et un round-trip chiffrer/déchiffrer synthétique sur la secondaire, puis la principale.
4. Ne modifier les destinataires SOPS de production qu'après les deux validations matérielles. Conserver l'identité logicielle CI/headless et l'escrow indépendant. Une **deuxième copie indépendante de l'identité privée escrow** reste une dette de récupération.

**Statut : NO-GO pour tout provisionnement/écriture PIV.** Les tests hors matériel et un slot vide ne suffisent pas à l'autoriser.


### 23 octobre 2026 — Checklist transactionnelle PIV82 (hors matériel)

Commande de préparation **sans lecteur, PIN, authentification ni écriture** :

```bash
python3 scripts/workstation/plan-age-yubikey-piv82-transaction.py --serial 11110002
python3 scripts/workstation/plan-age-yubikey-piv82-transaction.py --serial 11110001 --json
bash scripts/workstation/verify-age-yubikey-offline.sh
```

Six jalons ordonnés par carte : **inventaire → authentification AES256 supervisée → génération ECC P-256 non exportable PIV82 → signature X.509 avec cette clé → import et relecture du certificat → preuve `age-plugin-yubikey` avec données synthétiques**. Chaque jalon exige preuves explicites, nouvelle autorisation opérateur et arrêt sur échec. Ce plan **n'accepte pas `--apply`**, ne vérifie aucune preuve et ne déclare jamais GO.

1. **Inventaire** : isoler la secondaire `11110002`, confirmer la seule carte branchée, PIV82 vide, AES256 PIN-protected, PIV9A et OTP2 préservés. Préserver deux copies indépendantes de récupération logicielle. La principale `11110001` reste bloquée tant que l'interopérabilité de la secondaire n'a pas été prouvée.
2. **Authentification** : le chemin protégé du SDK Yubico Manager **5.8.0** peut appeler `verify_pin` deux fois, avant et après l'authentification de la management key stockée. Cette séquence ne justifie **aucun retry après erreur**. Contrôler manuellement le compteur juste avant ; arrêter immédiatement si PIN rejeté ou compteur douteux. Jamais de PIN/PUK/management key dans les sorties, journaux ou PR.
3. **Génération** : une autorisation spécifique est exigée pour créer une clé P-256 non exportable en PIV82 avec `PIN_POLICY.ALWAYS` et `TOUCH_POLICY.ALWAYS`. Si le slot devient occupé, ne jamais régénérer automatiquement, réinitialiser PIV ni altérer PIV9A/OTP2. Un échec d'import du certificat laisse une clé présente : arrêter et diagnostiquer.
4. **Certificat** : signer **sur PIV82**, puis valider via `verify-age-yubikey-piv82-certificate.py` contre une SPKI lue indépendamment. Attendus : O=`age-plugin-yubikey`, OU=`0.5.1`, OID `1.3.6.1.4.1.41482.3.8` de valeur `03 02`, ECDSA SHA-256. Après import, relire le certificat, comparer DER et SPKI et contrôler que PIV9A n'a pas changé. Un PEM signé par logiciel n'établit aucune liaison matérielle.
5. **Interopérabilité et SOPS** : découvrir l'identité et le destinataire du plugin, puis réussir le véritable round-trip age sur la secondaire. Répéter ensuite avec la principale. **Ne modifier aucun destinataire SOPS** tant que les deux cartes physiques distinctes n'ont pas réussi le déchiffrement, tout en conservant les destinataires logiciels et les deux copies indépendantes de l'escrow.

Contrats nouveaux : `tests/test_yubikey_piv82_transaction.py` (**6 tests hors matériel, 6/6 PASS localement**). La gate workstation découvre les fichiers `test_yubikey*.py` ; **46 tests attendus** en conservant le décompte précédent de 40, à reconfirmer sur la workstation. **NO-GO matériel inchangé.**

### 23 octobre 2026 — Compatibilité AES256 et attestation de PIV82

Validation opérateur après synchronisation : **47/47 tests PASS en 2,566 s** au HEAD `27d58bac` sur la workstation ; le PoC Yubico `sign_certificate_builder` avec session simulée **PASS**, incluant rejet des certificats falsifiés et des SPKI incorrectes. Ce résultat confirme la **validité du protocole simulé**, pas une signature réelle en PIV82.

**Blocage découvert dans les sources amont :** `age-plugin-yubikey` **v0.5.1** ne prend pas en charge les **management keys AES** pour son propre processus de provisionnement ([issue officielle #92](https://github.com/str4d/age-plugin-yubikey/issues/92), encore ouverte au 23/10/2026 ; [messages du binaire](https://docs.rs/crate/age-plugin-yubikey/0.5.1/source/i18n/en-US/age_plugin_yubikey.ftl)). Son interface interactive peut modifier le PIN/PUK ou la management key selon l'état initial ([README officiel](https://github.com/str4d/age-plugin-yubikey/tree/v0.5.1#manual-setup-and-technical-details)). **Interdiction d'utiliser `--generate`, la configuration interactive, `--force` ou toute logique de migration de clé de gestion avec les deux YubiKeys**. Le futur provisionnement, soumis à autorisation séparée, passe exclusivement par un chemin Yubico Manager SDK AES256 évalué hors matériel ; le plugin ne sert ensuite qu'à la découverte et au véritable déchiffrement age.

**La présence d'un OID `1.3.6.1.4.1.41482.3.8` = `03 02` sur un certificat X.509 autosigné n'atteste pas des politiques matérielles.** Après génération PIV82 et avant signature/import applicatif, une **phase d'attestation distincte** est exigée : certificat d'attestation issu du slot F9, vérification de la chaîne vers une racine Yubico approuvée (ne jamais accepter une racine F9 remplacée), SPKI identique à PIV82 et politiques PIN/touch ALWAYS/ALWAYS dans l'attestation. Référence : [Yubico PIV Attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html). En l'absence de chaîne fiable, **NO-GO** ; ne pas remplacer une preuve d'attestation par le seul fichier de certificat age.

Le plan `plan-age-yubikey-piv82-transaction.py` comporte maintenant **7 jalons** : inventaire, authentification, génération, **attestation**, signature du certificat, import, interopérabilité. La gate locale couvre **8 tests transactionnels PASS** (6 existants + 2 nouveaux) dans l'environnement isolé de l'agent. La suite complète est **49 tests attendus** sur workstation sous réserve d'absence d'autres modifications concurrentes. Aucun PIN, authentification, attestation réelle, écriture PIV ou modification SOPS effectués. **NO-GO matériel maintenu.**


### 23 octobre 2026 — Gate 49/49 validée, attestation hors matériel et synchronisation Git

Retour opérateur sur le checkout `/tmp/nabla-yubikey-pr259` : **49/49 tests PASS en 2,426 s** ; le PoC `sign_certificate_builder` du SDK a validé une signature synthétique et rejeté signature forgée/SPKI différente. Il n'y a toujours **aucune preuve de signature PIV82 réelle**. Un `git fetch` par SSH a échoué sur `github.com:22` (timeout) ; la commande suivante `git switch --detach origin/...` a seulement utilisé **la référence déjà en cache**, et son succès ne prouve pas une récupération distante réussie.

**Récupération ponctuelle via HTTPS, sans modification de remote, sans force/reset ni CI :**
```bash
cd /tmp/nabla-yubikey-pr259
git status --short
git -c 'url.https://github.com/.insteadOf=git@github.com:' \
  fetch --no-tags origin feat/fast-batch-talos-k8s-services-20261023
git rev-parse HEAD FETCH_HEAD
# Vérifier que l'arbre de travail est propre AVANT de changer de commit.
git switch --detach FETCH_HEAD
bash scripts/workstation/verify-age-yubikey-offline.sh
```
Si HTTPS est également inaccessible, **arrêter sans supposer que `origin/...` est à jour**. Conserver la révision du checkout et comparer son SHA au HEAD de la PR via GitHub. Ne pas modifier de configuration SSH globale pour contourner l'incident.

**Nouveau vérificateur d'attestation publique :** `scripts/workstation/verify-age-yubikey-piv82-attestation.py`. Entrées uniquement PEM publics (sans PC/SC) : certificat d'attestation slot 82, certificat signataire F9, autorité racine approuvée, intermédiaires facultatifs (dont bundles PEM officiels), SPKI PIV82 lue séparément, numéro de série prévu et **empreinte SHA256 de racine vérifiée indépendamment du fichier PEM**. Vérifie la chaîne et les signatures, l'absence d'expiration, une autorité racine véritablement ancrée, le sujet du slot 82, la liaison SPKI, l'OID de politique `03 02` et l'OID du numéro de série. Renvoie **NO-GO** au premier écart. N'interprète **jamais** le certificat applicatif autosigné comme une attestation matérielle.

Sans fichiers d'attestation réels, exécuter seulement la **simulation** :
```bash
~/.local/share/nabla/piv-sdk-venv/bin/python \
  scripts/workstation/test-age-yubikey-piv82-attestation-offline.py
```
L'outil de validation des vrais PEM exige `--attestation --f9 --root --public-key --serial --root-sha256`, et permet de fournir les intermédiaires via `--intermediate`. Pour ne pas accepter une fausse autorité, **ne jamais recopier l'empreinte SHA256 calculée depuis le PEM reçu comme valeur approuvée** : comparer avec une empreinte de racine Yubico authentifiée par une source séparée. La chaîne diffère pour les appareils **5.7.4+** (nouvelle racine et intermédiaires) et les firmwares antérieurs. Source : [Yubico PIV Attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html), [procédure de vérification](https://developers.yubico.com/yubico-piv-tool/Attestation.html).

Nouvelle gate : **2 tests de contrat supplémentaires**, soit **51 tests attendus** d'après le dernier 49/49 (sous réserve de commits concurrents) + un test cryptographique synthétique indépendant couvrant **8 cas négatifs** et un bundle intermédiaire. Les **10 tests transactionnels** et le banc cryptographique d'attestation ont été exécutés avec succès sur la copie isolée des fichiers modifiés de l'agent ; cela ne remplace ni le checkout complet de la workstation ni une opération matérielle. Aucun provisioning, aucune authentification PIN, aucune modification F9/PIV9A/OTP2/SOPS. **NO-GO matériel maintenu.**

### 24 octobre 2026 — Précontrôle F9 avant attestation PIV82

**Jalon réellement accessible avant provisionnement** : la secondaire `11110002` a un PIV82 vide. D'après la [documentation officielle Yubico](https://developers.yubico.com/yubico-piv-tool/Attestation.html), la commande d'attestation de PIV82 ne peut produire de certificat **avant génération sur la carte** d'une clé dans ce slot. Une tentative immédiate ne constituerait pas une preuve et ne doit pas déclencher de génération automatique.

Le script `scripts/workstation/inspect-age-yubikey-f9-chain.sh` inspecte **uniquement les métadonnées publiques** : exactement une YubiKey avec numéro de série attendu, firmware et certificat F9 exporté en PEM dans un répertoire temporaire privé, puis supprimé. Il ne sollicite aucun PIN, ne lance aucun `piv keys attest`, ne modifie aucun certificat, PIV9A, OTP2, clé AES256 ou destinataire SOPS. Le SHA-256 imprimé est **l'empreinte du certificat F9**, **pas** celle de la racine Yubico ; il n'autorise aucun GO.

```bash
# Ne connecter que la YubiKey secondaire.
bash scripts/workstation/inspect-age-yubikey-f9-chain.sh --serial 11110002
# Réexécuter la suite hors matériel sans CI payante.
bash scripts/workstation/verify-age-yubikey-offline.sh
```

L'attestation réelle PIV82 demeure **bloquée** jusqu'à approbation distincte d'une génération ECC P-256 avec PIN/touch ALWAYS, suivi d'une chaîne de confiance Yubico vérifiée contre une empreinte de racine approuvée **indépendamment**. Les firmwares 5.7.4+ utilisent la nouvelle racine 2025 et des intermédiaires, les versions antérieures une autre chaîne : [Yubico PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).

Contrats : `tests/test_yubikey_f9_inventory.py`, **8/8 tests hermétiques PASS** dans l'environnement isolé de l'agent, avec fausses commandes `ykman` et `openssl` seulement. Ils ont été exécutés sur la source du script intégrée à la PR ; ils ne prouvent pas l'état réel de F9. **NO-GO matériel et SOPS maintenu.**


### 24 octobre 2026 — PR #274 : reprise Git et F9

- Ancienne PR #271 fusionnée, suivi uniquement dans PR Draft #274 ; ne pas créer d'autre PR ni déclencher de CI GitHub payante.
- Nouveau diagnostic Git local : scripts/workstation/diagnose-age-yubikey-git-checkout.sh. Détecte detached HEAD, le retard sur une référence origin/master en cache, les modifications locales, l'absence du fichier de test attestation. Le résultat ne prouve pas la fraîcheur du serveur.
- Nouveau préflight F9 en lecture seule : scripts/workstation/inspect-age-yubikey-f9-chain.sh --serial 11110002. Une seule clé sélectionnée, firmware reconnu, export du certificat public F9 en temporaire privé puis suppression ; aucune commande PIN ou écriture sur carte. L'empreinte imprimée concerne F9, pas une autorité racine Yubico approuvée.
- Durcissement X.509 : interdiction de certificat PIV82 CA, vérification du key usage du signataire F9, pathLen des autorités CA, limite de taille des PEM ; 12 variantes adversariales synthétiques.
- Tests locaux isolés : 7/7 diagnostics Git PASS et 8/8 préflights F9 PASS. L'ensemble du dépôt doit être revérifié au HEAD de la PR sur la workstation ; **66 tests attendus** si aucun commit concurrent.
- Procédure pas à pas : docs/runbooks/yubikey-piv82-postmerge-diagnostics.md

Le slot PIV82 est encore vide selon le dernier inventaire. L'attestation PIV82 n'est possible qu'après une **génération de clé sur la YubiKey**, qui reste soumise à une autorisation explicite distincte. La lecture F9 ne constitue jamais un GO pour générer, signer, importer, modifier AES256/PIV9A/OTP2 ou migrer SOPS. Conserver la récupération logicielle et les deux copies indépendantes de l'escrow.

Documentation officielle : https://developers.yubico.com/yubico-piv-tool/Attestation.html ; https://developers.yubico.com/PIV/Introduction/PIV_attestation.html


### 24 octobre 2026 — Préparation de la vérification de la chaîne F9 ancienne

Résultat workstation : 66/66 PASS et 12 refus crypto PASS au HEAD 4f076aa5 ; secondaire 11110002, firmware 5.4.3, empreinte F9 SHA256 6C:6E:14:0A:69:81:14:C3:51:14:0C:1B:68:C4:B1:16:A7:D9:B4:49:29:76:62:39:2F:61:F1:78:54:90:34:DF. Cela ne prouve pas encore la confiance Yubico.

Pour les firmwares antérieurs à 5.7.4, la racine officielle est Yubico PIV Root CA Serial 263751 (https://developers.yubico.com/PKI/yubico-piv-ca-1.pem), SHA-256 DER 63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46. Elle est épinglée dans le vérificateur F9 hors matériel. La nouvelle option --save-public-f9 conserve uniquement une copie publique sans écrasement. Procédure : docs/runbooks/yubikey-piv82-postmerge-diagnostics.md section 5.

Contrats L1 isolés avant publication : 5/5 sauvegarde F9, 13/13 vérification X.509 synthétique. Suite complète du nouveau HEAD attendue sur workstation (71 tests unittest + deux fixtures autonomes). Pas de PIN, pas de modification PIV82, F9, OTP2, PIV9A, AES256 ou SOPS. **NO-GO matériel maintenu.**
