# YubiKey PIV82 / age — reprise après la fusion de PR #271

**Travail :** PR [#274](https://github.com/AlbanAndrieu/nabla-compose/pull/274), Draft, commits [skip ci]. Sécurité : **NO-GO matériel**.

## 0. Reprise automatisée sans checkout après redémarrage

**Dernières preuves réelles :** 71/71 unittest et 13 tests F9 PASS,
certificat F9 secondaire 11110002 (firmware 5.4.3) vérifié jusqu'à la
racine Yubico épinglée. PIV82, PIN/AES256 et SOPS restent NO-GO.

**Après reboot, /tmp/nabla-yubikey-pr259 peut avoir disparu.**
Ne pas chercher à réparer ce chemin. Le lanceur utilise désormais un
**dépôt bare persistant** dans
\`$HOME/.local/share/nabla/git/nabla-compose.git\` et crée un
worktree détaché et privé, unique pour chaque agent, sous
\`$HOME/.local/share/nabla/agent-worktrees/\`.

La procédure complète tient dans **un bloc**, exécutable depuis
n'importe quel répertoire. Le bootstrap :
1. Obtient le SHA exact de la branche PR #274 sur GitHub.
2. Crée le cache Git bare si absent, sous verrou.
3. Récupère le commit seulement s'il manque.
4. Extrait le script versionné de ce SHA, sans modifier de checkout.
5. Exécute les tests et le contrôle cryptographique F9 enregistré.
Chaque échec interrompt la suite. Aucune écriture matérielle.

~~~bash
bash <<'PR274_READONLY'
set -Eeuo pipefail
umask 077
remote=https://github.com/AlbanAndrieu/nabla-compose.git
branch=fix/homelab-operator-diagnostics-followup-20261024
state="${NABLA_AGENT_STATE_DIR:-$HOME/.local/share/nabla}"
cache="$state/git/nabla-compose.git"
[[ -d "$HOME" && ! -L "$state" && ! -L "$state/git" && ! -L "$cache" ]] || exit 3
mkdir -p -m 0700 "$state/git"
exec 9>"$state/.pr274-git.lock"
flock -w 20 9
if [[ ! -e "$cache" ]]; then git init --bare -q "$cache"; fi
[[ "$(git --git-dir="$cache" rev-parse --is-bare-repository)" == true ]]
ref="refs/heads/$branch"
response="$(git ls-remote --exit-code "$remote" "$ref")"
IFS=$'\t' read -r sha returned_ref <<< "$response"
[[ "$sha" =~ ^[0-9a-f]{40}$ && "$returned_ref" == "$ref" ]]
if ! git --git-dir="$cache" cat-file -e "$sha^{commit}" 2>/dev/null; then
  git --git-dir="$cache" fetch --no-tags --no-write-fetch-head "$remote" "$ref"
fi
git --git-dir="$cache" cat-file -e "$sha^{commit}"
launcher="$(mktemp)"
trap 'rm -f -- "$launcher"' EXIT
git --git-dir="$cache" show "$sha:scripts/workstation/run-age-yubikey-pr274-readonly.sh" > "$launcher"
flock -u 9
bash "$launcher" --pinned-sha "$sha"
PR274_READONLY
~~~

Le cache Git bare **survit aux redémarrages si HOME persiste**.
Sinon fournir un volume persistant avec \`NABLA_AGENT_STATE_DIR\`.
Le worktree est supprimé uniquement s'il est propre ; il est conservé
en cas de modifications inattendues. Aucun checkout original n'est touché.
Les certificats déjà validés sont réutilisés sans effacement.

**Preuves isolées de l'agent :** 11 tests de reprise Git réussis,
dont absence de /tmp, cache réutilisé, deux agents parallèles, échecs
de gate et de F9. La suite complète sur le HEAD de cette PR est
à revérifier sur la workstation (environ 82 tests unittest attendus).

## 1. Reprendre la branche correcte

L'opérateur est sur un detached HEAD dans /tmp/nabla-yubikey-pr259. Le précédent git pull ne peut déterminer la branche. Un échec SSH suivi d'un checkout de origin/* ne prouve pas une synchronisation récente.

Diagnostic **sans réseau et sans écriture Git** :

~~~bash
cd /tmp/nabla-yubikey-pr259
bash scripts/workstation/diagnose-age-yubikey-git-checkout.sh
~~~

Après avoir vérifié que git status --short est vide, synchroniser explicitement **la PR #274** avec HTTPS ; arrêter si fetch échoue :

~~~bash
cd /tmp/nabla-yubikey-pr259
git status --short
git fetch --no-tags https://github.com/AlbanAndrieu/nabla-compose.git \
  fix/homelab-operator-diagnostics-followup-20261024
git cat-file -e FETCH_HEAD:scripts/workstation/inspect-age-yubikey-f9-chain.sh
git switch --detach FETCH_HEAD
bash scripts/workstation/verify-age-yubikey-offline.sh
~/.local/share/nabla/piv-sdk-venv/bin/python \
  scripts/workstation/test-age-yubikey-piv82-attestation-offline.py
~~~

Ne pas faire de reset --hard, force-push, ou git pull dans un detached HEAD.

## 2. Première preuve matérielle : lecture du certificat public F9

Après validation logicielle, connecter **uniquement** la YubiKey secondaire 11110002 :

~~~bash
bash scripts/workstation/inspect-age-yubikey-f9-chain.sh --serial 11110002
~~~

Le script vérifie série unique, firmware et lisibilité X.509 du certificat public F9. Il n'utilise pas de PIN. Il n'effectue ni attestation PIV82 ni opération mutante ; le temporaire est supprimé. Une empreinte F9 **n'est pas l'empreinte de la racine Yubico**, et la présence de F9 n'atteste pas sa confiance.

## 3. Blocage du provisionnement PIV82

PIV82 est encore vide selon la dernière observation. Une attestation n'est possible qu'après génération de la clé PIV82 sur l'appareil. Ne pas lancer la génération pour obtenir un certificat d'attestation sans autorisation spécifique. Ne pas lancer age-plugin-yubikey --generate sur les clés existantes avec management key AES256.

Une fois la génération explicitement approuvée et exécutée par l'opérateur, contrôler la SPKI PIV82, le certificat F9, le certificat d'attestation 82, et la chaîne vers une racine Yubico **approuvée indépendamment**. Différencier 5.7.4+ (racine 2025/intermédiaires) des anciennes versions. Le vérificateur public strict travaille hors matériel.

## 4. Évidence et limites

Les contrats du diagnostic Git : 7/7 PASS en environnement hermétique ; les contrats F9 : 8/8 PASS en environnement hermétique. Les tests crypto synthétiques prévoient 12 refus ; la suite globale au nouveau HEAD doit être exécutée sur la workstation (66 tests attendus en absence d'autres modifications).

Aucune modification de PIV9A, F9, OTP2 KeePassXC, management key AES256, SOPS ou escrow. L'ordre reste secondaire 11110002 avant principale 11110001. Préserver deux copies indépendantes de récupération logicielle.

Sources : https://developers.yubico.com/PIV/Introduction/PIV_attestation.html ;
https://developers.yubico.com/yubico-piv-tool/Attestation.html ;
https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html.


## 5. Chaîne de confiance F9 — firmware 5.4.3

**Observation du 24 octobre 2026** : la YubiKey secondaire 11110002, firmware 5.4.3, possède un certificat public F9 lisible. Son empreinte SHA-256 observée est :

    6C:6E:14:0A:69:81:14:C3:51:14:0C:1B:68:C4:B1:16:A7:D9:B4:49:29:76:62:39:2F:61:F1:78:54:90:34:DF

La quality gate workstation sur HEAD 4f076aa5 a donné **66/66 PASS** en 12,220 secondes et le banc cryptographique a rejeté 12 attaques synthétiques. Cette validation précède la présente mise à jour.

**Racine applicable** : le firmware 5.4.3 relève de la racine **Yubico PIV Root CA Serial 263751**, dont le PEM officiel est https://developers.yubico.com/PKI/yubico-piv-ca-1.pem. La racine 2025 et ses intermédiaires ne sont pas applicables. L'empreinte SHA-256 DER du certificat racine publié par Yubico est :

    63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46

Cette empreinte de racine est **épinglée dans** scripts/workstation/verify-age-yubikey-f9-root-offline.py ; elle ne peut pas être remplacée par un argument de ligne de commande. Le validateur refuse une F9 présentant une empreinte différente de l'observation de la workstation, une signature contrefaite, un mauvais émetteur, une racine non CA, un firmware 5.7.4+ ou un certificat expiré. Aucune interaction avec la carte ni le réseau.

**Procédure en lecture seule**, uniquement avec la secondaire branchée après synchronisation de la PR #274 :

~~~bash
umask 077
mkdir -p "$HOME/.local/share/nabla/yubikey-f9-public"
bash scripts/workstation/inspect-age-yubikey-f9-chain.sh \
  --serial 11110002 \
  --save-public-f9 "$HOME/.local/share/nabla/yubikey-f9-public/f9-11110002.pem"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$HOME/.local/share/nabla/yubikey-f9-public/yubico-piv-ca-1.pem" \
  https://developers.yubico.com/PKI/yubico-piv-ca-1.pem
~/.local/share/nabla/piv-sdk-venv/bin/python \
  scripts/workstation/verify-age-yubikey-f9-root-offline.py \
  --serial 11110002 --firmware 5.4.3 \
  --f9 "$HOME/.local/share/nabla/yubikey-f9-public/f9-11110002.pem" \
  --root "$HOME/.local/share/nabla/yubikey-f9-public/yubico-piv-ca-1.pem" \
  --expected-f9-sha256 6C:6E:14:0A:69:81:14:C3:51:14:0C:1B:68:C4:B1:16:A7:D9:B4:49:29:76:62:39:2F:61:F1:78:54:90:34:DF
~~~

Le mode --save-public-f9 crée un **nouveau** fichier PEM public (permissions 0600) et refuse les chemins déjà occupés ou les symlinks. Le contenu F9 est public : ne pas committer ce certificat individuel dans le dépôt. En cas d'erreur, arrêter sans écriture matérielle.

**Validation de l'agent** : 5/5 contrats de conservation F9 et 13/13 tests synthétiques X.509 ont été exécutés dans un répertoire isolé. La gate est configurée pour **71 tests unittest attendus** (66 précédents et 5 nouveaux), suivis des deux fixtures cryptographiques autonomes. Le total réel doit être confirmé sur la workstation à partir du HEAD de PR exact.

**Interprétation stricte :** un PASS atteste la signature du fichier F9 public par la racine approuvée et la correspondance avec l'empreinte observée. Il ne prouve pas une opération live avec la clé privée F9, une clé PIV82 générée, une authentification AES256 ou un déchiffrement age. **NO-GO matériel et SOPS inchangé.**

Documentation officielle : https://developers.yubico.com/yubico-piv-tool/Attestation.html et https://developers.yubico.com/PIV/Introduction/PIV_attestation.html.

## 6. Régression de contrat sur l'ordre de la gate offline (24 octobre 2026)

La reprise automatisée au SHA `3504d6bd` a exécuté **80 tests** : 79 réussis et un test en erreur. Le contrat recherchait littéralement `python3 -m py_compile "$python_source"` alors que le script emploie la forme Bash équivalente `python3 -m py_compile "${python_source}"`. La gate n'a pas été modifiée : son contrôle de syntaxe précède toujours `unittest`.

Le contrat accepte désormais **les deux formes citées** et refuse une compilation absente, déplacée après `unittest` ou ciblant une autre variable. La reproduction ciblée des 5 cas a réussi. **80 tests unittest attendus** : le correctif final adapte une assertion existante, sans ajouter de test. À valider sur la workstation. Le lanceur a correctement arrêté l'exécution avant F9 ; aucune opération PIV, PIN ou SOPS n'a eu lieu.


## Suite YubiKey — preuve publique F9 et absence de GO matériel

La chaîne publique F9 de la secondaire 11110002 (firmware 5.4.3)
a été validée avec la racine historique Yubico épinglée. Cette
preuve ne démontre PAS qu'une clé PIV82 existe ni que le
décryptage age fonctionne. Le nouveau rapport hors matériel
scripts/workstation/report-age-yubikey-piv82-readiness.py
réutilise les PEM publics et retourne NO-GO, même pour F9 PASS.
Aucun lecteur, PIN, secret, réseau ou écriture sur la carte n'est
autorisé par ce rapport. Un inventaire PIV82 en lecture seule
est la prochaine preuve matérielle ; toutes les opérations
mutantes demandent des approbations séparées par phase.

Les scripts Bash opérateur doivent être exécutés dans un
processus enfant, jamais sourcés. Les worktrees partagent
les téléchargements uv mais gardent une .venv distincte.


## 7. Inventaire matériel PIV82 frais — secondaire seulement (option explicite)

Après F9 PASS, exécuter **le même lanceur** avec
`--inventory-secondary`. Cette option demande une lecture
fraîche sur la seule YubiKey secondaire **11110002**, firmware **5.4.3**.
La vérification hors matériel s'effectue avant l'accès au lecteur.
Elle ne reconfigure **aucun** slot et n'essaie pas de PIN.

La commande versionnée
`scripts/workstation/inspect-age-yubikey-piv82-secondary.py`
exécute uniquement les opérations publiques ci-dessous, avec un
délai maximum et une entrée standard fermée :

- `ykman list --serials` : une seule carte 11110002 ;
- `ykman --device 11110002 info` : firmware 5.4.3 ;
- `ykman --device 11110002 piv info` : gestion AES256 protégée par PIN ;
- `ykman --device 11110002 piv keys info 82` : présence du slot ;
- `ykman --device 11110002 piv keys info 9a` : présence des métadonnées de la clé existante.

Résultats JSON : `EMPTY_CONFIRMED` uniquement pour
le message exact « No key stored in slot 82 (RETIRED1) » et les
contrôles AES256/PIV9A confirmés ; `OCCUPIED` pour
des métadonnées de clé reconnues ; sinon `UNKNOWN`.
Codes de sortie : 0 pour l'inventaire vide observé (mais état
global `NO-GO`), 4 pour un slot occupé, 3
pour les erreurs de matériel, lecture, politique ou transport.
Ne jamais écraser un slot occupé, ni assimiler une erreur PC/SC
à une absence de clé. La validation F9 ne vaut pas preuve PIV82.

**Ne pas sourcer les scripts dans le terminal interactif.**
Utiliser le bloc de bootstrap en Bash enfant de la section 0, en
transmettant `--inventory-secondary` au lanceur
final, ou un worktree PR #274 déjà initialisé et validé.

Le mode par défaut du lanceur **n'accède à aucun slot PIV82**.
Les 10 contrats d'inventaire synthétique et les 3 tests
d'intégration du lanceur sont distincts d'une exécution réelle
sur la secondary. Les opérations PIV82 mutantes, la PIN
et SOPS restent **NO-GO**, quel que soit ce résultat.

## 8. Résultat réel de l'inventaire secondaire et optimisation Git

**Observation workstation transmise le 24 octobre 2026** : le lanceur a
validé le commit `56a42f8f04c5` sur la branche PR #274, **100/100 tests
unittest PASS**, la fixture PIV82 (12 scénarios négatifs) PASS et
**13/13 tests de chaîne F9 PASS**. La vérification publique du
certificat F9 a réussi, sans PIN.

Le contrôle matériel **sur la YubiKey secondaire 11110002 uniquement**
a répondu :

- firmware : `5.4.3` ;
- clé de gestion : `AES256_PIN_PROTECTED` ;
- PIV82 : **`EMPTY_CONFIRMED`** ;
- PIV9A : `PRESENT_METADATA` ;
- OTP2 : `NOT_VERIFIED` ;
- statut global : **`NO-GO`**, sans autorisation d'écriture.

Il s'agit d'un inventaire réel, mais pas d'une validation des copies
d'escrow, de la présence de OTP2, des essais PIN restants ou d'un
roundtrip age. L'étape d'authentification AES256 **n'est pas autorisée**.

**Optimisation du bootstrap** : la première exécution effectuait
deux recherches/fetch Git (dans le bootstrap puis dans le lanceur).
Le bootstrap transmet désormais le SHA déjà validé au lanceur
via `--pinned-sha "$sha"`. Celui-ci vérifie que le commit est présent
dans le cache bare, puis crée son worktree propre sans seconde requête
distante. Ce mode n'est une preuve de fraîcheur que si l'appelant
a d'abord vérifié le SHA distant ; en usage autonome le lanceur
continue à faire `ls-remote` et `fetch` si nécessaire.
La reprise n'exige toujours aucun checkout dans `/tmp`.

**Prochain verrou** : preuve indépendante du maintien OTP2/PIV9A,
des deux copies d'escrow logiciel et des conditions d'une future
authentification AES256 en séance supervisée. Aucune écriture PIV82,
PIN automatique ni mise à jour SOPS.


## 9. Réparation et consolidation du lanceur Git/F9/PIV82

Le journal opérateur du snapshot 56a42f8f04c5 contient 100 tests unittest
réussis, 12 cas négatifs de certificat synthétique, 13 tests F9, et
l'inventaire public secondaire : PIV82 EMPTY_CONFIRMED, PIV9A présent,
gestion AES256 protégée par PIN, statut global NO-GO.
Cette preuve **ne valide pas** le HEAD actuel de la PR.

Le lanceur avait été corrompu par une fusion de texte :
la commande `IFS=$'\t' read` était tronquée et les opérations
de worktree, quality gate, F9 et inventaire apparaissaient deux fois.
Le refactoring retire cette duplication, conserve un seul chemin
d'exécution et corrige l'analyse de la sortie `git ls-remote`.
Il maintient le cache bare persistant, le worktree unique par agent,
le verrou `flock`, le SHA Git vérifié et le nettoyage
uniquement des worktrees propres.

Trois tests de non-régression couvrent :
- la syntaxe Bash et **une seule** création de worktree ;
- la survie du shell parent après un refus de `source` ;
- l'ordre Git → gate hors matériel → signature F9 → rapport NO-GO
  → inventaire secondaire facultatif → résultat.

Le mode habituel n'effectue toujours aucune lecture PIV82.
La phase PIV82 demeure **NO-GO** : aucune authentification PIN,
génération de clé, modification AES256 ou migration SOPS.
La prochaine preuve demandée est la validation de la gate complète
sur la workstation au SHA de cette PR, pas une répétition d'actions
matérielles déjà prouvées.


## 10. Revalidation workstation — 106 tests hors matériel au SHA 56dc5230b4fd

Journal réel de l'opérateur, le 24 octobre 2026 :

- Worktree Git isolé sous HOME, sans prérequis sur le checkout /tmp après reboot ;
- SHA exact exécuté : **56dc5230b4fd**, branche de PR #274 ;
- **106/106 tests unittest PASS** en **28,009 secondes** ;
- Certificat F9 public : **PASS** avec empreinte observée et racine Yubico ancienne épinglée ;
- Fixture cryptographique synthétique PIV82 + **12 cas négatifs** : PASS ;
- Suite synthétique F9 : **13/13 PASS** ;
- Rapport public de préparation : `f9_trust=PASS`,
  `piv82=NOT_VERIFIED`,
  `age_decrypt=NOT_VERIFIED`,
  `hardware_mutation_authorized=false` ;
- Aucune nouvelle lecture PIV82 durant ce lancement, aucune demande de PIN,
  aucune écriture ou modification SOPS.

La preuve antérieure **PIV82 EMPTY_CONFIRMED** reste documentée en section 8.
Le rapport JSON du lancement hors matériel continue à dire
`piv82=NOT_VERIFIED` : c'est correct car le lanceur n'a pas
réexécuté l'inventaire matériel avec l'option dédiée. Ne pas confondre
ce champ avec la preuve historique d'inventaire.

Le SHA actuel de la PR peut avancer indépendamment des agents ; ce
PASS est **spécifique au commit testé**, pas à un HEAD ultérieur.

### Contrôles de récupération encore requis

1. Inventorier la présence et les supports des **deux copies
   indépendantes** d'escrow sans afficher, copier ou ouvrir une clé privée.
2. Confirmer l'état **OTP2** sur la secondaire par une preuve adaptée et
   non secrète, sans challenge ni écriture : l'audit général ne prouve
   pas sa configuration et ne doit plus afficher `✅ Confirmé`
   sur la seule base de l'historique.
3. Ne pas exécuter les scripts de déchiffrement ou d'authentification
   AES256 avant une décision opérateur séparée sur le périmètre, la
   conservation des secrets et les tentatives PIN restantes.
4. Ne pas générer ou occuper PIV82, ne pas toucher PIV9A/OTP2,
   ne pas changer de clé de gestion ni de destinataires SOPS.

**Statut : NO-GO matériel et SOPS.** La validation de l'inventaire
ne vaut pas preuve de récupération ou de déchiffrement réel.


## 11. Préservation OTP2 et escrow — métadonnées uniquement

Le nouveau diagnostic scripts/workstation/inspect-yubikey-recovery-readonly.py
est accessible dans le lanceur de la PR #274 derrière des options
facultatives. Le comportement habituel du lanceur ne change pas.

- --otp2-secondary : exige une seule YubiKey 11110002, le firmware
  5.4.3, puis appelle uniquement ykman otp info. Une réponse
  Slot 2: programmed confirme la présence d'une configuration ;
  elle **ne prouve pas le type HMAC-SHA1 ni la compatibilité KeePassXC**.
  Aucun challenge OTP, aucune saisie PIN et aucune écriture.
- --escrow-a /chemin/absolu/copie1.age et
  --escrow-b /chemin/absolu/copie2.age : exige deux chemins fournis
  ensemble. Contrôle seulement l'existence, le type de fichier,
  la taille non nulle, les liens symboliques et le système de fichiers.
  Ne lit aucun octet des sauvegardes et ne divulgue aucun chemin.
- Une paire de fichiers sur le même système de fichiers, un même
  inode, un lien symbolique ou une copie absente donne un contrôle
  incomplet ; aucun diagnostic n'autorise une opération matérielle.
- Deux fichiers sur deux systèmes de fichiers différents ne
  constituent **pas** une preuve de supports physiques indépendants,
  de chiffrement correct ou de capacité de restauration.

Le JSON déclare toujours status=NO-GO, otp2_hmac_sha1_verified=false,
keepassxc_verified=false, escrow_restoration_verified=false,
independent_physical_media_verified=false et
hardware_mutation_authorized=false. Un code retour 0 signifie
seulement que les observations demandées ont abouti. Les erreurs
de lecteur, les états ambigus et les chemins incomplets bloquent.

Ne pas lancer de restauration, de challenge-response, de
PIN, de génération PIV82, de changement OTP2/PIV9A/AES256,
ni de modification SOPS sans autorisation supplémentaire.
Éviter de refaire les contrôles F9 et PIV82 déjà validés si
leur reprise n'est pas nécessaire.

Valider d'abord les tests du nouveau script et du lanceur dans
la gate hors matériel de la PR. Cette étape n'exige aucune YubiKey.
Les observations OTP2 ou escrow réelles demeurent NOT_RUN tant
que l'opérateur n'a pas choisi d'options et fourni les chemins.


## 12. Poursuite sur PR #280 — branch selection sans PR #274 fermée

**25 octobre 2026.** Les PR #274 et #278 ont été fusionnées. Le
travail YubiKey est poursuivi dans [PR #280](https://github.com/AlbanAndrieu/nabla-compose/pull/280)
(branch `feat/apisix-standalone-poc-20261025`). Les résultats
106/106 et l'inventaire PIV82 `EMPTY_CONFIRMED` sont
des preuves **antérieures** ; la gate doit être exécutée de nouveau
sur le SHA de #280 avant toute conclusion sur les changements présents.

Le lanceur existant conserve son défaut historique PR #274 pour éviter
de modifier les contrats opérateur antérieurs. Utiliser explicitement
`--branch feat/apisix-standalone-poc-20261025` pour lire
le HEAD actuel de #280. Le SHA est identifié par `git ls-remote`
et vérifié avant création du worktree. Avec `--pinned-sha`,
l'opérateur doit valider la fraîcheur du SHA **avant** de lancer le
script ; ce mode ne vérifie pas lui-même le ref distant.

Le parcours par défaut reste **hors matériel**, sauf export F9 public
si la preuve manque. L'inventaire OTP2 et l'escrow exigent toujours
leurs options respectives. **Aucune action PIN, challenge OTP,
génération PIV82, modification AES256 ou migration SOPS.**

Avant toute reprise de l'escrow réel, confirmer les deux supports
physiques et la procédure d'une restauration supervisée séparée.
La lecture de métadonnées seule ne constitue pas une preuve de
récupération ; garder le statut matériel NO-GO.


## 13. PR #280 — second contrôle de série et gate récupération sans matériel

Le contrôle de la secondaire 11110002 n'est pas une autorisation PIV82.
Pour OTP2, le script inspect-yubikey-recovery-readonly.py vérifie
maintenant deux sources publiques : ykman list --serials et
le champ Serial number de ykman --device 11110002 info. Le firmware
doit rester 5.4.3. Un numéro absent, différent ou répété donne UNKNOWN.

Les copies chiffrées d'escrow doivent être des fichiers ordinaires
non vides, sans liens symboliques ni liens matériels multiples.
Le contrôle rejette aussi les chemins non absolus et les fichiers
dont l'extension n'est pas .age. Les statuts restent des **observations
de métadonnées uniquement** : ils ne prouvent ni contenu récupérable,
ni support physique distinct, ni fonctionnalité KeePassXC.

### Validation hors matériel (worktree PR #280)

Depuis un checkout de cette PR, exécuter une seule cible locale :

`just yubikey-recovery-test`

Cette cible vérifie la syntaxe Python/Bash puis lance uniquement les
contrats synthétiques OTP2, escrow et lanceur Git. Pas de réseau
explicite, aucun lecteur YubiKey, aucun PIN, challenge OTP ou secret
n'est requis. Une .venv n'est pas nécessaire pour ces tests standard
library. Le résultat ne vaut pas validation de toute la quality gate.

Pour exécuter le lanceur historique avec la branche active, transmettre
explicitement `--branch feat/apisix-standalone-poc-20261025`.
L'option `--pinned-sha` reste réservée au bootstrap qui
a déjà vérifié la fraîcheur du SHA distant. Ne pas utiliser l'ancienne
branche PR #274 fusionnée comme source de nouveaux contrôles.

Garder **NO-GO** : un résultat OTP2 PROGRAMMED_TYPE_UNVERIFIED ne
démontre pas le secret HMAC-SHA1 ni KeePassXC ; deux fichiers d'escrow
sur des systèmes de fichiers différents ne sont pas deux restaurations
validées. Ne pas générer PIV82, tester un PIN, lire des secrets, modifier
OTP2/PIV9A/AES256, ni changer les destinataires SOPS.


## 14. Validation locale des contrats OTP2 / escrow — 25 octobre 2026

**Journal fourni par l'opérateur**, exécuté avec
`just yubikey-recovery-test` :

- `python3 -m py_compile` : PASS sur les scripts et tests concernés ;
- `bash -n` : PASS sur le lanceur Git/YubiKey ;
- Tests de récupération OTP2/escrow : **16/16 PASS** (0,006 s) ;
- Tests d'intégration du lanceur : **28/28 PASS** (22,969 s) ;
- Total : **44/44 PASS**, sans exécution de commande matérielle.
- Le message d'usage dans le test de portée manquante est
  un résultat **attendu du test négatif**, pas un échec de la gate.

**Limite :** le journal transmis ne contient pas le SHA Git exécuté.
Cette preuve valide le contenu du worktree de l'opérateur au moment du
test, pas automatiquement tous les commits ultérieurs de la PR #280.
Le résultat n'atteste ni OTP2 réel, ni HMAC-SHA1/KeePassXC, ni présence,
indépendance physique ou restauration de deux copies d'escrow.

### Étape matérielle facultative et strictement read-only

La recette explicite `just yubikey-otp2-secondary-readonly`
exécute uniquement
`python3 scripts/workstation/inspect-yubikey-recovery-readonly.py --otp2-secondary`.
Elle requiert la seule YubiKey **11110002** (firmware 5.4.3) et
interroge trois commandes publiques allowlistées : liste des appareils,
identité/firmware, statut OTP. Aucune demande de PIN, aucun challenge,
aucune génération et aucune modification.

Le résultat `PROGRAMMED_TYPE_UNVERIFIED` valide seulement
la présence d'une configuration OTP2. Les états `EMPTY`
et `UNKNOWN` bloquent. Même avec retour 0,
`status=NO-GO` et `hardware_mutation_authorized=false`
restent inchangés. **Ne pas confondre succès de lecture et preuve
du secret KeePassXC.**

La recette ne doit être lancée que depuis un worktree isolé et actualisé
sur la branche PR #280. Elle n'exécute aucune gate de qualité large
et ne réutilise aucun chemin temporaire disparu après redémarrage.


## 15. Preuve OTP2 réelle — secondaire 11110002 (25 octobre 2026)

**Sortie opérateur** de `just yubikey-otp2-secondary-readonly` :

- `serial=11110002` — le diagnostic a vérifié l'unicité de la
  carte connectée, son numéro de série rapporté et le firmware
  attendu `5.4.3` avant la lecture OTP.
- `otp2=PROGRAMMED_TYPE_UNVERIFIED` — **slot 2 programmé
  sur la carte réelle**. Cette observation ne vérifie **pas** le type
  HMAC-SHA1, la clé secrète stockée ou un échange KeePassXC.
- `escrow=NOT_CHECKED` ; `escrow_restoration_verified=false` ;
  `independent_physical_media_verified=false`.
- `otp2_hmac_sha1_verified=false` ;
  `keepassxc_verified=false`.
- `status=NO-GO` et
  `hardware_mutation_authorized=false`.

**Provenance :** journal de la workstation fourni par l'opérateur,
sans SHA Git affiché. Ne pas attribuer cette preuve à un commit ultérieur ;
elle décrit l'état matériel observé au moment de l'exécution.

**Décision :** ne pas relancer inutilement l'inventaire OTP2 ;
conserver le slot existant et les fonctions KeePassXC intactes.
L'étape suivante concerne exclusivement les métadonnées des **deux
copies d'escrow déjà existantes**, si et seulement si leurs chemins
absolus sont connus. Utiliser alors
`inspect-yubikey-recovery-readonly.py --escrow-a PATH1.age --escrow-b PATH2.age`
sans l'option OTP2. Le script ne lit pas le contenu chiffré.

Même si les deux fichiers sont présents sur des systèmes de fichiers
différents, la restauration effective et l'indépendance physique
des supports restent **NOT_VERIFIED**. Aucun PIN, challenge OTP,
décryptage, provisionnement PIV82, changement AES256/OTP2/PIV9A
ou modification SOPS n'est autorisé.


## 16. Diagnostics des autres applications — PR #280

La configuration YubiKey comporte d'autres domaines que le slot PIV82.
Voir le [plan d'achèvement](yubikey-capabilities-completion-plan.md) :
récupération GPG/PostgreSQL, dépendances PKI du PIV9A historique,
FIDO2/passkeys/SSH, OpenPGP, OATH et PIV9C/9D/9E.

Nouveau script `scripts/workstation/inspect-yubikey-applications-readonly.py` :
seulement les commandes publiques `ykman` allowlistées, avec entrée
standard fermée et délai. Il vérifie une carte à la fois :
`just yubikey-applications-secondary-readonly`, puis lors d'une
séance distincte `just yubikey-applications-primary-readonly`.
Le script n'interroge ni OTP2, ni F9, ni PIV82 déjà documentés.
Aucun secret, certificat brut, identifiant de compte OATH/FIDO2 ou
empreinte GPG n'est publié. Le rapport JSON contient seulement des
états abstraits : `RESPONDS_METADATA_ONLY`, `EMPTY_CONFIRMED`,
`OCCUPIED_METADATA` ou `UNKNOWN`. Un état inconnu bloque avec
code non nul, sans conclure que l'application est absente.

La cible `just yubikey-applications-test` exécute les tests
synthétiques sans lecteur, réseau, PIN ni dépendance externe.
La réussite du diagnostic **n'est pas** la preuve d'une passkey
enregistrée, d'une signature OpenPGP fonctionnelle, d'une
récupération PostgreSQL, d'une PKI sûre ou d'un âge hardware
interopérable. Tous les chemins restent NO-GO pour mutations
matérielles et SOPS.


## 17. Preuve workstation et secondaire — diagnostics multi-applications (25 octobre 2026)

**Sortie réelle fournie par l'opérateur** après création de l'inventaire
FIDO2/OATH/OpenPGP/PIV et des diagnostics de poste. Le SHA de la
copie de travail n'était pas imprimé : ne pas attribuer ce résultat
aux commits publiés ensuite.

- `just yubikey-applications-test` : **12/12 PASS** ;
  compilation Python PASS.
- `just yubikey-workstation-test` : **8/8 PASS** ;
  compilation Python PASS. L'erreur affichée pendant le test négatif
  « No arguments supported » est attendue, car ce test se termine OK.
- `just yubikey-workstation-readonly` : identité SOPS
  logicielle présente, permissions/ownership conformes à la politique ;
  mapping PAM U2F présent mais non testé ; outil
  `pamu2fcfg` absent ; clé publique SSH FIDO2
  conventionnelle non trouvée.
- Outils présents, **interopérabilité non prouvée** : gpg, gpgconf,
  age, age-plugin-yubikey, sops, ykman, keepassxc,
  ssh-keygen, cryptsetup, lsblk, pcsc_scan.
- Socket GPG-agent **non trouvé à l'ancien chemin conventionnel**.
  **Cela ne prouve pas que l'agent soit absent ou arrêté**.
- `just yubikey-applications-secondary-readonly` sur
  **11110002**, firmware 5.4.3 : les quatre applets FIDO, OATH,
  OpenPGP et PIV répondent aux commandes publiques.
  Management key AES256 protégée par PIN.
  PIV9A OCCUPIED_METADATA. Slots 83, 9C, 9D et 9E EMPTY_CONFIRMED.
- Aucun nouvel essai PIN, test GPG de déchiffrement, challenge OTP,
  génération de clé, modification PAM ni opération SOPS.

**Corrigé dans #280 :** le contrôleur
`inspect-yubikey-workstation-readonly.py` interroge maintenant
**uniquement** `gpgconf --list-dirs agent-socket`
pour localiser le chemin propre à cette installation, au lieu
d'inférer `~/.gnupg/S.gpg-agent`.
Il applique `lstat` uniquement au chemin reçu et
ne lance pas l'agent ; ni chemin ni données d'identité n'apparaissent
dans le JSON. Il distingue les sources
`GPGCONF`, `GPGCONF_MISSING`,
`GPGCONF_ERROR` et `GPGCONF_INVALID_PATH`.
Un socket trouvé demeure `PRESENT_UNVERIFIED`, pas
une preuve de fonctionnement d'OpenPGP/scdaemon.
Les 5 nouveaux tests de chemin/socket sont hermétiques ; leur
validation sur la workstation au HEAD actuel est encore **NOT_RUN**.

**Prochaine étape non destructive :**
`just yubikey-workstation-test`
puis `just yubikey-workstation-readonly`.
Les états à regarder sont `gpg_agent_socket`
et `gpg_agent_socket_locator`.
L'étape suivante seulement, si nécessaire, sera un diagnostic
GPG/PCSC non interactif et sans démarrage automatique d'agent.
Les sauvegardes GPG/PostgreSQL et l'escrow age restent à vérifier
par une procédure de restauration isolée et autorisée.

**Toutes les opérations de configuration matérielle et de migration
SOPS restent NO-GO.**


## 18. Diagnostic consolidé en une commande — PR #280

La cible `just yubikey-diagnostics-secondary-readonly` réunit les contrôles du poste et des applications PIV/FIDO2/OATH/OpenPGP sur la seule carte 11110002. Voir [le runbook](yubikey-readonly-batch.md) pour les modes host-only, tests synthétiques et principale séparée. Aucun PIN, OTP2, F9, PIV82, déchiffrement, modification PAM ou SOPS n'est exécuté. Résultat global NO-GO même en cas d'observations positives. Les validations opérateur précédentes ne couvrent pas cette nouvelle cible.
