# KeePassXC / YubiKey OTP2 — validation de la carte secondaire

## Preuve acquise — 26 octobre 2026

**Poste opérateur :** `just yubikey-otp2-secondary-readonly`, sur
la secondaire `11110002`, après `git pull --ff-only`.

```json
{
  "serial": "11110002",
  "otp2": "PROGRAMMED_TYPE_UNVERIFIED",
  "otp2_hmac_sha1_verified": false,
  "keepassxc_verified": false,
  "escrow": "NOT_CHECKED",
  "hardware_mutation_authorized": false,
  "status": "NO-GO"
}
```

Le slot 2 est **programmé**, mais cette preuve n'identifie **pas** son
type. Ni la compatibilité HMAC-SHA1, ni le secret partagé avec la carte
principale, ni l'ouverture de la base KeePassXC ne sont prouvés.
Il est interdit de déduire `GO` du code de sortie zéro du diagnostic.

## Test fonctionnel KeePassXC — copie chiffrée uniquement

Effectuer cette procédure **localement sur la workstation**, en
présence de l'opérateur, sans envoyer la base KDBX ni les secrets à un
agent, GitHub, des logs ou une autre machine.

1. Vérifier qu'une voie de récupération indépendante de la YubiKey
   secondaire est encore utilisable. Ne pas commencer une migration
   de protection de la base.
2. Identifier une base KeePassXC **déjà protégée** par challenge-response
   HMAC-SHA1 et encore ouvrable avec la clé principale. Si aucune base
   n'est configurée ainsi, noter `NOT_CONFIGURED` et arrêter ici ;
   ne pas ajouter le facteur OTP2 uniquement pour réussir un test.
3. Fermer la base dans KeePassXC. Faire **une copie du fichier KDBX
   chiffré** dans un dossier local protégé, hors Git et hors synchronisation
   non maîtrisée. Ne pas faire d'export CSV/XML/HTML.
4. Débrancher la YubiKey secondaire. Brancher **uniquement** la principale
   `11110001`.
5. Ouvrir la **copie** KDBX dans KeePassXC. Indiquer les facteurs
   habituels dans l'interface locale (mot de passe, éventuel fichier-clé).
   Sélectionner le bon slot YubiKey pour cette base, puis déverrouiller.
6. Constater l'ouverture de la copie, puis **fermer sans enregistrer**.
   Si KeePassXC propose d'enregistrer une modification, l'annuler.
   Noter seulement `PRIMARY_UNLOCK=PASS` ou `FAIL`, sans contenu
   d'entrée ni nom de fichier.
7. Débrancher la principale. Brancher **uniquement** la secondaire
   `11110002`.
8. Ouvrir **exactement la même copie** KDBX dans KeePassXC avec les
   mêmes autres facteurs et le bon slot YubiKey.
9. Constater l'ouverture, puis **fermer sans enregistrer**.
   Noter seulement `SECONDARY_UNLOCK=PASS` ou `FAIL`.
10. Vérifier que la base originale n'a pas été modifiée et que
    la voie de récupération initiale reste disponible.
    Conserver ou supprimer la copie chiffrée conformément à la
    politique de sauvegarde locale.

### Critères d'acceptation

| Résultat | Conclusion |
| --- | --- |
| `PRIMARY_UNLOCK=PASS`, `SECONDARY_UNLOCK=PASS` sur **la même copie KDBX** | La secondaire sait déverrouiller cette base avec les mêmes autres facteurs. Compatible pour cette base et cet état. |
| `PRIMARY_UNLOCK=PASS`, `SECONDARY_UNLOCK=FAIL` | Carte secondaire **non validée** pour cette base. Ne pas réinitialiser le slot ; investiguer le mode OTP, le slot choisi et la correspondance du secret HMAC. |
| `PRIMARY_UNLOCK=FAIL` | Fixture/identifiants ou chemin principal non validés : arrêter, ne pas conclure sur la secondaire. |
| `NOT_CONFIGURED` | Aucun test de récupération KeePassXC par OTP2 n'est applicable sans une décision ultérieure d'ajout du facteur. |

**Ne jamais exécuter** `ykman otp chalresp`, `ykman otp delete`,
`ykman otp swap`, `ykman otp settings` ou `ykman otp chalresp` de
programmation à titre de diagnostic. Les opérations de configuration
sont distinctes d'un test de récupération : écraser le secret HMAC
risque de rendre l'ancienne base impossible à déverrouiller.

`ykman otp info` ne donne que l'état programmé/vide du slot :
l'utilisation HMAC-SHA1 s'établit par le test fonctionnel de la base,
sans extraire le secret HMAC (non exportable depuis le slot programmé).

## Limites et chantiers indépendants

Un `SECONDARY_UNLOCK=PASS` ne prouve ni une sauvegarde chiffrée
récupérable sur un autre support, ni l'accès SSH distant, ni OpenPGP,
ni PIV82/age, ni la restauration GPG/SOPS/PostgreSQL. Ces derniers
restent des preuves séparées dans
[yubikey-backup-five-execution.md](yubikey-backup-five-execution.md).

**Références officielles :**
- [KeePassXC — ouverture d'une base, sauvegarde et YubiKey](https://keepassxc.org/docs/KeePassXC_UserGuide)
- [KeePassXC — HMAC-SHA1 challenge-response](https://keepassxc.org/docs/)
- [Yubico — ykman otp info et commandes OTP](https://docs.yubico.com/software/yubikey/tools/ykman/OTP_Commands.html)
