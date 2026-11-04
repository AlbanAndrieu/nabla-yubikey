# Runbook — Vaultwarden : remplacer Yubico OTP par WebAuthn

> **État au 04/11/2026** : Vaultwarden 1.37.3 accepte les deux YubiKey en Yubico OTP (slot 1, programmé sur les deux). WebAuthn pas encore enregistré. Le slot 2 (challenge-response KeePassXC) n'est pas concerné.

## Pourquoi

| | Yubico OTP (slot 1) | FIDO2 WebAuthn |
| --- | --- | --- |
| Ce que fait la clé | tape un code de 44 caractères, comme un clavier | signe un défi envoyé par le site, ne tape rien |
| Hameçonnage | un faux site récupère le code et le rejoue sur le vrai tant qu'aucun code plus récent n'a servi | la signature est liée au domaine : un faux domaine n'obtient rien d'utilisable |
| Vérification | Vaultwarden interroge les serveurs YubiCloud de Yubico | locale à Vaultwarden, aucun tiers |
| Effleurement par erreur | tape un code dans la fenêtre active (constaté le 31/10) | rien : la clé ne clignote que quand un site demande |
| Place sur la clé | occupe le slot 1 | aucun slot ; identifiant non résident, il n'entame pas les 25 places résidentes |
| Téléphone | Bitwarden lit le slot 1 en NFC | FIDO2 en NFC, déjà ouvert |
| CLI `bw login` | `--method 3` | **non pris en charge** par la CLI |

## Comportement des slots OTP

- Appui court : slot 1. Appui long (2 à 3 s) : slot 2. Un slot vide ne fait rien.
- Le slot 2 est ici un challenge-response HMAC-SHA1 : il ne tape rien, c'est KeePassXC qui l'interroge.
- Slot 1 vidé : l'appui court ne fait plus rien. Le slot 2 et KeePassXC sont inchangés. L'interface OTP USB reste ouverte (le slot 2 en dépend) : le conseil `OTP_USB_ENABLED` reste affiché par la sonde, mais la frappe accidentelle disparaît.
- Jamais `ykman otp swap` : il déplacerait le challenge-response KeePassXC vers le slot 1.

## Avant de commencer

- **Code de récupération 2FA** : *Paramètres → Sécurité → Connexion en deux étapes → Afficher le code de récupération*, à ranger dans KeePassXC et dans l'archive hors ligne. Seul recours si les deux clés sont perdues.
- Ouvrir Vaultwarden **uniquement par l'URL de `DOMAIN`** (compose Vaultwarden) : WebAuthn lie la clé à ce domaine, une autre adresse (IP du LAN, nom local) la refuse.
- **CLI** : `bw login` ne propose pas WebAuthn. Avant de retirer l'OTP, choisir `bw login --apikey` (clé d'API personnelle, *Paramètres → Sécurité → Clés* ; elle remplace le second facteur pour la CLI, la ranger dans `pass`) ou garder l'OTP. `bw unlock` et `bw-unlock` ne demandent pas de second facteur.

## Étapes

1. **Principale** : *Connexion en deux étapes → FIDO2 WebAuthn → Gérer*, mot de passe maître, nom `principale`, *Lire la clé*, toucher la clé, *Enregistrer*. Si la liste contient déjà une clé, c'est peut-être la secondaire (identifiant « Bitwarden » relevé le 31/10) : la tester avant d'en ajouter une.
2. **Secondaire** : même chose, nom `secondaire`, en touchant la secondaire.
3. **Tests**, avec chaque clé seule, dans une fenêtre privée, puis dans l'extension, l'application de bureau et Bitwarden mobile (NFC, ou USB-C pour la principale). Choisir WebAuthn à la connexion et toucher la clé.
4. **Retirer l'OTP de Vaultwarden** (*YubiKey OTP → Gérer → Désactiver*) seulement quand l'étape 3 passe partout. Retirer aussi `YUBICO_CLIENT_ID` et `YUBICO_SECRET_KEY` s'ils sont réglés (environnement ou `/admin`).
5. **Vider le slot 1** : écriture matérielle, sur décision de l'opérateur, une clé à la fois.

```bash
ykman --device <série> otp info        # Slot 2: programmed
ykman --device <série> otp delete 1
ykman --device <série> otp info        # Slot 1: empty, Slot 2: programmed
ykman --device <série> config nfc --disable OTP --force   # facultatif : plus d'OTP en NFC
```

Puis rouvrir KeePassXC avec chaque clé et rejouer `just applets-readonly` et `just keepassxc-readonly`.

**Sans retour à l'identique** : l'identifiant OTP vidé est perdu. En recréer un demande `ykman otp yubiotp 1 …`, la publication du nouvel identifiant chez Yubico (ykman 5.8 n'a plus `--upload`) et un nouvel enregistrement dans Vaultwarden. Ne vider le slot 1 qu'après l'étape 4.
