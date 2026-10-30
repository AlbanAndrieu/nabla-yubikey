# Nabla YubiKey

**Statut : dépôt initialisé, migration non appliquée.**

Dépôt dédié aux **contrôles, tests hermétiques et procédures de
restauration YubiKey/age/SOPS/SSH-FIDO2**. Il succède progressivement
aux 84 recettes `yubikey-*` de
[Compose PR #295](https://github.com/AlbanAndrieu/nabla-compose/pull/295).

## Périmètre

- YubiKey 5 NFC : FIDO2/WebAuthn, SSH-sk, OpenPGP, PIV et OTP.
- Diagnostics read-only et fixtures hors matériel.
- Escrow age/SOPS : vérification des copies indépendantes, restauration
  isolée, métadonnées NFS.
- Préparation de sauvegardes et runbooks avec critères GO/NO-GO.

**Interdictions sans consentement spécifique :** effacer/provisionner
une YubiKey, modifier PIN/PUK/OTP/PIV, éditer PAM/authorized_keys,
déchiffrer ou transférer des clés de récupération. Les commandes
modificatrices doivent rester explicites, interactives et séparées
des checks.

Le dépôt est **public**. Ne jamais y committer des identités
`age`, archives `.age` privées, états smartcard, secrets, fichiers
`secrets.env.sops`, extraits d'historique ou copies de
`~/.gnupg`. Réviser les fichiers avant tout transfert.

## Responsabilités

- `ansible-workstation` : seulement les prérequis **OS** optionnels
  (`pcscd`, `libfido2`, `ykman`, `opensc`), jamais PAM ou
  les applets YubiKey.
- `nabla-compose` : dataset TrueNAS, exports NFS, ACL et intégrations.
- Ce dépôt : opérations matérielles explicites, vérifications client
  et méthodes de reprise testées.

La migration se fait par **copies de fichiers sélectionnés +
tests/fixturés**, jamais par réécriture aveugle de l'historique Git.

Voir [plan de migration](docs/migration.md). Le submodule dans
`nabla-compose` sera étudié après une première release locale testée.
