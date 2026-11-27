| item | classe | blocage | question ou commande de réception |
|------|--------|---------|----------------------------------|
3 — récupération age/SOPS | RUNTIME | restauration non testée (déchiffrement sur décision opérateur, clé USB escrow verrouillée) | Déverrouiller l'USB LUKS sur la Workstation pour valider la restauration PRA
5 — protocole matériel | RUNTIME | slots PIV82 non testés sans décision ni backup, OTP USB non modifié, PIV9A/PIV82 non mutés | Superviser sur Workstation test PIV82 (aucune modification OTP, PIV9A/PIV82)
6 — compatibilité | DÉCISION | intégration Compose pinée, test produits en batch, validation séparée dans Compose | Arbitrer double runbook Compose/YubiKey pour validation
10 — OATH | RUNTIME | aucun secret TOTP enregistré sur les deux clés, mot de passe non décidé | Inscrire tous les TOTP sur les deux YubiKey et décider du mot de passe OATH
