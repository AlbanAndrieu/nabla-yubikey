# Déverrouiller Vaultwarden sans taper le mot de passe maître (`bw-unlock`)

Étape 0 de la [roadmap](../roadmap.md). Le script vit dans
[dotfiles `bin/bw-unlock`](https://github.com/AlbanAndrieu/dotfiles/blob/main/bin/bw-unlock)
et s'installe dans `~/bin` ; il est utilisé par `nabla-compose`, `fastapi-sample`
et `ansible-workstation`.

## Principe

Le mot de passe maître est rangé dans `pass` (entrée `vaultwarden/master`,
modifiable par `BW_PASS_ENTRY`), donc chiffré GPG. `bw-unlock` le lit et le passe
à `bw unlock --passwordenv` : il n'apparaît ni à l'écran, ni dans l'historique,
ni dans la ligne de commande.

| Étape | État au 31/10/2026 |
| --- | --- |
| Mot de passe dans `pass`, déverrouillage par `bw-unlock` | **Prêt**, la clé `pass` est encore **logicielle** |
| Sous-clé de chiffrement OpenPGP sur la YubiKey principale et celle de secours | **À faire** (applet OpenPGP vide, 0/3) ; ensuite `bw-unlock` exige la YubiKey (contact + PIN OpenPGP) sans changer le script |

**PIV écarté :** `age-plugin-yubikey` refuse la clé de gestion PIV en AES
(clé testée) et la passer en TDES est une modification PIV interdite sans décision
séparée. Aucune clé age n'existe sur la carte (`age-plugin-yubikey --list-all` vide).

**Aucune nouvelle clé age créée (31/10)** : les deux `age-plugin-yubikey --generate`
ont échoué (PIN refusé, puis clé de gestion AES) avant toute écriture sur la carte.

**Pourquoi ne pas réutiliser la clé age existante** (`~/.config/mise/age.txt`, celle de
SOPS et de l'escrow) :

- c'est l'identité de **récupération** SOPS/escrow : y chiffrer aussi le mot de passe
  maître lierait le coffre et les secrets SOPS au même fichier ; une fuite donnerait tout ;
- si elle est logicielle (`AGE-SECRET-KEY-1…`), chiffrer pour une clé posée sur le même
  disque n'ajoute aucune protection par rapport au clair : la YubiKey n'interviendrait pas ;
- la méthode décidée ici est `pass` + sous-clé OpenPGP sur les deux YubiKey, sans PIV.

Vérifier son type sans l'afficher : `grep -c '^AGE-PLUGIN-YUBIKEY-' ~/.config/mise/age.txt`
(`1` = identité sur une YubiKey, peut-être celle de secours ; `0` = clé logicielle).

## Utilisation

Une seule fois :

```bash
bw-unlock --setup        # pass insert vaultwarden/master (saisie masquée)
```

Puis :

```bash
export BW_SESSION="$(bw-unlock)"
# … commandes bw …
bw lock
```

La CLI `bw` doit rester compatible avec le serveur : Vaultwarden 1.37.3 accepte
les clients jusqu'à 2026.6 ; `bw` 2026.10 échoue au déverrouillage (404 sur la
migration *key id backfill*). La version est figée dans `~/.config/mise/config.toml`.
