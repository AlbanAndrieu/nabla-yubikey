# Runbook — clé SSH FIDO2 résidente (ed25519-sk)

> **Attesté le 31/10/2026** sur Workstation (YubiKey 5 NFC, firmware 5.4.3, OpenSSH 10.2, GNOME/Wayland) : génération, signature directe et signature via `gcr-ssh-agent` PASS. Reconnexion de session et déploiement `authorized_keys`/GitHub **non attestés**.

Opération **modificatrice** : elle ajoute un identifiant résident sur la carte. À lancer soi-même, de façon interactive ; le PIN FIDO2 ne passe jamais par un script ni un agent IA.

## Prérequis (lecture seule)

```bash
ykman fido info          # PIN défini, essais restants
ssh -V                   # OpenSSH >= 8.9 (avertit avant d'écraser une clé résidente)
```

Garder une clé de secours (`~/.ssh/id_ed25519` ou une seconde YubiKey) : la clé privée FIDO2 n'est **pas exportable**, une carte perdue = clé perdue.

## Génération

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -O application=ssh:nabla -C "yubikey-5nfc" -f ~/.ssh/id_ed25519_sk
```

- Si OpenSSH annonce qu'une clé résidente `ssh:nabla` existe déjà : répondre **n** et choisir un autre `application=`.
- Passphrase : vide acceptable. Le fichier n'est qu'un *handle* ; PIN + toucher restent exigés à chaque signature (`verify-required`).
- Handle perdu : `ssh-keygen -K` le régénère depuis la carte.

## Où vit la clé

| Élément | Contenu |
| --- | --- |
| YubiKey (applet FIDO2) | Clé privée, non extractible |
| `~/.ssh/id_ed25519_sk` | Handle, inutile sans la carte |
| `gcr-ssh-agent` → `ssh-agent` | Charge automatiquement le handle depuis `~/.ssh` ; ne met **pas** le PIN en cache |
| Seahorse | Seulement la fenêtre de saisie du PIN (`SSH_ASKPASS`) |

Conséquence : **PIN + toucher à chaque signature** (connexion `ssh`, `git push` SSH, commit signé SSH). Pour réduire la fréquence : `ControlMaster auto` / `ControlPersist` dans `~/.ssh/config` (une authentification par connexion maîtresse), ou régénérer **sans** `verify-required` (toucher seul, le PIN n'est plus demandé : arbitrage de sécurité à décider explicitement).

## `~/.ssh/config` (attesté avec GitHub le 31/10)

ssh retient la **première** valeur lue : un `Host *` placé avant fait proposer `id_ed25519` d'abord, la YubiKey n'est alors jamais sollicitée. Mettre le bloc avant `Host *` :

```sshconfig
Host github.com
  User git
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_ed25519_sk
  IdentityFile ~/.ssh/id_ed25519
  ControlPersist 1h

Host *
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 10m
```

Contrôle : `ssh -G github.com | grep -E '^(identityfile|controlpersist) '`, puis `ssh -T github.com` (PIN demandé) et `ssh -O check github.com` (connexion maîtresse active, pas de nouveau PIN).

## Piège GNOME/Wayland : « agent refused operation »

`gcr-ssh-agent` demande le PIN via `/usr/bin/ssh-askpass` (`x11-ssh-askpass`), qui ne peut pas saisir le clavier sous Wayland et renvoie un PIN vide. Le compteur FIDO2 n'est pas décrémenté.

```bash
mkdir -p ~/.config/environment.d
printf 'SSH_ASKPASS=/usr/libexec/seahorse/ssh-askpass\n' > ~/.config/environment.d/50-ssh-askpass.conf
systemctl --user set-environment SSH_ASKPASS=/usr/libexec/seahorse/ssh-askpass
systemctl --user restart gcr-ssh-agent.service   # vide les clés chargées
```

Contournement ponctuel sans agent : `SSH_AUTH_SOCK= SSH_ASKPASS_REQUIRE=never ssh …`.

## Vérification

```bash
printf test > /tmp/sign-test.txt
ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sk -n test /tmp/sign-test.txt && echo AGENT_SIGNATURE_OK
ykman fido info          # essais PIN inchangés
```

**GO** : `AGENT_SIGNATURE_OK` et compteur PIN intact. **NO-GO déploiement** tant que la clé de secours n'est pas testée sur la même cible. L'ajout de la clé publique dans `authorized_keys` ou sur GitHub est une décision séparée : ne jamais retirer l'ancienne clé dans la même opération.
