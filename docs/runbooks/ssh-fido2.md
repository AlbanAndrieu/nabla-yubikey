# Runbook — clé SSH FIDO2 résidente (ed25519-sk)

> **Attesté le 31/10/2026** sur Workstation (YubiKey 5 NFC, firmware 5.4.3, OpenSSH 10.2, GNOME/Wayland) : génération, signature directe et via `gcr-ssh-agent`, push GitHub PASS. Seconde clé `ssh:nabla` sur la principale (5C NFC) acceptée par GitHub, secondaire absente sautée. Reconnexion de session et test GitHub avec la secondaire seule sous la config finale **non attestés**.

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

## Répartition des clés (31/10)

| Usage | Clé | Pourquoi |
| --- | --- | --- |
| `git push` GitHub depuis Workstation | `id_ed25519_sk_principale` (5C NFC) ou `id_ed25519_sk` (secondaire, 5 NFC) | Une clé `ssh:nabla` par YubiKey, les deux sur GitHub ; PIN + toucher ; une clé absente est sautée |
| truenas, pfsense | `id_ed25519` | Ces hôtes ne connaissent pas les YubiKey : ils les refusent sans demander de PIN, puis acceptent la clé fichier |
| Secours GitHub (break-glass) | `id_ed25519`, toujours enregistrée sur GitHub | **Jamais proposée automatiquement** : `GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519" git push` |
| Signature des commits | Clé OpenPGP (`commit.gpgsign = true`) | Commits « Verified » sur GitHub, indépendants de la clé SSH |

`ForwardAgent no` partout : un root distant pourrait utiliser l'agent transféré, y compris la clé fichier sans aucune confirmation. TrueNAS utilise sa propre clé pour ses accès sortants.

## `~/.ssh/config` (attesté avec GitHub le 31/10)

ssh retient la **première** valeur lue (`IdentityFile` s'accumule dans l'ordre de lecture). Organisation retenue :

- `~/.ssh/config` : inventaire privé des hôtes (IP, ports, comptes), jamais versionné, se termine par `Match all` + `Include ~/.config/ssh/common.conf` pour que ses blocs gagnent.
- `~/.config/ssh/common.conf` : défauts publics, versionnables dans les dotfiles.

```sshconfig
Host github.com
  User git
  PreferredAuthentications publickey
  ControlPersist 8h          # un PIN par journée de travail
  ServerAliveInterval 60     # garde la connexion maîtresse à travers NAT/WARP

Host *
  IdentitiesOnly yes
  ForwardAgent no
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 10m
  IdentityFile ~/.ssh/id_ed25519_sk_principale   # YubiKey principale
  IdentityFile ~/.ssh/id_ed25519_sk              # YubiKey secondaire

# Clé fichier pour les serveurs uniquement.
Match host "*,!github.com"
  IdentityFile ~/.ssh/id_ed25519
```

**Pourquoi exclure `id_ed25519` de GitHub (constaté le 31/10) :** ssh essaie les clés présentes dans l'agent **dans l'ordre de l'agent**, pas dans l'ordre de la config. `gcr-ssh-agent` charge toutes les clés de `~/.ssh` ; avec la secondaire débranchée, sa signature échouait (`agent refused operation`) et `id_ed25519`, aussi enregistrée sur GitHub, authentifiait **sans PIN ni toucher** avant la principale. Une clé `_sk` créée après l'ouverture de session n'est dans l'agent qu'après `ssh-add` (ou la session suivante).

**Arbitrage `ControlPersist 8h` (choisi le 31/10) :** tant que la connexion maîtresse est ouverte, tout processus du compte peut pousser sur GitHub sans PIN ni toucher. La fermer avant une absence : `ssh -O exit github.com`.

Contrôle sans réseau ni PIN : `just ssh-fido2-readonly` (`GO` attendu, dont `github_file_key: FILE_KEY_MISSING`). Puis, avec **chaque** YubiKey seule :

```bash
ssh -O exit github.com; ssh -v -T github.com 2>&1 | grep -E 'Server accepts key|successfully authenticated'
```

La dernière ligne `Server accepts key` doit nommer la clé `_sk` de la YubiKey branchée, jamais `id_ed25519`. Attesté le 31/10 avec la principale (la secondaire absente est sautée).

La sonde lit `ssh -G`, l'environnement systemd utilisateur (seulement `SSH_ASKPASS` et `WAYLAND_DISPLAY`) et `git config --global` ; elle n'affiche ni chemin, ni clé, ni empreinte.

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
