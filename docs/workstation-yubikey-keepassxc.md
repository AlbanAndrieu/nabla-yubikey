# YubiKey + KeePassXC — workstation

Canonical tools live in `nabla-compose/scripts/workstation/`.
Bootstrap `bootstrap-yubikey-manager.sh --check|--apply` installs/checks
Ubuntu-packaged ykman. Run diagnostics separately.

## Verified recovery (2026-10-16)

- Primary: USB-C YubiKey `11110001`, HMAC-SHA1 slot 2.
- Backup: USB-A/NFC YubiKey `11110002`, HMAC-SHA1 slot 2.
- A previously saved **20-byte** HMAC secret was confirmed offline against
  the primary key's reference response for the fixed challenge.
- The secondary slot 2 was then programmed manually using `ykman otp chalresp 2`
  (previous slot contents replaced), and the exact same challenge yielded
  the same 40-hex-digit response. No `.kdbx` migration needed.
- The user's “ça fonctionne” confirms the successful second-key check;
  keep explicit KeePassXC database-open testing in both-key recovery validation.

## Usage

```bash
bash scripts/workstation/bootstrap-yubikey-manager.sh --check
bash scripts/workstation/diagnose-yubikey-keepassxc.sh --serial 11110002 --challenge
# Optional: only if HMAC_SECRET was already exported securely
bash scripts/workstation/diagnose-yubikey-keepassxc.sh --verify-secret
```

`--verify-secret` checks the exported `HMAC_SECRET` against a known
reference HMAC response **without printing the value**. Spaces/newlines in
the secret's formatting are removed in-memory. Comparison to one known
challenge verifies matching key material, not the origin of the secret.

**Security:** Do not store `HMAC_SECRET` in shell startup, `.env`, repo,
GitHub Actions, shell history, or logs. An exported variable is inherited by
child processes and can be visible to privileged local processes. Prefer a
restricted password manager/secret store, and `unset HMAC_SECRET` after use.
The diagnostic never programs devices. Programming an occupied slot is
destructive and always remains a manual, explicitly authorized step.
Original YubiKey HMAC secrets cannot be extracted from hardware.
