# Agent policy — nabla-yubikey

This **public** repository owns YubiKey/FIDO2/PIV/OpenPGP/OTP/age/SOPS/SSH-sk
**procedures, offline tests and read-only diagnostics**. Infrastructure,
TrueNAS/NFS storage and network belong to `nabla-compose`; Ubuntu OS
prerequisites belong to `ansible-workstation`. Read this file first and
only the relevant runbook/skill. [Conditional PR procedure](docs/agent-pr-workflow.md).

## Non-negotiable security

- Do not change a YubiKey, provision/erase an applet, alter PIN/PUK/PIV/
  OTP/OpenPGP slots, PAM, `authorized_keys`, encryption identities, escrow,
  serial numbers or backup material **without explicit task-specific approval**.
- Never read, print, stage, export or commit private keys, `BW_SESSION`,
  tokens, smartcard state, personal serials, GPG stores or encrypted recovery
  secrets. Do not use `set -x` around secrets.
- Read-only probes must check target device identity and fail closed when
  serial/permissions/capability is absent. Do not infer hardware state from
  source files or tests. Preserve rollback and independent backups.

## Actual execution mode

- **Claude Code on verified Ubuntu Workstation:** run `just test` first,
  optionally the specific `*-readonly` probe **after** confirming the
  operator has approved host/hardware reads. Never use `just check` as an
  implicit authorization to write to hardware.
- **Codex/API-only or disconnected:** `AGENT_EXECUTION_MODE=offline`.
  Confine work to source, tests, docs and fixtures; no `ykman`, `gpg`,
  `ssh`, NFS, Vaultwarden or hardware probes. Mark runtime and hardware
  `NOT_RUN`. `AGENT_EXECUTION_MODE=workstation` is not permission to
  mutate a key.
- Distinguish `CODED`, `TESTED`, `DEPLOYED`, `ACCEPTED`; no false PASS.

## PR-first and publication batching

1. Locate **open PRs**, compare exact base/HEAD and overlapping files,
   **reuse the compatible PR** and keep one owner per shared skill, runbook
   or roadmap. No speculative duplicate branches.
2. **Rebase the selected branch before editing** in an isolated worktree,
   resolve all conflicts against the actual current base and rerun targeted
   offline tests. No history rewrite without a verified lease and explicit
   approval; a reviewed merge is the fallback where force is prohibited.
3. Accumulate small corrections into **one coherent tested batch** on the
   existing Draft PR. No micro-push per spelling or minor diagnostic tweak.
   Exceptions: urgent production/security stabilization or completion of a
   cross-service migration that requires coordinated dependent changes.
4. Never commit directly to `master`, bypass hooks, weaken security gates,
   trigger unrelated CI, auto-merge or claim a missing hardware check passed.
   Publish short evidence: `PR@SHA | changes | tests | risks | next`.

The local `just test` remains the hermetic gate; hardware acceptance is a
separate opt-in proof. See [roadmap](docs/roadmap.md).
