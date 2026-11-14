# YubiKey agent collaboration — conditional operator reference

**Authority:** [AGENTS.md](../AGENTS.md). Only load for a PR/agent task.
The migration status in [docs/roadmap.md](roadmap.md) does **not**
authorize hardware operations or retries.

## One PR, one scoped owner

First search for open PRs. Choose a compatible existing branch before
starting an agent task and inventory common paths to avoid parallel edits
to a shared `SKILL.md` or runbook. No open PR means accumulate a coherent
offline-tested batch instead of proposing a cosmetic new PR.

Workstation flow:
```bash
git fetch origin master
git status --short
git log --left-right --oneline HEAD...origin/master
# If behind: rebase on origin/master and resolve exact conflicts;
# verify every changed file and run just test before publishing.
just test
```
A published-branch rebase requires an explicit, exact-HEAD
`--force-with-lease` authorization; otherwise merge the base non-force
after review. Never use a blind force, reset hard or drop another agent's
commits. No default-branch changes.

**Batch threshold:** avoid pushes for trivial isolated edits. Publish once
per tested logical unit. Production-security stabilization or a migration
that has updated all dependent services may justify an immediate push.
Keep PR Draft and no auto merge. Do not disable pre-commit/security checks.

## Capability boundary

| Agent | Evidence | Prohibited inference |
| --- | --- | --- |
| Workstation Claude Code | `just test` and explicitly chosen read-only probe | Unit tests alone do not prove hardware/backup health |
| Remote Codex / source-only | stdlib tests, docs, fixtures, exact-SHA Git diff | no YubiKey serial, PIN attempt, physical touch, NFS/TrueNAS |

Private serials must never enter issue comments or CLI output shared with
an agent. A verification blocked by missing hardware is `NOT_RUN`, not
a clean or failed physical device.
