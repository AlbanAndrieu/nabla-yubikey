#!/usr/bin/env bash
# Local-only Git diagnostic: no fetch, checkout, reset, hardware access or writes.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'Execute with bash; do not source.\n' >&2
  return 2
fi
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "${script_dir}/../.." && pwd)"
ref=origin/master
while (($#)); do
  case "$1" in
    --repo) (($# >= 2)) || exit 2; repo="$2"; shift 2 ;;
    --ref) (($# >= 2)) || exit 2; ref="$2"; shift 2 ;;
    --help|-h)
      printf 'Usage: bash diagnose-age-yubikey-git-checkout.sh [--repo PATH] [--ref origin/master]\n'
      printf 'Read-only; never fetches, checks out, modifies Git refs or contacts hardware.\n'
      exit 0 ;;
    *) printf 'Unexpected argument\n' >&2; exit 2 ;;
  esac
done
case "${ref}" in
  origin/*) ;;
  *) printf 'NO-GO: only an origin/* tracking ref is permitted\n' >&2; exit 2 ;;
esac
if ! git -C "${repo}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'NO-GO: not a Git worktree\n' >&2
  exit 3
fi
head="$(git -C "${repo}" rev-parse --verify HEAD)" || exit 3
branch="$(git -C "${repo}" symbolic-ref -q --short HEAD || true)"
if [[ -z "${branch}" ]]; then
  printf 'INFO: detached HEAD %s (git pull cannot infer branch)\n' "${head:0:12}"
else
  printf 'INFO: current branch %s at %s\n' "${branch}" "${head:0:12}"
fi
# The comparison is against the LOCALLY cached tracking ref, never the live server.
clean=1
if [[ -n "$(git -C "${repo}" status --porcelain --untracked-files=normal)" ]]; then
  printf 'NO-GO: worktree has local tracked or untracked changes; preserve them before switching\n' >&2
  clean=0
fi
stale=1
if git -C "${repo}" rev-parse --verify --quiet --end-of-options "${ref}^{commit}" >/dev/null; then
  tracked="$(git -C "${repo}" rev-parse "${ref}^{commit}")"
  if [[ "${head}" == "${tracked}" ]]; then
    printf 'INFO: HEAD equals cached %s (%s); remote freshness UNKNOWN\n' "${ref}" "${tracked:0:12}"
    stale=0
  elif git -C "${repo}" merge-base --is-ancestor HEAD "${tracked}"; then
    printf 'NO-GO: HEAD is behind cached %s (%s)\n' "${ref}" "${tracked:0:12}" >&2
  elif git -C "${repo}" merge-base --is-ancestor "${tracked}" HEAD; then
    printf 'WARN: HEAD contains commits beyond cached %s; review history before switching\n' "${ref}"
  else
    printf 'NO-GO: HEAD diverges from cached %s; do not reset\n' "${ref}" >&2
  fi
else
  printf 'NO-GO: local tracking ref %s is missing; remote freshness UNKNOWN\n' "${ref}" >&2
fi
required='scripts/workstation/test-age-yubikey-piv82-attestation-offline.py'
if [[ ! -f "${repo}/${required}" ]]; then
  printf 'NO-GO: attestation test missing from this checkout (stale revision likely)\n' >&2
  stale=1
fi
printf 'INFO: git pull on detached HEAD is not appropriate; this script performs no fetch\n'
printf 'INFO: when network works, fetch the merged code with HTTPS:\n'
printf '  git fetch --no-tags https://github.com/AlbanAndrieu/nabla-compose.git master\n'
printf '  git status --short     # ensure it is clean before switching\n'
printf '  git switch --detach FETCH_HEAD\n'
if (( clean == 0 || stale != 0 )); then
  exit 3
fi
printf 'PASS: local checkout matches the cached ref and contains the attestation test; network freshness unverified\n'
