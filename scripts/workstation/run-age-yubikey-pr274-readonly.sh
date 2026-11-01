#!/usr/bin/env bash
# Historical PR #274 defaults retained; --branch selects a new PR without altering an operator checkout.
# Never executes git pull/reset, changes the operator checkout, accesses PIN or writes PIV.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf 'Execute with bash; never source this script.\n' >&2
  return 2
fi
set -Eeuo pipefail
PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"
BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"
umask 077

repo='/tmp/nabla-yubikey-pr259'
state_dir="${NABLA_AGENT_STATE_DIR:-${HOME:-/nonexistent}/.local/share/nabla}"
evidence_dir="${state_dir}/yubikey-f9-public"
inventory_secondary=false
recovery_otp2=false
escrow_a=''
escrow_b=''
pinned_sha=''
remote='https://github.com/AlbanAndrieu/nabla-compose.git'
branch='fix/homelab-operator-diagnostics-followup-20261024'
observed_f9='6C:6E:14:0A:69:81:14:C3:51:14:0C:1B:68:C4:B1:16:A7:D9:B4:49:29:76:62:39:2F:61:F1:78:54:90:34:DF'
expected_root='63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546'
root_url='https://developers.yubico.com/PKI/yubico-piv-ca-1.pem'
usage() {
  printf 'Usage: bash run-age-yubikey-pr274-readonly.sh [--repo PATH] [--evidence-dir PATH] [--branch NAME] [--pinned-sha SHA] [--inventory-secondary] [--otp2-secondary] [--escrow-a PATH --escrow-b PATH]\n'
  printf 'No pre-existing checkout required. Persistent bare Git cache under HOME; isolated worktree per run.\n'
  printf 'Use --inventory-secondary for fresh public metadata on secondary 11110002 (never writes the card).\n'
  printf 'Use --branch NAME to select the active PR; legacy PR #274 is the default for old scripts.\n'
  printf 'Use --pinned-sha SHA after a verified git ls-remote bootstrap to avoid duplicate Git network calls.\n'
  printf 'Does not git pull, switch operator checkout, write PIV, request PIN or change SOPS.\n'
}
while (($#)); do
  case "$1" in
    --repo)
      (($# >= 2)) || { usage >&2; exit 2; }
      repo="$2"; shift 2 ;;
    --branch)
      (($# >= 2)) || { usage >&2; exit 2; }
      branch="$2"; shift 2 ;;
    --inventory-secondary) inventory_secondary=true; shift ;;
    --otp2-secondary) recovery_otp2=true; shift ;;
    --escrow-a)
      (($# >= 2)) || { usage >&2; exit 2; }
      escrow_a="$2"; shift 2 ;;
    --escrow-b)
      (($# >= 2)) || { usage >&2; exit 2; }
      escrow_b="$2"; shift 2 ;;
    --pinned-sha)
      (($# >= 2)) || { usage >&2; exit 2; }
      pinned_sha="$2"; shift 2 ;;
    --evidence-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      evidence_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
# Reject invalid ref names before contacting Git or any device.
if [[ "$branch" == -* ]] || ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
  printf 'NO-GO: invalid branch name\n' >&2
  exit 2
fi
if [[ -n "$escrow_a" || -n "$escrow_b" ]]; then
  [[ -n "$escrow_a" && -n "$escrow_b" ]] || {
    printf 'NO-GO: escrow requires BOTH existing backup paths\n' >&2
    exit 2
  }
fi
# Test harness may substitute a local bare repo, never on a production invocation.
if [[ "${NABLA_YUBIKEY_TEST_MODE:-0}" == 1 && -n "${NABLA_YUBIKEY_TEST_REMOTE:-}" ]]; then
  remote="${NABLA_YUBIKEY_TEST_REMOTE}"
fi

die() { printf 'NO-GO: %s\n' "$*" >&2; exit 3; }
command -v git >/dev/null || die 'Missing git'
command -v flock >/dev/null || die 'Missing flock'
[[ -n "${HOME:-}" && -d "${HOME}" ]] || die 'HOME unavailable'
cache="$state_dir/git/nabla-compose.git"
worktree_base="$state_dir/agent-worktrees"
for path in "$state_dir" "$state_dir/git" "$cache" "$worktree_base"; do
  [[ ! -L "$path" ]] || die "Refusing symlink in persistent Git state: $path"
done
mkdir -p -m 0700 -- "$state_dir" "$state_dir/git" "$worktree_base"
[[ -d "$worktree_base" && -d "$state_dir/git" ]] || die 'Unable to create private state directories'
# Lock only Git metadata operations, never the expensive security tests.
exec 9>"$state_dir/.pr274-git.lock"
flock -w 20 9 || die 'Git metadata lock busy'
if [[ -e "$cache" ]]; then
  [[ -d "$cache" ]] || die 'Git cache is not a directory'
  [[ "$(git --git-dir="$cache" rev-parse --is-bare-repository 2>/dev/null)" == true ]] || die 'Git cache is not bare'
else
  git init --bare -q "$cache" || die 'Cannot initialize persistent Git cache'
fi
# /tmp is optional. Never checkout, pull or reset its old workspace.
if [[ -e "$repo" ]]; then
  if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    old_sha="$(git -C "$repo" rev-parse HEAD)"
    printf 'INFO: source checkout %s at %.12s remains unchanged\n' "$repo" "$old_sha"
    if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
      printf 'WARN: original checkout has changes; preserving them\n'
    fi
  else
    printf 'WARN: legacy checkout path is not a Git worktree; ignored\n'
  fi
else
  printf 'INFO: legacy checkout %s absent after reboot; persistent Git cache will be used\n' "$repo"
fi
printf 'INFO: git pull skipped: tracking exact remote SHA instead\n'
ref="refs/heads/$branch"
if [[ -n "$pinned_sha" ]]; then
  [[ "$pinned_sha" =~ ^[0-9a-f]{40}$ ]] || die 'Pinned commit must be a full 40-hex SHA'
  sha="$pinned_sha"
  # The invoking bootstrap must have compared this SHA against the live PR ref.
  # Standalone --pinned-sha is a cached snapshot, NOT proof of remote freshness.
  git --git-dir="$cache" cat-file -e "$sha^{commit}" ||
    die 'Pinned commit missing in persistent cache; refusing unverified fetch'
  printf 'INFO: cached caller-pinned snapshot %.12s; no remote lookup (caller verifies freshness)\n' "$sha"
else
  response="$(git ls-remote --exit-code "$remote" "$ref")" ||
    die 'Remote branch lookup failed; Git state unchanged'
  IFS=$'\t' read -r sha ref_name <<< "$response"
  [[ "$sha" =~ ^[0-9a-f]{40}$ && "$ref_name" == "$ref" ]] ||
    die 'Unexpected remote ref result'
  if ! git --git-dir="$cache" cat-file -e "$sha^{commit}" 2>/dev/null; then
    git --git-dir="$cache" fetch --no-tags --no-write-fetch-head "$remote" "$ref" ||
      die 'Fetch failed; no checkout changed'
  fi
  git --git-dir="$cache" cat-file -e "$sha^{commit}" || die 'Remote commit missing after fetch'
fi
# Other agents cannot change the pinned SHA; FETCH_HEAD is never used.
parent="$(mktemp -d "$worktree_base/pr274.XXXXXXXX")" || die 'Could not reserve a private worktree path'
worktree="$parent/source"
tmp_root=""
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "${tmp_root:-}" && -f "$tmp_root" ]]; then rm -f -- "$tmp_root"; fi
  if [[ -d "${worktree:-}" ]] && git -C "$worktree" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [[ -z "$(git -C "$worktree" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
      if flock -w 20 9; then
        git --git-dir="$cache" worktree remove "$worktree" >/dev/null 2>&1 || \
          printf 'WARN: clean worktree could not be removed: %s\n' "$worktree" >&2
        flock -u 9
      else
        printf 'WARN: cannot acquire cleanup lock; worktree preserved: %s\n' "$worktree" >&2
      fi
    else
      printf 'WARN: worktree changed during tests; preserved: %s\n' "$worktree" >&2
    fi
  fi
  if [[ -d "${parent:-}" ]]; then rmdir "$parent" 2>/dev/null || true; fi
  exit "$status"
}
trap cleanup EXIT
git --git-dir="$cache" worktree add --detach "$worktree" "$sha" >/dev/null || die 'Could not create isolated worktree'
flock -u 9
[[ "$(git -C "$worktree" rev-parse HEAD)" == "$sha" ]] || die 'Snapshot SHA mismatch'
printf 'INFO: isolated PR snapshot %.12s at %s\n' "$sha" "$worktree"
[[ -f "$worktree/scripts/workstation/verify-age-yubikey-offline.sh" && \
   -f "$worktree/scripts/workstation/verify-age-yubikey-f9-root-offline.py" ]] || \
  die 'Verification scripts missing at pinned PR SHA'

# The offline gate is already hardware-free; abort on any failure.
(cd -- "${worktree}" && bash scripts/workstation/verify-age-yubikey-offline.sh) || die 'Offline gate failed; F9 validation not attempted'

[[ ! -L "${evidence_dir}" ]] || die 'Evidence directory is a symlink'
mkdir -p -m 0700 -- "${evidence_dir}"
f9="${evidence_dir}/f9-${BACKUP_SERIAL}.pem"
root="${evidence_dir}/yubico-piv-ca-1.pem"
[[ ! -L "${f9}" && ! -L "${root}" ]] || die 'Refusing symlink evidence'
if [[ ! -f "${f9}" ]]; then
  # Explicitly read-only YubiKey export. Never overwrite existing certificates.
  printf 'INFO: stored public F9 missing, attempting one read-only export of secondary 11110002\n'
  bash "${worktree}/scripts/workstation/inspect-age-yubikey-f9-chain.sh" \
    --serial "${BACKUP_SERIAL}" --save-public-f9 "${f9}" || die 'Read-only F9 export failed'
fi
if [[ ! -f "${root}" ]]; then
  command -v curl >/dev/null || die 'curl unavailable to acquire public root'
  command -v openssl >/dev/null || die 'openssl unavailable to fingerprint public root'
  tmp_root="$(mktemp "${evidence_dir}/.yubico-root.XXXXXXXX")" || die 'Unable to stage public root'
  # tmp is a public certificate downloaded over HTTPS, not an executable.
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 5 --max-time 20 --output "${tmp_root}" "${root_url}" || die 'Official Yubico root download failed'
  actual_root="$(openssl x509 -in "${tmp_root}" -outform DER | sha256sum | cut -d' ' -f1)" || die 'Cannot fingerprint Yubico root'
  if [[ "${actual_root}" != "${expected_root}" ]]; then
    rm -f -- "${tmp_root}"
    die 'Official root fingerprint mismatches pinned SHA256'
  fi
  (set -C; cat "${tmp_root}" >"${root}") || die 'Cannot save root without clobbering existing evidence'
  rm -f -- "${tmp_root}"
  tmp_root=""
  printf 'INFO: pinned Yubico legacy public root downloaded and verified\n'
fi
python_bin="${HOME}/.local/share/nabla/piv-sdk-venv/bin/python"
if [[ "${NABLA_YUBIKEY_TEST_MODE:-0}" == 1 && -n "${NABLA_YUBIKEY_TEST_PYTHON:-}" ]]; then
  python_bin="${NABLA_YUBIKEY_TEST_PYTHON}"
fi
[[ -x "${python_bin}" ]] || die 'Isolated PIV SDK Python missing'
"${python_bin}" "${worktree}/scripts/workstation/verify-age-yubikey-f9-root-offline.py" \
  --serial "${BACKUP_SERIAL}" --firmware 5.4.3 \
  --f9 "${f9}" --root "${root}" --expected-f9-sha256 "${observed_f9}" || \
  die 'Public F9 certificate failed pinned legacy-root validation'
[[ -f "$worktree/scripts/workstation/report-age-yubikey-piv82-readiness.py" ]] ||
  die 'PIV82 readiness report missing at pinned SHA'
"$python_bin" "$worktree/scripts/workstation/report-age-yubikey-piv82-readiness.py" \
  --f9 "$f9" --root "$root" --json ||
  die 'Public F9 readiness report failed closed'
if [[ "$recovery_otp2" == true || -n "$escrow_a" ]]; then
  recovery_script="$worktree/scripts/workstation/inspect-yubikey-recovery-readonly.py"
  [[ -f "$recovery_script" ]] || die 'Read-only recovery inspector missing at pinned SHA'
  recovery_args=()
  if [[ "$recovery_otp2" == true ]]; then recovery_args+=(--otp2-secondary); fi
  if [[ -n "$escrow_a" ]]; then
    recovery_args+=(--escrow-a "$escrow_a" --escrow-b "$escrow_b")
  fi
  "$python_bin" "$recovery_script" "${recovery_args[@]}" ||
    die 'Public OTP2/escrow recovery evidence incomplete; NO-GO remains'
fi
if [[ "${inventory_secondary}" == true ]]; then
  [[ -f "${worktree}/scripts/workstation/inspect-age-yubikey-piv82-secondary.py" ]] ||
    die 'Read-only PIV82 inventory script missing at pinned SHA'
  "${python_bin}" "${worktree}/scripts/workstation/inspect-age-yubikey-piv82-secondary.py" \
    --serial "${BACKUP_SERIAL}" --json ||
    die 'Fresh PIV82 secondary inventory not confirmed; NO-GO for provisioning'
fi
printf 'PASS: snapshot %.12s, offline gate and observed secondary F9 public trust\n' "${sha}"
printf 'NO-GO: no PIN, AES256 authentication, PIV82 generation or SOPS mutation was authorized\n'
