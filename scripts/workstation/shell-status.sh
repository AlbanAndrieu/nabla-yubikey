#!/usr/bin/env bash
# Source-only status formatting for interactive workstation scripts.
# No output on import. Respect NO_COLOR and non-TTY log consumers.
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
  NABLA_GREEN=$'\033[32m'
  NABLA_YELLOW=$'\033[33m'
  NABLA_RED=$'\033[31m'
  NABLA_BLUE=$'\033[34m'
  NABLA_RESET=$'\033[0m'
else
  NABLA_GREEN='' NABLA_YELLOW='' NABLA_RED='' NABLA_BLUE='' NABLA_RESET=''
fi
nabla_status() {
  local kind="$1"; shift
  local symbol color
  case "$kind" in
    ok) symbol='✅'; color="$NABLA_GREEN" ;;
    warn) symbol='⚠️'; color="$NABLA_YELLOW" ;;
    error) symbol='❌'; color="$NABLA_RED" ;;
    info) symbol='ℹ️'; color="$NABLA_BLUE" ;;
    *) printf 'Unknown status type\n' >&2; return 2 ;;
  esac
  if [[ ! -t 1 || "${NO_COLOR+x}" || "${TERM:-dumb}" == dumb || "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" == C ]]; then
    case "$kind" in ok) symbol='[OK]' ;; warn) symbol='[WARN]' ;; error) symbol='[ERROR]' ;; info) symbol='[INFO]' ;; esac
  fi
  if [[ "$kind" == error || "$kind" == warn ]]; then
    printf '%s%s %s%s\n' "$color" "$symbol" "$*" "$NABLA_RESET" >&2
  else
    printf '%s%s %s%s\n' "$color" "$symbol" "$*" "$NABLA_RESET"
  fi
}
