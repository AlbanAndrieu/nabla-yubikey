# shellcheck shell=bash

# Shared, side-effect-free shell primitives for operator scripts.
# Keep this file small: domain logic belongs in dedicated libraries/scripts.
# Self-contained on purpose: reboot bundles copy this file alone.

# Decorate only interactive terminals. Logs, pipes, CI and NO_COLOR keep the
# stable plain-text prefixes that tests and log parsers rely on.
nabla_ui_color_enabled() {
  # no-color.org: a non-empty NO_COLOR disables color.
  [[ -t "${1:-1}" && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]
}

# Color variables for scripts that compose their own lines; empty when the
# stdout is not an interactive terminal.
# shellcheck disable=SC2034 # NABLA_UI_* are read by the sourcing script
nabla_ui_init() {
  NABLA_UI_RESET='' NABLA_UI_GREEN='' NABLA_UI_YELLOW='' NABLA_UI_RED='' NABLA_UI_BLUE=''
  if nabla_ui_color_enabled 1; then
    NABLA_UI_RESET=$'\033[0m'
    NABLA_UI_GREEN=$'\033[32m'
    NABLA_UI_YELLOW=$'\033[33m'
    NABLA_UI_RED=$'\033[31m'
    NABLA_UI_BLUE=$'\033[36m'
  fi
}

nabla_tty_style() {
  local fd="$1" color="$2" icon="$3" label="$4"
  shift 4
  if nabla_ui_color_enabled "${fd}"; then
    case "${NABLA_UI_ASCII:-0}:${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
      0:*UTF-8* | 0:*utf8* | 0:*utf-8*) label="${icon} ${label}" ;;
      *) ;;
    esac
    printf '\033[%sm%s\033[0m %s\n' "${color}" "${label}" "$*"
  else
    printf '%s %s\n' "${label}" "$*"
  fi
}

fail() {
  nabla_tty_style 2 '1;31' '❌' 'ERROR:' "$*" >&2
  exit 1
}

warn() {
  nabla_tty_style 2 33 '⚠️ ' 'WARN:' "$*" >&2
}

ok() {
  nabla_tty_style 1 32 '✅' 'OK:' "$*"
}

info() {
  nabla_tty_style 1 36 'ℹ️ ' 'INFO:' "$*"
}

section() {
  printf '\n'
  nabla_tty_style 1 '1;34' '🔷' '==>' "$*"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "${1:-run as root}"
}

require_commands() {
  local required
  for required in "$@"; do
    command -v "${required}" >/dev/null 2>&1 || fail "${required} is required"
  done
}
