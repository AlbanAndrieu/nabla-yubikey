#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---check}"
VERSION="${NABLA_YKMAN_VERSION:-5.8.0}"
BIN_DIR="${HOME}/.local/bin"
LINK="${BIN_DIR}/ykman"
SYSTEM_YKMAN="/usr/bin/ykman"
AGE_PLUGIN_VERSION="${NABLA_AGE_PLUGIN_YUBIKEY_VERSION:-0.5.1}"
AGE_PLUGIN_BIN="${HOME}/.cargo/bin/age-plugin-yubikey"
AGE_PLUGIN_LINK="${BIN_DIR}/age-plugin-yubikey"

# shellcheck source=../lib/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../lib/common.sh"

case "${MODE}" in
  --check|--apply) ;;
  -h|--help)
    cat <<'EOF'
usage: bash scripts/workstation/bootstrap-yubikey-manager.sh [--check|--apply]

Install the distro-packaged YubiKey Manager CLI on an Ubuntu/Debian workstation.
Ubuntu Resolute currently ships yubikey-manager 5.9.2, avoiding local pyscard
compilation. Installs pinned age-plugin-yubikey via Cargo --locked on --apply.
No PIV slots, PINs or keys are changed.
~/.local/bin/ykman points to /usr/bin/ykman so a stale
/usr/local/bin/ykman cannot shadow the packaged executable.
EOF
    exit 0
    ;;
  *) fail "unknown mode: ${MODE}" ;;
esac

[[ "${EUID}" -ne 0 ]] || fail "run as the normal workstation user, not root"

check_install() {
  [[ -x "${SYSTEM_YKMAN}" ]] || return 1
  actual="$("${SYSTEM_YKMAN}" --version 2>/dev/null | awk '{print $NF}')"
  [[ "${actual}" == "${VERSION}" ]] || {
    printf 'ERROR: packaged ykman version=%s expected=%s\n' "${actual:-<unknown>}" "${VERSION}" >&2
    return 1
  }
  [[ -L "${LINK}" ]] || return 1
  [[ "$(readlink -f "${LINK}")" == "${SYSTEM_YKMAN}" ]] || return 1
}

check_age_plugin() {
  [[ -x "${AGE_PLUGIN_BIN}" && -L "${AGE_PLUGIN_LINK}" ]] || return 1
  [[ "$(readlink -f "${AGE_PLUGIN_LINK}")" == "${AGE_PLUGIN_BIN}" ]] || return 1
  local version
  version="$("${AGE_PLUGIN_BIN}" --version 2>/dev/null || true)"
  [[ "${version}" == *"${AGE_PLUGIN_VERSION}"* ]]
}

report_path() {
  printf 'canonical=%s link=%s\n' "${SYSTEM_YKMAN}" "${LINK}"
  type -a ykman 2>/dev/null || true
  printf "age-plugin-yubikey expected=%s path=%s\n" "${AGE_PLUGIN_VERSION}" "${AGE_PLUGIN_LINK}"
  if [[ -x /usr/local/bin/ykman ]] && ! /usr/local/bin/ykman --version >/dev/null 2>&1; then
    printf 'WARNING: stale broken launcher remains at /usr/local/bin/ykman; it is intentionally not deleted.\n' >&2
  fi
}

if [[ "${MODE}" == "--check" ]]; then
  report_path
  check_install || fail "packaged ykman ${VERSION} is not ready; run --apply"
  printf 'OK: YubiKey Manager %s ready at %s\n' "${VERSION}" "${SYSTEM_YKMAN}"
  check_age_plugin || fail "age-plugin-yubikey ${AGE_PLUGIN_VERSION} missing; run --apply"
  printf 'OK: age-plugin-yubikey %s ready (no provisioning)\n' "${AGE_PLUGIN_VERSION}"
  exit 0
fi

command -v apt-get >/dev/null 2>&1 ||
  fail "apt-get is required on this workstation path"
sudo apt-get update
sudo apt-get install -y --no-install-recommends yubikey-manager pcscd libu2f-udev libpcsclite-dev pkg-config

[[ -x "${SYSTEM_YKMAN}" ]] ||
  fail "package installation completed but ${SYSTEM_YKMAN} is missing"
actual="$("${SYSTEM_YKMAN}" --version 2>/dev/null | awk '{print $NF}')"
[[ "${actual}" == "${VERSION}" ]] ||
  fail "distribution package installed ykman ${actual:-<unknown>}; expected ${VERSION}"

install -d -m 700 "${BIN_DIR}"
ln -sfn "${SYSTEM_YKMAN}" "${LINK}"
check_install || fail "packaged ykman failed post-install self-check"

if ! check_age_plugin; then
  command -v cargo >/dev/null 2>&1 || fail "Cargo not found: install approved Rust toolchain before --apply"
  # pcsc-sys discovers libpcsclite through pkg-config, not via pcscd.
  # Some workstations export a restrictive PKG_CONFIG_LIBDIR or SYSROOT.
  # Use the distro's canonical multiarch pkg-config directory for this build.
  command -v dpkg-architecture >/dev/null 2>&1 ||
    fail "dpkg-architecture missing: cannot resolve system PC/SC pkg-config directory"
  triplet="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
  pc_dir="/usr/lib/${triplet}/pkgconfig"
  pc_file="${pc_dir}/libpcsclite.pc"
  [[ -r "${pc_file}" ]] ||
    fail "PC/SC metadata missing: ${pc_file} (check libpcsclite-dev installation)"
  command -v /usr/bin/pkg-config >/dev/null 2>&1 ||
    fail "system pkg-config missing at /usr/bin/pkg-config"
  # Scoped environment: no changes to the user's global Rust or pkg-config config.
  pc_paths="${pc_dir}:/usr/lib/pkgconfig:/usr/share/pkgconfig"
  pc_version="$(env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_SYSROOT_DIR \
    PKG_CONFIG=/usr/bin/pkg-config PKG_CONFIG_PATH="${pc_paths}" \
    /usr/bin/pkg-config --modversion libpcsclite 2>/dev/null)" ||
    fail "system libpcsclite is not resolvable by pkg-config despite installed headers"
  printf 'OK: PC/SC build dependency libpcsclite %s resolved through %s\n' "${pc_version}" "${pc_dir}"
  env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_SYSROOT_DIR \
    PKG_CONFIG=/usr/bin/pkg-config PKG_CONFIG_PATH="${pc_paths}" \
    cargo install --locked --version "${AGE_PLUGIN_VERSION}" age-plugin-yubikey
  [[ -x "${AGE_PLUGIN_BIN}" ]] || fail "Cargo binary missing: ${AGE_PLUGIN_BIN}"
  ln -sfn "${AGE_PLUGIN_BIN}" "${AGE_PLUGIN_LINK}"
fi
check_age_plugin || fail "age-plugin-yubikey post-install check failed"

printf 'OK: installed YubiKey Manager %s from the workstation distribution\n' "${VERSION}"
printf 'OK: age-plugin-yubikey %s installed (no device modification)\n' "${AGE_PLUGIN_VERSION}"
# shellcheck disable=SC2016 # Print literal $PATH for the operator to evaluate.\nprintf 'INFO: export PATH="%s:$PATH"; hash -r\n' "${BIN_DIR}"
report_path
