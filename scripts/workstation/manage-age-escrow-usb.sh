#!/usr/bin/env bash
# Manage an existing LUKS2 USB escrow; never format or overwrite an age identity.
set -euo pipefail
umask 077
action=check
uuid=''
expected_recipient='age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938'
mapper=nabla_escrow_usb
mountpoint=/mnt/nabla-escrow
usage() {
  cat <<'EOF'
Usage: manage-age-escrow-usb.sh --luks-uuid UUID [--check|--open|--close|--init-identity]
  --check          Read-only state, default.
  --open           Unlock existing LUKS2 and mount existing ext4 filesystem.
  --close          Sync, unmount and close LUKS mapper.
  --init-identity  Create age escrow identity ONLY if absent on an already mounted USB;
                   requires explicit confirmation of identity creation.
  --luks-uuid      Actual LUKS partition UUID from blkid; not filesystem UUID.
Never formats a disk, erases PIV, resets a YubiKey, or overwrites an age identity.
Regenerating an identity WILL NOT recreate the old identity or decrypt old backups.
EOF
}
while (($#)); do
  case "$1" in
    --luks-uuid) (($# > 1)) || exit 2; uuid="$2"; shift 2 ;;
    --check|--open|--close|--init-identity) action="${1#--}"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'Unknown option' >&2; exit 2 ;;
  esac
done
[[ "${uuid}" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] || {
  echo 'Pass exact LUKS UUID; never assume /dev/sdd remains the USB disk' >&2; exit 2;
}
device="/dev/disk/by-uuid/${uuid}"
[[ -b "${device}" ]] || { echo 'LUKS UUID device not found' >&2; exit 1; }
# Unprivileged blkid may return no TYPE for a block device: use lsblk/udev.
physical_device="$(readlink -f -- "${device}")"
fstype="$(lsblk -dn -o FSTYPE "${physical_device}" | tr -d '[:space:]')"
actual_uuid="$(lsblk -dn -o UUID "${physical_device}" | tr -d '[:space:]')"
[[ "${fstype}" == crypto_LUKS && "${actual_uuid,,}" == "${uuid,,}" ]] || {
  echo 'Selected partition TYPE/UUID does not match LUKS escrow' >&2; exit 1;
}
# Resolve child crypt device from the UUID-selected partition, not a fixed mapper name.
mapfile -t children < <(lsblk -nr -o PATH,TYPE "${device}" | awk '$2=="crypt" {print $1}')
if (( ${#children[@]} > 1 )); then
  echo 'Ambiguous multiple unlocked crypt mappings; refusing' >&2; exit 2
fi
active_mapper="${children[0]:-}"
active_mount=''
if [[ -n "${active_mapper}" ]]; then
  active_mount="$(lsblk -nr -o MOUNTPOINTS "${active_mapper}" | grep '^/' | head -n 1 || true)"
fi
if [[ "${action}" == check ]]; then
  echo 'LUKS UUID verified; current state:'
  lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS "${device}"
  if [[ -n "${active_mount}" ]]; then
    echo 'Unlocked and mounted; auto-mount path detected.'
  elif [[ -n "${active_mapper}" ]]; then
    echo 'Unlocked but not mounted.'
  else
    echo 'Locked.'
  fi
  exit 0
fi
if [[ "${action}" == open ]]; then
  if [[ -n "${active_mount}" ]]; then
    echo 'Existing unlocked USB mount detected; no changes made.'
    exit 0
  fi
  [[ -z "${active_mapper}" ]] || {
    echo 'Already unlocked but unmounted; manual inspection required' >&2; exit 2;
  }
  sudo mkdir -p "${mountpoint}"
  sudo cryptsetup open "${device}" "${mapper}"
  if ! sudo mount "/dev/mapper/${mapper}" "${mountpoint}"; then
    echo 'Mount failed; mapper remains open for inspection' >&2; exit 1
  fi
  echo 'Escrow unlocked and mounted.'
  exit 0
fi
[[ -n "${active_mapper}" && -n "${active_mount}" ]] || {
  echo 'Escrow device is not mounted; refusing' >&2; exit 2;
}
[[ "$(findmnt -rn -o FSTYPE -T "${active_mount}")" == ext4 ]] || {
  echo 'Unexpected escrow filesystem type; refusing' >&2; exit 2;
}
if [[ "${action}" == close ]]; then
  sync
  if [[ "${active_mount}" == /run/media/"$(id -un)"/* ]]; then
    command -v udisksctl >/dev/null || { echo 'udisksctl required for automount close' >&2; exit 1; }
    udisksctl unmount -b "${active_mapper}"
    udisksctl lock -b "${device}"
  elif [[ "${active_mount}" == "${mountpoint}" && "${active_mapper}" == "/dev/mapper/${mapper}" ]]; then
    sudo umount "${active_mount}"
    sudo cryptsetup close "${mapper}"
  else
    echo 'Unexpected mount/mapping; refuse automatic close' >&2; exit 2;
  fi
  echo 'Escrow closed.'
  exit 0
fi
[[ "${action}" == init-identity ]] || exit 2
folder="${active_mount}/age-escrow"
identity="${folder}/recovery-identity.txt"
if [[ -e "${identity}" || -L "${identity}" ]]; then
  derived="$(age-keygen -y "${identity}")" || { echo 'Existing identity unreadable' >&2; exit 1; }
  [[ "${derived}" == "${expected_recipient}" ]] || {
    echo 'Existing identity does NOT match documented recipient. Do not overwrite.' >&2; exit 1;
  }
  echo 'Existing original age identity verified; no changes made.'
  exit 0
fi
echo 'WARNING: a NEW age identity cannot decrypt data encrypted for the ORIGINAL identity.'
echo 'Restore the ORIGINAL private identity from its independent backup if rebuilding a lost USB.'
read -r -p "Type CREATE-NEW-IDENTITY to generate a NEW incompatible identity: " confirm
[[ "${confirm}" == CREATE-NEW-IDENTITY ]] || { echo 'Cancelled' >&2; exit 2; }
install -d -m 700 "${folder}"
age-keygen -o "${identity}"
chmod 600 "${identity}"
echo 'New identity created on existing encrypted filesystem; update escrow recipient and backups.'
