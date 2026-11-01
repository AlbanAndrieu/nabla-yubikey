# Recipes migrated from nabla-compose (1 Nov 2026), same names and commands.
# Real serials come from YUBIKEY_PRIMARY_SERIAL / YUBIKEY_BACKUP_SERIAL, never from this file.

# Explicit physical read-only OTP2 metadata check on secondary 11110002.
# This proves only slot programmed/empty; NEVER proves HMAC-SHA1 or KeePassXC.
# Status remains NO-GO even when this recipe exits successfully.
yubikey-otp2-secondary-readonly:
    python3 scripts/workstation/inspect-yubikey-recovery-readonly.py --otp2-secondary

# GnuPG Assuan GETINFO only. Uses --no-autostart and never handles secrets.
yubikey-gpg-agent-test:
    python3 -m py_compile scripts/workstation/inspect-gpg-agent-readonly.py tests/test_yubikey_gpg_agent_readonly.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_gpg_agent_readonly.py' -v

yubikey-gpg-agent-readonly:
    python3 scripts/workstation/inspect-gpg-agent-readonly.py

# One command: all hermetic YubiKey contract groups, then one public snapshot
# on the secondary only. Never re-runs OTP2/F9/PIV82 hardware reads.
yubikey-diagnostics-all-secondary:
    just yubikey-recovery-test
    just yubikey-applications-test
    just yubikey-workstation-test
    just yubikey-diagnostics-test
    just yubikey-gpg-agent-test
    python3 scripts/workstation/diagnose-yubikey-readonly-batch.py --hardware --serial ${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL} --gpg-agent-probe

# Concurrent software readiness: five hermetic suites + host and GPG probes.
# NO-GO even when all gates PASS; never mutates keys, PAM, SOPS or GPG.
yubikey-parallel-test:
    python3 -m py_compile scripts/workstation/run-yubikey-parallel-readonly.py tests/test_yubikey_parallel_readonly.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_parallel_readonly.py' -v

# Host-only: GPG/scdaemon/PCSC process presence, SSH-agent public identities,
# PostgreSQL recovery tool availability. No credentials, signing or hardware.
yubikey-dependencies-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-dependencies-readonly.py tests/test_yubikey_dependencies_readonly.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_dependencies_readonly.py' -v

yubikey-dependencies-readonly:
    python3 scripts/workstation/inspect-yubikey-dependencies-readonly.py

# Synthetic PostgreSQL-only recovery: tests and a non-mutating local image check.
# Requires NABLA_POSTGRES_FIXTURE_IMAGE_SHA256 to reference a cached local image.
yubikey-postgres-fixture-test:
    bash -n scripts/workstation/verify-postgres-fixture-recovery.sh
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_postgres_fixture_recovery.py' -v

# Isolated software-only age/SOPS roundtrip, never uses any real escrow,
# private identity, .sops.yaml or YubiKey; key generated in temp directory.
yubikey-software-recovery-test:
    python3 -m py_compile scripts/workstation/verify-yubikey-software-age-sops-fixture.py tests/test_yubikey_software_age_sops_fixture.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_software_age_sops_fixture.py' -v

# Tools presence only, no software crypto and no hardware.
yubikey-software-recovery-check:
    python3 scripts/workstation/verify-yubikey-software-age-sops-fixture.py --check

# Synthetic-only encrypted header parser contracts, no real secret or NFS.
yubikey-escrow-age-header-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-escrow-age-header.py tests/test_yubikey_escrow_age_header.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_age_header.py' -v

# Stat-only local source preflight. Does NOT read the ciphertext header.
yubikey-escrow-age-header-check:
    python3 scripts/workstation/inspect-yubikey-escrow-age-header.py --check

# Reads only the first 8192 bytes of the existing encrypted file. Does NOT
# decrypt, display recipient arguments, expose secrets, copy or write data.
yubikey-escrow-age-header-inspect:
    python3 scripts/workstation/inspect-yubikey-escrow-age-header.py --inspect --acknowledge INSPECT_EXISTING_ENCRYPTED_AGE_HEADER_ONLY

# Existing SanDisk LUKS2 escrow: identify UUID from redacted lsblk metadata.
# No USB unlock, age identity read, decryption, mount or mutation.
yubikey-escrow-usb-status:
    python3 scripts/workstation/diagnose-age-escrow-usb-presence.py --check

# Synthetic USB discovery contracts. No real USB, LUKS, age key or sudo used.
yubikey-escrow-usb-test:
    python3 -m py_compile scripts/workstation/diagnose-age-escrow-usb-presence.py tests/test_age_escrow_usb_presence.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_age_escrow_usb_presence.py' -v

# Original SanDisk MUST already be physically connected and LUKS unlocked.
# Only inspect metadata of expected recovery age identity on the known ext4.
yubikey-escrow-usb-identity-check:
    python3 scripts/workstation/inspect-age-escrow-usb-identity.py --check

# Synthetic-only metadata gate (never reads a real USB age identity).
yubikey-escrow-usb-identity-test:
    python3 -m py_compile scripts/workstation/inspect-age-escrow-usb-identity.py tests/test_age_escrow_usb_identity_metadata.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_age_escrow_usb_identity_metadata.py' -v

# Independent recovery of the original SanDisk's private age identity.
# CAUTION: --backup prompts interactively for an INDEPENDENT passphrase.
# Source USB must be physically connected, unlocked and mounted.
# No raw identity written locally or to TrueNAS, no overwrite.
yubikey-usb-identity-backup-test:
    python3 -m py_compile scripts/workstation/backup-usb-age-identity.py tests/test_usb_age_identity_independent_backup.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_age_identity_independent_backup.py' -v

# Read-only metadata and destination check. No key opened or written.
yubikey-usb-identity-backup-check:
    python3 scripts/workstation/backup-usb-age-identity.py --check

# EXPLICIT opt-in to write one age -p encrypted backup on workstation and TrueNAS.
# Requires a true interactive terminal. Never feed secrets via environment/argv.
yubikey-usb-identity-backup:
    python3 scripts/workstation/backup-usb-age-identity.py --backup --acknowledge CREATE_NEW_PASSPHRASE_ENCRYPTED_USB_IDENTITY_BACKUPS

# Hermetic checks of independent restoration; no USB, age or TrueNAS access.
yubikey-usb-identity-restore-test:
    python3 -m py_compile scripts/workstation/verify-usb-age-identity-independent-backup.py tests/test_usb_age_identity_independent_restore.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_age_identity_independent_restore.py' -v

# Post-backup read-only metadata gate. Original SanDisk is NOT required.
yubikey-usb-identity-restore-check:
    python3 scripts/workstation/verify-usb-age-identity-independent-backup.py --check

# Opt-in, interactive age decrypt twice in RAM; only public recipient compared.
# Run only AFTER backup, preferably with original SanDisk physically disconnected.
yubikey-usb-identity-restore-verify:
    python3 scripts/workstation/verify-usb-age-identity-independent-backup.py --verify --acknowledge VERIFY_BOTH_PASSPHRASE_ENCRYPTED_USB_IDENTITY_BACKUPS

# Synthetic-only 4-level NFS4 ACL inventory contracts; no real SSH or secrets.
yubikey-usb-identity-nfs4-acl-test:
    python3 -m py_compile scripts/workstation/inspect-usb-identity-backup-nfs4-acl.py tests/test_usb_identity_backup_nfs4_acl.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_identity_backup_nfs4_acl.py' -v

# Local metadata-only preflight on EXISTING workstation and NFS ciphertext.
# Does not use USB, read archive data or invoke SSH.
yubikey-usb-identity-nfs4-acl-check:
    python3 scripts/workstation/inspect-usb-identity-backup-nfs4-acl.py --check

# Explicit remote TrueNAS filesystem.getacl inventory via pinned SSH.
# Does not inspect raw ACE output locally or claim effective authorization.
yubikey-usb-identity-nfs4-acl-probe:
    python3 scripts/workstation/inspect-usb-identity-backup-nfs4-acl.py --probe --acknowledge INSPECT_NEW_USB_IDENTITY_BACKUP_NFS4_ACLS_READONLY

# Hermetic TrueNAS mode-boundary checks; no actual server or ciphertext access.
yubikey-usb-identity-server-modes-test:
    python3 -m py_compile scripts/workstation/inspect-usb-identity-backup-server-modes.py tests/test_usb_identity_backup_server_modes.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_identity_backup_server_modes.py' -v

# Metadata-only local readiness, no SSH and no original SanDisk.
yubikey-usb-identity-server-modes-check:
    python3 scripts/workstation/inspect-usb-identity-backup-server-modes.py --check

# Strict read-only SSH evidence of server 0700/0600 and owner consistency.
# No UID, GID, private paths, raw ACEs or ciphertext bytes printed.
yubikey-usb-identity-server-modes-probe:
    python3 scripts/workstation/inspect-usb-identity-backup-server-modes.py --probe --acknowledge INSPECT_USB_AGE_BACKUP_TRUENAS_MODES_READONLY

# Hermetic TrueNAS NFS export security mapping audit: no network, USB or secrets.
yubikey-usb-identity-nfs-export-test:
    python3 -m py_compile scripts/workstation/inspect-usb-age-backup-nfs-export.py tests/test_usb_age_backup_nfs_export.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_age_backup_nfs_export.py' -v

# Workstation metadata preflight only. Does not contact TrueNAS or read archives.
yubikey-usb-identity-nfs-export-check:
    python3 scripts/workstation/inspect-usb-age-backup-nfs-export.py --check

# TrueNAS sharing.nfs.query via fixed-host SSH, with redacted status only.
# Exit 0 attests inventory, NOT proof of effective NFS permissions.
yubikey-usb-identity-nfs-export-probe:
    python3 scripts/workstation/inspect-usb-age-backup-nfs-export.py --probe --acknowledge INSPECT_USB_AGE_NFS_EXPORT_MAPPING_READONLY

# Synthetic read-only NFS TCP/2049 client-count contracts; no remote access.
yubikey-usb-identity-nfs-consumers-test:
    python3 -m py_compile scripts/workstation/inspect-usb-age-nfs-consumers.py tests/test_usb_age_nfs_consumers.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_usb_age_nfs_consumers.py' -v

# Local metadata check only; no USB, SSH or ciphertext reads.
yubikey-usb-identity-nfs-consumers-check:
    python3 scripts/workstation/inspect-usb-age-nfs-consumers.py --check

# Explicit TrueNAS remote SSH read-only ss(8) TCP/2049 snapshot.
# Counts ALL NFS exports, NOT exact export consumers; never derive allowlist.
yubikey-usb-identity-nfs-consumers-probe:
    python3 scripts/workstation/inspect-usb-age-nfs-consumers.py --probe --acknowledge INSPECT_NFS_TCP_CLIENT_FOOTPRINT_READONLY

# Legacy existing LUKS UUID script, check-only mode; may display lsblk data.
# Prefer the redacted yubikey-escrow-usb-status recipe for routine triage.
yubikey-escrow-usb-legacy-check:
    bash scripts/workstation/manage-age-escrow-usb.sh --luks-uuid 3742c7b9-ccb7-4b5e-b1db-18bcf916c548 --check

# Private terminal prompts for two existing .age backups. Does not print paths,
# read data, decrypt, require USB, or assert physical independence.
yubikey-escrow-pair-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-escrow-pair-interactive.py tests/test_yubikey_escrow_pair_interactive.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_pair_interactive.py' -v

# No paths collected or files accessed.
yubikey-escrow-pair-check:
    python3 scripts/workstation/inspect-yubikey-escrow-pair-interactive.py --check

# Auto-discover matching *.age basenames only in known local source and
# mounted-backup directories. Read-only stat checks, no paths printed.
yubikey-escrow-pair-discover:
    python3 scripts/workstation/inspect-yubikey-escrow-pair-interactive.py --discover

# Report only directory availability, bounded age-file counts and whether the
# effective HOME matches the current account. No filenames or file contents.
yubikey-escrow-pair-diagnose:
    python3 scripts/workstation/inspect-yubikey-escrow-pair-interactive.py --diagnose

# Validate TrueNAS NFS visibility contracts without contacting workstation
# mounts, archive data, SSH services, or real credentials.
yubikey-escrow-nfs-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-escrow-nfs-server.py tests/test_yubikey_escrow_nfs_server.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_nfs_server.py' -v

# Inspect mount-source identity and local age basename metadata only.
# No remote network access.
yubikey-escrow-nfs-check:
    python3 scripts/workstation/inspect-yubikey-escrow-nfs-server.py --check

# Optional server-side read-only metadata query via existing SSH credentials;
# enforces known_hosts; no password prompt, key, age decryption or write.
yubikey-escrow-nfs-probe:
    python3 scripts/workstation/inspect-yubikey-escrow-nfs-server.py --probe --ssh-target albandrieu@172.17.0.24 --acknowledge INSPECT_NFS_SERVER_METADATA_ONLY

# Snapshot history check: 3 dataset-level roots, 32 snapshots per root per
# page, at most 1024 directory entries inventoried per root per probe.
# No archive content read, no write, no privileged ZFS command.
yubikey-escrow-history-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-escrow-nfs-history.py tests/test_yubikey_escrow_nfs_history.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_nfs_history.py' -v

# Local preflight only: no SSH, ZFS queries, age reads or hardware access.
yubikey-escrow-history-check:
    python3 scripts/workstation/inspect-yubikey-escrow-nfs-history.py --check

# Contracts only. Runs a simulated write on a temporary local directory,
# never real NFS, existing backup or YubiKey.
yubikey-escrow-copy-test:
    python3 -m py_compile scripts/workstation/create-yubikey-escrow-nfs-copy.py tests/test_yubikey_escrow_nfs_copy.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_nfs_copy.py' -v

# Metadata-only check; does not open archive contents or create files.
# No automatic "copy-run" recipe: writing requires a separately supervised
# explicit command documented in the recovery runbook.
yubikey-escrow-copy-check:
    python3 scripts/workstation/create-yubikey-escrow-nfs-copy.py --check

# Existing age escrow postcopy contracts only. Never touches the real files.
yubikey-escrow-postcopy-test:
    python3 -m py_compile scripts/workstation/verify-yubikey-escrow-nfs-postcopy.py tests/test_yubikey_escrow_nfs_postcopy.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_nfs_postcopy.py' -v

# Metadata-only gate: no encrypted data reads, no SSH, no writes.
yubikey-escrow-postcopy-check:
    python3 scripts/workstation/verify-yubikey-escrow-nfs-postcopy.py --check

# Explicitly rereads ciphertext and checks TrueNAS visibility via read-only
# SSH. Does not prove NFSv4 ACL or age/SOPS restoration.
yubikey-escrow-postcopy-verify:
    python3 scripts/workstation/verify-yubikey-escrow-nfs-postcopy.py --verify --acknowledge RECHECK_EXISTING_AGE_ESCROW_CIPHERTEXT_AND_TRUENAS

# TrueNAS native ACL metadata inspection, synthetic-only test.
yubikey-escrow-acl-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-escrow-truenas-acl.py tests/test_yubikey_escrow_truenas_acl.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_truenas_acl.py' -v

# Check expected NFS mount and unique encrypted source file; no SSH.
yubikey-escrow-acl-check:
    python3 scripts/workstation/inspect-yubikey-escrow-truenas-acl.py --check

# Read native ACL metadata via TrueNAS filesystem.getacl over trusted SSH.
# Never prints raw ACL, account identifiers or encrypted bytes.
yubikey-escrow-acl-probe:
    python3 scripts/workstation/inspect-yubikey-escrow-truenas-acl.py --probe --acknowledge INSPECT_EXISTING_TRUENAS_AGE_ESCROW_ACL_READONLY

# Explicit supervised read-only TrueNAS snapshot metadata inventory via SSH.
# Does NOT use sudo/zfs CLI, restore, copy, decrypt, or export private names.
yubikey-escrow-history-probe:
    python3 scripts/workstation/inspect-yubikey-escrow-nfs-history.py --probe --acknowledge INSPECT_AGE_ESCROW_ZFS_HISTORY_ONLY

# Continue to the next bounded window, e.g.:
# just yubikey-escrow-history-page 1
# Page 0..31, lexicographic snapshot-name order (not chronological).
yubikey-escrow-history-page page:
    python3 scripts/workstation/inspect-yubikey-escrow-nfs-history.py --probe --page {{page}} --acknowledge INSPECT_AGE_ESCROW_ZFS_HISTORY_ONLY

# Synthetic contracts only, never touch real backups or YubiKeys.
yubikey-escrow-compare-test:
    python3 -m py_compile scripts/workstation/compare-yubikey-escrow-pair-readonly.py tests/test_yubikey_escrow_pair_compare.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_escrow_pair_compare.py' -v

# No backup read, no device probe.
yubikey-escrow-compare-check:
    python3 scripts/workstation/compare-yubikey-escrow-pair-readonly.py --check

# Explicitly READ two existing encrypted backups, compare byte-for-byte,
# never print contents or digests, never decrypt or change anything.
yubikey-escrow-compare-run:
    python3 scripts/workstation/compare-yubikey-escrow-pair-readonly.py --compare --acknowledge COMPARE_EXISTING_ENCRYPTED_ESCROWS

# Optional: manual pairing with two hidden TTY prompts when automatic
# discovery misses. Same metadata gate, no decrypted content or writes.
yubikey-escrow-compare-manual:
    python3 scripts/workstation/compare-yubikey-escrow-pair-readonly.py --compare-manual --acknowledge COMPARE_EXISTING_ENCRYPTED_ESCROWS

# Explicitly request private local paths via hidden interactive TTY prompts.
# Never reads content or proves decryption. Returns NO-GO even on success.
yubikey-escrow-pair-inspect:
    python3 scripts/workstation/inspect-yubikey-escrow-pair-interactive.py --inspect --acknowledge INSPECT_EXISTING_ESCROW_METADATA

# Explicit synthetic test with disposable age key and JSON only.
yubikey-software-recovery-run:
    python3 scripts/workstation/verify-yubikey-software-age-sops-fixture.py --run --acknowledge SYNTHETIC_SOFTWARE_ONLY

yubikey-postgres-fixture-check:
    bash scripts/workstation/verify-postgres-fixture-recovery.sh --check

# Opt-in: ephemeral container, no network, no ports, no production backup.
yubikey-postgres-fixture-run:
    bash scripts/workstation/verify-postgres-fixture-recovery.sh --run --acknowledge SYNTHETIC_ONLY

# Five YubiKey backup workstreams prepared in parallel; NO configuration writes.
yubikey-backup-five-test:
    python3 -m py_compile scripts/workstation/prepare-yubikey-backup-five.py tests/test_yubikey_backup_five_workstreams.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_backup_five_workstreams.py' -v

yubikey-backup-five-readonly:
    python3 scripts/workstation/prepare-yubikey-backup-five.py

# A single 11110002 must be connected; hardware metadata only, after host checks.
yubikey-backup-five-secondary-readonly:
    python3 scripts/workstation/prepare-yubikey-backup-five.py --secondary-public-inventory

# SSH FIDO backup enrollment on workstation only. Never touches PIV, OTP2,
# existing SSH keys, authorized_keys, hosts or SOPS. Card serial checked first.
yubikey-backup-ssh-test:
    python3 -m py_compile scripts/workstation/enroll-yubikey-backup-ssh-fido2.py tests/test_yubikey_backup_ssh_fido2_enrollment.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_backup_ssh_fido2_enrollment.py' -v

yubikey-backup-ssh-check:
    python3 scripts/workstation/enroll-yubikey-backup-ssh-fido2.py --check

# Offline contracts for existing key only; never generate another SSH credential.
yubikey-backup-ssh-signature-test:
    python3 -m py_compile scripts/workstation/verify-yubikey-backup-ssh-fido2-signature.py tests/test_yubikey_backup_ssh_fido2_signature.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_backup_ssh_fido2_signature.py' -v

# Public key fingerprint/permissions only. No USB, no signing.
yubikey-backup-ssh-signature-check:
    python3 scripts/workstation/verify-yubikey-backup-ssh-fido2-signature.py --check

# Explicit local fixture sign + verify, supervised PIN/passphrase/touch.
# Does not authenticate to any server or change existing SSH keys.
yubikey-backup-ssh-signature-run:
    python3 scripts/workstation/verify-yubikey-backup-ssh-fido2-signature.py --sign --acknowledge SIGN_EXISTING_FIDO2_BACKUP_${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL}

# Explicit interactive hardware enrollment; no auto-retry or overwrites.
yubikey-backup-ssh-enroll:
    python3 scripts/workstation/enroll-yubikey-backup-ssh-fido2.py --enroll --acknowledge ENROLL_SSH_FIDO2_BACKUP_${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL}

# OpenPGP public transport only. --probe may auto-start scdaemon (opt-in).
yubikey-backup-openpgp-test:
    python3 -m py_compile scripts/workstation/probe-yubikey-backup-openpgp.py tests/test_yubikey_backup_openpgp_probe.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_backup_openpgp_probe.py' -v

yubikey-backup-openpgp-check:
    python3 scripts/workstation/probe-yubikey-backup-openpgp.py --check

# Single backup YubiKey and interactive TTY required, no PIN or private keys.
yubikey-backup-openpgp-probe:
    python3 scripts/workstation/probe-yubikey-backup-openpgp.py --probe --acknowledge QUERY_OPENPGP_BACKUP_${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL}

yubikey-parallel-host-readonly:
    python3 scripts/workstation/run-yubikey-parallel-readonly.py

# Public inventory only; a single secondary must be attached. Device access
# follows the parallel host gates and NEVER runs concurrently with another probe.
yubikey-parallel-secondary-readonly:
    python3 scripts/workstation/run-yubikey-parallel-readonly.py --secondary

# One-shot read-only snapshot. Never asks PIN, challenge, writes or decrypts.
yubikey-diagnostics-test:
    python3 -m py_compile scripts/workstation/diagnose-yubikey-readonly-batch.py tests/test_yubikey_readonly_batch.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_readonly_batch.py' -v

yubikey-diagnostics-host-readonly:
    python3 scripts/workstation/diagnose-yubikey-readonly-batch.py

yubikey-diagnostics-secondary-readonly:
    python3 scripts/workstation/diagnose-yubikey-readonly-batch.py --hardware --serial ${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL}

yubikey-diagnostics-primary-readonly:
    python3 scripts/workstation/diagnose-yubikey-readonly-batch.py --hardware --serial ${YUBIKEY_PRIMARY_SERIAL:?set YUBIKEY_PRIMARY_SERIAL}

# Public applet/PIV metadata only. Connect exactly one selected YubiKey.
# These observations NEVER authorize provisioning, PIN input, OTP challenge or reset.
yubikey-applications-secondary-readonly:
    python3 scripts/workstation/inspect-yubikey-applications-readonly.py --serial ${YUBIKEY_BACKUP_SERIAL:?set YUBIKEY_BACKUP_SERIAL}

yubikey-applications-primary-readonly:
    python3 scripts/workstation/inspect-yubikey-applications-readonly.py --serial ${YUBIKEY_PRIMARY_SERIAL:?set YUBIKEY_PRIMARY_SERIAL}

# Local tool and file-metadata readiness; never opens secrets or connects a token.
yubikey-workstation-readonly:
    python3 scripts/workstation/inspect-yubikey-workstation-readonly.py

yubikey-workstation-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-workstation-readonly.py tests/test_yubikey_workstation_readonly.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_workstation_readonly.py' -v

# No device required; hermetic allowlist, transport and metadata contracts.
yubikey-applications-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-applications-readonly.py tests/test_yubikey_applications_readonly.py
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_applications_readonly.py' -v

# Offline, no-hardware YubiKey recovery contracts (stdlib only).
yubikey-recovery-test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-recovery-readonly.py tests/test_yubikey_recovery_readonly.py tests/test_yubikey_pr274_readonly_runner.py
    bash -n scripts/workstation/run-age-yubikey-pr274-readonly.sh
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_recovery_readonly.py' -v
    env -u YUBIKEY_PRIMARY_SERIAL -u YUBIKEY_BACKUP_SERIAL python3 -m unittest discover -s tests -p 'test_yubikey_pr274_readonly_runner.py' -v
