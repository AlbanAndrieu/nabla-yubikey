#!/usr/bin/env python3
"""Read-only PIV82 operator checklist; never touches a reader or records secrets.

This plan is not proof of any gate, and offers no --apply or resume mechanism.
Individual phases require a fresh operator decision and independent evidence.
"""
from __future__ import annotations

import os
import argparse
import json
from dataclasses import asdict, dataclass

BACKUP = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
PRIMARY = os.environ.get("YUBIKEY_PRIMARY_SERIAL", "11110001")


@dataclass(frozen=True)
class Phase:
    name: str
    required_evidence: tuple[str, ...]
    acceptance: str
    hazard: str


PHASES: tuple[Phase, ...] = (
    Phase(
        "inventory",
        ("exactly-one-serial", "piv82-empty", "piv9a-present",
         "aes256-pin-protected", "otp2-baseline"),
        "Archive redacted read-only inventory; abort if state has changed.",
        "Do not mistake a CLI error for proof of an empty slot.",
    ),
    Phase(
        "authenticate",
        ("explicit-approval-auth", "fresh-pin-attempts-ge-3",
         "protected-pivman-mode", "no-derived-key"),
        "Confirm AES256 authentication only in a supervised session; record a yes/no outcome.",
        "SDK 5.8.0 protected-key path can verify PIN twice; do not auto-retry after failure.",
    ),
    Phase(
        "generate",
        ("explicit-approval-generate", "fresh-inventory", "piv82-empty",
         "aes256-auth-pass", "pin-always", "touch-always"),
        "Generate P-256 non-exportable key in 0x82 only; retain SPKI and public metadata.",
        "Irreversible slot occupancy; never reset PIV or affect PIV9A/OTP2.",
    ),
    Phase(
        "attestation",
        ("explicit-approval-attest", "fresh-piv82-public-spki",
         "f9-attestation-chain-verifiable", "trusted-yubico-root",
         "attested-spki-matches-piv82", "attested-pin-touch-03-02"),
        "Verify F9-issued PIV82 attestation and trust chain independently, including SPKI and on-device policies.",
        "A self-signed age certificate with extension 03:02 is only a claim; F9 may be replaced.",
    ),
    Phase(
        "certificate",
        ("explicit-approval-sign", "piv82-public-spki", "on-card-signature",
         "subject-age-plugin-yubikey", "policy-oid-03-02",
         "independent-x509-verifier-pass"),
        "Sign with the PIV82 key, then validate X.509 against independently read SPKI.",
        "Software-signed certificate does not prove possession of the PIV82 private key.",
    ),
    Phase(
        "install",
        ("explicit-approval-import", "cert-signature-valid",
         "slot82-readback-matches", "piv9a-unchanged"),
        "Import certificate to 0x82; read back and compare DER/SPKI and baseline 9A.",
        "Certificate import failure leaves a populated key; stop rather than regenerating.",
    ),
    Phase(
        "interoperability",
        ("plugin-identity-visible", "recipient-derived", "synthetic-age-roundtrip",
         "otp2-unchanged", "piv9a-unchanged"),
        "Confirm plugin recipient/identity and decrypt disposable ciphertext on this card.",
        "An X.509-valid certificate alone is not proof that age decrypt works.",
    ),
)


def build_plan(serial: str) -> dict:
    if serial not in (BACKUP, PRIMARY):
        raise ValueError("Unknown YubiKey serial")
    prerequisites = (
        [f"independent secondary interoperability PASS (serial {BACKUP})"]
        if serial == PRIMARY else []
    )
    return {
        "status": "NO-GO",
        "mode": "read-only-plan-no-device-access",
        "serial": serial,
        "order": "secondary-then-primary",
        "prerequisites": prerequisites,
        "rules": [
            "Each phase requires its own explicit approval; no blanket authorization.",
            "Stop immediately on any missing evidence, error or PIN failure.",
            "Never auto-retry PIN, regenerate a populated slot or reset PIV.",
            "Never invoke age-plugin-yubikey --generate or interactive setup: v0.5.1 lacks AES management-key support.",
            "Do not use a self-signed age certificate policy OID as proof of hardware policies.",
            "Never read, print, persist or commit PIN/PUK/management/private keys.",
            "Preserve OTP2, PIV9A, AES256 management key, software SOPS recipients.",
            "No SOPS recipient change before BOTH physical cards pass a real age roundtrip.",
            "Complete two independently recoverable software escrow copies first.",
        ],
        "phases": [asdict(phase) for phase in PHASES],
        "compatibility": {
            "age_plugin_yubikey_version": "0.5.1",
            "aes_management_key_provisioning": "BLOCKED; use reviewed external Yubico SDK path only",
            "list_all": "read-only discovery only after on-card validation",
            "attestation": "independent Yubico/F9 trust-chain evidence required; never trust policy OID alone",
            "attestation_verifier": "scripts/workstation/verify-age-yubikey-piv82-attestation.py",
            "root_fingerprint": "must be independently approved; never derive trust from supplied PEM",
        },
        "completion": "Hardware provisioning requires separate operator authorization; planning is never GO.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, choices=(BACKUP, PRIMARY))
    parser.add_argument("--json", action="store_true", help="Print public checklist as JSON")
    args = parser.parse_args()
    plan = build_plan(args.serial)
    if args.json:
        print(json.dumps(plan, indent=2, ensure_ascii=False))
    else:
        print(f"NO-GO — PIV82 transaction plan for {args.serial} (no hardware access)")
        for prerequisite in plan["prerequisites"]:
            print(f"PREREQUISITE: {prerequisite}")
        for index, phase in enumerate(PHASES, 1):
            print(f"\n{index}. {phase.name}: {phase.acceptance}")
            print("   Required evidence: " + ", ".join(phase.required_evidence))
            print("   STOP condition: " + phase.hazard)
        print("\nNo stage is authorized or executed by this plan; SOPS remains unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
