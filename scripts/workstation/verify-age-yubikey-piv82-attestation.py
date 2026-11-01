#!/usr/bin/env python3
"""Verify public PIV82 attestation against an independently approved Yubico root.

Offline only: no device, PIV session, PIN, private key, shell or subprocess.
The --root-sha256 fingerprint MUST come from a separately authenticated source,
never be copied from the untrusted --root file merely to silence a failure.
"""
from __future__ import annotations

import os
import argparse
import datetime as dt
import hmac
from pathlib import Path
import re
import sys

POLICY_OID = "1.3.6.1.4.1.41482.3.8"
SERIAL_OID = "1.3.6.1.4.1.41482.3.7"
SLOT_82_SUBJECT = "YubiKey PIV Attestation 82"
KNOWN_SERIALS = {os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002"), os.environ.get("YUBIKEY_PRIMARY_SERIAL", "11110001")}


def validate(attestation_pem: bytes, f9_pem: bytes, root_pem: bytes,
             intermediate_pems: list[bytes], expected_spki_pem: bytes,
             *, serial: str, trusted_root_sha256: str) -> None:
    """Validate the entire provided chain, on-device policy and public-key binding."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

    if serial not in KNOWN_SERIALS:
        raise ValueError("Unknown hardware serial")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", trusted_root_sha256):
        raise ValueError("Root fingerprint must be an independently approved SHA-256 hex")
    # Yubico's current official intermediate PEM is a bundle: select the
    # necessary issuer chain, never silently ignore appended PEM certificates.
    cert_pattern = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")

    def parse_pem(blob: bytes, *, allow_bundle: bool):
        blocks = cert_pattern.findall(blob)
        if (not blocks or (not allow_bundle and len(blocks) != 1)
                or cert_pattern.sub(b"", blob).strip()):
            raise ValueError("Malformed PEM or unexpected certificate bundle")
        return [x509.load_pem_x509_certificate(b) for b in blocks]

    leaf = parse_pem(attestation_pem, allow_bundle=False)[0]
    f9 = parse_pem(f9_pem, allow_bundle=False)[0]
    root = parse_pem(root_pem, allow_bundle=False)[0]
    available = [c for blob in intermediate_pems for c in parse_pem(blob, allow_bundle=True)]
    if len(available) > 16:
        raise ValueError("Too many intermediate certificate candidates")
    chain = [leaf, f9]
    while chain[-1].issuer != root.subject:
        candidates = [c for c in available if c.subject == chain[-1].issuer]
        if len(candidates) != 1 or candidates[0] in chain:
            raise ValueError("Ambiguous or incomplete F9-to-trust-root issuer chain")
        chain.append(candidates[0])
    chain.append(root)
    approved = trusted_root_sha256.lower()
    actual_root = root.fingerprint(hashes.SHA256()).hex()
    if not hmac.compare_digest(actual_root, approved):
        raise ValueError("Root is not the independently approved trust anchor")
    now = dt.datetime.now(dt.timezone.utc)
    for index, cert in enumerate(chain):
        if index == 0:
            try:
                if cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca:
                    raise ValueError("PIV82 attestation unexpectedly asserts CA authority")
            except x509.ExtensionNotFound:
                pass
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError("Attestation chain contains expired or not-yet-valid certificate")
        if not isinstance(cert.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise ValueError("Unsupported attestation-chain signature digest")
        for extension in cert.extensions:
            if extension.critical and isinstance(extension.value, x509.UnrecognizedExtension):
                raise ValueError("Unknown critical attestation extension")
        if index == 1:
            try:
                usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not usage.digital_signature and not usage.key_cert_sign:
                    raise ValueError("F9 certificate prohibits attestation signing")
            except x509.ExtensionNotFound:
                pass
        if index > 1:
            # Slot F9 attestation signer is a hardware credential, not necessarily
            # a general CA (some firmware certs do not have CA:true).
            constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not constraints.ca:
                raise ValueError("Intermediate/root is not a CA")
            if constraints.path_length is not None:
                subordinate_ca_count = 0
                for subordinate in chain[1:index]:
                    if subordinate.subject == subordinate.issuer:
                        continue
                    try:
                        subordinate_ca_count += int(subordinate.extensions.get_extension_for_oid(
                            ExtensionOID.BASIC_CONSTRAINTS).value.ca)
                    except x509.ExtensionNotFound:
                        pass
                if subordinate_ca_count > constraints.path_length:
                    raise ValueError("Attestation CA path-length restriction violated")
            try:
                usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not usage.key_cert_sign:
                    raise ValueError("Attestation issuer cannot sign certificates")
            except x509.ExtensionNotFound:
                pass

    def verify_signed(cert, issuer):
        if cert.issuer != issuer.subject:
            raise ValueError("Attestation issuer/subject mismatch")
        public = issuer.public_key()
        if isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(cert.signature, cert.tbs_certificate_bytes,
                          ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public, rsa.RSAPublicKey):
            public.verify(cert.signature, cert.tbs_certificate_bytes,
                          padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            raise ValueError("Unsupported attestation issuer key type")

    for cert, issuer in zip(chain, chain[1:]):
        verify_signed(cert, issuer)
    if root.subject != root.issuer:
        raise ValueError("Trust anchor is not self-issued")
    verify_signed(root, root)
    actual_key = leaf.public_key()
    expected_key = serialization.load_pem_public_key(expected_spki_pem)
    if (not isinstance(actual_key, ec.EllipticCurvePublicKey)
            or not isinstance(expected_key, ec.EllipticCurvePublicKey)
            or not isinstance(actual_key.curve, ec.SECP256R1)
            or not isinstance(expected_key.curve, ec.SECP256R1)
            or actual_key.public_numbers() != expected_key.public_numbers()):
        raise ValueError("Attested SPKI is not the expected PIV82 EC P-256 key")
    common_names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != SLOT_82_SUBJECT:
        raise ValueError("Attestation is not for PIV slot 82")
    policy = leaf.extensions.get_extension_for_oid(ObjectIdentifier(POLICY_OID))
    if policy.critical or not isinstance(policy.value, x509.UnrecognizedExtension):
        raise ValueError("Malformed PIV82 PIN/touch extension")
    if policy.value.value != b"\x03\x02":
        raise ValueError("Attested policies are not PIN ALWAYS / TOUCH ALWAYS")
    serial_extension = leaf.extensions.get_extension_for_oid(ObjectIdentifier(SERIAL_OID))
    if (serial_extension.critical or not isinstance(serial_extension.value, x509.UnrecognizedExtension)
            or not 1 <= len(serial_extension.value.value) <= 8
            or int.from_bytes(serial_extension.value.value, "big") != int(serial)):
        raise ValueError("Attested hardware serial mismatch")


def read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular public PEM file, not a symlink")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Unreasonable public certificate input size")
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True, type=Path)
    parser.add_argument("--f9", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--intermediate", action="append", type=Path, default=[],
                        help="Zero or more issuer certificates in F9-to-root order")
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--serial", choices=sorted(KNOWN_SERIALS), required=True)
    parser.add_argument("--root-sha256", required=True,
                        help="Root fingerprint pinned independently of the PEM file")
    args = parser.parse_args()
    try:
        validate(read_regular(args.attestation), read_regular(args.f9),
                 read_regular(args.root), [read_regular(p) for p in args.intermediate],
                 read_regular(args.public_key), serial=args.serial,
                 trusted_root_sha256=args.root_sha256)
    except Exception as exc:
        # Deliberately never echo file contents, exception messages or secret-looking paths.
        print(f"NO-GO: PIV82 attestation rejected ({type(exc).__name__})", file=sys.stderr)
        return 3
    print("PASS: offline PIV82 attestation chain, approved root, serial, SPKI and 03:02 policies")
    print("NO-GO hardware: a valid PEM set is not an on-device live operation or age decrypt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
