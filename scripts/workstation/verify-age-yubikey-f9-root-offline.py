#!/usr/bin/env python3
"""Verify a previously exported public F9 certificate against the legacy Yubico root.

No network, PIV/PCSC access, PIN, or writes. This does NOT attest an empty PIV82.
The fingerprint of F9 must come from the operator's earlier live, read-only run.
"""
from __future__ import annotations

import os
import argparse
import datetime as dt
import hmac
from pathlib import Path
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

LEGACY_ROOT_SHA256 = "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546"
LEGACY_ROOT_COMMON_NAME = "Yubico PIV Root CA Serial 263751"
EXPECTED_SECONDARY = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")


def _hex_fingerprint(value: str) -> str:
    digest = value.replace(":", "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("Expected a 64-hex-character SHA-256 certificate fingerprint")
    return digest


def _cert(pem: bytes) -> x509.Certificate:
    if len(pem) > 1024 * 1024 or not re.fullmatch(
        rb"\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*", pem
    ):
        raise ValueError("Expected exactly one PEM X.509 certificate")
    return x509.load_pem_x509_certificate(pem)


def validate(f9_pem: bytes, root_pem: bytes, *, observed_f9_sha256: str,
             trusted_root_sha256: str, firmware: str) -> None:
    """Validate a pinned public F9/root pair, not the actual live card identity."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", firmware):
        raise ValueError("Unrecognized firmware version")
    if tuple(map(int, firmware.split("."))) >= (5, 7, 4):
        raise ValueError("This verifier only supports legacy PIV roots before 5.7.4")
    root = _cert(root_pem)
    f9 = _cert(f9_pem)
    expected_root = _hex_fingerprint(trusted_root_sha256)
    expected_f9 = _hex_fingerprint(observed_f9_sha256)
    if not hmac.compare_digest(root.fingerprint(hashes.SHA256()).hex(), expected_root):
        raise ValueError("Trust anchor SHA-256 fingerprint differs from approved root")
    if not hmac.compare_digest(f9.fingerprint(hashes.SHA256()).hex(), expected_f9):
        raise ValueError("F9 SHA-256 fingerprint differs from live observation")
    cn = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != LEGACY_ROOT_COMMON_NAME:
        raise ValueError("Unexpected Yubico legacy root subject")
    if root.issuer != root.subject:
        raise ValueError("Legacy root is not self-issued")
    ca = root.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if not ca.ca:
        raise ValueError("Trust anchor does not permit certificate signing")
    try:
        ku = root.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.key_cert_sign:
            raise ValueError("Trust anchor key usage prohibits certificate signing")
    except x509.ExtensionNotFound:
        pass
    try:
        usage = f9.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not (usage.key_cert_sign or usage.digital_signature):
            raise ValueError("F9 certificate key usage prohibits attestation signing")
    except x509.ExtensionNotFound:
        pass
    now = dt.datetime.now(dt.timezone.utc)
    for cert in (root, f9):
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError("Root/F9 is expired or not yet valid")
        if not isinstance(cert.signature_hash_algorithm,
                          (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise ValueError("Disallowed signature digest")
        for ext in cert.extensions:
            if ext.critical and isinstance(ext.value, x509.UnrecognizedExtension):
                raise ValueError("Unknown critical X.509 extension")
    if f9.issuer != root.subject:
        raise ValueError("F9 certificate issuer does not match the legacy root")

    def verify(child: x509.Certificate, public) -> None:
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(child.signature, child.tbs_certificate_bytes,
                          padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(child.signature, child.tbs_certificate_bytes,
                          ec.ECDSA(child.signature_hash_algorithm))
        else:
            raise ValueError("Unsupported CA public-key algorithm")

    verify(root, root.public_key())
    verify(f9, root.public_key())


def _read_public(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Refusing symlink, non-regular or oversized public PEM")
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--f9", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--serial", choices=(EXPECTED_SECONDARY,), required=True)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--expected-f9-sha256", required=True,
                        help="Fingerprint from previously recorded live F9 inspection")
    args = parser.parse_args()
    try:
        validate(_read_public(args.f9), _read_public(args.root),
                 observed_f9_sha256=args.expected_f9_sha256,
                 trusted_root_sha256=LEGACY_ROOT_SHA256,
                 firmware=args.firmware)
    except Exception as error:
        print(f"NO-GO: legacy F9 trust verification rejected ({type(error).__name__})",
              file=sys.stderr)
        return 3
    print("PASS: F9 PEM fingerprint matches observation and validates to PINNED legacy Yubico root")
    print("NO-GO: this does not attest PIV82, prove a live card binding or validate age decrypt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
