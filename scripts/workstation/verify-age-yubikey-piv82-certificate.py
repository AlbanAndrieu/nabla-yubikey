#!/usr/bin/env python3
"""Fail-closed, offline age-plugin-yubikey certificate verifier.

Only handles public PEM inputs, never opens PC/SC or accepts private keys.
Exit 0 means certificate format valid, NOT authorization to write a YubiKey.
"""
import argparse
import datetime
from pathlib import Path
import sys

OID = "1.3.6.1.4.1.41482.3.8"


def validate(cert_pem: bytes, key_pem: bytes) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    cert = x509.load_pem_x509_certificate(cert_pem)
    public = serialization.load_pem_public_key(key_pem)
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
        public.curve, ec.SECP256R1
    ):
        raise ValueError("Expected an EC P-256 public key")
    actual = cert.public_key()
    if not isinstance(actual, ec.EllipticCurvePublicKey) or not isinstance(
        actual.curve, ec.SECP256R1
    ):
        raise ValueError("Certificate key must be P-256")
    if actual.public_numbers() != public.public_numbers():
        raise ValueError("Certificate SPKI does not match expected PIV82 public key")
    if cert.subject != cert.issuer:
        raise ValueError("Certificate is not self-issued")
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Certificate is not currently valid")
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if len(org) != 1 or org[0].value != "age-plugin-yubikey":
        raise ValueError("Subject organization does not match plugin convention")
    unit = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if len(unit) != 1 or unit[0].value != "0.5.1":
        raise ValueError("Unexpected age-plugin-yubikey version")
    ext = cert.extensions.get_extension_for_oid(ObjectIdentifier(OID))
    if ext.critical or not isinstance(ext.value, x509.UnrecognizedExtension):
        raise ValueError("Policy extension must be unrecognized and noncritical")
    if ext.value.value != bytes((3, 2)):
        raise ValueError("PIN/touch policy is not ALWAYS/ALWAYS")
    for extension in cert.extensions:
        if extension.critical and isinstance(extension.value, x509.UnrecognizedExtension):
            raise ValueError("Unknown critical extension")
    if cert.signature_algorithm_oid != x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
        raise ValueError("Expected ECDSA SHA-256 signature")
    public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline certificate check; no YubiKey access")
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path,
                        help="Expected PIV82 SPKI PEM from a separate read-only key export")
    args = parser.parse_args()
    try:
        for path in (args.certificate, args.public_key):
            if path.is_symlink() or not path.is_file():
                raise ValueError("Refusing symlink or nonregular input file")
        validate(args.certificate.read_bytes(), args.public_key.read_bytes())
    except Exception as exc:
        print(f"NO-GO certificate validation: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print("PASS: X.509 P-256, matching public key, ECDSA signature and PIN/touch 03:02")
    print("NO-GO hardware: AES256 authentication, slot binding and age decrypt unverified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
