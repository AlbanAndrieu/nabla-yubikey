#!/usr/bin/env python3
"""Offline contract for Yubico's REAL sign_certificate_builder, using a fake PIV session.

No PC/SC device is opened. All keys exist in RAM; nothing is written to disk.
This is NOT a hardware enrolment utility.
"""
from __future__ import annotations

import datetime
from pathlib import Path
import runpy
import sys


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"--help", "-h"}:
        print("Usage: python test-age-yubikey-piv-signing-sdk-offline.py (mock session, no hardware)")
        return 0
    if len(sys.argv) != 1:
        print("Unexpected arguments", file=sys.stderr)
        return 2

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier
    from ykman.piv import sign_certificate_builder
    from yubikit.piv import KEY_TYPE, SLOT

    policy_oid = ObjectIdentifier("1.3.6.1.4.1.41482.3.8")
    policy_bytes = bytes((3, 2))
    key = ec.generate_private_key(ec.SECP256R1())

    class InMemoryPivSession:
        """Substitute only the sign operation; the SDK builds certificate DER."""

        def sign(self, slot, key_type, data, hash_algorithm, padding):
            if slot != SLOT.RETIRED1 or key_type != KEY_TYPE.ECCP256:
                raise ValueError("Unexpected PIV signing slot or algorithm")
            if not isinstance(hash_algorithm, hashes.SHA256):
                raise ValueError("Unexpected digest")
            return key.sign(data, ec.ECDSA(hash_algorithm))

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "age-plugin-yubikey"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "0.5.1"),
        x509.NameAttribute(NameOID.COMMON_NAME, "nabla-age-backup"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.UnrecognizedExtension(policy_oid, policy_bytes), critical=False)
    )
    cert = sign_certificate_builder(
        InMemoryPivSession(), SLOT.RETIRED1, KEY_TYPE.ECCP256, builder, hashes.SHA256
    )
    key.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    ext = cert.extensions.get_extension_for_oid(policy_oid)
    assert ext.critical is False and ext.value.value == policy_bytes
    assert cert.subject == cert.issuer == subject
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    # Cross-check the EXACT result returned by the Yubico SDK with the same
    # fail-closed validator intended for public PIV82 certificates.
    validate = runpy.run_path(
        str(Path(__file__).with_name("verify-age-yubikey-piv82-certificate.py"))
    )["validate"]
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    validate(cert_pem, public_pem)
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_public_pem = wrong_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        validate(cert_pem, wrong_public_pem)
    except ValueError:
        pass
    else:
        raise AssertionError("Verifier accepted a different public key")
    forged_cert = builder.sign(wrong_key, hashes.SHA256())
    try:
        validate(forged_cert.public_bytes(serialization.Encoding.PEM), public_pem)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("Verifier accepted a signature from a different key")
    print("PASS: SDK-signed cert passed strict validator; mismatched SPKI and forged signature rejected")
    print("PASS: real Yubico certificate builder + mock PIV signature + P-256 verification + 03:02 extension")
    print("NO-GO: mock session does not validate AES256 card auth, PIV82 import or age decryption")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
