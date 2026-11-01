#!/usr/bin/env python3
"""Exercise certificate verifier with valid and adversarial ephemeral fixtures.

No hardware, filesystem secrets, device API or private-key export.
"""
import datetime
import importlib.util
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

CHECKER = Path(__file__).with_name("verify-age-yubikey-piv82-certificate.py")
spec = importlib.util.spec_from_file_location("age_cert_checker", CHECKER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    key_pem = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    other_pem = other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "age-plugin-yubikey"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "0.5.1"),
        x509.NameAttribute(NameOID.COMMON_NAME, "nabla-age-backup"),
    ])

    def certificate(policy=b"\x03\x02", *, critical=False, issuer=None,
                    signing_key=None, expired=False, organization=None):
        name = subject
        if organization is not None:
            name = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "0.5.1"),
            ])
        start = now - datetime.timedelta(days=10)
        end = now - datetime.timedelta(days=1) if expired else now + datetime.timedelta(days=1)
        builder = (x509.CertificateBuilder()
                   .subject_name(name)
                   .issuer_name(issuer or name)
                   .public_key(signer.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(start)
                   .not_valid_after(end)
                   .add_extension(x509.UnrecognizedExtension(
                       ObjectIdentifier(module.OID), policy), critical=critical))
        return builder.sign(signing_key or signer, hashes.SHA256()).public_bytes(
            serialization.Encoding.PEM
        )

    module.validate(certificate(), key_pem)
    rejected = 0
    for label, cert, pub in [
        ("wrong public key", certificate(), other_pem),
        ("wrong PIN/touch", certificate(b"\x02\x02"), key_pem),
        ("critical policy", certificate(critical=True), key_pem),
        ("expired certificate", certificate(expired=True), key_pem),
        ("wrong organization", certificate(organization="wrong"), key_pem),
        ("wrong issuer", certificate(issuer=x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "unexpected")
        ])), key_pem),
        ("wrong signing private key", certificate(signing_key=other), key_pem),
    ]:
        try:
            module.validate(cert, pub)
        except Exception:
            rejected += 1
        else:
            raise AssertionError("Verifier accepted invalid case: " + label)
    print(f"PASS: valid certificate accepted; {rejected} malformed certificates rejected")
    print("NO-GO hardware: AES256 session and age decryption still not tested")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h"):
        print("Usage: python test-age-yubikey-certificate-negative-offline.py (no hardware)")
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit(2)
