"""Offline synthetic F9/root-chain contracts; no YubiKey or network access."""
import datetime as dt
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = Path(__file__).with_name("verify-age-yubikey-f9-root-offline.py")
spec = importlib.util.spec_from_file_location("f9_root_verifier", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def mkcert(subject, issuer, pub, signer, *, ca, key_sign=True, expire=False):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(pub).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=2))
               .not_valid_after(now - dt.timedelta(days=1) if expire else now + dt.timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False, key_cert_sign=key_sign,
                   crl_sign=False, encipher_only=False, decipher_only=False), critical=True))
    return builder.sign(signer, hashes.SHA256())


class F9RootOfflineContract(unittest.TestCase):
    def setUp(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.f9_key = ec.generate_private_key(ec.SECP256R1())
        name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        self.root_name = name(module.LEGACY_ROOT_COMMON_NAME)
        self.f9_name = name("synthetic F9 signer")
        self.root = mkcert(self.root_name, self.root_name, self.root_key.public_key(),
                           self.root_key, ca=True)
        self.f9 = mkcert(self.f9_name, self.root_name, self.f9_key.public_key(),
                         self.root_key, ca=False)

    def pem(self, cert):
        return cert.public_bytes(serialization.Encoding.PEM)

    def verify(self, root=None, f9=None, root_pin=None, f9_pin=None, firmware="5.4.3"):
        root, f9 = root or self.root, f9 or self.f9
        return module.validate(self.pem(f9), self.pem(root),
                               observed_f9_sha256=f9_pin or self.f9.fingerprint(hashes.SHA256()).hex(),
                               trusted_root_sha256=root_pin or self.root.fingerprint(hashes.SHA256()).hex(),
                               firmware=firmware)

    def test_positive_legacy_synthetic_root(self):
        self.verify()

    def test_f9_fingerprint_mismatch(self):
        with self.assertRaisesRegex(ValueError, "F9 SHA-256 fingerprint"):
            self.verify(f9_pin="00" * 32)

    def test_legacy_root_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "Trust anchor SHA-256"):
            self.verify(root_pin="00" * 32)

    def test_unsupported_new_firmware(self):
        with self.assertRaisesRegex(ValueError, "before 5.7.4"):
            self.verify(firmware="5.7.4")

    def test_unrecognized_firmware(self):
        with self.assertRaisesRegex(ValueError, "Unrecognized firmware"):
            self.verify(firmware="unknown")

    def test_forged_f9_with_matching_issuer_is_rejected(self):
        attacker = ec.generate_private_key(ec.SECP256R1())
        forged = mkcert(self.f9_name, self.root_name, self.f9_key.public_key(), attacker, ca=False)
        with self.assertRaises(Exception):
            self.verify(f9=forged, f9_pin=forged.fingerprint(hashes.SHA256()).hex())

    def test_other_issuer_rejected(self):
        other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted")])
        leaf = mkcert(self.f9_name, other, self.f9_key.public_key(), self.root_key, ca=False)
        with self.assertRaisesRegex(ValueError, "issuer does not match"):
            self.verify(f9=leaf, f9_pin=leaf.fingerprint(hashes.SHA256()).hex())

    def test_expired_f9_rejected(self):
        leaf = mkcert(self.f9_name, self.root_name, self.f9_key.public_key(),
                      self.root_key, ca=False, expire=True)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.verify(f9=leaf, f9_pin=leaf.fingerprint(hashes.SHA256()).hex())

    def test_root_not_ca_rejected(self):
        root = mkcert(self.root_name, self.root_name, self.root_key.public_key(),
                      self.root_key, ca=False)
        with self.assertRaisesRegex(ValueError, "does not permit"):
            self.verify(root=root, root_pin=root.fingerprint(hashes.SHA256()).hex())

    def test_unexpected_root_subject_rejected(self):
        badname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker CA")])
        root = mkcert(badname, badname, self.root_key.public_key(), self.root_key, ca=True)
        with self.assertRaisesRegex(ValueError, "Unexpected Yubico"):
            self.verify(root=root, root_pin=root.fingerprint(hashes.SHA256()).hex())

    def test_incorrect_fingerprint_format_rejected(self):
        with self.assertRaisesRegex(ValueError, "64-hex"):
            self.verify(f9_pin="not-a-digest")

    def test_pem_bundle_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one PEM"):
            module.validate(self.pem(self.f9) + self.pem(self.root), self.pem(self.root),
                            observed_f9_sha256=self.f9.fingerprint(hashes.SHA256()).hex(),
                            trusted_root_sha256=self.root.fingerprint(hashes.SHA256()).hex(),
                            firmware="5.4.3")

    def test_cli_cannot_override_legacy_root_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            f9 = Path(directory) / "f9.pem"
            root = Path(directory) / "root.pem"
            f9.write_bytes(self.pem(self.f9))
            root.write_bytes(self.pem(self.root))
            args = [sys.executable, str(SCRIPT), "--f9", str(f9), "--root", str(root),
                    "--serial", module.EXPECTED_SECONDARY, "--firmware", "5.4.3",
                    "--expected-f9-sha256", self.f9.fingerprint(hashes.SHA256()).hex()]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertIn("NO-GO", result.stderr)
            arbitrary_pin = subprocess.run(args + ["--root-sha256", self.root.fingerprint(hashes.SHA256()).hex()],
                                           capture_output=True, text=True)
            self.assertNotEqual(arbitrary_pin.returncode, 0)


if __name__ == "__main__":
    unittest.main()
