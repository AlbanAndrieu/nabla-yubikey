"""Fail-closed readiness tests: no PC/SC, PIN, network, or SOPS."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts/workstation/report-age-yubikey-piv82-readiness.py"
spec = importlib.util.spec_from_file_location("nabla_piv82_readiness", SRC)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class ReadinessContracts(TestCase):
    def test_missing_f9_fails_closed(self):
        class Fake:
            LEGACY_ROOT_SHA256 = "dummy"
            _read_public = staticmethod(lambda path: path.read_bytes())
            validate = staticmethod(lambda *args, **kwargs: None)
        with TemporaryDirectory() as tmp, patch.object(reporter, "verifier_module", return_value=Fake):
            result = reporter.readiness(Path(tmp) / "absent-f9", Path(tmp) / "absent-root")
        self.assertEqual(result["f9_trust"], "FAIL")
        self.assertFalse(result["hardware_mutation_authorized"])

    def test_trusted_f9_always_remains_no_go(self):
        class Fake:
            LEGACY_ROOT_SHA256 = "dummy"
            _read_public = staticmethod(lambda path: path.read_bytes())
            validate = staticmethod(lambda *args, **kwargs: None)
        with TemporaryDirectory() as tmp:
            f9, root = Path(tmp) / "f9", Path(tmp) / "root"
            f9.write_bytes(b"PUBLIC F9")
            root.write_bytes(b"PUBLIC ROOT")
            with patch.object(reporter, "verifier_module", return_value=Fake):
                result = reporter.readiness(f9, root)
        self.assertEqual(result["f9_trust"], "PASS")
        self.assertEqual(result["piv82"], "NOT_VERIFIED")
        self.assertEqual(result["age_decrypt"], "NOT_VERIFIED")
        self.assertEqual(result["status"], "NO-GO")
        self.assertFalse(result["hardware_mutation_authorized"])

    def test_invalid_signature_yields_no_go(self):
        class Fake:
            LEGACY_ROOT_SHA256 = "dummy"
            _read_public = staticmethod(lambda path: b"PUBLIC")
            @staticmethod
            def validate(*args, **kwargs):
                raise ValueError("invalid signature")
        with patch.object(reporter, "verifier_module", return_value=Fake):
            result = reporter.readiness(Path("x"), Path("y"))
        self.assertEqual(result["f9_trust"], "FAIL")
        self.assertFalse(result["hardware_mutation_authorized"])

    def test_script_has_no_hardware_or_secret_actions(self):
        source = SRC.read_text()
        for unsafe in ("ykman ", "verify_pin(", "PivSession(", "sops --", "--generate"):
            self.assertNotIn(unsafe, source)
        self.assertIn('"status": "NO-GO"', source)


if __name__ == "__main__":
    main()
