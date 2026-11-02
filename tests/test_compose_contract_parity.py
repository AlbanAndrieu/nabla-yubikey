"""Hermetic AST-only parity contract: no imports, subprocesses or hardware access."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/ops/compare-compose-contracts.py"
spec = importlib.util.spec_from_file_location("compare_compose_contracts", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

FIELDS = ("status", "mode", "hardware_mutation_authorized", "ssh_agent")


def script(fields=FIELDS, extra=""):
    mapping = ", ".join(f"{key!r}: None" for key in fields)
    return f"def snapshot():\n    return {{{mapping}}}\n{extra}"


class Sibling:
    def __init__(self, content: str):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.target = self.root / module.SCRIPT
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text(content, encoding="utf-8")

    def close(self):
        self.folder.cleanup()


class ComposeSchemaContracts(unittest.TestCase):
    def test_identical_fields_do_not_claim_runtime_parity(self):
        old = Sibling(script())
        new = Sibling(script(extra="# refactored implementation\n"))
        try:
            with patch("subprocess.run") as run:
                result = module.compare(old.root, new.root)
            run.assert_not_called()
            self.assertEqual(result["status"], "SCHEMA_MATCH")
            self.assertTrue(result["fields_match"])
            self.assertFalse(result["source_identical"])
            self.assertFalse(result["runtime_parity_verified"])
            self.assertFalse(result["hardware_mutation_authorized"])
            self.assertEqual(result["source_path"], module.SCRIPT.as_posix())
            self.assertNotIn(str(old.root), json.dumps(result))
            self.assertNotIn(str(new.root), json.dumps(result))
        finally:
            old.close()
            new.close()

    def test_missing_or_extra_field_is_visible_without_exposing_values(self):
        old = Sibling(script())
        new = Sibling(script(("status", "mode", "hardware_mutation_authorized", "new_flag")))
        try:
            report = module.compare(old.root, new.root)
            self.assertEqual(report["status"], "NO-GO")
            self.assertEqual(report["missing_fields"], ["ssh_agent"])
            self.assertEqual(report["extra_fields"], ["new_flag"])
            self.assertIn("SNAPSHOT_FIELDS_DIFFER", report["blocking"])
        finally:
            old.close()
            new.close()

    def test_missing_required_key_is_always_no_go(self):
        old = Sibling(script(("mode", "ssh_agent")))
        new = Sibling(script(("mode", "ssh_agent")))
        try:
            report = module.compare(old.root, new.root)
            self.assertEqual(report["status"], "NO-GO")
            self.assertIn("REQUIRED_FIELD_MISSING", report["blocking"])
        finally:
            old.close()
            new.close()

    def test_unavailable_symlink_and_dynamic_snapshots_fail_closed(self):
        old = Sibling(script())
        new = Sibling(script())
        try:
            new.target.unlink()
            new.target.symlink_to(old.target)
            report = module.compare(old.root, new.root)
            self.assertEqual(report["status"], "NO-GO")
            self.assertEqual(report["yubikey_source"], "UNAVAILABLE")
            new.target.unlink()
            new.target.write_text("def snapshot():\n    return dict(status='GO')\n")
            self.assertEqual(module.compare(old.root, new.root)["status"], "NO-GO")
        finally:
            old.close()
            new.close()

    def test_cli_status_and_assertion_are_separate(self):
        old = Sibling(script())
        try:
            with patch.object(module, "ROOT", old.root):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = module.main(["--compose-root", str(old.root), "--assert-field-parity"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "SCHEMA_MATCH")
            old.target.unlink()
            with patch.object(module, "ROOT", old.root):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = module.main(["--compose-root", str(old.root), "--assert-field-parity"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out.getvalue())["status"], "NO-GO")
        finally:
            old.close()


if __name__ == "__main__":
    unittest.main()
