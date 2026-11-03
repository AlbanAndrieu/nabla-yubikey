"""Hermetic assertions for non-destructive age/SOPS synthetic recovery."""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workstation/verify-yubikey-software-age-sops-fixture.py"
spec = importlib.util.spec_from_file_location("nabla_age_sops_synthetic", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
GOOD_TOOLS = {x: f"/opt/safe/{x}" for x in mod.TOOLS}
PUBLIC = "age1" + "q" * 58

class Contracts(unittest.TestCase):
    def test_check_is_read_only_and_does_not_execute_tools(self):
        with patch.object(mod, "tool_paths", return_value=GOOD_TOOLS), \
             patch.object(mod, "synthetic_roundtrip") as run:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(mod.main(["--check"]), 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["state"], "SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED")
            self.assertFalse(payload["real_escrow_restoration_verified"])
            run.assert_not_called()

    def test_run_requires_exact_authorization_before_work(self):
        with patch.object(mod, "synthetic_roundtrip") as run, \
             redirect_stderr(io.StringIO()):
            for args in (["--run"], ["--run", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", mod.ACK], ["--restore"], []):
                with self.subTest(args=args), self.assertRaises(SystemExit) as e:
                    mod.main(args)
                self.assertEqual(e.exception.code, 2)
            run.assert_not_called()

    def test_missing_tools_is_not_misreported_success(self):
        with patch.object(mod.shutil, "which", side_effect=lambda name: None if name == "sops" else "/usr/bin/" + name), \
             patch.object(mod, "synthetic_roundtrip") as run:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(mod.main(["--run", "--acknowledge", mod.ACK]), 3)
            self.assertEqual(json.loads(out.getvalue())["state"], "REQUIRED_SOFTWARE_TOOLS_NOT_FOUND")
            run.assert_not_called()

    def test_command_failure_and_output_remain_redacted(self):
        err = b"sensitive /home/person/.config/sops/age/keys.txt SECRET"
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", err)):
            self.assertIsNone(mod.run_command(["/usr/bin/age"], {}, Path("/tmp")))
        self.assertNotIn("SECRET", mod.run_command.__doc__)

    def test_age_recipient_rejects_invalid_or_oversized(self):
        for out in (b"", b"AGE-SECRET-KEY-1" + b"q" * 50, b"x" * 201, b"age1invalid\n"):
            with self.subTest(out=out[:10]), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, out, b"")):
                self.assertIsNone(mod.run_command(["/usr/bin/age-keygen"], {}, Path("/tmp"), recipient_output=True))
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, (PUBLIC + "\n").encode(), b"")):
            self.assertEqual(mod.run_command(["/usr/bin/age-keygen"], {}, Path("/tmp"), recipient_output=True), PUBLIC)

    def test_age_sops_roundtrip_uses_ephemeral_paths_only(self):
        events = []
        def fixture_runner(argv, *, env, cwd, stdin, stdout, stderr, timeout, check):
            events.append((argv, env, cwd))
            self.assertEqual(stdin, subprocess.DEVNULL)
            self.assertEqual(stderr, subprocess.DEVNULL)
            self.assertNotIn("SOPS_AGE_KEY", env)
            self.assertNotIn("AWS_PROFILE", env)
            self.assertEqual(env["HOME"], str(cwd))
            self.assertEqual(env["XDG_CONFIG_HOME"], str(cwd))
            self.assertNotIn("GNUPGHOME_ORIGINAL", env)
            if argv[0] == GOOD_TOOLS["age-keygen"] and "-o" in argv:
                key = Path(argv[-1]); key.write_text("AGE-SECRET-KEY synthetic\n"); key.chmod(0o600)
                return subprocess.CompletedProcess([], 0, b"", b"")
            if argv[0] == GOOD_TOOLS["age-keygen"]:
                return subprocess.CompletedProcess([], 0, (PUBLIC + "\n").encode(), b"")
            if argv[0] == GOOD_TOOLS["age"] and "-r" in argv:
                Path(argv[argv.index("-o")+1]).write_bytes(b"AGE ciphertext")
                return subprocess.CompletedProcess([], 0, b"", b"")
            if argv[0] == GOOD_TOOLS["age"] and "-d" in argv:
                Path(argv[argv.index("-o")+1]).write_bytes(Path(argv[-1].replace("fixture.age", "plain.json")).read_bytes())
                return subprocess.CompletedProcess([], 0, b"", b"")
            if argv[0] == GOOD_TOOLS["sops"] and "encrypt" in argv:
                Path(argv[argv.index("--output")+1]).write_text("fake encrypted")
                return subprocess.CompletedProcess([], 0, b"", b"")
            if argv[0] == GOOD_TOOLS["sops"] and "decrypt" in argv:
                Path(argv[argv.index("--output")+1]).write_text(json.dumps(mod.FIXTURE))
                return subprocess.CompletedProcess([], 0, b"", b"")
            raise AssertionError("Unexpected command")
        with patch.object(mod.subprocess, "run", side_effect=fixture_runner), \
             patch.dict(os.environ, {"AWS_PROFILE": "private", "SOPS_AGE_KEY": "secret", "GNUPGHOME_ORIGINAL": "private"}):
            self.assertEqual(mod.synthetic_roundtrip(GOOD_TOOLS), "AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS")
        self.assertEqual(len(events), 6)
        self.assertEqual([e[0][0] for e in events], [GOOD_TOOLS["age-keygen"], GOOD_TOOLS["age-keygen"], GOOD_TOOLS["age"], GOOD_TOOLS["age"], GOOD_TOOLS["sops"], GOOD_TOOLS["sops"]])
        self.assertFalse(Path(events[0][2]).exists())

    def test_mismatched_age_decrypt_stops_before_sops(self):
        events = []
        def runner(argv, **kwargs):
            events.append(argv)
            if len(events) == 1:
                key = Path(argv[-1]); key.write_text("secret"); key.chmod(0o600)
            if len(events) == 2:
                return subprocess.CompletedProcess([], 0, (PUBLIC + "\n").encode(), b"")
            if len(events) == 4:
                Path(argv[argv.index("-o")+1]).write_text("incorrect")
            return subprocess.CompletedProcess([], 0, b"", b"")
        with patch.object(mod.subprocess, "run", side_effect=runner):
            self.assertEqual(mod.synthetic_roundtrip(GOOD_TOOLS), "AGE_SYNTHETIC_ROUNDTRIP_MISMATCH")
        self.assertEqual(len(events), 4)

    def test_sops_json_mismatch_fails_closed(self):
        def fake(argv, **kwargs):
            if argv[0] == GOOD_TOOLS["age-keygen"] and "-o" in argv:
                key = Path(argv[-1]); key.write_text("secret"); key.chmod(0o600)
                return subprocess.CompletedProcess([], 0, b"", b"")
            if argv[0] == GOOD_TOOLS["age-keygen"]:
                return subprocess.CompletedProcess([], 0, (PUBLIC + "\n").encode(), b"")
            if argv[0] == GOOD_TOOLS["age"] and "-d" in argv:
                Path(argv[argv.index("-o")+1]).write_bytes(Path(kwargs["cwd"] / "plain.json").read_bytes())
            if argv[0] == GOOD_TOOLS["sops"] and "decrypt" in argv:
                Path(argv[argv.index("--output")+1]).write_text('{}')
            return subprocess.CompletedProcess([], 0, b"", b"")
        with patch.object(mod.subprocess, "run", side_effect=fake):
            self.assertEqual(mod.synthetic_roundtrip(GOOD_TOOLS), "SOPS_SYNTHETIC_ROUNDTRIP_MISMATCH")

    def test_report_cannot_claim_real_recovery(self):
        with patch.object(mod, "tool_paths", return_value=GOOD_TOOLS), \
             patch.object(mod, "synthetic_roundtrip", return_value="AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS"):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(mod.main(["--run", "--acknowledge", mod.ACK]), 0)
            result = json.loads(out.getvalue())
            self.assertTrue(result["synthetic_software_roundtrip_verified"])
            self.assertEqual(result["status"], "NO-GO")
            self.assertFalse(result["real_escrow_restoration_verified"])
            self.assertFalse(result["piv82_decrypt_verified"])
            self.assertFalse(result["hardware_mutation_authorized"])

if __name__ == '__main__':
    unittest.main()
