"""Pure offline phase-order and safety tests; no YubiKey or SDK required."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/workstation/plan-age-yubikey-piv82-transaction.py"
spec = importlib.util.spec_from_file_location("piv82_transaction_plan", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Piv82TransactionContract(unittest.TestCase):
    def test_secondary_order_and_explicit_per_phase_approvals(self):
        plan = module.build_plan(module.BACKUP)
        self.assertEqual(plan["status"], "NO-GO")
        self.assertEqual(plan["prerequisites"], [])
        phases = plan["phases"]
        self.assertEqual([phase["name"] for phase in phases], [
            "inventory", "authenticate", "generate", "attestation", "certificate",
            "install", "interoperability"
        ])
        for name in ("authenticate", "generate", "attestation", "certificate", "install"):
            phase = next(x for x in phases if x["name"] == name)
            self.assertTrue(any(g.startswith("explicit-approval-") for g in phase["required_evidence"]))

    def test_primary_requires_proven_secondary(self):
        plan = module.build_plan(module.PRIMARY)
        self.assertTrue(any("secondary interoperability PASS" in item
                            for item in plan["prerequisites"]))
        self.assertEqual(plan["phases"][-1]["name"], "interoperability")

    def test_unknown_serial_is_rejected(self):
        with self.assertRaises(ValueError):
            module.build_plan("00000000")

    def test_rules_guard_sops_and_escrow(self):
        plan = module.build_plan(module.BACKUP)
        rules = " ".join(plan["rules"]).lower()
        for word in ("no sops recipient change", "both physical cards",
                     "software escrow copies", "never auto-retry pin", "otp2", "piv9a"):
            self.assertIn(word, rules)

    def test_attestation_requires_trusted_chain_not_self_asserted_oid(self):
        phases = module.build_plan(module.BACKUP)["phases"]
        attest = next(phase for phase in phases if phase["name"] == "attestation")
        required = set(attest["required_evidence"])
        self.assertTrue({"trusted-yubico-root", "attested-spki-matches-piv82",
                         "attested-pin-touch-03-02"} <= required)
        self.assertLess([p["name"] for p in phases].index("attestation"),
                        [p["name"] for p in phases].index("certificate"))
        self.assertIn("only a claim", attest["hazard"])

    def test_aes_plugin_generation_is_blocked_and_hardware_remains_no_go(self):
        plan = module.build_plan(module.PRIMARY)
        self.assertEqual(plan["status"], "NO-GO")
        self.assertEqual(plan["compatibility"]["age_plugin_yubikey_version"], "0.5.1")
        self.assertIn("BLOCKED", plan["compatibility"]["aes_management_key_provisioning"])
        self.assertIn("age-plugin-yubikey --generate", " ".join(plan["rules"]))
        self.assertIn("Do not use a self-signed", " ".join(plan["rules"]))

    def test_attestation_verifier_accepts_only_public_offline_inputs(self):
        source = ROOT / "scripts/workstation/verify-age-yubikey-piv82-attestation.py"
        body = source.read_text()
        for expected in ("--root-sha256", "--public-key", "--serial", "--attestation", "--f9",
                         "hmac.compare_digest"):
            # The validator must require an approved trust anchor and key binding.
            self.assertIn(expected, body)
        for forbidden in ("import yubikit", "import ykman", "import smartcard",
                          "subprocess.run(", "os.system(", "getpass(", "piv reset"):
            self.assertNotIn(forbidden, body)
        compiled = subprocess.run([sys.executable, "-m", "py_compile", str(source)],
                                  capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)

    def test_attestation_adversarial_fixture_is_wired_to_gate(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-piv82-attestation-offline.py"
        gate = (ROOT / "scripts/workstation/verify-age-yubikey-offline.sh").read_text()
        self.assertIn("test-age-yubikey-piv82-attestation-offline.py", gate)
        self.assertIn("verify-age-yubikey-piv82-attestation.py", gate)
        body = script.read_text()
        for marker in ("missing intermediate", "wrong serial", "wrong issuer signature",
                       "bad policy", "untrusted root", "wrong public key"):
            self.assertIn(marker, body)
        self.assertNotIn("import yubikit", body)

    def test_machine_readable_output_is_no_go(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--serial", module.BACKUP,
                                 "--json"], capture_output=True, text=True, check=True)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["mode"], "read-only-plan-no-device-access")
        self.assertEqual(doc["status"], "NO-GO")
        self.assertEqual(len(doc["phases"]), 7)

    def test_no_apply_or_hardware_command(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--serial", module.BACKUP,
                                 "--apply"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        source = SCRIPT.read_text()
        for dangerous in ("import yubikit", "import ykman", "import smartcard",
                          "subprocess.run(", "os.system(", "getpass(", "piv.reset("):
            self.assertNotIn(dangerous, source)


if __name__ == "__main__":
    unittest.main()
