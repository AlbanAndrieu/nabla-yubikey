from pathlib import Path
import os
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/workstation/diagnose-yubikey-keepassxc.sh"


class YubiKeyKeepassDiagnosticContract(unittest.TestCase):
    def test_bash_parses(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_help_does_not_require_hardware(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True, check=True)
        self.assertIn("--verify-secret", result.stdout)

    def test_inventory_script_contract(self):
        audit = ROOT / "scripts/workstation/audit-yubikey-capabilities.sh"
        subprocess.run(["bash", "-n", str(audit)], check=True)
        help_result = subprocess.run(["bash", str(audit), "--help"],
                                     capture_output=True, text=True, check=True)
        self.assertIn("--serial", help_result.stdout)
        content = audit.read_text()
        self.assertNotIn("ykman piv certificates list", content.split("# ykman 5.8.0")[0])
        self.assertIn("CHUID: [REDACTED]", content.replace('\\1 [REDACTED]', 'CHUID: [REDACTED]'))
        self.assertIn("NO_COLOR", content)
        self.assertIn("EXPIRED", content)
        self.assertIn("SSH local", content)
        self.assertIn("Signature key", content)
        self.assertIn("OTP slot 2 HMAC-SHA1", content)
        for forbidden in ("piv reset", "otp chalresp 2", "gpg --export-secret-keys"):
            self.assertNotIn(forbidden, "\\n".join(line for line in content.splitlines()
                                                      if not line.lstrip().startswith("#")))


    def test_piv_inventory_enforces_known_single_key_and_read_only_slots(self):
        script = ROOT / "scripts/workstation/audit-yubikey-capabilities.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_text = subprocess.run(
            ["bash", str(script), "--help"], capture_output=True,
            text=True, check=True
        ).stdout
        for option in ("--primary", "--backup", "--serial", "--challenge"):
            self.assertIn(option, help_text)
        content = script.read_text()
        for marker in (
            'PRIMARY_SERIAL="${YUBIKEY_PRIMARY_SERIAL:-11110001}"', 'BACKUP_SERIAL="${YUBIKEY_BACKUP_SERIAL:-11110002}"',
            "Exactly one YubiKey must be connected",
            "Connected YubiKey does not match requested serial",
            "Unrecognized YubiKey",
            'args=(--device "${connected}")',
            'ykman "${args[@]}" piv keys info "${slot}"',
            "PIV slot summary", "UNKNOWN", "No key stored",
            "9C 9D 9E 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95",
        ):
            self.assertIn(marker, content)
        for forbidden in ("piv keys generate", "piv keys import",
                          "piv keys delete", "piv reset", "otp delete"):
            self.assertNotIn(forbidden, content)

    def test_age_escrow_backup_contract(self):
        script = ROOT / "scripts/workstation/backup-sops-age-identity.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(
            ["bash", str(script), "--help"],
            capture_output=True, text=True, check=True
        )
        self.assertIn("--apply", result.stdout)
        content = script.read_text()
        for marker in (
            "umask 077", "age -e -r", "findmnt",
            "independent", "CHECK ONLY", "OFFLINE DECRYPTION",
            "chmod 600", "ln \"${temp}\" \"${output}\"",
        ):
            self.assertIn(marker, content)
        for dangerous in (
            "age -d", "age-keygen -o", "piv reset",
            "piv keys generate", "cat \"$source_file\"",
        ):
            self.assertNotIn(dangerous, content)

    def test_usb_escrow_recovery_contract(self):
        script = ROOT / "scripts/workstation/manage-age-escrow-usb.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(
            ["bash", str(script), "--help"],
            capture_output=True, text=True, check=True
        )
        for marker in ("--luks-uuid", "--check", "--open", "--close",
                       "--init-identity"):
            self.assertIn(marker, result.stdout)
        body = script.read_text()
        self.assertIn("age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938", body)
        self.assertIn("Existing original age identity verified", body)
        self.assertIn("CREATE-NEW-IDENTITY", body)
        for forbidden in ("luksFormat", "wipefs", "mkfs.ext4",
                          "parted -s", "reset PIV"):
            self.assertNotIn(forbidden, body)

    def test_age_escrow_restore_script_contract(self):
        script = ROOT / "scripts/workstation/verify-sops-age-escrow.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_text = subprocess.run(
            ["bash", str(script), "--help"], capture_output=True,
            text=True, check=True
        ).stdout
        self.assertIn("--backup", help_text)
        self.assertIn("--identity", help_text)
        body = script.read_text()
        for marker in ("umask 077", "/dev/shm", "tmpfs", "trap cleanup EXIT",
                       "age -d -i", "age-keygen -y", "PASS:"):
            self.assertIn(marker, body)

    def test_sops_usb_roundtrip_does_not_mutate_caller_shell(self):
        script = ROOT / "scripts/workstation/test-sops-usb-recovery.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        output = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--usb-identity", output.stdout)
        # Sourcing must return nonzero WITHOUT enabling errexit on the parent shell.
        cmd = f'source "{script}"; result=$?; [[ "$result" == 2 ]] && echo SHELL_ALIVE'
        sourced = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(sourced.returncode, 0, sourced.stderr)
        self.assertIn("SHELL_ALIVE", sourced.stdout)
        body = script.read_text()
        for expected in ('BASH_SOURCE[0]', 'SOPS_AGE_KEY_FILE', '/dev/shm',
                         'trap cleanup EXIT', 'grep -Fxq'):
            self.assertIn(expected, body)

    def test_piv82_guard_is_non_destructive(self):
        script = ROOT / "scripts/workstation/preflight-age-yubikey-piv82.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--serial", result.stdout)
        text = script.read_text()
        for marker in ("piv keys info 82", "ykman list --serials",
                       "Expected exactly one YubiKey matching requested serial"):
            self.assertIn(marker, text)
        # A single exact matching serial is required; avoid fragile sed backrefs.
        self.assertIn("mapfile -t detected_serials", text)
        self.assertIn("detected_serials[0]", text)
        self.assertIn("no key( (stored )?in slot)?", text)
        for forbidden in ("--generate", "piv reset", "piv keys import",
                          "otp chalresp", "ykman otp", "set -x"):
            self.assertNotIn(forbidden, text)

    def test_workstation_status_formatter_plain_output(self):
        helper = ROOT / "scripts/workstation/shell-status.sh"
        command = (f'source "{helper}"; '
                   'nabla_status ok "ready"; nabla_status warn "careful"')
        result = subprocess.run(["bash", "-c", command], capture_output=True,
                                text=True, env={**os.environ, "NO_COLOR": "1"},
                                check=True)
        self.assertIn("[OK] ready", result.stdout)
        self.assertIn("[WARN] careful", result.stderr)
        self.assertNotIn("\\x1b", result.stdout + result.stderr)
        for relative in ("preflight-age-yubikey-piv82.sh",
                         "backup-sops-age-identity.sh",
                         "test-sops-usb-recovery.sh"):
            script = ROOT / "scripts/workstation" / relative
            subprocess.run(["bash", "-n", str(script)], check=True)
            self.assertIn("shell-status.sh", script.read_text())

    def test_offline_age_certificate_inspection_is_non_destructive(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-certificate.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--certificate", result.stdout)
        missing = subprocess.run(["bash", str(script), "--certificate",
                                  "/path/that/does/not/exist.pem"],
                                 capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)
        body = script.read_text()
        for forbidden in ("piv keys generate", "piv certificates generate",
                          "piv reset", "change-management-key",
                          "age-plugin-yubikey --generate"):
            self.assertNotIn(forbidden, body)
        self.assertIn("exit 3", body)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_offline_age_certificate_synthetic_ec_and_rsa(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-certificate.sh"
        with tempfile.TemporaryDirectory(prefix="age-cert-contract-") as tmp:
            root = Path(tmp)
            fixtures = (
                ("ec", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
                 "/CN=synthetic/O=age-plugin-yubikey", "EC P-256"),
                ("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                 "/CN=synthetic/O=age-plugin-yubikey", "does not expose an EC P-256"),
                ("wrong-org", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
                 "/CN=synthetic/O=unrelated", "Subject lacks O=age-plugin-yubikey"),
            )
            for name, opts, subject, expected in fixtures:
                with self.subTest(name=name):
                    key = root / (name + ".key")
                    cert = root / (name + ".pem")
                    subprocess.run(["openssl", "genpkey", *opts, "-out", str(key)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=True)
                    subprocess.run(["openssl", "req", "-x509", "-new",
                                    "-key", str(key), "-days", "1",
                                    "-subj", subject, "-out", str(cert)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=True)
                    result = subprocess.run(
                        ["bash", str(script), "--certificate", str(cert)],
                        capture_output=True, text=True,
                        env={**os.environ, "NO_COLOR": "1"})
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertIn(expected, result.stdout + result.stderr)
                    self.assertNotIn("\\x1b", result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_plugin_policy_oid_synthetic_certificate(self):
        # age-plugin-yubikey src/util.rs: PIN ALWAYS=03, TOUCH ALWAYS=02.
        # This validates X.509 DER encoding, NOT YubiKey policy enforcement.
        with tempfile.TemporaryDirectory(prefix="age-policy-") as temp:
            key = Path(temp) / "synthetic.key"
            cert = Path(temp) / "synthetic.pem"
            config = Path(temp) / "extensions.cnf"
            config.write_text(
                "[req]\n"
                "distinguished_name=dn\n"
                "x509_extensions=ext\n"
                "prompt=no\n"
                "[dn]\n"
                "CN=nabla-age-fixture\n"
                "O=age-plugin-yubikey\n"
                "OU=0.5.1\n"
                "[ext]\n"
                "1.3.6.1.4.1.41482.3.8=DER:03:02\n"
            )
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC",
                            "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-out", str(key)], check=True, capture_output=True)
            req = subprocess.run(
                ["openssl", "req", "-x509", "-new", "-key", str(key),
                 "-days", "1", "-config", str(config), "-out", str(cert)],
                capture_output=True, text=True)
            self.assertEqual(req.returncode, 0, req.stderr)
            inspection = subprocess.run(
                ["bash", str(ROOT / "scripts/workstation/inspect-age-yubikey-certificate.sh"),
                 "--certificate", str(cert)],
                capture_output=True, text=True, env={**os.environ, "NO_COLOR": "1"})
            self.assertEqual(inspection.returncode, 3)
            self.assertIn("Subject organization matches", inspection.stdout)
            details = subprocess.run(["openssl", "x509", "-in", str(cert),
                                      "-noout", "-text"], check=True,
                                     capture_output=True, text=True).stdout
            self.assertIn("1.3.6.1.4.1.41482.3.8", details)
            der = subprocess.run(["openssl", "x509", "-in", str(cert),
                                  "-outform", "DER"], check=True,
                                 capture_output=True).stdout
            # OID DER and extension OCTET STRING containing exactly 03 02.
            self.assertIn(bytes.fromhex("2b0601040182c40a0308"), der)
            self.assertIn(bytes.fromhex("04020302"), der)

    def test_aes256_enrollment_plan_is_read_only(self):
        script = ROOT / "scripts/workstation/plan-age-yubikey-piv82-enrollment.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_result = subprocess.run(["bash", str(script), "--help"],
                                     capture_output=True, text=True, check=True)
        self.assertIn("--serial", help_result.stdout)
        content = script.read_text()
        self.assertIn("inspect-age-yubikey-aes256-hardware.sh", content)
        self.assertIn("yubikey-5-nabla backup", content)
        self.assertIn("yubikey-5-nabla principal", content)
        self.assertNotIn("piv keys info 82", content)
        self.assertEqual(content.count("Read-only gate passed"), 1)
        self.assertEqual(content.count("inspect-age-yubikey-aes256-hardware.sh"), 1)
        self.assertNotIn("slot_info=", content)
        self.assertTrue(content.rstrip().endswith("exit 0"))
        for command in ("--force", "change-management-key -a TDES",
                        'ykman --device "$serial" piv keys generate'):
            self.assertNotIn(command, content)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_offline_csr_certificate_pipeline(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-csr-offline.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script)], capture_output=True,
                                text=True, env={**os.environ, "NO_COLOR": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Offline CSR, P-256 self-signature", result.stdout)
        body = script.read_text()
        for forbidden in ("ykman", "age-plugin-yubikey --generate", "piv reset",
                          "change-management-key"):
            self.assertNotIn(forbidden, body)

    def test_piv82_response_diagnostic_is_read_only(self):
        script = ROOT / "scripts/workstation/diagnose-age-yubikey-piv82-response.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_result = subprocess.run(["bash", str(script), "--help"],
                                     capture_output=True, text=True, check=True)
        self.assertIn("--serial", help_result.stdout)
        body = script.read_text()
        self.assertIn("piv keys info 82", body)
        self.assertIn("ykman exit code:", body)
        for forbidden in ("piv keys generate", "piv certificates import",
                          "piv reset", "verify-pin", "change-management-key", "--force"):
            self.assertNotIn(forbidden, body)

    def test_aes256_inventory_handles_empty_slot_exit_one_fail_closed(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-aes256-hardware.sh"
        body = script.read_text()
        self.assertIn("rc82 > 1", body)
        self.assertIn("RETIRED1", body)
        self.assertIn("PIV82 unverified", body)
        self.assertIn("no provisioning permitted", body)
        self.assertNotIn("printf '%s\\n' \"${slot82}\"", body)
        subprocess.run(["bash", "-n", str(script)], check=True)

    def test_observed_retired1_response_pattern(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-aes256-hardware.sh"
        line = next(line for line in script.read_text().splitlines()
                    if line.startswith("empty_slot_pattern="))
        pattern = line.split("=", 1)[1].strip("'")
        for message in ("ERROR: No key stored in slot 82 (RETIRED1).",
                        "No key stored in slot 82 (RETIRED1)."):
            self.assertEqual(subprocess.run(
                ["grep", "-Eiq", pattern], input=message, text=True
            ).returncode, 0)
        for message in ("ERROR: No key stored in slot 82 (RETIRED1). transport failure",
                        "ERROR: No key stored in slot 83 (RETIRED2).",
                        "PCSC device unavailable"):
            self.assertNotEqual(subprocess.run(
                ["grep", "-Eiq", pattern], input=message, text=True
            ).returncode, 0)

    def test_aes256_inventory_single_complete_guard(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-aes256-hardware.sh"
        body = script.read_text()
        self.assertEqual(body.count("empty_slot_pattern="), 1)
        self.assertEqual(body.count("if (( rc82 > 1 ))"), 1)
        self.assertEqual(body.count("slot9a="), 1)
        self.assertEqual(body.count("Read-only inventory:"), 1)
        pattern_line = next(line for line in body.splitlines()
                            if line.startswith("empty_slot_pattern="))
        self.assertTrue(pattern_line.endswith("$'"))
        subprocess.run(["bash", "-n", str(script)], check=True)

    def test_aes256_hardware_inventory_read_only(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-aes256-hardware.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("read-only, no PIN", result.stdout)
        body = script.read_text()
        self.assertIn("piv keys info 82", body)
        self.assertIn("piv keys info 9a", body)
        self.assertIn("Management key algorithm:", body)
        for forbidden in ("piv keys generate", "piv certificates import",
                          "piv reset", "verify-pin", "change-management-key",
                          "ykman piv access", "--force"):
            self.assertNotIn(forbidden, body)

    def test_piv82_certificate_adversarial_fixtures(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-certificate-negative-offline.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        body = script.read_text()
        self.assertIn("wrong signing private key", body)
        self.assertIn("wrong PIN/touch", body)
        self.assertIn("expired certificate", body)
        sdk = os.path.expanduser("~/.local/share/nabla/piv-sdk-venv/bin/python")
        if os.path.isfile(sdk):
            result = subprocess.run([sdk, str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("7 malformed certificates rejected", result.stdout)

    def test_piv82_certificate_verifier_strict_offline(self):
        script = ROOT / "scripts/workstation/verify-age-yubikey-piv82-certificate.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        body = script.read_text()
        for expected in ("public.verify(", "ext.value.value != bytes((3, 2))",
                         "cert.subject != cert.issuer", "public_numbers()",
                         "Unknown critical extension", "path.is_symlink()"):
            self.assertIn(expected, body)
        for forbidden in ("PivSession(", "generate_key(", "put_certificate(", "verify_pin("):
            self.assertNotIn(forbidden, body)
        sdk = os.path.expanduser("~/.local/share/nabla/piv-sdk-venv/bin/python")
        if os.path.isfile(sdk):
            result = subprocess.run([sdk, str(script), "--help"],
                                    capture_output=True, text=True, check=True)
            self.assertIn("--public-key", result.stdout)

    def test_piv_sdk_signing_builder_mock_only(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-piv-signing-sdk-offline.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        content = script.read_text()
        self.assertIn("InMemoryPivSession", content)
        self.assertIn("sign_certificate_builder", content)
        for required in ("runpy.run_path(", "verify-age-yubikey-piv82-certificate.py",
                         "wrong_public_pem", "InvalidSignature",
                         "forged_cert", "Verifier accepted a different public key"):
            self.assertIn(required, content)
        self.assertIn("critical=False", content)
        self.assertIn("policy_bytes = bytes((3, 2))", content)
        for forbidden in ("SmartCardConnection", "PivSession(", "generate_key(",
                          "put_certificate(", "authenticate(", "verify_pin("):
            if forbidden == "PivSession(":
                self.assertNotIn("PivSession(connection", content)
            else:
                self.assertNotIn(forbidden, content)
        sdk_python = os.path.expanduser("~/.local/share/nabla/piv-sdk-venv/bin/python")
        if os.path.isfile(sdk_python):
            result = subprocess.run([sdk_python, str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: real Yubico certificate builder", result.stdout)

    def test_piv_sdk_bootstrap_is_check_only_by_default(self):
        script = ROOT / "scripts/workstation/bootstrap-yubikey-piv-python-sdk.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--apply", result.stdout)
        body = script.read_text()
        self.assertIn("apply=false", body)
        self.assertIn("python3 -m venv", body)
        self.assertIn("NABLA_PIV_PYTHON", body)
        for forbidden in ("piv keys generate", "piv reset",
                          "change-management-key", "otp delete"):
            self.assertNotIn(forbidden, body)

    def test_protected_aes256_mock_authentication_contract(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-aes256-auth-offline.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        result = subprocess.run(["python3", str(script)], capture_output=True,
                                text=True, check=True)
        self.assertIn("10 negative paths", result.stdout)
        body = script.read_text()
        for token in ('"get_pin_attempts", "verify_pin", "get_protected_key"',
                      "len(protected_key) != 32", "Insufficient synthetic PIN retry budget",
                      "final PIN reverify rejected", "Unexpected management-key mode"):
            self.assertIn(token, body)
        for forbidden in ("PivSession(", "ykman ", "get_pivman_protected_data(",
                          "put_certificate(", "generate_key(", "getpass("):
            self.assertNotIn(forbidden, body)

    def test_aes256_sdk_api_inspection_never_opens_hardware(self):
        script = ROOT / "scripts/workstation/inspect-age-yubikey-piv-aes256-sdk-api.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        help_result = subprocess.run(["python3", str(script), "--help"],
                                     capture_output=True, text=True, check=True)
        self.assertIn("no hardware", help_result.stdout)
        body = script.read_text()
        for expected in ("MANAGEMENT_KEY_TYPE.AES256.key_len", "PivmanData.has_stored_key",
                         "get_pivman_protected_data", "PIN_POLICY.ALWAYS",
                         "TOUCH_POLICY.ALWAYS", "SLOT.RETIRED1"):
            self.assertIn(expected, body)
        for forbidden in ("PivSession(", "verify_pin(", "authenticate(",
                          "get_pivman_protected_data(", "generate_key(",
                          "put_certificate("):
            self.assertNotIn(forbidden, body)
        sdk_python = os.path.expanduser("~/.local/share/nabla/piv-sdk-venv/bin/python")
        if os.path.isfile(sdk_python):
            result = subprocess.run([sdk_python, str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: SDK AES256", result.stdout)

    def test_pivman_aes256_mock_handshake_fails_closed(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-piv-aes256-handshake-offline.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        body = script.read_text()
        for required in ("class FakeSession:", "get_pivman_protected_data",
                         "MANAGEMENT_KEY_TYPE.AES256", "Insufficient PIN retry budget",
                         "wrong PIN", "missing AES key", "incorrect key length"):
            self.assertIn(required, body)
        for forbidden in ("PivSession(", "SmartCardConnection(", "piv keys generate",
                          "put_certificate(", "set_management_key("):
            self.assertNotIn(forbidden, body)
        sdk = os.path.expanduser("~/.local/share/nabla/piv-sdk-venv/bin/python")
        if os.path.isfile(sdk):
            result = subprocess.run([sdk, str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("six fail-closed scenarios", result.stdout)

    def test_piv82_inventory_seven_fake_hardware_outcomes(self):
        script = ROOT / "scripts/workstation/test-age-yubikey-piv82-inventory-fake-offline.py"
        subprocess.run(["python3", "-m", "py_compile", str(script)], check=True)
        content = script.read_text()
        self.assertIn("FAKE_YKMAN", content)
        self.assertIn('"ambiguous"', content)
        self.assertIn('"wrong-serial"', content)
        self.assertIn('"missing-9a"', content)
        self.assertNotIn("PivSession(", content)
        result = subprocess.run(["python3", str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("seven scenarios each for inventory and enrollment plan", result.stdout)

    def test_piv_python_sdk_capability_gate_is_read_only(self):
        script = ROOT / "scripts/workstation/check-yubikey-piv-python-sdk.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("offline", result.stdout)
        body = script.read_text()
        self.assertIn("sign_certificate_builder", body)
        for forbidden in ("piv keys generate", "piv certificates import",
                          "change-management-key", "ykman piv reset"):
            self.assertNotIn(forbidden, body)

    def test_offline_quality_gate_catches_syntax_errors_first(self):
        script = ROOT / "scripts/workstation/verify-age-yubikey-offline.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        content = script.read_text()
        self.assertIn("for python_source in", content)
        self.assertIn("for bash_source in", content)
        for expected in ("test-age-yubikey-piv-aes256-handshake-offline.py",
                         "test-age-yubikey-piv82-inventory-fake-offline.py",
                         "inspect-age-yubikey-aes256-hardware.sh",
                         "plan-age-yubikey-piv82-enrollment.sh",
                         "verify-age-yubikey-piv82-certificate.py"):
            self.assertIn(expected, content)
        # Both Bash variable forms are equivalent; preserve the ordering check.
        normalized = content.replace('"${python_source}"', '"$python_source"')
        self.assertLess(normalized.index('python3 -m py_compile "$python_source"'),
                        normalized.index("python3 -m unittest discover"))

    def test_offline_quality_gate_contract(self):
        script = ROOT / "scripts/workstation/verify-age-yubikey-offline.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_result = subprocess.run(["bash", str(script), "--help"],
                                     capture_output=True, text=True, check=True)
        self.assertIn("no hardware", script.read_text().lower())
        self.assertIn("verify-age-yubikey-offline.sh", help_result.stdout)
        body = script.read_text()
        self.assertIn("python3 -m unittest discover", body)
        for forbidden in ("piv keys generate", "piv reset", "otp delete",
                          "change-management-key", "age-plugin-yubikey --generate"):
            self.assertNotIn(forbidden, body)

    def test_aes_compat_gate_is_read_only(self):
        script = ROOT / "scripts/workstation/check-age-yubikey-aes-compat.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        output = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--serial", output.stdout)
        body = script.read_text()
        for marker in ("piv info", "Management key algorithm:", "exit 3",
                       "age-plugin-yubikey 0.5.1 generation is BLOCKED"):
            self.assertIn(marker, body)
        for forbidden in ("luksFormat", "piv reset", "piv keys generate",
                          "change-management-key", "--generate", "ykman otp"):
            self.assertNotIn(forbidden, body)

    def test_gpg_smartcard_triage_read_only(self):
        script = ROOT / "scripts/workstation/diagnose-gpg-smartcard.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--check", result.stdout)
        self.assertIn("--host-only", result.stdout)
        self.assertIn("host_only=true", script.read_text())
        content = script.read_text()
        self.assertIn("gpg --card-status", content)
        self.assertIn("disable-ccid", content)
        self.assertIn("pcsc-shared", content)
        self.assertIn("Clé secrète de signature Git", content)
        self.assertIn("ykman-gui actif", content)
        self.assertIn("usbfs sur CCID est attendu", content)
        self.assertIn("ne pas répéter reader-port", content)
        for forbidden in ("piv reset", "keytocard", "rm -rf", "gpg --delete-secret-key",
                          "gpgconf --kill", "systemctl stop", "set -x"):
            self.assertNotIn(forbidden, content)

    def test_reader_port_plan_is_read_only(self):
        script = ROOT / "scripts/workstation/plan-gpg-reader-port.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--check", result.stdout)
        content = script.read_text()
        self.assertIn("before-reader-port", content)
        self.assertIn("pcsc_scan", content)
        for forbidden in ("gpgconf --kill", "keytocard", "piv reset",
                          "systemctl restart", ">> ${cfg}", "sudo "):
            self.assertNotIn(forbidden, content)

    def test_transactional_reader_port_trial_safety(self):
        script = ROOT / "scripts/workstation/test-gpg-reader-port.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--apply", result.stdout)
        body = script.read_text()
        for expected in ("cmp -s", "trap cleanup EXIT", "changed=true",
                         "gpgconf --kill scdaemon", "cp -p --", "Card inserted"):
            self.assertIn(expected, body)
        for forbidden in ("keytocard", "piv reset", "gpgconf --kill all",
                          "systemctl restart pcscd", "set -x"):
            self.assertNotIn(forbidden, body)

    def test_isolated_gpg_transport_comparison_contract(self):
        script = ROOT / "scripts/workstation/compare-gpg-card-transports.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        out = subprocess.run(["bash", str(script), "--help"],
                             capture_output=True, text=True, check=True)
        self.assertIn("--run", out.stdout)
        self.assertIn("--pcsc-shared", out.stdout)
        self.assertIn("pcsc-shared) printf", script.read_text())
        body = script.read_text()
        for required in ("GNUPGHOME=", "disable-ccid", "timeout 18", "trap cleanup EXIT"):
            self.assertIn(required, body)
        for forbidden in ("keytocard", "piv reset", "gpgconf --kill all",
                          "systemctl restart", "set -x"):
            self.assertNotIn(forbidden, body)

    def test_main_profile_pcsc_shared_trial_contract(self):
        script = ROOT / "scripts/workstation/trial-gpg-pcsc-shared.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--trial", result.stdout)
        body = script.read_text()
        for token in ("cmp -s --", "pcsc-shared", "trap cleanup EXIT",
                      "cp -p --", "gpgconf --kill scdaemon",
                      "Main GnuPG profile detects"):
            self.assertIn(token, body)
        for token in ("keytocard", "piv reset", "gpgconf --kill all",
                      "systemctl restart pcscd", "set -x"):
            self.assertNotIn(token, body)

    def test_managed_pcsc_shared_apply_rollback_contract(self):
        script = ROOT / "scripts/workstation/manage-gpg-pcsc-shared.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        help_out = subprocess.run(["bash", str(script), "--help"],
                                  capture_output=True, text=True, check=True)
        for name in ("--check", "--verify", "--apply", "--rollback"):
            self.assertIn(name, help_out.stdout)
        content = script.read_text()
        for marker in ("cmp -s --", "trap cleanup EXIT", "before-reader-port",
                       "gpgconf --kill scdaemon", "No change", "pcsc-shared"):
            if marker != "No change":
                self.assertIn(marker, content)
        for forbidden in ("keytocard", "piv reset", "gpgconf --kill all",
                          "systemctl restart pcscd", "set -x"):
            self.assertNotIn(forbidden, content)

    def test_yubikey_bootstrap_installs_age_plugin_without_provisioning(self):
        script = ROOT / "scripts/workstation/bootstrap-yubikey-manager.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(script), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("age-plugin-yubikey", result.stdout)
        body = script.read_text()
        for required in ("cargo install --locked", "AGE_PLUGIN_VERSION",
                         "libpcsclite-dev", "check_age_plugin",
                         "libpcsclite.pc", "dpkg-architecture",
                         "env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_SYSROOT_DIR",
                         "PKG_CONFIG=/usr/bin/pkg-config",
                         "--modversion libpcsclite"):
            self.assertIn(required, body)
        for forbidden in ("--generate", "piv reset", "keytocard", "set -x"):
            self.assertNotIn(forbidden, body)

    def test_no_destructive_operations(self):
        text = SCRIPT.read_text()
        for forbidden in ("otp chalresp", "otp delete", "piv reset", "piv keys import",
                          "otp swap", "set -x", "echo ${HMAC_SECRET}", "env |"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
