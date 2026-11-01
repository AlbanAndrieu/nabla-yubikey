"""Hermetic regression tests for concurrent, fail-closed YubiKey readiness."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/run-yubikey-parallel-readonly.py"
spec = importlib.util.spec_from_file_location("parallel_yubikey_readonly", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def completed(data: dict, *, code: int = 0):
    return subprocess.CompletedProcess(
        [], code, json.dumps(data), "DO_NOT_LEAK_FROM_STDERR"
        if code else "",
    )


def safe_host():
    return {"status": "NO-GO", "hardware_mutation_authorized": False}


def safe_hardware():
    return {**safe_host(), "device": {"serial": module.SECONDARY},
            "pin_requested": False, "otp_challenge_executed": False,
            "decrypt_executed": False}


class ParallelYubiKeyContracts(unittest.TestCase):
    def test_fixed_jobs_are_only_synthetic_test_recipes(self):
        self.assertEqual(len(module.TEST_JOBS), 6)
        self.assertEqual(len(module.HOST_JOBS), 3)
        for command in module.TEST_JOBS.values():
            self.assertEqual(command[0], "just")
            self.assertTrue(command[1].startswith("yubikey-"))
            self.assertTrue(command[1].endswith("-test"))
        for command in module.HOST_JOBS.values():
            self.assertTrue(command[1].endswith("-readonly.py"))
        self.assertEqual(module.HARDWARE_JOB[-4:], (
            "--hardware", "--serial", module.SECONDARY, "--gpg-agent-probe",
        ))

    def test_jobs_are_actually_concurrent(self):
        barrier = threading.Barrier(6)
        def mocked(name, cmd, **kwargs):
            barrier.wait(timeout=3)
            return {"job": name, "state": "PASS"}
        with patch.object(module, "run_job", side_effect=mocked) as mock:
            result = module.parallel(module.TEST_JOBS)
        self.assertEqual(set(result.values()), {"PASS"})
        self.assertEqual(mock.call_count, 6)

    def test_all_expected_jobs_are_required_before_hardware(self):
        with patch.object(module, "parallel", return_value={
            "recovery": "PASS", "applications": "PASS",
            "workstation": "PASS", "coordinator": "PASS",
            "gpg_agent": "PASS",
        }), patch.object(module, "run_job") as hardware:
            result, code = module.execute(True)
        self.assertEqual(code, 3)
        self.assertEqual(result["hardware"], "NOT_CHECKED")
        hardware.assert_not_called()

    def test_missing_new_dependency_host_probe_blocks_hardware(self):
        with patch.object(module, "parallel", side_effect=[
            dict.fromkeys(module.TEST_JOBS, "PASS"),
            {"workstation": "PASS", "gpg_agent": "PASS"},
        ]), patch.object(module, "run_job") as hardware:
            result, code = module.execute(True)
        self.assertEqual(code, 3)
        self.assertEqual(result["hardware"], "NOT_CHECKED")
        hardware.assert_not_called()

    def test_failing_contract_blocks_host_and_hardware(self):
        with patch.object(module, "parallel", return_value={
            **dict.fromkeys(module.TEST_JOBS, "PASS"), "recovery": "FAILED",
        }) as parallel, patch.object(module, "run_job") as hardware:
            result, code = module.execute(True)
        self.assertEqual(code, 3)
        self.assertEqual(result["hardware"], "NOT_CHECKED")
        self.assertEqual(result["status"], "NO-GO")
        self.assertEqual(parallel.call_count, 1)
        hardware.assert_not_called()

    def test_failing_host_blocks_hardware(self):
        with patch.object(module, "parallel", side_effect=[
            dict.fromkeys(module.TEST_JOBS, "PASS"),
            {"workstation": "PASS", "gpg_agent": "UNKNOWN"},
        ]), patch.object(module, "run_job") as hardware:
            result, code = module.execute(True)
        self.assertEqual(code, 3)
        self.assertEqual(result["hardware"], "NOT_CHECKED")
        hardware.assert_not_called()

    def test_host_only_never_touches_hardware(self):
        with patch.object(module, "parallel", side_effect=[
            dict.fromkeys(module.TEST_JOBS, "PASS"),
            dict.fromkeys(module.HOST_JOBS, "PASS"),
        ]) as parallel, patch.object(module, "run_job") as hardware:
            result, code = module.execute(False)
        self.assertEqual(code, 0)
        self.assertEqual(result["hardware"], "NOT_CHECKED")
        self.assertFalse(result["hardware_mutation_authorized"])
        self.assertEqual(parallel.call_count, 2)
        hardware.assert_not_called()

    def test_hardware_is_sequential_after_independent_gates(self):
        observed = []
        def suites(jobs, **kwargs):
            observed.append(("parallel", tuple(jobs)))
            return dict.fromkeys(jobs, "PASS")
        def hardware(name, cmd, **kwargs):
            observed.append(("hardware", tuple(cmd)))
            return {"job": name, "state": "PASS"}
        with patch.object(module, "parallel", side_effect=suites), \
             patch.object(module, "run_job", side_effect=hardware):
            result, code = module.execute(True)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "NO-GO")
        self.assertEqual(result["configuration"], "NOT_AUTHORIZED")
        self.assertEqual([x[0] for x in observed], ["parallel", "parallel", "hardware"])

    def test_subprocess_closed_stdin_timeout_and_no_raw_output(self):
        with patch.object(module.subprocess, "run",
                          return_value=completed(safe_host())) as runner:
            result = module.run_job("gpg_agent", module.HOST_JOBS["gpg_agent"],
                                    read_json=True)
        self.assertEqual(result, {"job": "gpg_agent", "state": "PASS"})
        self.assertEqual(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(runner.call_args.kwargs["timeout"], 150)
        self.assertFalse(runner.call_args.kwargs["check"])
        self.assertNotIn("stdout", result)
        self.assertNotIn("stderr", result)

    def test_hardware_wrong_serial_and_unsafe_flags_fail_closed(self):
        for payload in (
            {**safe_hardware(), "device": {"serial": "11110001"}},
            {**safe_hardware(), "pin_requested": True},
            {**safe_hardware(), "decrypt_executed": True},
            {**safe_hardware(), "hardware_mutation_authorized": True},
            {**safe_hardware(), "status": "GO"},
        ):
            with self.subTest(payload=payload), \
                 patch.object(module.subprocess, "run",
                              return_value=completed(payload)):
                self.assertEqual(module.run_job(
                    "hardware", module.HARDWARE_JOB, read_json=True)["state"],
                    "UNKNOWN")

    def test_malformed_json_exit_failure_timeout_fail_closed(self):
        cases = (
            subprocess.CompletedProcess([], 0, "{bad", ""),
            subprocess.CompletedProcess([], 1, "", "secret"),
            subprocess.CompletedProcess([], 0, "X" * 65537, ""),
        )
        for result in cases:
            with self.subTest(code=result.returncode), \
                 patch.object(module.subprocess, "run", return_value=result):
                self.assertNotEqual(module.run_job(
                    "workstation", module.HOST_JOBS["workstation"],
                    read_json=True)["state"], "PASS")
        with patch.object(module.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(["just"], 150)):
            self.assertEqual(module.run_job("recovery", module.TEST_JOBS["recovery"])["state"],
                             "UNKNOWN")

    def test_cli_rejects_implicit_primary_or_secrets_before_commands(self):
        for argv in (["--primary"], ["--pin", "123456"], ["--otp2-secondary"]):
            with self.subTest(argv=argv), \
                 patch.object(module, "execute") as execute, \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    module.main(argv)
                self.assertEqual(error.exception.code, 2)
                execute.assert_not_called()

    def test_json_always_no_go(self):
        captured = io.StringIO()
        with patch.object(module, "execute", return_value=(
            {"status": "NO-GO", "configuration": "NOT_AUTHORIZED"}, 0
        )), redirect_stdout(captured):
            self.assertEqual(module.main([]), 0)
        self.assertEqual(json.loads(captured.getvalue())["status"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
