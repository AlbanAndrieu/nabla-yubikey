"""Opt-in, hermetic comparison of legacy and migrated dependency probes.

Requires a trusted local sibling nabla-compose checkout. Both source modules
are imported but *every* external observation made by snapshot is patched.
No hardware, subprocess, socket, database, secret, or network interaction.
This validates representative mocked values, not live workstation parity.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from probe_loader import load_probe

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_ROOT = Path(os.environ.get("COMPOSE_ROOT", str(ROOT.parent / "nabla-compose")))
SOURCE = COMPOSE_ROOT / "scripts/workstation/inspect-yubikey-dependencies-readonly.py"
MIGRATED = load_probe("inspect-yubikey-dependencies-readonly.py")


def legacy_module():
    """Only import the exact, locally trusted legacy script in this opt-in test."""
    spec = importlib.util.spec_from_file_location("legacy_dependencies_probe", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recorded_snapshot(module, present_tools: frozenset[str], states: dict) -> dict:
    """Replace every effectful snapshot dependency with deterministic metadata."""
    def which(name: str):
        return "/mock/bin/" + name if name in present_tools else None

    with ExitStack() as stack:
        stack.enter_context(patch.object(module, "process_state",
                                         side_effect=lambda name, uid=None: states[name]))
        stack.enter_context(patch.object(module, "ssh_agent_state",
                                         return_value=states["ssh_agent"]))
        stack.enter_context(patch.object(module, "scdaemon_agent_state",
                                         return_value=states["agent_scdaemon"]))
        stack.enter_context(patch.object(module, "postgres_versioned_tools_state",
                                         return_value=states["postgres_versioned"]))
        stack.enter_context(patch.object(module, "postgres_pg_config_server_tools_state",
                                         return_value=states["pg_config"]))
        stack.enter_context(patch.object(module.shutil, "which", side_effect=which))
        with patch("subprocess.run") as run:
            result = module.snapshot()
            run.assert_not_called()
    return result


class LegacyDependencyParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("trusted Compose checkout unavailable: legacy parity NOT_RUN")
        cls.legacy = legacy_module()

    def test_synthetic_snapshot_value_parity(self):
        cases = [
            (frozenset(), {
                "scdaemon": "PROCESS_NOT_OBSERVED",
                "pcscd": "PROCESS_NOT_OBSERVED",
                "ssh_agent": "SOCKET_NOT_CONFIGURED",
                "agent_scdaemon": "TOOL_MISSING",
                "postgres_versioned": "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS",
                "pg_config": "PG_CONFIG_MISSING",
            }),
            (frozenset(("age", "sops", "gpg", "ssh-add")), {
                "scdaemon": "PROCESS_PRESENT_UNVERIFIED",
                "pcscd": "PROCESS_NOT_OBSERVED",
                "ssh_agent": "PUBLIC_IDENTITIES_PRESENT_UNVERIFIED",
                "agent_scdaemon": "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED",
                "postgres_versioned": "PARTIAL_VERSIONED_SERVER_BINARIES",
                "pg_config": "PG_CONFIG_SERVER_BINARIES_PARTIAL",
            }),
            (frozenset(("pg_restore", "pg_dump", "psql", "initdb", "pg_ctl")), {
                "scdaemon": "UNKNOWN",
                "pcscd": "TOOL_MISSING",
                "ssh_agent": "UNKNOWN",
                "agent_scdaemon": "NOT_CONFIRMED",
                "postgres_versioned": "UNKNOWN",
                "pg_config": "BINDIR_UNAVAILABLE",
            }),
        ]
        for installed, states in cases:
            with self.subTest(installed=sorted(installed)):
                expected = recorded_snapshot(self.legacy, installed, states)
                actual = recorded_snapshot(MIGRATED, installed, states)
                self.assertEqual(actual, expected)
                self.assertEqual(actual["status"], "NO-GO")
                self.assertFalse(actual["hardware_mutation_authorized"])

    def test_invalid_arguments_have_identical_code_and_no_json(self):
        for module in (self.legacy, MIGRATED):
            with self.subTest(module=module.__name__):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr), \
                     patch.object(module, "snapshot") as snapshot:
                    code = module.main(["--reset"])
                self.assertEqual(code, 2)
                self.assertEqual(stdout.getvalue(), "")
                snapshot.assert_not_called()

    def test_successful_json_serialization_and_exit_code(self):
        states = {
            "scdaemon": "PROCESS_NOT_OBSERVED", "pcscd": "PROCESS_NOT_OBSERVED",
            "ssh_agent": "SOCKET_NOT_CONFIGURED", "agent_scdaemon": "TOOL_MISSING",
            "postgres_versioned": "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS",
            "pg_config": "PG_CONFIG_MISSING",
        }
        expected = recorded_snapshot(self.legacy, frozenset(), states)
        for module in (self.legacy, MIGRATED):
            with self.subTest(module=module.__name__):
                stdout = io.StringIO()
                with patch.object(module, "snapshot", return_value=expected), \
                     redirect_stdout(stdout):
                    code = module.main([])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(stdout.getvalue()), expected)
                self.assertEqual(stdout.getvalue().count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
