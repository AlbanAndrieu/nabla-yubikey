"""Hermetic contracts: SSH FIDO2 key split from local configuration only."""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-ssh-fido2-readonly.py"
spec = importlib.util.spec_from_file_location("ssh_fido2_readonly", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

GITHUB = "user git\nidentityfile ~/.ssh/id_ed25519_sk\nidentityfile ~/.ssh/id_ed25519\nforwardagent no\n"
SERVER = "user albandrieu\nidentityfile ~/.ssh/id_ed25519_sk\nidentityfile ~/.ssh/id_ed25519\nforwardagent no\n"
AGENT_ENV = "HOME=/home/u\nSSH_ASKPASS=/usr/libexec/seahorse/ssh-askpass\nWAYLAND_DISPLAY=wayland-0\nGITHUB_TOKEN=x\n"
SIGNING = {"commit.gpgsign": "true\n", "gpg.format": ""}


def fake_run(outputs):
    def run(command, **kwargs):
        if command[:2] == ["ssh", "-G"]:
            return SimpleNamespace(returncode=0, stdout=outputs[command[2]])
        if command[0] == "systemctl":
            return SimpleNamespace(returncode=0, stdout=outputs["systemctl"])
        return SimpleNamespace(returncode=0, stdout=outputs[command[-1]])
    return run


def snapshot_with(**overrides):
    outputs = {"github.com": GITHUB, "truenas": SERVER, "pfsense": SERVER,
               "systemctl": AGENT_ENV, **SIGNING, **overrides}
    with patch.object(module.shutil, "which", return_value="/usr/bin/x"), \
         patch.object(module.subprocess, "run", side_effect=fake_run(outputs)):
        return module.snapshot()


class SshFido2Contracts(unittest.TestCase):
    def test_ssh_g_is_offline_and_bounded(self):
        with patch.object(module.shutil, "which", return_value="/usr/bin/ssh"), \
             patch.object(module.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout=GITHUB)) as run:
            options = module.ssh_config("github.com")
        self.assertEqual(run.call_args.args[0], ["ssh", "-G", "github.com"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["identityfile"][0], "~/.ssh/id_ed25519_sk")
        with patch.object(module.shutil, "which", return_value="/usr/bin/ssh"), \
             patch.object(module.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout="x" * 70000)):
            self.assertIsNone(module.ssh_config("github.com"))

    def test_ssh_failure_fails_closed(self):
        with patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.subprocess, "run") as run:
            self.assertIsNone(module.ssh_config("github.com"))
            run.assert_not_called()
        with patch.object(module.shutil, "which", return_value="/usr/bin/ssh"), \
             patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired(["ssh"], 5)):
            self.assertIsNone(module.ssh_config("github.com"))
        self.assertEqual(module.identity_order(None), "UNKNOWN")
        self.assertEqual(module.forward_agent(None), "UNKNOWN")

    def test_identity_order(self):
        self.assertEqual(module.identity_order({"identityfile": ["a_sk", "b"]}), "SK_FIRST")
        self.assertEqual(module.identity_order({"identityfile": ["b", "a_sk"]}), "SK_NOT_FIRST")
        self.assertEqual(module.identity_order({"identityfile": ["b"]}), "SK_NOT_OFFERED")
        self.assertEqual(module.identity_order({}), "SK_NOT_OFFERED")

    def test_askpass_x11_under_wayland_is_blocking(self):
        wayland = {"WAYLAND_DISPLAY": "wayland-0"}
        self.assertEqual(module.askpass_state(wayland), "X11_ASKPASS_UNDER_WAYLAND")
        self.assertEqual(module.askpass_state({**wayland, "SSH_ASKPASS": "/usr/bin/ssh-askpass"}),
                         "X11_ASKPASS_UNDER_WAYLAND")
        self.assertEqual(module.askpass_state({**wayland, "SSH_ASKPASS": "/usr/libexec/seahorse/ssh-askpass"}),
                         "CONFIGURED_UNVERIFIED")
        self.assertEqual(module.askpass_state({}), "NOT_WAYLAND_UNVERIFIED")

    def test_commit_signing(self):
        with patch.object(module, "git_config", side_effect=["true", ""]):
            self.assertEqual(module.commit_signing_state(), "OPENPGP")
        with patch.object(module, "git_config", side_effect=["true", "ssh"]):
            self.assertEqual(module.commit_signing_state(), "NOT_OPENPGP")
        with patch.object(module, "git_config", return_value=""):
            self.assertEqual(module.commit_signing_state(), "DISABLED")
        with patch.object(module, "git_config", return_value=None):
            self.assertEqual(module.commit_signing_state(), "UNKNOWN")

    def test_agent_environment_keeps_only_askpass_variables(self):
        with patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"), \
             patch.object(module.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout=AGENT_ENV)) as run:
            env = module.agent_environment()
        self.assertEqual(run.call_args.args[0], ["systemctl", "--user", "show-environment"])
        self.assertEqual(set(env), {"SSH_ASKPASS", "WAYLAND_DISPLAY"})

    def test_file_key_offered_to_servers(self):
        self.assertEqual(module.file_key_offered({"identityfile": ["a_sk", "b"]}), "FILE_KEY_OFFERED")
        self.assertEqual(module.file_key_offered({"identityfile": ["a_sk"]}), "FILE_KEY_MISSING")
        self.assertEqual(module.file_key_offered(None), "UNKNOWN")

    def test_snapshot_go_without_paths_or_other_variables(self):
        outputs = {"github.com": GITHUB, "truenas": SERVER, "pfsense": SERVER,
                   "systemctl": AGENT_ENV, **SIGNING}
        out = io.StringIO()
        with patch.object(module.shutil, "which", return_value="/usr/bin/x"), \
             patch.object(module.subprocess, "run", side_effect=fake_run(outputs)), \
             redirect_stdout(out):
            self.assertEqual(module.main([]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "GO")
        for leaked in ("id_ed25519", "GITHUB_TOKEN", "seahorse"):
            self.assertNotIn(leaked, out.getvalue())
        self.assertFalse(report["hardware_mutation_authorized"])

    def test_snapshot_no_go_cases(self):
        sk_only = "identityfile ~/.ssh/id_ed25519_sk\nforwardagent no\n"
        self.assertEqual(snapshot_with(truenas=sk_only)["status"], "NO-GO")
        self.assertEqual(snapshot_with(pfsense=SERVER.replace("forwardagent no", "forwardagent yes"))["status"],
                         "NO-GO")
        self.assertEqual(snapshot_with(systemctl="WAYLAND_DISPLAY=wayland-0\n")["status"], "NO-GO")
        file_first = "identityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_ed25519_sk\n"
        self.assertEqual(snapshot_with(**{"github.com": file_first})["status"], "NO-GO")

    def test_arguments_rejected(self):
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(["--fix"]), 2)


if __name__ == "__main__":
    unittest.main()
