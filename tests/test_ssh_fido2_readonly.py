"""Hermetic contracts: SSH FIDO2 key split from local configuration only."""
from __future__ import annotations

import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from probe_loader import load_probe

module = load_probe("inspect-ssh-fido2-readonly.py")

GITHUB = "user git\nforwardx11 no\nidentityfile ~/.ssh/id_ed25519_sk_principale\nidentityfile ~/.ssh/id_ed25519_sk\nforwardagent no\n"
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
    with patch("shutil.which", return_value="/usr/bin/x"), \
         patch("subprocess.run", side_effect=fake_run(outputs)):
        return module.snapshot()


class SshFido2Contracts(unittest.TestCase):
    def test_ssh_g_is_offline_and_bounded(self):
        with patch("shutil.which", return_value="/usr/bin/ssh"), \
             patch("subprocess.run",
                          return_value=SimpleNamespace(returncode=0, stdout=GITHUB)) as run:
            options = module.ssh_config("github.com")
        self.assertEqual(run.call_args.args[0], ["ssh", "-G", "github.com"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["identityfile"][0], "~/.ssh/id_ed25519_sk_principale")
        with patch("shutil.which", return_value="/usr/bin/ssh"), \
             patch("subprocess.run",
                          return_value=SimpleNamespace(returncode=0, stdout="x" * 70000)):
            self.assertIsNone(module.ssh_config("github.com"))

    def test_ssh_failure_fails_closed(self):
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as run:
            self.assertIsNone(module.ssh_config("github.com"))
            run.assert_not_called()
        with patch("shutil.which", return_value="/usr/bin/ssh"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["ssh"], 5)):
            self.assertIsNone(module.ssh_config("github.com"))
        self.assertEqual(module.identity_order(None), "UNKNOWN")
        self.assertEqual(module.forward_agent(None), "UNKNOWN")

    def test_identity_order(self):
        self.assertEqual(module.identity_order({"identityfile": ["a_sk", "b"]}), "SK_FIRST")
        self.assertEqual(module.identity_order({"identityfile": ["b", "a_sk"]}), "SK_NOT_FIRST")
        self.assertEqual(module.identity_order({"identityfile": ["b"]}), "SK_NOT_OFFERED")
        self.assertEqual(module.identity_order({}), "SK_NOT_OFFERED")

    def test_labelled_security_key_is_not_a_file_key(self):
        self.assertTrue(module.is_sk("~/.ssh/id_ed25519_sk_principale"))
        self.assertTrue(module.is_sk("~/.ssh/id_ecdsa_sk"))
        self.assertFalse(module.is_sk("~/.ssh/id_ed25519"))
        self.assertFalse(module.is_sk("~/.ssh/task_skeleton/id_ed25519"))
        self.assertEqual(module.file_key_offered({"identityfile": ["~/.ssh/id_ed25519_sk_principale"]}),
                         "FILE_KEY_MISSING")

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
        with patch("shutil.which", return_value="/usr/bin/systemctl"), \
             patch("subprocess.run",
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
        with patch("shutil.which", return_value="/usr/bin/x"), \
             patch("subprocess.run", side_effect=fake_run(outputs)), \
             redirect_stdout(out):
            self.assertEqual(module.main([]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "GO")
        for leaked in ("id_ed25519", "GITHUB_TOKEN", "seahorse"):
            self.assertNotIn(leaked, out.getvalue())
        self.assertFalse(report["hardware_mutation_authorized"])

    def test_snapshot_no_go_cases(self):
        sk_only = "identityfile ~/.ssh/id_ed25519_sk\nforwardagent no\n"
        file_first = "identityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_ed25519_sk\n"
        cases = {
            "TRUENAS_FILE_KEY_MISSING": {"truenas": sk_only},
            "PFSENSE_AGENT_FORWARDED": {"pfsense": SERVER.replace("forwardagent no", "forwardagent yes")},
            "AGENT_X11_ASKPASS_UNDER_WAYLAND": {"systemctl": "WAYLAND_DISPLAY=wayland-0\n"},
            "GITHUB_FILE_KEY_OFFERED": {"github.com": GITHUB + "identityfile ~/.ssh/id_ed25519\n"},
            "GITHUB_SK_NOT_FIRST": {"github.com": file_first},
            "COMMIT_SIGNING_DISABLED": {"commit.gpgsign": ""},
        }
        for code, overrides in cases.items():
            report = snapshot_with(**overrides)
            self.assertEqual(report["status"], "NO-GO", code)
            self.assertIn(code, report["blocking"])

    def test_absent_or_duplicate_forward_agent_value_is_not_safe(self):
        self.assertEqual(module.forward_agent({}), "UNKNOWN")
        self.assertEqual(module.forward_agent({"forwardagent": ["no", "yes"]}), "UNKNOWN")
        self.assertEqual(module.forward_agent({"forwardagent": ["yes"]}), "AGENT_FORWARDED")
        self.assertEqual(module.forward_agent({"forwardagent": ["no"]}), "NOT_FORWARDED")
        report = snapshot_with(pfsense=SERVER + "forwardagent yes\n")
        self.assertEqual(report["server_agent_forwarding"]["pfsense"], "UNKNOWN")
        self.assertEqual(report["status"], "NO-GO")

    def test_metadata_runner_rejects_unapproved_and_malformed_commands(self):
        with patch("shutil.which", return_value="/usr/bin/x"), \
             patch("subprocess.run") as runner:
            for command in (["ssh", "-T", "github.com"], ["ssh", "-G", "example.com"],
                            ["git", "config", "--global", "--get", "credential.helper"],
                            ["systemctl", "--user", "start", "gcr-ssh-agent"]):
                self.assertIsNone(module.read_metadata(command))
            runner.assert_not_called()
        with patch("shutil.which", return_value="/usr/bin/ssh"), \
             patch("subprocess.run", return_value=SimpleNamespace(
                 returncode=0, stdout="forwardagent no\nbadline\n")):
            self.assertIsNone(module.ssh_config("github.com"))

    def test_unset_git_config_distinct_from_failed_git_command(self):
        with patch("shutil.which", return_value="/usr/bin/git"), \
             patch("subprocess.run", return_value=SimpleNamespace(
                 returncode=1, stdout="")):
            self.assertEqual(module.git_config("gpg.format"), "")
        with patch("shutil.which", return_value="/usr/bin/git"), \
             patch("subprocess.run", return_value=SimpleNamespace(
                 returncode=2, stdout="")):
            self.assertIsNone(module.git_config("gpg.format"))

    def test_arguments_rejected(self):
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(["--fix"]), 2)


if __name__ == "__main__":
    unittest.main()
