#!/usr/bin/env python3
"""Check the SSH FIDO2 key split from local configuration only.

Uses `ssh -G` (no connection), the systemd user environment and git config.
Never contacts the agent, the YubiKey or a remote host, never asks for a PIN
and never prints key material, fingerprints or paths.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

GIT_HOST = "github.com"
SERVER_HOSTS = ("truenas", "pfsense")


def ssh_config(host: str) -> dict[str, list[str]] | None:
    """Return resolved `ssh -G` options, or None when they cannot be trusted."""
    if not shutil.which("ssh"):
        return None
    try:
        done = subprocess.run(["ssh", "-G", host], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=5, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or len(done.stdout) > 65536 or "\x00" in done.stdout:
        return None
    options: dict[str, list[str]] = {}
    for line in done.stdout.splitlines():
        key, _, value = line.partition(" ")
        options.setdefault(key.lower(), []).append(value)
    return options


def identity_order(options: dict[str, list[str]] | None) -> str:
    if options is None:
        return "UNKNOWN"
    files = options.get("identityfile", [])
    if not any(path.endswith("_sk") for path in files):
        return "SK_NOT_OFFERED"
    return "SK_FIRST" if files[0].endswith("_sk") else "SK_NOT_FIRST"


def file_key_offered(options: dict[str, list[str]] | None) -> str:
    """Servers keep the file key: an unknown YubiKey is refused without a PIN prompt."""
    if options is None:
        return "UNKNOWN"
    files = options.get("identityfile", [])
    return "FILE_KEY_OFFERED" if any(not path.endswith("_sk") for path in files) else "FILE_KEY_MISSING"


def forward_agent(options: dict[str, list[str]] | None) -> str:
    if options is None:
        return "UNKNOWN"
    return "AGENT_FORWARDED" if options.get("forwardagent", ["no"])[0] != "no" else "NOT_FORWARDED"


def agent_environment() -> dict[str, str]:
    """Read only the askpass variables of the systemd user manager, which starts gcr-ssh-agent."""
    if not shutil.which("systemctl"):
        return {}
    try:
        done = subprocess.run(["systemctl", "--user", "show-environment"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, timeout=5, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return {}
    if done.returncode != 0 or len(done.stdout) > 65536:
        return {}
    wanted = ("SSH_ASKPASS", "WAYLAND_DISPLAY")
    return {key: value for key, _, value in (line.partition("=") for line in done.stdout.splitlines())
            if key in wanted}


def askpass_state(env: dict[str, str]) -> str:
    """x11-ssh-askpass cannot grab the keyboard under Wayland and sends an empty PIN."""
    askpass = env.get("SSH_ASKPASS", "")
    if not env.get("WAYLAND_DISPLAY"):
        return "NOT_WAYLAND_UNVERIFIED"
    if not askpass or "x11-ssh-askpass" in askpass or askpass == "/usr/bin/ssh-askpass":
        return "X11_ASKPASS_UNDER_WAYLAND"
    return "CONFIGURED_UNVERIFIED"


def git_config(key: str) -> str | None:
    if not shutil.which("git"):
        return None
    try:
        done = subprocess.run(["git", "config", "--global", "--get", key],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, timeout=5, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 else ""


def commit_signing_state() -> str:
    sign = git_config("commit.gpgsign")
    if sign is None:
        return "UNKNOWN"
    if sign != "true":
        return "DISABLED"
    return "OPENPGP" if git_config("gpg.format") in ("", "openpgp") else "NOT_OPENPGP"


def snapshot() -> dict:
    github = identity_order(ssh_config(GIT_HOST))
    servers = {host: ssh_config(host) for host in SERVER_HOSTS}
    report = {
        "mode": "SSH_FIDO2_LOCAL_CONFIG_ONLY",
        "github_identity": github,
        "server_identity": {host: file_key_offered(opts) for host, opts in servers.items()},
        "server_agent_forwarding": {host: forward_agent(opts) for host, opts in servers.items()},
        "agent_askpass": askpass_state(agent_environment()),
        "commit_signing": commit_signing_state(),
        "ssh_fido_login_verified": False,
        "hardware_mutation_authorized": False,
    }
    ok = (github == "SK_FIRST"
          and all(state == "FILE_KEY_OFFERED" for state in report["server_identity"].values())
          and all(state == "NOT_FORWARDED" for state in report["server_agent_forwarding"].values())
          and report["agent_askpass"] != "X11_ASKPASS_UNDER_WAYLAND"
          and report["commit_signing"] == "OPENPGP")
    report["status"] = "GO" if ok else "NO-GO"
    return report


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("No arguments supported", file=sys.stderr)
        return 2
    print(json.dumps(snapshot(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
