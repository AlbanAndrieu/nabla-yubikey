#!/usr/bin/env python3
"""Check the SSH FIDO2 key split from local configuration only.

Uses `ssh -G` (no connection), the systemd user environment and git config.
Never contacts the agent, the YubiKey or a remote host, never asks for a PIN
and never prints key material, fingerprints or paths.
"""
from __future__ import annotations

import re
import sys

from probe_common import main_json, run_bounded, verdict

GIT_HOST = "github.com"
SERVER_HOSTS = ("truenas", "pfsense")


def ssh_config(host: str) -> dict[str, list[str]] | None:
    """Return resolved `ssh -G` options, or None when they cannot be trusted."""
    raw = run_bounded(["ssh", "-G", host], timeout=5)
    if raw is None:
        return None
    options: dict[str, list[str]] = {}
    for line in raw.splitlines():
        key, _, value = line.partition(" ")
        options.setdefault(key.lower(), []).append(value)
    return options


def is_sk(path: str) -> bool:
    """Security-key handles are named id_<type>_sk, optionally with a _<label> suffix."""
    return re.search(r"_sk(_[^/]*)?$", path) is not None


def identity_order(options: dict[str, list[str]] | None) -> str:
    if options is None:
        return "UNKNOWN"
    files = options.get("identityfile", [])
    if not any(is_sk(path) for path in files):
        return "SK_NOT_OFFERED"
    return "SK_FIRST" if is_sk(files[0]) else "SK_NOT_FIRST"


def file_key_offered(options: dict[str, list[str]] | None) -> str:
    """Servers keep the file key: an unknown YubiKey is refused without a PIN prompt."""
    if options is None:
        return "UNKNOWN"
    files = options.get("identityfile", [])
    return "FILE_KEY_OFFERED" if any(not is_sk(path) for path in files) else "FILE_KEY_MISSING"


def forward_agent(options: dict[str, list[str]] | None) -> str:
    if options is None:
        return "UNKNOWN"
    return "AGENT_FORWARDED" if options.get("forwardagent", ["no"])[0] != "no" else "NOT_FORWARDED"


def agent_environment() -> dict[str, str]:
    """Read only the askpass variables of the systemd user manager, which starts gcr-ssh-agent."""
    raw = run_bounded(["systemctl", "--user", "show-environment"], timeout=5) or ""
    wanted = ("SSH_ASKPASS", "WAYLAND_DISPLAY")
    return {key: value for key, _, value in (line.partition("=") for line in raw.splitlines())
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
    """Value of a global git setting, "" when unset (exit 1), None when git cannot answer."""
    raw = run_bounded(["git", "config", "--global", "--get", key], timeout=5, ok_codes=(0, 1))
    return None if raw is None else raw.strip()


def commit_signing_state() -> str:
    sign = git_config("commit.gpgsign")
    if sign is None:
        return "UNKNOWN"
    if sign != "true":
        return "DISABLED"
    return "OPENPGP" if git_config("gpg.format") in ("", "openpgp") else "NOT_OPENPGP"


def assess(report: dict) -> list[str]:
    """Each blocking code names the host or setting that breaks the key split."""
    blocking = []
    if report["github_identity"] != "SK_FIRST":
        blocking.append(f"GITHUB_{report['github_identity']}")
    # Agent keys are tried in agent order: an offered file key signs without PIN when a YubiKey is absent.
    if report["github_file_key"] != "FILE_KEY_MISSING":
        blocking.append(f"GITHUB_{report['github_file_key']}")
    for host in SERVER_HOSTS:
        if report["server_identity"][host] != "FILE_KEY_OFFERED":
            blocking.append(f"{host.upper()}_{report['server_identity'][host]}")
        if report["server_agent_forwarding"][host] != "NOT_FORWARDED":
            blocking.append(f"{host.upper()}_{report['server_agent_forwarding'][host]}")
    if report["agent_askpass"] == "X11_ASKPASS_UNDER_WAYLAND":
        blocking.append("AGENT_X11_ASKPASS_UNDER_WAYLAND")
    if report["commit_signing"] != "OPENPGP":
        blocking.append(f"COMMIT_SIGNING_{report['commit_signing']}")
    return blocking


def snapshot() -> dict:
    github_options = ssh_config(GIT_HOST)
    servers = {host: ssh_config(host) for host in SERVER_HOSTS}
    report = {
        "mode": "SSH_FIDO2_LOCAL_CONFIG_ONLY",
        "github_identity": identity_order(github_options),
        "github_file_key": file_key_offered(github_options),
        "server_identity": {host: file_key_offered(opts) for host, opts in servers.items()},
        "server_agent_forwarding": {host: forward_agent(opts) for host, opts in servers.items()},
        "agent_askpass": askpass_state(agent_environment()),
        "commit_signing": commit_signing_state(),
        "ssh_fido_login_verified": False,
        "hardware_mutation_authorized": False,
    }
    return verdict(report, assess(report), [])


def main(argv: list[str] | None = None) -> int:
    return main_json(snapshot, argv)


if __name__ == "__main__":
    sys.exit(main())
