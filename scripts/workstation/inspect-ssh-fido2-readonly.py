#!/usr/bin/env python3
"""Check the SSH FIDO2 key split from local configuration only.

Uses `ssh -G` (no connection), the systemd user environment and git config.
Never contacts the agent, the YubiKey or a remote host, never asks for a PIN
and never prints key material, fingerprints or paths.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

GIT_HOST = "github.com"
SERVER_HOSTS = ("truenas", "pfsense")


def read_metadata(command: list[str], timeout: int = 5) -> tuple[int, str] | None:
    """Bounded, allowlisted, no-stdin commands only; never return stderr."""
    permitted = (
        command[:2] == ["ssh", "-G"] and len(command) == 3
        and command[2] in (GIT_HOST, *SERVER_HOSTS)
    ) or command == ["systemctl", "--user", "show-environment"] or (
        command[:4] == ["git", "config", "--global", "--get"]
        and len(command) == 5 and command[4] in ("commit.gpgsign", "gpg.format")
    )
    if not permitted or not shutil.which(command[0]):
        return None
    try:
        done = subprocess.run(command, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=timeout, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    if (not isinstance(done.stdout, str) or len(done.stdout) > 65536
            or "\x00" in done.stdout):
        return None
    # git config --get returns 1 for an unset key; other failures fail closed.
    allowed_codes = (0, 1) if command[0] == "git" else (0,)
    if done.returncode not in allowed_codes:
        return None
    return done.returncode, done.stdout


def ssh_config(host: str) -> dict[str, list[str]] | None:
    """Read ssh's resolved options without network access or agent use."""
    result = read_metadata(["ssh", "-G", host])
    if result is None:
        return None
    options: dict[str, list[str]] = {}
    for line in result[1].splitlines():
        key, sep, value = line.partition(" ")
        if not sep or not value or not key.isascii() or not key.isalpha():
            return None
        options.setdefault(key.lower(), []).append(value)
    return options or None


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
    """Require one unambiguous resolved value; missing is not proof of no forwarding."""
    if options is None:
        return "UNKNOWN"
    values = options.get("forwardagent", [])
    if values == ["no"]:
        return "NOT_FORWARDED"
    if values == ["yes"]:
        return "AGENT_FORWARDED"
    return "UNKNOWN"


def agent_environment() -> dict[str, str]:
    """Read only the SSH askpass metadata, never echo the full environment."""
    result = read_metadata(["systemctl", "--user", "show-environment"])
    if result is None:
        return {}
    wanted = ("SSH_ASKPASS", "WAYLAND_DISPLAY")
    return {key: value for key, sep, value in
            (line.partition("=") for line in result[1].splitlines())
            if sep and key in wanted and len(value) <= 4096}


def askpass_state(env: dict[str, str]) -> str:
    """x11-ssh-askpass cannot grab the keyboard under Wayland and sends an empty PIN."""
    askpass = env.get("SSH_ASKPASS", "")
    if not env.get("WAYLAND_DISPLAY"):
        return "NOT_WAYLAND_UNVERIFIED"
    if not askpass or "x11-ssh-askpass" in askpass or askpass == "/usr/bin/ssh-askpass":
        return "X11_ASKPASS_UNDER_WAYLAND"
    return "CONFIGURED_UNVERIFIED"


def git_config(key: str) -> str | None:
    result = read_metadata(["git", "config", "--global", "--get", key])
    if result is None:
        return None
    return "" if result[0] == 1 else result[1].strip()


def commit_signing_state() -> str:
    sign = git_config("commit.gpgsign")
    if sign is None:
        return "UNKNOWN"
    if sign != "true":
        return "DISABLED"
    return "OPENPGP" if git_config("gpg.format") in ("", "openpgp") else "NOT_OPENPGP"


def snapshot() -> dict:
    github_options = ssh_config(GIT_HOST)
    github = identity_order(github_options)
    servers = {host: ssh_config(host) for host in SERVER_HOSTS}
    report = {
        "mode": "SSH_FIDO2_LOCAL_CONFIG_ONLY",
        "github_identity": github,
        # Agent keys are tried in agent order: an offered file key signs without PIN when a YubiKey is absent.
        "github_file_key": file_key_offered(github_options),
        "server_identity": {host: file_key_offered(opts) for host, opts in servers.items()},
        "server_agent_forwarding": {host: forward_agent(opts) for host, opts in servers.items()},
        "agent_askpass": askpass_state(agent_environment()),
        "commit_signing": commit_signing_state(),
        "ssh_fido_login_verified": False,
        "hardware_mutation_authorized": False,
    }
    ok = (github == "SK_FIRST" and report["github_file_key"] == "FILE_KEY_MISSING"
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
