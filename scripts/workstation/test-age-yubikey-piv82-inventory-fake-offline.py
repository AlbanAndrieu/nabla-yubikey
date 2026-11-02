#!/usr/bin/env python3
"""Exercise Bash AES256 inventory against a deterministic fake ykman.

No real card may be contacted: PATH is prepended with a synthetic ykman.
"""
import os
from pathlib import Path
import subprocess
import tempfile

SCRIPT = Path(__file__).with_name("inspect-age-yubikey-aes256-hardware.sh")
PLAN = Path(__file__).with_name("plan-age-yubikey-piv82-enrollment.sh")
FAKE_YKMAN = r'''#!/usr/bin/env python3
import os
import sys
args = sys.argv[1:]
mode = os.environ.get("FAKE_MODE", "empty")
with open(os.environ["FAKE_COMMAND_LOG"], "a", encoding="utf-8") as stream:
    stream.write(" ".join(args) + "\n")
if args == ["list", "--serials"]:
    print("11110001" if mode == "wrong-serial" else "11110002")
elif args == ["--device", "11110002", "piv", "info"]:
    print("Management key algorithm: " + ("TDES" if mode == "wrong-aes" else "AES256"))
    print("Management key is stored on the YubiKey, protected by PIN.")
elif args == ["--device", "11110002", "piv", "keys", "info", "82"]:
    if mode == "occupied":
        print("Key type: ECCP256")
    elif mode == "transport":
        print("Error: PCSC connection lost", file=sys.stderr)
        sys.exit(1)
    elif mode == "ambiguous":
        print("ERROR: No key stored in slot 82 (RETIRED1). extra text", file=sys.stderr)
        sys.exit(1)
    else:
        print("ERROR: No key stored in slot 82 (RETIRED1).", file=sys.stderr)
        sys.exit(1)
elif args == ["--device", "11110002", "piv", "keys", "info", "9a"]:
    if mode == "missing-9a":
        print("ERROR: No key stored in slot 9A (AUTHENTICATION).", file=sys.stderr)
        sys.exit(1)
    print("Key type: RSA2048")
else:
    print("Unexpected fake ykman invocation", file=sys.stderr)
    sys.exit(99)
'''


def main() -> None:
    if not SCRIPT.is_file() or not PLAN.is_file():
        raise RuntimeError("Missing inventory or enrollment plan script")
    with tempfile.TemporaryDirectory(prefix="nabla-fake-ykman-") as dirname:
        directory = Path(dirname)
        shim = directory / "ykman"
        shim.write_text(FAKE_YKMAN, encoding="utf-8")
        shim.chmod(0o700)
        fake_plugin = directory / "age-plugin-yubikey"
        fake_plugin.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        fake_plugin.chmod(0o700)
        for mode, expected_code in (
            ("empty", 0), ("occupied", 3), ("ambiguous", 3),
            ("transport", 3), ("wrong-serial", 3), ("wrong-aes", 3),
            ("missing-9a", 3),
        ):
            for script in (SCRIPT, PLAN):
                log = directory / "calls.log"
                log.write_text("", encoding="utf-8")
                env = {**os.environ,
                       "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
                       "FAKE_MODE": mode,
                       "FAKE_COMMAND_LOG": str(log), "NO_COLOR": "1"}
                result = subprocess.run(
                    ["bash", str(script), "--serial", "11110002"],
                    env=env, text=True, capture_output=True, check=False,
                )
                if result.returncode != expected_code:
                    raise AssertionError(f"{script.name}, {mode}: exit {result.returncode}, expected {expected_code}: {result.stderr} {result.stdout}")
                calls = log.read_text(encoding="utf-8").splitlines()
                whitelist = {"list --serials", "--device 11110002 piv info",
                             "--device 11110002 piv keys info 82",
                             "--device 11110002 piv keys info 9a"}
                if not calls or not set(calls).issubset(whitelist):
                    raise AssertionError(f"Unexpected ykman commands in {mode}: {calls}")
                if mode == "empty" and "PIV82 empty" not in result.stdout:
                    raise AssertionError(f"Empty PIV82 did not pass {script.name}")
                if mode != "empty" and "Read-only inventory:" in result.stdout:
                    raise AssertionError(f"Unsafe PASS for mode {mode}")

    print("PASS: seven scenarios each for inventory and enrollment plan, fail-closed on errors")
    print("NO-GO hardware: all invocations were intercepted by a fake ykman executable")


if __name__ == "__main__":
    main()
