# Nabla YubiKey: offline-first. Explicit hardware actions live elsewhere.
default:
    @just --list

test:
    python3 -m py_compile scripts/workstation/*.py tests/*.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v

dependencies-readonly:
    python3 scripts/workstation/inspect-yubikey-dependencies-readonly.py

ssh-fido2-readonly:
    python3 scripts/workstation/inspect-ssh-fido2-readonly.py
