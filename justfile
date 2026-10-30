# Nabla YubiKey: offline-first. Explicit hardware actions live elsewhere.
default:
    @just --list

test:
    python3 -m py_compile scripts/workstation/inspect-yubikey-dependencies-readonly.py tests/test_yubikey_dependencies_readonly.py
    python3 -m unittest discover -s tests -p 'test_yubikey_dependencies_readonly.py' -v

dependencies-readonly:
    python3 scripts/workstation/inspect-yubikey-dependencies-readonly.py
