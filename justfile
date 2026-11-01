# Nabla YubiKey: offline-first. Explicit hardware actions live elsewhere.
default:
    @just --list

test:
    python3 -m py_compile scripts/workstation/*.py tests/*.py
    python3 -m unittest discover -s tests -p 'test_*.py' -q

# Verbose output only when investigating a failing case.
test-verbose:
    python3 -m py_compile scripts/workstation/*.py tests/*.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v

# Hermetic tests, then every read-only probe; never writes to a YubiKey.
check: test dependencies-readonly ssh-fido2-readonly applets-readonly keepassxc-readonly

# Offline schema comparison only. Never executes Compose scripts or probes.
# Override COMPOSE_ROOT in your shell if the repositories are not siblings.
compose-contract:
    python3 scripts/ops/compare-compose-contracts.py --compose-root "${COMPOSE_ROOT:-../nabla-compose}" --assert-field-parity

dependencies-readonly:
    python3 scripts/workstation/inspect-yubikey-dependencies-readonly.py

ssh-fido2-readonly:
    python3 scripts/workstation/inspect-ssh-fido2-readonly.py

applets-readonly:
    python3 scripts/workstation/inspect-yubikey-applets-readonly.py

keepassxc-readonly:
    python3 scripts/workstation/inspect-keepassxc-readonly.py
