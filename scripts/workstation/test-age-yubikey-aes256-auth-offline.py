#!/usr/bin/env python3
"""Offline fail-closed model of PIN-protected AES256 PIV authentication.

All data are synthetic; no SDK reader, real PIN or management key is accessed.
"""
import argparse


SYNTHETIC_PIN = "MOCK_ONLY"
SYNTHETIC_KEY = bytes(range(32))


class FakeSession:
    def __init__(self, *, pin_valid=True, key_valid=True, key=SYNTHETIC_KEY,
                 retries=3, readable=True, reverify_valid=True):
        self.events = []
        self.pin_valid = pin_valid
        self.key_valid = key_valid
        self.key = key
        self.retries = retries
        self.readable = readable
        self.reverify_valid = reverify_valid
        self.pin_verified = False

    def get_pin_attempts(self):
        self.events.append("get_pin_attempts")
        return self.retries

    def verify_pin(self, pin):
        self.events.append("verify_pin")
        attempt = self.events.count("verify_pin")
        if not self.pin_valid or pin != SYNTHETIC_PIN or (
            attempt == 2 and not self.reverify_valid
        ):
            raise ValueError("Synthetic PIN verification failed")
        self.pin_verified = True

    def get_protected_key(self):
        self.events.append("get_protected_key")
        if not self.pin_verified or not self.readable:
            raise ValueError("Synthetic protected key cannot be read")
        return self.key

    def authenticate(self, key):
        self.events.append("authenticate")
        if not self.key_valid or key != SYNTHETIC_KEY:
            raise ValueError("Synthetic AES256 authentication failed")


class FakePivman:
    def __init__(self, *, stored=True, derived=False):
        self.has_stored_key = stored
        self.has_derived_key = derived


def authenticate_mock(session, pivman):
    """Model ordering only; this function is deliberately not a hardware API."""
    if session.get_pin_attempts() < 3:
        raise ValueError("Insufficient synthetic PIN retry budget")
    if not pivman.has_stored_key or pivman.has_derived_key:
        raise ValueError("Unexpected management-key mode")
    session.verify_pin(SYNTHETIC_PIN)
    protected_key = session.get_protected_key()
    if not isinstance(protected_key, bytes) or len(protected_key) != 32:
        raise ValueError("Synthetic key is not AES256")
    session.authenticate(protected_key)
    session.verify_pin(SYNTHETIC_PIN)


def self_test():
    good = FakeSession()
    authenticate_mock(good, FakePivman())
    expected = ["get_pin_attempts", "verify_pin", "get_protected_key",
                "authenticate", "verify_pin"]
    if good.events != expected:
        raise AssertionError(f"Wrong synthetic authentication order: {good.events}")
    cases = [
        ("blocked PIN", FakeSession(retries=0), FakePivman()),
        ("low retry budget", FakeSession(retries=2), FakePivman()),
        ("wrong PIN", FakeSession(pin_valid=False), FakePivman()),
        ("unprotected key", FakeSession(), FakePivman(stored=False)),
        ("deprecated derived key", FakeSession(), FakePivman(derived=True)),
        ("protected data unreadable", FakeSession(readable=False), FakePivman()),
        ("missing key", FakeSession(key=None), FakePivman()),
        ("short key", FakeSession(key=SYNTHETIC_KEY[:-1]), FakePivman()),
        ("authentication rejected", FakeSession(key_valid=False), FakePivman()),
        ("final PIN reverify rejected", FakeSession(reverify_valid=False), FakePivman()),
    ]
    for label, session, pivman in cases:
        try:
            authenticate_mock(session, pivman)
        except ValueError:
            if session.events.count("verify_pin") > 2:
                raise AssertionError(f"Unexpected PIN retries in {label}")
            if label != "final PIN reverify rejected" and session.events.count("authenticate") > 1:
                raise AssertionError(f"Unexpected authentication retries in {label}")
        else:
            raise AssertionError(f"Fail-open synthetic scenario: {label}")
    print(f"PASS: protected AES256 mock sequence and {len(cases)} negative paths")
    print("NO-GO hardware: no real card, PIN, management key, signing or import")


def main():
    parser = argparse.ArgumentParser(description="Fake PIV AES256 auth only; no hardware")
    parser.parse_args()
    self_test()


if __name__ == "__main__":
    main()
