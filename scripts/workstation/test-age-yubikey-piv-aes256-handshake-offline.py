#!/usr/bin/env python3
"""Offline PIN-protected AES256 Pivman protocol exercise using a fake PIV session.

No reader access, real PIN, secret retrieval or hardware mutation.
"""
from __future__ import annotations

import argparse


def run() -> None:
    from ykman.piv import (
        OBJECT_ID_PIVMAN_DATA, OBJECT_ID_PIVMAN_PROTECTED_DATA,
        PivmanData, PivmanProtectedData, get_pivman_data,
        get_pivman_protected_data,
    )
    from yubikit.piv import MANAGEMENT_KEY_TYPE

    if MANAGEMENT_KEY_TYPE.AES256.key_len != 32:
        raise AssertionError("SDK AES256 does not use 32 bytes")

    synthetic_pin = "SYNTHETIC-ONLY"
    synthetic_key = bytes(range(32))

    class FakeSession:
        def __init__(self, *, pin=synthetic_pin, retries=3, key=synthetic_key,
                     stored=True):
            self.pin = pin
            self.retries = retries
            self.log: list[str] = []
            self.pivman = PivmanData()
            self.pivman.mgm_key_protected = stored
            self.protected = PivmanProtectedData()
            self.protected.key = key
            self.verified = False

        def get_pin_attempts(self):
            self.log.append("pin_attempts")
            return self.retries

        def verify_pin(self, candidate):
            self.log.append("verify_pin")
            if candidate != self.pin:
                raise ValueError("PIN rejected (synthetic)")
            self.verified = True

        def get_object(self, oid):
            if oid == OBJECT_ID_PIVMAN_DATA:
                self.log.append("pivman_metadata")
                return self.pivman.get_bytes()
            if oid == OBJECT_ID_PIVMAN_PROTECTED_DATA and self.verified:
                self.log.append("protected_object")
                return self.protected.get_bytes()
            raise ValueError("Protected object not accessible")

        def authenticate(self, key):
            self.log.append("authenticate")
            if key != synthetic_key or len(key) != 32:
                raise ValueError("Synthetic management authentication rejected")

    def guarded_protocol(session, pin):
        # Only called with FakeSession. Not an entry point for hardware.
        if session.get_pin_attempts() < 3:
            raise ValueError("Insufficient PIN retry budget")
        data = get_pivman_data(session)
        if not data.has_stored_key or data.has_derived_key:
            raise ValueError("Expected a PIN-protected, non-derived management key")
        session.verify_pin(pin)
        protected_data = get_pivman_protected_data(session)
        if protected_data.key is None or len(protected_data.key) != 32:
            raise ValueError("Expected stored AES256 management key")
        session.authenticate(protected_data.key)
        session.verify_pin(pin)

    ok = FakeSession()
    guarded_protocol(ok, synthetic_pin)
    assert ok.log == ["pin_attempts", "pivman_metadata", "verify_pin",
                      "protected_object", "authenticate", "verify_pin"], ok.log

    scenarios = [
        ("wrong PIN", FakeSession(), "INVALID"),
        ("low retry budget", FakeSession(retries=1), synthetic_pin),
        ("blocked PIN", FakeSession(retries=0), synthetic_pin),
        ("unprotected Pivman key", FakeSession(stored=False), synthetic_pin),
        ("missing AES key", FakeSession(key=None), synthetic_pin),
        ("incorrect key length", FakeSession(key=b"bad"), synthetic_pin),
    ]
    for label, session, pin in scenarios:
        try:
            guarded_protocol(session, pin)
        except ValueError:
            assert "authenticate" not in session.log, label
            assert session.log.count("verify_pin") <= 1, label
        else:
            raise AssertionError(f"Did not fail closed: {label}")

    print("PASS: Yubico Pivman AES256 mock handshake, correct order, six fail-closed scenarios")
    print("NO-GO hardware: all PINs and keys synthetic; no PIV reader accessed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline mocked PIV AES256 handshake; no hardware")
    parser.parse_args()
    run()


if __name__ == "__main__":
    main()
