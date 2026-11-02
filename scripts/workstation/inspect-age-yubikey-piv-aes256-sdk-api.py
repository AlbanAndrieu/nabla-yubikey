#!/usr/bin/env python3
"""Inspect installed Yubico PIV AES256 APIs without connecting to a device.

Never creates a PivSession, verifies a PIN, or reads management-key bytes.
"""
import argparse
import inspect
import sys


def check() -> None:
    from ykman.piv import (
        PivmanData,
        PivmanProtectedData,
        get_pivman_data,
        get_pivman_protected_data,
    )
    from yubikit.piv import (
        KEY_TYPE,
        MANAGEMENT_KEY_TYPE,
        PIN_POLICY,
        TOUCH_POLICY,
        PivSession,
        SLOT,
    )

    if MANAGEMENT_KEY_TYPE.AES256.key_len != 32:
        raise RuntimeError("Unexpected AES256 management-key length")
    if SLOT.RETIRED1.value != 0x82 or KEY_TYPE.ECCP256.name != "ECCP256":
        raise RuntimeError("Unexpected PIV82 or EC-P256 SDK constants")
    if PIN_POLICY.ALWAYS.name != "ALWAYS" or TOUCH_POLICY.ALWAYS.name != "ALWAYS":
        raise RuntimeError("PIN/touch ALWAYS policy unavailable")
    if not isinstance(PivmanData.has_stored_key, property):
        raise RuntimeError("Pivman stored-key property unavailable")
    if not hasattr(PivmanProtectedData(), "key"):
        raise RuntimeError("Protected data key descriptor unavailable")
    if not callable(get_pivman_data) or not callable(get_pivman_protected_data):
        raise RuntimeError("Pivman metadata API unavailable")
    if "pin" not in inspect.signature(PivSession.verify_pin).parameters:
        raise RuntimeError("PIV PIN verification signature changed")
    # SDK 5.8 keeps compatibility overloads: implementation accepts *args/**kwargs.
    if not callable(PivSession.authenticate):
        raise RuntimeError("PIV management-key authentication API unavailable")
    print("PASS: SDK AES256 (32-byte), protected Pivman data, PIV82 and PIN/touch ALWAYS APIs")
    print("NO-GO: no PIN verification, authentication, hardware signing or import was attempted")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline introspection of Yubico SDK; no hardware")
    parser.parse_args()
    try:
        check()
    except (ImportError, AttributeError, RuntimeError, ValueError) as error:
        print(f"NO-GO: SDK interface mismatch: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
