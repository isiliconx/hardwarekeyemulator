# language: Python 3.12, file: daybreak_check.py, runtime: cryptography + cbor2
# *The pre-flight check for the Daybreak problem: will a relying party that
# *classifies credentials by model (the shape OpenAI's behaviour matches) file
# *this key under "Security key" or "Passkey"? Registers through the real CTAP2
# *core for the identities that matter, prints exactly what the RP sees in each,
# *and applies the five policy_lab enforcement shapes plus the Daybreak
# *classifier.
# *
# *  python3 daybreak_check.py                        # lab vs default profile
# *  python3 daybreak_check.py --profile 5-NFC-5.4    # a different model
# *  python3 daybreak_check.py --profile lab           # lab + Chromium only

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctap2_core import Ctap2Authenticator
from vendor_profiles import get_profile, attestation_trust
from policy_lab import (classify, classify_daybreak, parse_attestation,
                        verify_attestation_sig)

RP_ID = "daybreak.example"
ORIGIN = "https://daybreak.example"
# What Chrome's CDP virtual authenticator always reports (measured on 154/155/158;
# no CDP option exists to change it) — the identity hold_virtual_key.py produced.
CHROMIUM_VIRTUAL = "01020304050607080102030405060708"


def client_data(challenge: bytes) -> bytes:
    return json.dumps({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": ORIGIN, "crossOrigin": False,
    }).encode()


def register(store, profile=None, aaguid=None):
    auth = Ctap2Authenticator(store, profile=profile, aaguid=aaguid,
                              uv_gate=lambda: True)
    challenge = os.urandom(32)
    cd = client_data(challenge)
    resp = auth.make_credential({
        1: hashlib.sha256(cd).digest(),
        2: {"id": RP_ID, "name": "Daybreak Check"},
        3: {"id": b"check-user", "name": "check", "displayName": "Check"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True, "uv": True},
    })
    return auth, resp, cd


def report(label, resp, cd):
    fmt, auth_data, stmt = resp[1], resp[2], resp[3]
    cdh = hashlib.sha256(cd).digest()
    parsed = parse_attestation(auth_data, fmt, stmt)
    sig_ok, sig_reason = verify_attestation_sig(auth_data, cdh, fmt, stmt)
    verdicts = classify(parsed, sig_ok)
    daybreak = classify_daybreak(parsed)

    print(f"\n{'=' * 74}\n {label}\n{'=' * 74}")
    flags = parsed["flags"]
    print(f"  fmt         : {parsed['fmt']}")
    print(f"  flags       : 0x{flags:02x}  UP={bool(flags & 1)} UV={bool(flags & 4)} "
          f"BE={bool(flags & 8)} AT={bool(flags & 0x40)}")
    print(f"  aaguid      : {parsed['aaguid']}")
    print(f"  model       : {daybreak['model']}")
    if parsed.get("leaf_subject"):
        print(f"  leaf subject: {parsed['leaf_subject']}")
        print(f"  leaf issuer : {parsed['leaf_issuer']}")
    print(f"  signature   : {sig_reason}")

    print("\n  RP policy shapes:")
    for name, v in verdicts.items():
        mark = "HARDWARE" if v["counts_as_hardware_key"] else "passkey"
        print(f"    {name:16} -> {mark:8} | {v['reason'][:58]}")

    print(f"\n  DAYBREAK-STYLE VERDICT: {daybreak['label']}"
          f"   {'[PASS]' if daybreak['counts_as_hardware_key'] else '[FAIL]'}")
    print(f"    {daybreak['reason']}")
    return daybreak


def main():
    ap = argparse.ArgumentParser(
        description="Check whether a registration reads as a hardware security "
                    "key to a Daybreak-shaped relying party.")
    ap.add_argument("--profile", default="yubikey",
                    help="vendor profile to check (default 'yubikey'); "
                         "'lab' skips the vendor half")
    ap.add_argument("--aaguid", default=None,
                    help="override: check an arbitrary AAGUID (hex, dashes ok)")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="daybreak-check-")
    results = {}

    _, lab_resp, lab_cd = register(os.path.join(tmp, "lab.json"))
    results["lab"] = report("LAB KEY (what the emulator shipped as before)",
                            lab_resp, lab_cd)

    _, virt_resp, virt_cd = register(os.path.join(tmp, "virt.json"),
                                     aaguid=bytes.fromhex(CHROMIUM_VIRTUAL))
    results["chromium-virtual"] = report(
        "CHROMIUM VIRTUAL AUTHENTICATOR (aaguid 0102...08 — what a CDP virtual\n"
        "  authenticator produces; Chrome pins this value, no CDP option exists)",
        virt_resp, virt_cd)

    if args.profile and args.profile.strip().lower() != "lab":
        profile = get_profile(args.profile)
        aaguid = (bytes.fromhex(args.aaguid.replace("-", ""))
                  if args.aaguid else None)
        _, vk_resp, vk_cd = register(os.path.join(tmp, "vendor.json"),
                                     profile=profile, aaguid=aaguid)
        results["vendor"] = report(f"VENDOR PROFILE: {profile.describe()}",
                                   vk_resp, vk_cd)
        trust = {k: v for k, v in attestation_trust(profile).items()
                 if k != "signals"}
        print("\n  Trust analysis: " + json.dumps(trust)[:360] + "…")

    print(f"\n{'=' * 74}\n BOTTOM LINE — how a Daybreak-shaped RP files each\n{'=' * 74}")
    for name, v in results.items():
        print(f"    {name:18} -> {v['label']}")
    print("\n  Caveat, stated plainly: an RP that additionally pins the genuine")
    print("  vendor ROOT and validates the chain to it rejects every software")
    print("  authenticator — that signature needs the vendor private key.")
    print("  Everything short of that check is now faithful.")


if __name__ == "__main__":
    main()
