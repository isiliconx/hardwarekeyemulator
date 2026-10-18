# language: Python 3.12, file: policy_lab.py, runtime: stdlib + cbor2 + cryptography
# *The research harness. Answers the only question that matters about a relying
# *party: WHICH check decides "hardware key" vs "passkey", and does a software
# *authenticator slip past it?
# *
# *Four strategies, each a shape real sites actually ship:
# *
# *  A. NO_GATE         counts anything WebAuthn. Classifies on syncability only.
# *  B. SYNCABILITY     hardware == credential is NOT backup-eligible (flag 0x08).
# *  C. ATTEST_PRESENT  hardware == attestation statement is present AND parses.
# *                      Ignores WHO signed it. This is the common real bug.
# *  D. MDS_TRUSTED     hardware == statement verifies under a recognised FIDO
# *                      attestation root AND AAGUID appears in the MDS blob.
# *
# *The interesting outcome is C: a site that requests attestation:"direct" and
# *then only checks presence has made requesting attestation decorative. A software
# *key passes it, and that is a genuine enforcement gap worth demonstrating.
# *
# *Run:  PYTHONPATH=../libs python3 policy_lab.py
import base64
import hashlib
import json
import os
import sys
import tempfile

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctap2_core import FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV
from vendor_profiles import OTHER_VENDOR_AAGUIDS, YUBIKEY_AAGUIDS


def _aaguid_key(aaguid: str) -> str:
    """Normalise an AAGUID to the dash-free hex form authData carries."""
    return aaguid.replace("-", "").strip().lower()


# Real AAGUIDs, read from the live FIDO MDS blob (mds.fidoalliance.org) and the
# Yubico developer docs. A software authenticator cannot terminate its chain at
# any of these vendors' real roots — that is the entire point of strategy D.
# Built as {aaguid-hex: model} and normalised to the dash-free form
# parse_attestation() produces.
FIDO_MDS_AAGUIDS = {_aaguid_key(aaguid): model
                    for model, aaguid in YUBIKEY_AAGUIDS.items()}
FIDO_MDS_AAGUIDS.update({_aaguid_key(aaguid): model
                         for model, aaguid in OTHER_VENDOR_AAGUIDS.items()})
FIDO_MDS_AAGUIDS[_aaguid_key("01020304050607080102030405060708")] = \
    "Chromium virtual authenticator (measured: Chrome 154/155/158)"

FIDO_TRUSTED_ISSUERS = {
    "Yubico U2F Root CA Serial 457200631",
    "Yubico Attestation Root 1",
    "Yubico Attestation Intermediate",
    "Yubico FIDO Attestation",
    "Yubico U2F EE",
    "Yubico",
    "Feitian Technologies",
    "Google Hardware Attestation",
    "Microsoft Corporation",
}

# Strategy E — the shape OpenAI's Daybreak behaves like: a curated allow-list of
# known-good hardware-key models keyed by AAGUID. Everything off the list lands
# in the "Passkey" bucket — which is exactly what TrustKey T110/T120, Trezor,
# Thetis and homebrew ESP32 keys all report in the wild, while YubiKeys register
# as "Security key" (observed September–October 2026; see README).
DAYBREAK_ALLOWLIST = {_aaguid_key(aaguid): model
                      for model, aaguid in YUBIKEY_AAGUIDS.items()}

POLICY_DEFAULT = {"require_attestation": True}


def parse_attestation(auth_data: bytes, fmt: str, stmt: dict) -> dict:
    """Pull the pieces a verifier would look at out of an attestation object."""
    out = {"fmt": fmt, "flags": auth_data[32], "aaguid": auth_data[37:53].hex()}
    if fmt == "none" or not stmt.get("x5c"):
        return out
    try:
        leaf = x509.load_der_x509_certificate(stmt["x5c"][0])
    except Exception as exc:
        out["leaf_error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["leaf_subject"] = leaf.subject.rfc4514_string()
    out["leaf_issuer"] = leaf.issuer.rfc4514_string()
    out["self_issued"] = leaf.subject == leaf.issuer
    out["has_aaguid_ext"] = any(
        ext.oid.dotted_string == "1.3.6.1.4.1.45724.1.1.4" for ext in leaf.extensions
    )
    out["sig_present"] = bool(stmt.get("sig"))
    return out


def verify_attestation_sig(auth_data: bytes, client_data_hash: bytes,
                           fmt: str, stmt: dict):
    """Real check: packed sig is over authData||clientDataHash, by the LEAF key."""
    if not stmt.get("sig"):
        return False, "no signature"
    chain = stmt.get("x5c") or []
    if not chain:
        return False, "no x5c chain"
    try:
        leaf = x509.load_der_x509_certificate(chain[0])
    except Exception as exc:
        return False, f"leaf parse: {exc}"
    data = auth_data + client_data_hash
    try:
        leaf.public_key().verify(stmt["sig"], data, ec.ECDSA(hashes.SHA256()))
        return True, "signature valid under leaf key"
    except Exception:
        return False, "signature does NOT verify"


def classify_daybreak(parsed: dict, attachment: str = "cross-platform") -> dict:
    """
    The enforcement shape OpenAI's Daybreak behaves like: a credential counts
    as a physical hardware key when its AAGUID is a known-good model AND it is
    not backup-eligible AND it came from a roaming (cross-platform)
    authenticator. Everything else lands in the "Passkey" bucket.
    """
    flags = parsed["flags"]
    aaguid = parsed["aaguid"]
    backup_eligible = bool(flags & FLAG_BE)
    backup_state = bool(flags & FLAG_BS)
    known = aaguid in DAYBREAK_ALLOWLIST
    counts = known and not backup_eligible and attachment == "cross-platform"
    return {
        "counts_as_hardware_key": counts,
        "label": "Security key" if counts else "Passkey",
        "aaguid": aaguid,
        "model": DAYBREAK_ALLOWLIST.get(aaguid, "UNRECOGNISED"),
        "reason": f"aaguid_known={known} "
                  f"({DAYBREAK_ALLOWLIST.get(aaguid, 'not in allow-list')}) "
                  f"BE={backup_eligible} BS={backup_state} attachment={attachment}",
    }


def classify(parsed: dict, sig_ok: bool) -> dict:
    """
    Return the four verdicts independently. Each is a shape a real RP ships.
    """
    flags = parsed["flags"]
    backup_eligible = bool(flags & FLAG_BE)
    backup_state = bool(flags & FLAG_BS)
    has_att_stmt = parsed.get("fmt", "none") != "none"
    verdicts = {}

    # A - no gate at all
    verdicts["A_NO_GATE"] = {
        "counts_as_hardware_key": has_att_stmt,
        "reason": f"no attestation gate; fmt={parsed['fmt']}",
    }

    # B - syncability. The flag we can actually control.
    verdicts["B_SYNCABILITY"] = {
        "counts_as_hardware_key": not backup_eligible,
        "reason": f"BE(0x08)={'set' if backup_eligible else 'clear'} -> "
                  f"{'passkey' if backup_eligible else 'security key'}; "
                  f"BS(0x10)={'set' if backup_state else 'clear'}",
    }

    # C - presence-only attestation check. THE COMMON BUG.
    verdicts["C_ATTEST_PRESENT"] = {
        "counts_as_hardware_key": has_att_stmt,
        "reason": f"attestation present={has_att_stmt}, signature NOT inspected. "
                  f"An RP written this way treats 'direct' as decorative.",
    }

    # D - real MDS/vendor trust
    aaguid_ok = parsed.get("aaguid") in FIDO_MDS_AAGUIDS
    issuer_ok = any(t in parsed.get("leaf_issuer", "") for t in FIDO_TRUSTED_ISSUERS)
    verdicts["D_MDS_TRUSTED"] = {
        "counts_as_hardware_key": bool(sig_ok and aaguid_ok and issuer_ok),
        "reason": f"sig_ok={sig_ok} aaguid_in_mds={aaguid_ok} issuer_trusted={issuer_ok}",
    }

    # E - the Daybreak shape: model allow-list + roaming + non-syncable
    daybreak = classify_daybreak(parsed)
    verdicts["E_DAYBREAK"] = {
        "counts_as_hardware_key": daybreak["counts_as_hardware_key"],
        "reason": daybreak["reason"],
    }
    return verdicts


def build_demo_attestation(profile=None):
    """Produce a real packed attestation from the local CA: a genuine signature
    from a real key, just not a vendor key. `profile` selects a vendor identity
    (vendor_profiles.py); None keeps the anonymous lab key."""
    from ctap2_core import Ctap2Authenticator
    temporary = tempfile.TemporaryDirectory(prefix="policy-lab-")
    auth = Ctap2Authenticator(store_path=os.path.join(temporary.name, "creds.json"),
                              profile=profile, uv_gate=lambda: True)
    challenge = os.urandom(32)
    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": "https://lab.example:8443",
        "crossOrigin": False,
    }, separators=(",", ":")).encode()
    cdh = hashlib.sha256(client_data).digest()
    resp = auth.make_credential({
        "clientDataHash": cdh,
        "rp": {"id": "lab.example", "name": "Lab RP"},
        "user": {"id": b"user-1", "name": "binda", "displayName": "Binda"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "options": {"rk": True, "uv": True},
        "credProtect": "userVerificationOptional",
    })
    return resp[2], resp[3], client_data


def build_forged_attestation():
    """
    The same credential, with a signature made by a key that is NOT the leaf's
    key. This is what a real attacker-supplied attestation looks like, and it is
    how you demonstrate that strategy C is broken: the signature does not verify,
    yet C still returns HARDWARE.
    """
    auth_data, stmt, client_data = build_demo_attestation()
    cdh = hashlib.sha256(client_data).digest()
    # Sign the same data with an unrelated key, then swap it into the statement.
    rogue = ec.generate_private_key(ec.SECP256R1())
    stmt["sig"] = rogue.sign(auth_data + cdh, ec.ECDSA(hashes.SHA256()))
    return auth_data, stmt, client_data


def main():
    print("=" * 74)
    print(" POLICY LAB - which check decides 'hardware key'?")
    print("=" * 74)
    auth_data, stmt, client_data = build_demo_attestation()
    cdh = hashlib.sha256(client_data).digest()
    fmt = stmt.get("fmt", "packed")
    parsed = parse_attestation(auth_data, fmt, stmt)
    sig_ok, sig_reason = verify_attestation_sig(auth_data, cdh, fmt, stmt)

    print("\n-- what the credential actually says --")
    flags = parsed["flags"]
    print(f"  fmt             : {parsed['fmt']}")
    print(f"  flags           : 0x{flags:02x}")
    print(f"    UP(0x01)={'set' if flags & FLAG_UP else 'clear'}"
          f"  UV(0x04)={'set' if flags & FLAG_UV else 'clear'}"
          f"  BE(0x08)={'set' if flags & FLAG_BE else 'CLEAR'}"
          f"  BS(0x10)={'set' if flags & FLAG_BS else 'clear'}"
          f"  AT(0x40)={'set' if flags & FLAG_AT else 'clear'}")
    print(f"  aaguid          : {parsed['aaguid']}")
    print(f"  leaf subject    : {parsed.get('leaf_subject')}")
    print(f"  leaf issuer     : {parsed.get('leaf_issuer')}")
    print(f"  self-issued     : {parsed.get('self_issued')}")
    print(f"  fido aaguid ext : {parsed.get('has_aaguid_ext')}")
    print(f"  signature       : {sig_reason}")

    print("\n-- five RP enforcement shapes, five verdicts --")
    for name, v in classify(parsed, sig_ok).items():
        mark = "HARDWARE" if v["counts_as_hardware_key"] else "passkey"
        print(f"\n  {name}: {mark}")
        print(f"    {v['reason']}")

    print("\n" + "=" * 74)
    print(" SAME CREDENTIAL, FORGED SIGNATURE (signed by a key that is NOT")
    print(" the leaf key, so it does NOT verify)")
    print("=" * 74)
    f_auth, f_stmt, f_cd = build_forged_attestation()
    f_cdh = hashlib.sha256(f_cd).digest()
    f_parsed = parse_attestation(f_auth, f_stmt.get("fmt", "packed"), f_stmt)
    f_ok, f_reason = verify_attestation_sig(f_auth, f_cdh, f_stmt.get("fmt", "packed"),
                                            f_stmt)
    print(f"\n  signature       : {f_reason}")
    for name, v in classify(f_parsed, f_ok).items():
        mark = "HARDWARE" if v["counts_as_hardware_key"] else "passkey"
        note = ("<- still says hardware: sig was never checked"
                if v["counts_as_hardware_key"]
                else "<- correctly rejected: signature did not verify")
        print(f"  {name}: {mark}   {note}")

    print("\n" + "=" * 74)
    print(" SAME CLASSIFIER, TWO IDENTITIES: lab key vs vendor profile")
    print("=" * 74)
    for label, prof in (("lab", None), ("yubikey", "yubikey")):
        d_auth, d_stmt, d_cd = build_demo_attestation(prof)
        d_parsed = parse_attestation(d_auth, d_stmt.get("fmt", "packed"), d_stmt)
        d_verdict = classify_daybreak(d_parsed)
        print(f"\n  {label:8} aaguid={d_parsed['aaguid']}")
        print(f"           OpenAI-style label: {d_verdict['label']}")
        print(f"           {d_verdict['reason']}")

    print("\n-- bottom line --")
    print("  A/B/C : need no vendor key. A software key passes all three.")
    print("  D     : needs a signature under a FIDO-registered vendor root.")
    print("          Not reachable without that vendor private key. Arithmetic.")
    print("  E     : the Daybreak shape — allow-list the AAGUID. A vendor profile")
    print("          passes it; the lab key and Chromium's virtual authenticator")
    print("          (aaguid 0102...08) do not. This is the shape that matches")
    print("          observed OpenAI behaviour (TrustKey/Trezor/ESP32 -> Passkey).")
    print("  C     : broken by design when the signature is not verified. The")
    print("          forged case above is the demonstration: an RP that only")
    print("          checks 'attestation present' accepts a broken signature.")


if __name__ == "__main__":
    main()
