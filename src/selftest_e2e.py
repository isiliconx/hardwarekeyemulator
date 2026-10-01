# language: Python 3.12, file: selftest_e2e.py, runtime: cryptography + cbor2
# *End-to-end: browser -> CTAPHID -> CTAP2 core -> RP verification -> attestation analysis.*
# *This is the test that proves the emulator is a working authenticator, not a demo.*

import hashlib as _hashlib
import base64
import json
import os
import sys
import threading
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyze_attestation import inspect
from ctap2_core import (
    Ctap2Authenticator, FLAG_AT, FLAG_BE, FLAG_UP, FLAG_UV,
    parse_attested_credential_id,
)
from ctaphid import CtapHidDevice, CtapHidDeviceSide, LoopbackTransport
from rp_verify import (
    POLICY, RpError, verify_assertion, verify_registration,
)

_temp = tempfile.TemporaryDirectory(prefix="fido2lab-e2e-")
STORE = os.path.join(_temp.name, "creds.json")

RP_ID = "lab.example"
ORIGIN = f"https://{RP_ID}"
ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


def client_data(ceremony: str, challenge: bytes, origin: str = ORIGIN) -> bytes:
    """Build the ClientDataJSON a real page would send."""
    return json.dumps({
        "type": ceremony,
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": origin,
        "crossOrigin": False,
    }).encode()


def webauthn_attestation(response: dict) -> dict:
    return {"fmt": response[1], "authData": response[2], "attStmt": response[3]}


def bring_up(attestation_mode="packed_x5c"):
    auth = Ctap2Authenticator(
        store_path=STORE,
        attestation_mode=attestation_mode,
        uv_gate=lambda: True,
    )
    host_t = LoopbackTransport().open()
    dev_t = host_t.peer().open()
    side = CtapHidDeviceSide(dev_t, auth, verbose=False)
    threading.Thread(target=side.serve_forever, daemon=True).start()
    host = CtapHidDevice(host_t, verbose=False)
    host.init_sequence()
    return auth, host


print("== registration ceremony (webauthn.create) ==")
auth, host = bring_up("packed_x5c")
challenge = os.urandom(32)
cd = client_data("webauthn.create", challenge)

cd_hash = _hashlib.sha256(cd).digest()
status, resp = host.make_credential({
    1: cd_hash,
    2: {"id": RP_ID, "name": "Lab IdP"},
    3: {"id": os.urandom(16), "name": "binda", "displayName": "Binda"},
    4: [{"type": "public-key", "alg": -7}],
    7: {"rk": True, "up": True, "uv": True},
})
check("makeCredential returned OK", status == 0x00, hex(status))
resp = webauthn_attestation(resp)

reg = verify_registration(
    RP_ID, cd, resp, challenge, expected_origin=ORIGIN
)
check("RP verified the registration", bool(reg["credential_id"]))
check("credential id is 32 bytes", len(reg["credential_id"]) == 32, len(reg["credential_id"]))
check("UP/UV flags seen by RP", reg["flags"] & FLAG_UP and reg["flags"] & FLAG_UV)
check("AT flag set at RP", reg["flags"] & FLAG_AT != 0)
check("fmt is packed", reg["fmt"] == "packed", reg["fmt"])

print("\n== attestation analysis (the hard part) ==")
analysis = inspect(resp, resp["authData"], cd_hash)
print(json.dumps({k: v for k, v in analysis.items() if k != "findings"}, indent=2, default=str))
for f in analysis["findings"]:
    mark = "REJECTABLE" if f["rp_can_reject"] else "informational"
    print(f"  [{mark}] {f['signal']}")
    print(f"      RP sees : {f['what_rp_sees']}")
    print(f"      RP check: {f['how']}")
check("analysis produced a verdict", "verdict" in analysis)
check("leaf is issued by a real root (not self-issued)",
      analysis["leaf_is_self_issued"] is False)
check("leaf carries the FIDO AAGUID extension",
      analysis["leaf_has_fido_extension"] is True)
check("root is NOT a trusted FIDO attestation CA",
      analysis.get("root_is_trusted_fido_ca") is False)
check("untrusted root is a rejectable signal",
      any("untrusted" in f["signal"] for f in analysis["findings"] if f["rp_can_reject"]))
print(f"  verdict: {analysis['verdict']}")

print("\n== RP refuses attestation-less registration (policy on) ==")
strict = {**POLICY, "require_attestation": True}
try:
    verify_registration(
        RP_ID, cd, resp, challenge, expected_origin=ORIGIN, policy=strict
    )
    check("RP rejects untrusted attestation chain", False, "accepted!")
except RpError as exc:
    check("RP policy gate is live", True)
    print(f"      RP said: {exc}")

print("\n== authentication ceremony (webauthn.get) ==")
challenge2 = os.urandom(32)
cd2 = client_data("webauthn.get", challenge2)
cd2_hash = _hashlib.sha256(cd2).digest()
status2, resp2 = host.get_assertion({
    1: RP_ID,
    2: cd2_hash,
    3: [{"type": "public-key", "id": reg["credential_id"], "transports": ["usb"]}],
    5: {"up": True, "uv": True},
})
check("getAssertion returned OK", status2 == 0x00, hex(status2))
res = verify_assertion(
    RP_ID, cd2, resp2, reg["public_key_der"], reg["sign_count"], challenge2,
    expected_origin=ORIGIN,
)
check("RP verified the assertion signature", bool(res["credential_id"]))
check("user handle returned", res["user_handle"] is not None)
check("single assertion omits enumeration count", res["number_of_credentials"] is None)
print(f"      sign count advanced {reg['sign_count']} -> {res['sign_count']}")

print("\n== cloned-counter detection (RP refuses a stalled counter) ==")
try:
    verify_assertion(
        RP_ID, cd2, resp2, reg["public_key_der"], res["sign_count"], challenge2,
        expected_origin=ORIGIN,
    )
    check("RP detects stalled signature counter", False, "accepted a replayed count")
except RpError as exc:
    check("RP detects stalled signature counter", True)
    print(f"      RP said: {exc}")

print("\n== wrong ceremony type is rejected ==")
try:
    bad = client_data("webauthn.get", challenge)
    verify_registration(
        RP_ID, bad, resp, challenge, expected_origin=ORIGIN
    )
    check("RP rejects wrong ceremony type", False, "accepted")
except RpError as exc:
    check("RP rejects wrong ceremony type", True)
    print(f"      RP said: {exc}")

print("\n== cross-origin replay is rejected ==")
try:
    foreign = client_data("webauthn.create", challenge, origin="https://evil.example")
    verify_registration(
        RP_ID, foreign, resp, challenge, expected_origin=ORIGIN
    )
    check("RP rejects foreign origin", False, "accepted")
except (RpError, KeyError) as exc:
    check("RP rejects foreign origin", True)
    print(f"      RP said: {exc}")

print("\n== attestation modes compared ==")
for mode in ("none", "packed_self", "packed_x5c"):
    a = Ctap2Authenticator(store_path=os.path.join(_temp.name, f"{mode}.json"),
                           attestation_mode=mode)
    r = webauthn_attestation(a.make_credential({
        1: os.urandom(32), 2: {"id": RP_ID, "name": "Lab"},
        3: {"id": os.urandom(16), "name": "u"},
        4: [{"type": "public-key", "alg": -7}], 7: {"rk": True},
    }))
    rep = inspect(r, r["authData"], os.urandom(32))
    sigs = len([f for f in rep.get("findings", []) if f["rp_can_reject"]])
    print(f"  {mode:14} fmt={r['fmt']:6} rejectable_signals={sigs}")
    if mode == "none":
        check("fmt=none is itself rejectable when attestation is required", sigs >= 1, sigs)
    if mode == "packed_self":
        check("self-attestation has no x5c", rep["attestation_chain_length"] == 0)

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
