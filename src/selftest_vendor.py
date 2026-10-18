# language: Python 3.12, file: selftest_vendor.py, runtime: cryptography + cbor2
# *Vendor-identity self-test: the whole Daybreak story in one script. Register
# *through the CTAP2 core over real CTAPHID framing as a YubiKey 5C NFC
# *(fw 5.7.4+), verify the RP view, walk the attestation, prove the assertion
# *path, then run the same classifier on the lab identity for contrast.*

import hashlib as _hashlib
import base64
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyze_attestation import inspect
from ctap2_core import (
    Ctap2Authenticator, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
    parse_attested_credential_id,
)
from ctaphid import CtapHidDevice, CtapHidDeviceSide, LoopbackTransport
from policy_lab import (classify, classify_daybreak, parse_attestation,
                        verify_attestation_sig)
from rp_verify import RpError, verify_assertion, verify_registration
from vendor_profiles import get_profile

_temp = tempfile.TemporaryDirectory(prefix="fido2lab-vendor-")

RP_ID = "lab.example"
ORIGIN = f"https://{RP_ID}"
PROFILE = "5C-NFC-5.7.4"
AAGUID = "d7781e5de35346aaafe23ca49f13332a"

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


def client_data(ceremony, challenge, origin=ORIGIN):
    return json.dumps({
        "type": ceremony,
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": origin,
        "crossOrigin": False,
    }).encode()


def webauthn_attestation(response):
    return {"fmt": response[1], "authData": response[2], "attStmt": response[3]}


def bring_up(profile):
    store = os.path.join(_temp.name, f"{profile or 'lab'}.json")
    auth = Ctap2Authenticator(store_path=store, profile=profile,
                              uv_gate=lambda: True)
    host_t = LoopbackTransport().open()
    dev_t = host_t.peer().open()
    side = CtapHidDeviceSide(dev_t, auth, verbose=False)
    threading.Thread(target=side.serve_forever, daemon=True).start()
    host = CtapHidDevice(host_t, verbose=False)
    host.init_sequence()
    return auth, host


def register(host):
    challenge = os.urandom(32)
    cd = client_data("webauthn.create", challenge)
    status, resp = host.make_credential({
        1: _hashlib.sha256(cd).digest(),
        2: {"id": RP_ID, "name": "Lab IdP"},
        3: {"id": os.urandom(16), "name": "binda", "displayName": "Binda"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True, "uv": True},
    })
    return status, webauthn_attestation(resp), cd, challenge


print("== vendor profile: registration over real CTAPHID framing ==")
profile = get_profile(PROFILE)
print(f"      model: {profile.model} | aaguid: {profile.aaguid}")
auth, host = bring_up(PROFILE)
status, resp, cd, challenge = register(host)
check("makeCredential returned OK", status == 0x00, hex(status))
check("authData carries the YubiKey 5C NFC AAGUID",
      resp["authData"][37:53].hex() == AAGUID, resp["authData"][37:53].hex())

reg = verify_registration(RP_ID, cd, resp, challenge, expected_origin=ORIGIN)
check("RP verified the vendor registration", bool(reg["credential_id"]))
check("RP read the model AAGUID", reg["aaguid"].hex() == AAGUID)
check("fmt is packed", reg["fmt"] == "packed", reg["fmt"])

print("\n== attestation analysis (what an RP can read) ==")
cd_hash = _hashlib.sha256(cd).digest()
analysis = inspect(resp, resp["authData"], cd_hash)
print(f"      aaguid identity: {analysis['aaguid_identity']}")
check("analyzer recognises the AAGUID", analysis["aaguid_known"] is True)
check("analyzer recognises the root NAME",
      analysis.get("root_is_trusted_fido_ca") is True)
check("chain length is three (leaf -> batch CA -> root)",
      analysis["attestation_chain_length"] == 3)
check("leaf is not self-issued", analysis["leaf_is_self_issued"] is False)
check("leaf carries the FIDO AAGUID extension",
      analysis["leaf_has_fido_extension"] is True)
check("packed signature verifies", analysis.get("self_signature_valid") is True)

print("\n== the honest limit, still enforced ==")
try:
    verify_registration(RP_ID, cd, resp, challenge, expected_origin=ORIGIN,
                        policy={"require_attestation": True})
    check("pinned-root policy rejects the lab chain", False, "accepted!")
except RpError as exc:
    check("pinned-root policy still rejects (no vendor private key)", True)
    print(f"      RP said: {exc}")

print("\n== Daybreak-shaped verdict ==")
parsed = parse_attestation(resp["authData"], resp["fmt"], resp["attStmt"])
sig_ok, sig_reason = verify_attestation_sig(resp["authData"], cd_hash,
                                            resp["fmt"], resp["attStmt"])
verdicts = classify(parsed, sig_ok)
daybreak = classify_daybreak(parsed)
check("signature valid under leaf key", sig_ok)
check("strategy E counts it as a hardware key",
      verdicts["E_DAYBREAK"]["counts_as_hardware_key"])
check("OpenAI-style label is 'Security key'", daybreak["label"] == "Security key")
print(f"      label: {daybreak['label']} | model: {daybreak['model']}")

print("\n== assertion path (sign-ins) ==")
challenge2 = os.urandom(32)
cd2 = client_data("webauthn.get", challenge2)
status2, resp2 = host.get_assertion({
    1: RP_ID,
    2: _hashlib.sha256(cd2).digest(),
    3: [{"type": "public-key", "id": reg["credential_id"], "transports": ["usb"]}],
    5: {"up": True, "uv": True},
})
check("getAssertion returned OK", status2 == 0x00, hex(status2))
res = verify_assertion(RP_ID, cd2, resp2, reg["public_key_der"],
                       reg["sign_count"], challenge2, expected_origin=ORIGIN)
check("RP verified the assertion", bool(res["credential_id"]))
check("assertion carries no attested data (sign-ins are identity-free)",
      len(resp2[2]) == 37, len(resp2[2]))

print("\n== same classifier, lab identity ==")
auth2, host2 = bring_up(None)
status3, resp3, cd3, challenge3 = register(host2)
check("lab makeCredential returned OK", status3 == 0x00, hex(status3))
parsed3 = parse_attestation(resp3["authData"], resp3["fmt"], resp3["attStmt"])
daybreak3 = classify_daybreak(parsed3)
check("lab identity files as 'Passkey'", daybreak3["label"] == "Passkey")
print(f"      label: {daybreak3['label']} | aaguid: {parsed3['aaguid']}")

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
