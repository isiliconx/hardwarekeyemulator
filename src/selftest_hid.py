# language: Python 3.12, file: selftest_hid.py, runtime: cbor2 + cryptography
# *exercises the CTAP2 core through real CTAPHID framing over the loopback carrier.*
# *if this passes, the same byte stream works over /dev/hidg0 — framing is the hard part.*

import os
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2
from ctap2_core import (
    Ctap2Authenticator, CtapError, FLAG_AT, FLAG_UP, FLAG_UV,
    parse_attested_credential_id,
)
from ctaphid import (
    CtapHidDevice, CtapHidDeviceSide, LoopbackTransport, CMD_INIT, CMD_CBOR,
)

STORE = "/tmp/fido2lab-selftest/creds.json"
os.makedirs("/tmp/fido2lab-selftest", exist_ok=True)
if os.path.exists(STORE):
    os.remove(STORE)

RP_ID = "lab.example"
ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


print("== boot authenticator + device side ==")
auth = Ctap2Authenticator(store_path=STORE, attestation_mode="packed_x5c")
dev_a = LoopbackTransport().open()          # host side carrier
dev_b = dev_a.peer().open()                # device side carrier
side = CtapHidDeviceSide(dev_b, auth, verbose=True)
threading.Thread(target=side.serve_forever, daemon=True).start()

print("== CTAPHID INIT handshake ==")
host = CtapHidDevice(dev_a, auth)
channel = host.init_sequence()
check("channel allocated", isinstance(channel, int) and channel != 0xFFFFFFFF)
check("channel nonzero", channel != 0)

print("== CBOR PING ==")
pong = host.ping(b"hello")
check("ping echo", pong == b"hello", pong)

print("== authenticatorGetInfo (0x04) ==")
info = host.get_info()
check("info has versions", 1 in info and -7 in info[1], list(info))
check("info advertises ES256", -7 in info[1])
check("rk supported", info[0x0C]["rk"] is True)
print("   versions:", info[1], "maxMsgSize:", info.get(2))

print("== large payload fragmentation (multi-frame CONT) ==")
big = os.urandom(400)
ping_big = host.ping(big)
check(f"{len(big)}-byte ping round-trips through CONT frames", ping_big == big,
      f"got {len(ping_big)}")

print("== authenticatorMakeCredential (0x01) ==")
client_data_hash = os.urandom(32)
# Numeric keys exactly as a browser sends them: 1=clientDataHash, 2=rp, 3=user,
# 4=pubKeyCredParams, 5=excludeList, 7=options.
params = {
    1: client_data_hash,
    2: {"id": RP_ID, "name": "Lab IdP"},
    3: {"id": os.urandom(16).hex(), "name": "binda", "displayName": "Binda"},
    4: [{"type": "public-key", "alg": -7}],
    7: {"rk": True},
}
status, resp = host.make_credential(params)
check("makeCredential status OK", status == 0x00, hex(status))
check("response has fmt", "fmt" in resp, list(resp))
check("fmt is packed", resp.get("fmt") == "packed", resp.get("fmt"))
auth_data = resp["authData"]
check("AT flag set", auth_data[32] & FLAG_AT != 0)
check("UP flag set", auth_data[32] & FLAG_UP != 0)
check("UV flag set", auth_data[32] & FLAG_UV != 0, hex(auth_data[32]))
# Per spec the credential ID is not a CBOR response field — parse it from authData.
cred_id = parse_attested_credential_id(resp["authData"])
check("credentialId parsed from authData", len(cred_id) == 32, len(cred_id))
check("x5c has leaf + root", len(resp["attStmt"]["x5c"]) == 2,
      len(resp["attStmt"].get("x5c", [])))
check("user present in store", len(auth.list_credentials(RP_ID)) == 1)

print("== authenticatorGetAssertion (0x02) ==")
assert_params = {
    1: RP_ID,
    2: client_data_hash,
    3: [{"type": "public-key", "id": cred_id.hex(), "transports": ["usb"]}],
    5: {"up": True, "uv": True},
}
status2, resp2 = host.get_assertion(assert_params)
check("getAssertion status OK", status2 == 0x00, hex(status2))
check("assertion returns credentialId", resp2[1] == cred_id)
check("signature present", len(resp2[3]) > 0)
check("no AT flag on assertion", resp2[2][32] & FLAG_AT == 0)
check("signCount in authData", struct.unpack(">I", resp2[2][33:37])[0] >= 1,
      struct.unpack(">I", resp2[2][33:37])[0])

print("== resident credential lookup (no allowList) ==")
status3, resp3 = host.get_assertion({1: RP_ID, 2: client_data_hash})
check("discoverable assertion OK", status3 == 0x00, hex(status3))
check("same credential", resp3[1] == cred_id)
check("user entity returned", resp3.get(4) is not None)

print("== wrong rpId is rejected ==")
status4, _ = host.get_assertion({1: "evil.example", 2: client_data_hash,
                                  3: [{"type": "public-key", "id": cred_id.hex()}]})
check("foreign rpId -> CTAP2_ERR_NO_CREDENTIALS", status4 == 0x2F, hex(status4))

print("== excludeList blocks re-registration ==")
status5, _ = host.make_credential({**params, 5: [{"type": "public-key", "id": cred_id.hex()}]})
check("excludeList -> CTAP2_ERR_CREDENTIAL_EXCLUDED", status5 == 0x19, hex(status5))

print("== unsupported algorithm ==")
status6, _ = host.make_credential({**params, 4: [{"type": "public-key", "alg": -8}]})
check("ES256-only -> CTAP2_ERR_UNSUPPORTED_ALGORITHM", status6 == 0x26, hex(status6))

# A refused UP/UV must come back as a CTAP2 *status byte* on the wire, not a
# transport exception — that is what a real key does and what browsers expect.
print("== UP gate that refuses ==")
auth.up_gate = lambda: False
st, _ = host.make_credential(params)
check("UP refusal -> CTAP2_ERR_UP_REQUIRED (0x3b)", st == 0x3B, hex(st))
auth.up_gate = lambda: True

print("== UV gate that refuses ==")
auth.uv_gate = lambda: False
st, _ = host.make_credential(params)
check("UV refusal -> CTAP2_ERR_UV_BLOCKED (0x3c)", st == 0x3C, hex(st))
auth.uv_gate = lambda: True
auth._uv_retries = 8
auth._uv_blocked = False
auth.save()

print("== persistence across restart ==")
sid = auth.list_credentials(RP_ID)[0]
auth2 = Ctap2Authenticator(store_path=STORE)
check("credential survived reload", len(auth2.list_credentials(RP_ID)) == 1)
check("same credentialId", auth2.list_credentials(RP_ID)[0].credential_id == cred_id)
check("aaguid persisted", auth2._ca.aaguid == auth._ca.aaguid)
check("attestation CA persisted", auth2._ca.root_cert_der == auth._ca.root_cert_der)

print("== attestation modes ==")
for mode in ("none", "packed_self", "packed_x5c"):
    a = Ctap2Authenticator(store_path=f"/tmp/fido2lab-selftest/m-{mode}.json",
                           attestation_mode=mode)
    r = a.make_credential({
        1: os.urandom(32), 2: {"id": RP_ID, "name": "Lab"},
        3: {"id": os.urandom(16).hex(), "name": "u"}, 4: [{"alg": -7}],
    })
    if mode == "none":
        check("fmt=none, empty stmt", r["fmt"] == "none" and r["attStmt"] == {})
    elif mode == "packed_self":
        check("fmt=packed self-attestation", r["fmt"] == "packed" and r["attStmt"]["x5c"] == [])
    else:
        check("fmt=packed with x5c chain", r["fmt"] == "packed" and len(r["attStmt"]["x5c"]) == 2)

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
