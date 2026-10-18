import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import cbor2
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctap2_core import Ctap2Authenticator

NODE = shutil.which("node")
YUBIKEY_5C_NFC = "d7781e5de35346aaafe23ca49f13332a"

pytestmark = pytest.mark.skipif(NODE is None, reason="node is required")

HARNESS = r'''
const [,, attHex, mode, shimPath] = process.argv;
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  let s = "";
  for (const x of new Uint8Array(b)) s += x.toString(16).padStart(2, "0");
  return s;
}
globalThis.window = globalThis;
globalThis.__HKE_AAGUID__ = "d7781e5de35346aaafe23ca49f13332a";
globalThis.__HKE_SHIM_MODE__ = mode;
const originalBytes = hexToBytes(attHex);
const originalBuffer = originalBytes.buffer.slice(0, originalBytes.length);
const fakeResponse = {
  attestationObject: originalBuffer,
  clientDataJSON: new Uint8Array([1, 2, 3]).buffer,
  getTransports: () => ["usb"],
};
const fakeCred = {
  type: "public-key",
  id: "credid",
  rawId: new Uint8Array(8).buffer,
  response: fakeResponse,
  getClientExtensionResults: () => ({}),
  authenticatorAttachment: "cross-platform",
};
let getSawAssertion = false;
// Node >=21 ships a built-in `navigator` global that cannot be reassigned, so
// the shim is evaluated with a shadowed `navigator` parameter instead.
const nav = {
  credentials: {
    create: async (opts) => fakeCred,
    get: async () => { getSawAssertion = true; },
  },
};
new Function("navigator", "window", "btoa",
             require("fs").readFileSync(shimPath, "utf8"))(
    nav, globalThis, btoa);
(async () => {
  const out = await nav.credentials.create({ publicKey: {} });
  await nav.credentials.get({});   // assertions must stay untouched
  console.log("RESULT:" + JSON.stringify({
    patchedHex: bytesToHex(out.response.attestationObject),
    passthrough: out.response.attestationObject === originalBuffer,
    json: out.toJSON ? out.toJSON() : null,
    getUntouched: getSawAssertion,
    transports: out.response.getTransports(),
  }));
})();
'''


def build_attestation_object(tmp_path, profile=None):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), profile=profile,
                              uv_gate=lambda: True)
    resp = auth.make_credential({
        1: b"\x11" * 32,
        2: {"id": "shim.example", "name": "Shim"},
        3: {"id": b"u", "name": "u", "displayName": "U"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True, "uv": True},
    })
    return cbor2.dumps({"fmt": resp[1], "authData": resp[2],
                        "attStmt": resp[3]}, canonical=True)


def run_shim(att_bytes, mode, tmp_path):
    harness = tmp_path / "harness.cjs"
    harness.write_text(HARNESS)
    proc = subprocess.run(
        [NODE, str(harness), att_bytes.hex(), mode,
         str(ROOT / "src" / "aaguid_shim.js")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT:"):
            return json.loads(line[len("RESULT:"):])
    raise AssertionError(f"no RESULT line: {proc.stdout!r} stderr={proc.stderr!r}")


def test_shim_patches_lab_attestation_to_yubikey(tmp_path):
    att = build_attestation_object(tmp_path)
    result = run_shim(att, "aaguid", tmp_path)
    parsed = cbor2.loads(bytes.fromhex(result["patchedHex"]))
    original = cbor2.loads(att)

    assert parsed["authData"][37:53].hex() == YUBIKEY_5C_NFC
    assert parsed["fmt"] == "packed"
    assert "x5c" in parsed["attStmt"] and "sig" in parsed["attStmt"]
    assert result["passthrough"] is False
    # only the 16 AAGUID bytes changed; everything else is byte-identical
    assert parsed["authData"][:37] == original["authData"][:37]
    assert parsed["authData"][53:] == original["authData"][53:]
    assert result["transports"] == ["usb"]
    assert result["getUntouched"] is True    # assertions carry no AAGUID


def test_shim_none_mode_reencodes(tmp_path):
    att = build_attestation_object(tmp_path)
    result = run_shim(att, "none", tmp_path)
    parsed = cbor2.loads(bytes.fromhex(result["patchedHex"]))
    original = cbor2.loads(att)

    assert parsed["fmt"] == "none"
    assert parsed["attStmt"] == {}
    assert parsed["authData"][37:53].hex() == YUBIKEY_5C_NFC
    assert parsed["authData"][:37] == original["authData"][:37]
    assert parsed["authData"][53:] == original["authData"][53:]


def test_shim_passthrough_when_already_patched(tmp_path):
    att = build_attestation_object(tmp_path, profile="5C-NFC-5.7.4")
    result = run_shim(att, "aaguid", tmp_path)
    assert result["passthrough"] is True
    assert bytes.fromhex(result["patchedHex"]) == att


def test_shim_passthrough_on_garbage(tmp_path):
    result = run_shim(os.urandom(64), "aaguid", tmp_path)
    assert result["passthrough"] is True


def test_shim_tojson_carries_patched_object(tmp_path):
    att = build_attestation_object(tmp_path)
    result = run_shim(att, "aaguid", tmp_path)
    payload = result["json"]
    assert payload["type"] == "public-key"
    inner = cbor2.loads(base64.urlsafe_b64decode(
        payload["response"]["attestationObject"] + "=="))
    assert inner["authData"][37:53].hex() == YUBIKEY_5C_NFC
    assert payload["response"]["transports"] == ["usb"]


def test_extension_shim_in_sync_with_canonical():
    src = (ROOT / "src" / "aaguid_shim.js").read_text()
    ext = (ROOT / "ext_aaguid_shim" / "shim.js").read_text()
    assert ext.endswith(src), "ext_aaguid_shim/shim.js must embed src/aaguid_shim.js verbatim"
    assert 'window.__HKE_AAGUID__' in ext
    manifest = json.loads((ROOT / "ext_aaguid_shim" / "manifest.json").read_text())
    script = manifest["content_scripts"][0]
    assert script["world"] == "MAIN"          # page world, so the RP's JS sees it
    assert script["run_at"] == "document_start"


def test_hold_aaguid_builds_configured_shim_source():
    import hold_aaguid
    source = hold_aaguid.shim_source(YUBIKEY_5C_NFC, "none")
    assert f'window.__HKE_AAGUID__ = "{YUBIKEY_5C_NFC}"' in source
    assert 'window.__HKE_SHIM_MODE__ = "none"' in source
    assert "findAuthData" in source
