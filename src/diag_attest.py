# language: Python 3.12, file: diag_attest.py, runtime: websockets
# *Captures a REAL registration ceremony (real challenge, real clientDataJSON,
# *real attestationObject) and verifies the packed attestation signature the way a
# *spec-compliant RP does: over authData || SHA-256(clientDataJSON), using the key
# *in the x5c leaf certificate.*

import asyncio
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from drive_browser import PageSession

RP = os.environ.get("RP_URL", "https://lab.example:8443")

JS = """
(async () => {
  function b64(buf){ const s=new Uint8Array(buf); let t='';
    for (const b of s) t+=String.fromCharCode(b);
    return btoa(t).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }
  const ch = await (await fetch('/api/challenge')).json();
  const s = ch.challenge.replace(/-/g,'+').replace(/_/g,'/');
  const t = atob(s+'==='.slice((s.length+3)%4));
  const a = new Uint8Array(t.length);
  for (let i=0;i<t.length;i++) a[i]=t.charCodeAt(i);
  const c = await navigator.credentials.create({
    publicKey: {
      challenge: a,
      rp: { id: 'lab.example', name: 'Lab RP' },
      user: { id: new Uint8Array([1,2,3,4,5,6,7,8]),
              name: 'binda', displayName: 'Binda' },
      pubKeyCredParams: [{type:'public-key', alg:-7}],
      attestation: 'direct',
      timeout: 10000,
    }
  });
  return JSON.stringify({
    clientDataJSON: b64(c.response.clientDataJSON),
    attestationObject: b64(c.response.attestationObject),
    rawId: b64(c.rawId),
  });
})()
"""


async def main():
    async with PageSession() as b:
        await b.open_page(RP)
        await b.add_authenticator(transport="usb", resident_key=True,
                                  user_verification=True)
        out = await b.evaluate(JS, "capture")
        if not out:
            print("capture failed")
            return
        data = json.loads(out)

        cd = base64.urlsafe_b64decode(data["clientDataJSON"] + "==")
        ao = cbor2.loads(base64.urlsafe_b64decode(data["attestationObject"] + "=="))
        cd_hash = hashlib.sha256(cd).digest()
        ad = ao["authData"]
        stmt = ao["attStmt"]
        leaf = x509.load_der_x509_certificate(stmt["x5c"][0])

        print(f"fmt        : {ao['fmt']}")
        print(f"alg        : {stmt['alg']}")
        print(f"x5c length : {len(stmt['x5c'])}")
        print(f"leaf CN    : {leaf.subject.rfc4514_string()}")
        print(f"self-issued: {leaf.subject == leaf.issuer}")
        print(f"clientData : {cd.decode()[:110]}")
        print(f"cd_hash    : {cd_hash.hex()[:24]}…")
        print(f"authData   : {len(ad)} bytes, flags 0x{ad[32]:02x}")

        signed = ad + cd_hash
        for label, key in [("leaf cert key", leaf.public_key())]:
            try:
                key.verify(stmt["sig"], signed, ECDSA(hashes.SHA256()))
                print(f"\nVERIFIED with {label} over authData||clientDataHash")
            except Exception as exc:
                print(f"\nFAILED with {label}: {type(exc).__name__}")

        # Also try the credential public key (self-attestation shape).
        clen = int.from_bytes(ad[53:55], "big")
        cose = cbor2.loads(ad[55 + clen:])
        from cryptography.hazmat.primitives.asymmetric import ec
        ck = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"),
            ec.SECP256R1()).public_key()
        try:
            ck.verify(stmt["sig"], signed, ECDSA(hashes.SHA256()))
            print("VERIFIED with credential key (self-attestation shape)")
        except Exception as exc:
            print(f"not self-attestation: {type(exc).__name__}")

        with open("/tmp/real_ceremony.json", "w") as fh:
            json.dump({"clientDataJSON": data["clientDataJSON"],
                       "attestationObject": data["attestationObject"],
                       "rawId": data["rawId"]}, fh)
        print("\nsaved /tmp/real_ceremony.json")
        await b.close_page()


if __name__ == "__main__":
    asyncio.run(main())
