# language: Python 3.12, file: policy_server.py, runtime: stdlib + flask + cbor2
# *The enforcement-gap demonstrator. ONE forged credential, FOUR RP policy
# *shapes, so the difference in verdict is attributable to policy and nothing else.
# *
# *Run this on infrastructure you own. The point is to read off which checks a
# *given verifier actually performs:
# *
# *   /api/register?strategy=A   no attestation gate at all
# *   /api/register?strategy=B   hardware == NOT backup-eligible (flag 0x08)
# *   /api/register?strategy=C   hardware == attestation PRESENT only  <-- the gap
# *   /api/register?strategy=D   hardware == verifies under a trusted FIDO root
# *
# *Submit the SAME forged attestation to all four. If C accepts it and D rejects
# *it, the verifier shape is now measured rather than guessed.
# *
# *Run:  PYTHONPATH=../libs python3 policy_server.py --port 8444
import base64
import hashlib
import json
import os
import sys

import cbor2
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from policy_lab import FIDO_MDS_AAGUIDS, FIDO_TRUSTED_ISSUERS, verify_attestation_sig

app = Flask(__name__)
app.secret_key = os.urandom(32)
RP_ID = "policy.example"
STORE = "/tmp/policy_server_db.json"
STRATEGIES = ("A", "B", "C", "D")


def _load():
    if os.path.exists(STORE):
        with open(STORE) as fh:
            return json.load(fh)
    return {}


def _save(db):
    with open(STORE, "w") as fh:
        json.dump(db, fh)


@app.route("/")
def index():
    rows = "\n".join(
        f"<tr><td><b>{s}</b></td><td>{desc}</td></tr>" for s, desc in [
            ("A", "no attestation gate"),
            ("B", "hardware == NOT backup-eligible"),
            ("C", "hardware == attestation PRESENT only (the gap)"),
            ("D", "hardware == verifies under trusted FIDO root"),
        ])
    return f"""<!doctype html><meta charset=utf-8><title>Policy Lab</title>
<style>
 body{{font:15px/1.6 system-ui,sans-serif;margin:40px;max-width:760px}}
 table{{border-collapse:collapse;margin:20px 0}} td,th{{border:1px solid #ccc;
 padding:8px 12px;text-align:left}} code{{background:#f4f4f4;padding:2px 5px}}
 button{{font:inherit;padding:8px 16px;margin-right:8px;cursor:pointer}}
 #out{{white-space:pre-wrap;font-family:ui-monospace,monospace;background:#f6f6f6;
 padding:14px;border:1px solid #ddd;min-height:120px}}
</style>
<h1>Policy Lab</h1>
<p>One forged credential, four enforcement shapes. Same input every time.</p>
<table><tr><th>Strategy</th><th>Check</th></tr>{rows}</table>
<button onclick="go('A')">Submit to A</button>
<button onclick="go('B')">Submit to B</button>
<button onclick="go('C')">Submit to C</button>
<button onclick="go('D')">Submit to D</button>
<div id=out>ready</div>
<script>
function b64(buf){{const s=new Uint8Array(buf);let t='';
 for(const b of s)t+=String.fromCharCode(b);
 return btoa(t).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}}
async function go(strategy){{
 const out=document.getElementById('out');
 out.textContent='submitting to strategy '+strategy+'...';
 try{{
  const ch=await (await fetch('/api/challenge')).json();
  const s=ch.challenge.replace(/-/g,'+').replace(/_/g,'/');
  const t=atob(s+'==='.slice((s.length+3)%4));
  const a=new Uint8Array(t.length);
  for(let i=0;i<t.length;i++)a[i]=t.charCodeAt(i);
  const c=await navigator.credentials.create({{publicKey:{{
   challenge:a,
   rp:{{id:location.hostname,name:'Policy Lab'}},
   user:{{id:new Uint8Array(16),name:'binda',displayName:'Binda'}},
   pubKeyCredParams:[{{type:'public-key',alg:-7}},{{type:'public-key',alg:-257}}],
   authenticatorSelection:{{residentKey:'preferred',userVerification:'required'}},
   attestation:'direct', timeout:15000}}}});
  const r=await fetch('/api/register?strategy='+strategy,{{
   method:'POST',headers:{{'Content-Type':'application/json'}},
   body:JSON.stringify({{response:{{
    clientDataJSON:b64(c.response.clientDataJSON),
    attestationObject:b64(c.response.attestationObject)}}}})}});
  const j=await r.json();
  out.textContent='strategy '+strategy+'\\n'+JSON.stringify(j,null,2);
 }}catch(e){{out.textContent='strategy '+strategy+'\\nERROR '+e.name+': '+e.message;}}
}}
</script>"""


@app.route("/api/challenge")
def api_challenge():
    import secrets
    from flask import session
    ch = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    session["challenge"] = ch
    return jsonify({"challenge": ch})


def classify(parsed, stmt, cdh, auth_data, strategy):
    """Return (counts_as_hardware, reason) for one strategy."""
    flags = auth_data[32]
    fmt = parsed.get("fmt", "none")
    has_att = fmt != "none"
    sig_ok, sig_reason = verify_attestation_sig(auth_data, cdh, fmt, stmt)
    aaguid = auth_data[37:53].hex()
    issuer = ""
    if stmt.get("x5c"):
        from cryptography import x509
        try:
            issuer = x509.load_der_x509_certificate(stmt["x5c"][0]).issuer.rfc4514_string()
        except Exception:
            pass

    if strategy == "A":
        return has_att, f"no gate; fmt={fmt}"
    if strategy == "B":
        return not (flags & 0x08), f"BE(0x08)={'set' if flags & 0x08 else 'clear'}"
    if strategy == "C":
        # THE GAP: presence only. Signature never inspected.
        return has_att, "attestation present, signature NOT verified"
    if strategy == "D":
        aaguid_ok = aaguid in FIDO_MDS_AAGUIDS
        issuer_ok = any(t in issuer for t in FIDO_TRUSTED_ISSUERS)
        return bool(sig_ok and aaguid_ok and issuer_ok), \
               f"sig_ok={sig_ok} aaguid_in_mds={aaguid_ok} issuer_trusted={issuer_ok}"
    raise ValueError(strategy)


@app.route("/api/register", methods=["POST"])
def api_register():
    strategy = (request.args.get("strategy") or "C").upper()
    if strategy not in STRATEGIES:
        return jsonify({"ok": False, "error": f"strategy must be one of {STRATEGIES}"}), 400

    body = request.get_json(force=True)
    client_data = base64.urlsafe_b64decode(body["response"]["clientDataJSON"] + "==")
    att_obj = base64.urlsafe_b64decode(body["response"]["attestationObject"] + "==")
    cdh = hashlib.sha256(client_data).digest()

    try:
        parsed = cbor2.loads(att_obj)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"not CBOR: {exc}"}), 400

    auth_data = parsed["authData"]
    stmt = parsed.get("attStmt") or {}
    fmt = parsed.get("fmt", "none")

    sig_ok, sig_reason = verify_attestation_sig(auth_data, cdh, fmt, stmt)
    hardware, reason = classify(parsed, stmt, cdh, auth_data, strategy)
    flags = auth_data[32]

    db = _load()
    verdict = {
        "strategy": strategy,
        "accepted": True,
        "counts_as_hardware_key": hardware,
        "reason": reason,
        "fmt": fmt,
        "flags": f"0x{flags:02x}",
        "backup_eligible": bool(flags & 0x08),
        "aaguid": auth_data[37:53].hex(),
        "attestation_signature_valid": sig_ok,
        "signature_note": sig_reason,
    }

    # Store it, so you can prove the accepted credential really is reusable.
    cred_id = auth_data[53:53 + 16]
    import struct
    clen = struct.unpack(">H", auth_data[53:55])[0]
    cred_id = auth_data[55:55 + clen]
    db[cred_id.hex()] = {
        "strategy": strategy,
        "counts_as_hardware_key": hardware,
        "signature_valid": sig_ok,
        "fmt": fmt,
    }
    _save(db)

    verdict["ok"] = True
    verdict["verified"] = True
    verdict["stored_credentials"] = len(db)
    return jsonify(verdict)


@app.route("/api/audit")
def api_audit():
    return jsonify({"store": _load()})


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    app.run(host=args.host, port=args.port, ssl_context="adhoc", threaded=True)
