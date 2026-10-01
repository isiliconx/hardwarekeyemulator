# language: Python 3.12, file: lab_server.py, runtime: flask
# *Local relying party. Serves a real WebAuthn registration + authentication page.
# *Binds to lab.example via a self-signed cert so the rpId matches the key scope —
# *WebAuthn requires a secure context and a correct rpId, so localhost alone won't
# *exercise the same path a deployed site hits.*
# *
# *  PYTHONPATH=../libs python3 lab_server.py --port 8443
# *  then open https://lab.example:8443 (add /etc/hosts entry: 127.0.0.1 lab.example)*

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time

from flask import Flask, jsonify, request, session

from ctap2_core import parse_attested_credential_id
from rp_verify import POLICY, RpError, verify_assertion, verify_registration

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab_users.json")
RP_ID = "lab.example"
ORIGIN = f"https://{RP_ID}:8443"
app.config["WEBAUTHN_ORIGIN"] = ORIGIN
DB_LOCK = threading.RLock()
# ponytail: one process owns challenges and DB; use shared storage for multiple workers.
PENDING_CHALLENGES = {}
CHALLENGE_TTL = 300
CHALLENGE_LOCK = threading.Lock()


def load_db() -> dict:
    with DB_LOCK:
        if os.path.exists(DB_PATH):
            with open(DB_PATH) as fh:
                return json.load(fh)
        return {}


def save_db(db: dict):
    with DB_LOCK:
        tmp = DB_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(db, fh, indent=1)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, DB_PATH)


def update_db(mutator):
    """Apply one read-modify-write transaction while holding the database lock."""
    with DB_LOCK:
        db = load_db()
        result = mutator(db)
        save_db(db)
        return result, db


def challenge() -> str:
    value = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(value).decode().rstrip("=")
    now = time.monotonic()
    with CHALLENGE_LOCK:
        for pending, expires in list(PENDING_CHALLENGES.items()):
            if expires <= now or pending == session.get("challenge"):
                PENDING_CHALLENGES.pop(pending, None)
        PENDING_CHALLENGES[encoded] = now + CHALLENGE_TTL
    session["challenge"] = encoded
    return encoded


def consume_challenge() -> bytes:
    encoded = session.pop("challenge", None)
    with CHALLENGE_LOCK:
        expires = PENDING_CHALLENGES.pop(encoded, None)
    if expires is None or expires <= time.monotonic():
        raise RpError("missing, expired, or already-consumed ceremony challenge")
    return base64.urlsafe_b64decode(encoded + "==")


# --------------------------------------------------------------------------- page

PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>FIDO2 Lab RP</title>
<style>
 body{font-family:ui-monospace,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}
 button{font:inherit;padding:.5rem 1rem;margin:.3rem;cursor:pointer}
 pre{background:#111;color:#0f0;padding:1rem;overflow:auto;border-radius:6px}
 .ok{color:#0a0}.bad{color:#a00}
</style></head><body>
<h1>FIDO2 Lab RP</h1>
<p>rpId: <code>%(rp_id)s</code> — register and authenticate against the emulated key.</p>
<button onclick="reg()">Register credential</button>
<button onclick="auth()">Authenticate</button>
<button onclick="attest()">Request attestation</button>
<pre id="out">ready.</pre>
<script>
const rpId = '__RP_ID__';
const out = document.getElementById('out');
const log = (o, ok) => {
  out.textContent = JSON.stringify(o, null, 2);
  out.className = ok ? 'ok' : 'bad';
};
// NOT async: an async b64() returns a Promise, which JSON-serialises to {} and
// leaves the RP receiving a dict where it expects a base64url string.
function b64(buf){ const s=new Uint8Array(buf); let t='';
  for (const b of s) t+=String.fromCharCode(b);
  return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function unb64(s){ s=s.replace(/-/g,'+').replace(/_/g,'/');
  const t=atob(s+'==='.slice((s.length+3)%4)); const a=new Uint8Array(t.length);
  for(let i=0;i<t.length;i++) a[i]=t.charCodeAt(i); return a; }
// b64url -> ArrayBuffer. b64() above already returns base64url, and passing that
// straight into unb64() gives back the string "[object Object]" — Array.from()
// on a typed array of bytes is what the challenge actually needs.
function b64urlToBuf(s){ return unb64(s).buffer; }

async function reg(){
  try{
    const ch = await (await fetch('/api/challenge')).json();
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: unb64(ch.challenge),
        rp: { id: rpId, name: 'Lab RP' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)),
                 name: 'binda', displayName: 'Binda' },
        pubKeyCredParams: [{type:'public-key', alg:-7},{type:'public-key', alg:-257}],
        authenticatorSelection: { residentKey:'required', userVerification:'required' },
        attestation: 'direct',
        timeout: 30000,
      }
    });
    const resp = {
      id: cred.id, type: cred.type,
      rawId: b64(cred.rawId),
      response: {
        clientDataJSON: b64(cred.response.clientDataJSON),
        attestationObject: b64(cred.response.attestationObject),
      },
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    };
    const r = await (await fetch('/api/register',{method:'POST',body:JSON.stringify(resp)})).json();
    log(r, r.ok !== false);
  }catch(e){ log({error:String(e)}); }
}

async function auth(){
  try{
    const ch = await (await fetch('/api/challenge')).json();
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: unb64(ch.challenge),
        rpId: rpId,
        userVerification: 'required',
        timeout: 30000,
      }
    });
    const resp = {
      id: cred.id, rawId: b64(cred.rawId),
      response: {
        clientDataJSON: b64(cred.response.clientDataJSON),
        authenticatorData: b64(cred.response.authenticatorData),
        signature: b64(cred.response.signature),
        userHandle: cred.response.userHandle ? b64(cred.response.userHandle) : null,
      },
    };
    const r = await (await fetch('/api/authenticate',{method:'POST',body:JSON.stringify(resp)})).json();
    log(r, r.ok !== false);
  }catch(e){ log({error:String(e)}); }
}

async function attest(){
  try{
    const ch = await (await fetch('/api/challenge')).json();
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: unb64(ch.challenge),
        rp: { id: rpId, name: 'Lab RP' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)),
                 name: 'binda', displayName: 'Binda' },
        pubKeyCredParams: [{type:'public-key', alg:-7}],
        authenticatorSelection: { residentKey:'required' },
        attestation: 'direct',
      }
    });
    const ao = JSON.parse(new TextDecoder().decode(
        Uint8Array.from(atob(cred.response.attestationObject), c=>c.charCodeAt(0))));
    log({
      attestation: ao.authenticatorData.slice(32,55) && 'see server',
      fmt: ao.attStmt ? Object.keys(ao.attStmt) : null,
      note: 'see /api/attestation for the analyser output',
    });
  }catch(e){ log({error:String(e)}); }
}
</script></body></html>"""


@app.route("/")
def index():
    return PAGE.replace("__RP_ID__", RP_ID)


# --------------------------------------------------------------------------- api

@app.route("/api/challenge")
def api_challenge():
    return jsonify({"challenge": challenge()})


@app.route("/api/register", methods=["POST"])
def api_register():
    import cbor2

    body = request.get_json(force=True)
    try:
        expected = consume_challenge()
    except RpError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    client_data = base64.urlsafe_b64decode(body["response"]["clientDataJSON"] + "==")
    att_obj = base64.urlsafe_b64decode(body["response"]["attestationObject"] + "==")

    try:
        parsed = cbor2.loads(att_obj)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"attestationObject not CBOR: {exc}"}), 400

    try:
        reg = verify_registration(
            RP_ID, client_data, parsed, expected,
            expected_origin=app.config["WEBAUTHN_ORIGIN"],
        )
    except RpError as exc:
        return jsonify({"ok": False, "error": str(exc),
                        "detail": "RP verification failed"}), 400

    key = base64.urlsafe_b64encode(reg["credential_id"]).decode()

    def store_registration(db):
        db[key] = {
            "public_key": base64.b64encode(reg["public_key_der"]).decode(),
            "sign_count": reg["sign_count"],
            "aaguid": reg["aaguid"].hex(),
            "fmt": reg["fmt"],
            "backup_eligible": reg["backup_eligible"],
            "backup_state": reg["backup_state"],
        }

    _, db = update_db(store_registration)

    return jsonify({
        "ok": True,
        "verified": True,
        "credential_id": reg["credential_id"].hex(),
        "aaguid": reg["aaguid"].hex(),
        "fmt": reg["fmt"],
        "sign_count": reg["sign_count"],
        "backup_eligible": reg["backup_eligible"],
        "backup_state": reg["backup_state"],
        "total_credentials": len(db),
    })


@app.route("/api/authenticate", methods=["POST"])
def api_authenticate():
    import cbor2

    body = request.get_json(force=True)
    try:
        expected = consume_challenge()
    except RpError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    client_data = base64.urlsafe_b64decode(body["response"]["clientDataJSON"] + "==")
    auth_data = base64.urlsafe_b64decode(body["response"]["authenticatorData"] + "==")
    signature = base64.urlsafe_b64decode(body["response"]["signature"] + "==")
    raw_id = base64.urlsafe_b64decode(body["rawId"] + "==")

    key = base64.urlsafe_b64encode(raw_id).decode()

    assertion = {
        1: {"type": "public-key", "id": raw_id},
        2: auth_data,
        3: signature,
        4: None,
    }
    def verify_and_advance(db):
        record = db.get(key)
        if not record:
            raise RpError("unknown credential")
        result = verify_assertion(
            RP_ID, client_data, assertion,
            base64.b64decode(record["public_key"]),
            record["sign_count"], expected,
            expected_origin=app.config["WEBAUTHN_ORIGIN"],
        )
        record["sign_count"] = result["sign_count"]
        return result

    try:
        res, _ = update_db(verify_and_advance)
    except RpError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    return jsonify({"ok": True, "verified": True,
                    "sign_count": res["sign_count"],
                    "flags": f"0x{auth_data[32]:02x}"})


def ensure_cert():
    """Self-signed cert for lab.example so rpId matches and the context is secure."""
    cert = os.path.join(os.path.dirname(DB_PATH), "lab.pem")
    key = os.path.join(os.path.dirname(DB_PATH), "lab.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "365",
        "-subj", f"/CN={RP_ID}",
        "-addext", f"subjectAltName=DNS:{RP_ID}",
    ], check=True, capture_output=True)
    return cert, key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    cert, key = ensure_cert()
    app.config["WEBAUTHN_ORIGIN"] = f"https://{RP_ID}:{args.port}"
    print(f"RP on {app.config['WEBAUTHN_ORIGIN']}  (cert: {cert})")
    print(f"add to /etc/hosts:  127.0.0.1  {RP_ID}")
    app.run(host=args.host, port=args.port,
            ssl_context=(cert, key), debug=False, threaded=True)


if __name__ == "__main__":
    main()
