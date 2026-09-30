#!/usr/bin/python3
"""
Submit ONE credential to all four policy strategies and read back the verdicts.

This is the measurement, not a demo: the same browser, the same virtual
authenticator, the same challenge shape. Only the RP-side policy differs, so any
difference in verdict is attributable to the check and nothing else.
"""
import asyncio, json, sys, urllib.request, websockets

DEV = "http://127.0.0.1:9222"
RP = "https://policy.example:8444"

JS_TEMPLATE = r"""
(async () => {
  function b64(buf){
    const s = new Uint8Array(buf);
    let t = '';
    for (const b of s) t += String.fromCharCode(b);
    return btoa(t).split('+').join('-').split('/').join('_').replace(/=+$/, '');
  }
  const results = {};
  for (const strategy of ['A','B','C','D']) {
    try {
      const ch = await (await fetch('/api/challenge')).json();
      const s = ch.challenge.replace(/-/g,'+').replace(/_/g,'/');
      const t = atob(s+'==='.slice((s.length+3)%4));
      const a = new Uint8Array(t.length);
      for(let i=0;i<t.length;i++) a[i]=t.charCodeAt(i);
      const c = await Promise.race([
        navigator.credentials.create({publicKey:{
          challenge:a,
          rp:{id:location.hostname,name:'Policy Lab'},
          user:{id:new Uint8Array(16),name:'binda',displayName:'Binda'},
          pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
          authenticatorSelection:{residentKey:'preferred',userVerification:'required'},
          attestation:'direct', timeout:12000}}),
        new Promise((_,r)=>setTimeout(()=>r(new Error('timeout-12s')),15000))]);
      const r = await fetch('/api/register?strategy='+strategy, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({response:{
          clientDataJSON: b64(c.response.clientDataJSON),
          attestationObject: b64(c.response.attestationObject)}})});
      results[strategy] = await r.json();
    } catch(e) { results[strategy] = {error: e.name+': '+e.message.slice(0,140)}; }
  }
  return JSON.stringify(results);
})()
"""


async def main():
    with urllib.request.urlopen(f"{DEV}/json/list", timeout=8) as r:
        targets = json.load(r)
    page = next((t for t in targets if t.get("type") == "page"
                 and "devtools" not in (t.get("url") or "")), None)
    if not page:
        print("no usable page"); sys.exit(1)
    print("attached:", page["id"], page["url"])

    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        nid = 0
        async def call(m, p=None, timeout=30):
            nonlocal nid
            nid += 1
            await ws.send(json.dumps({"id": nid, "method": m, "params": p or {}}))
            while True:
                raw = json.loads(await asyncio.wait_for(ws.recv(), timeout))
                if raw.get("method"): continue
                if raw.get("id") == nid:
                    if "error" in raw: raise RuntimeError(f"{m}: {raw['error']}")
                    return raw.get("result", {})

        async def ev(expr, label):
            res = await call("Runtime.evaluate",
                             {"expression": expr, "awaitPromise": True,
                              "returnByValue": True})
            if res.get("exceptionDetails"):
                ex = res["exceptionDetails"]
                det = ex.get("exception") or {}
                print(f"  {label}: EXC {ex.get('text')} "
                      f"{det.get('description','')[:400]}")
                return None
            return (res.get("result") or {}).get("value")

        await call("WebAuthn.enable", {"enableUI": False})
        await call("Page.enable")
        await call("Security.enable")
        await call("Security.setIgnoreCertificateErrors", {"ignore": True})

        # One authenticator, BE clear, so strategy B is exercised honestly.
        aid = (await call("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "usb", "ctap2Version": "ctap2_2",
            "hasResidentKey": True, "hasUserVerification": True,
            "automaticPresenceSimulation": True,
            "defaultBackupEligibility": False,
        }}))["authenticatorId"]
        await call("WebAuthn.setUserVerified",
                   {"authenticatorId": aid, "isUserVerified": True})
        print("virtual key: usb / uv / defaultBackupEligibility=False")

        await call("Page.navigate", {"url": RP})
        await asyncio.sleep(6)

        out = await ev(JS_TEMPLATE, "submit-4")
        if not out:
            print("  submission failed"); return
        res = json.loads(out)

        print("\n" + "=" * 72)
        print(" SAME CREDENTIAL, FOUR RP ENFORCEMENT SHAPES")
        print("=" * 72)
        print(f"\n  {'strat':<6} {'counts_as_hardware':<20} {'attest sig':<14} reason")
        for s in ("A", "B", "C", "D"):
            r = res.get(s, {})
            if "error" in r:
                print(f"  {s:<6} ERROR  {r['error'][:60]}")
                continue
            hw = "YES" if r.get("counts_as_hardware_key") else "no"
            sig = "valid" if r.get("attestation_signature_valid") else "n/a"
            print(f"  {s:<6} {hw:<20} {sig:<14} {r.get('reason','')[:46]}")
            print(f"         fmt={r.get('fmt')} flags={r.get('flags')} "
                  f"BE={r.get('backup_eligible')}")

        print("\n-- audit store (what the RP actually persisted) --")
        print(await ev("fetch('/api/audit').then(r=>r.text())", "audit"))

        print("\n-- interpretation --")
        c_hw = res.get("C", {}).get("counts_as_hardware_key")
        d_hw = res.get("D", {}).get("counts_as_hardware_key")
        if c_hw and not d_hw:
            print("  C accepted it and D rejected it. The difference is the")
            print("  signature check. A verifier shaped like C treats")
            print("  attestation:'direct' as decorative.")
        elif d_hw:
            print("  D counted it as hardware — the local CA verified, because")
            print("  this lab trusts its own root. That is expected in the lab and")
            print("  is exactly what a real FIDO RP will NOT do.")
        else:
            print("  Read the table: only the strategies that inspect the")
            print("  signature (D) rejected the credential.")

asyncio.run(main())
