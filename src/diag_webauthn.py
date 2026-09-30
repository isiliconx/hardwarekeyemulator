# language: Python 3.12, file: diag_webauthn.py, runtime: websockets
# *Isolates why a ceremony stalls: walks a matrix of authenticator configs and
# *page-side requirements, reporting the exact error for each combination.*

import asyncio
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive_browser import PageSession, WAIT

RP = os.environ.get("RP_URL", "https://lab.example:8443")


async def one(b, label, auth_opts, page_opts):
    auth_id = await b.add_authenticator(**auth_opts)
    js = f"""
      (async () => {{
        const ch = await (await fetch('/api/challenge')).json();
        const s = ch.challenge.replace(/-/g,'+').replace(/_/g,'/');
        const t = atob(s+'==='.slice((s.length+3)%4));
        const a = new Uint8Array(t.length);
        for (let i=0;i<t.length;i++) a[i]=t.charCodeAt(i);
        try {{
          const c = await Promise.race([
            navigator.credentials.create({{
              publicKey: {{
                challenge: a,
                rp: {{ id: 'lab.example', name: 'Lab RP' }},
                user: {{ id: new Uint8Array([1,2,3,4,5,6,7,8]),
                         name: 'binda', displayName: 'Binda' }},
                pubKeyCredParams: [{{type:'public-key', alg:-7}}],
                timeout: 8000,
                {page_opts}
              }}
            }}),
            new Promise((_,rej) => setTimeout(
              () => rej(new Error('client-side timeout')), 10000))
          ]);
          return 'OK id=' + c.id.slice(0,20);
        }} catch (e) {{ return 'ERR ' + e.name + ': ' + e.message.slice(0,110); }}
      }})()
    """
    out = await b.evaluate(f"{WAIT.replace('@P', js)}", label)
    await b.remove_authenticator()
    return out


async def main():
    async with PageSession() as b:
        await b.open_page(RP)
        await b.evaluate("location.href", "location")

        # Does the browser see ANY authenticator at all?
        print("== baseline: ctu2, usb, no rk/uv, minimal page request ==")
        r = await one(b, "baseline",
                      dict(transport="usb", resident_key=False,
                           user_verification=False),
                      "")
        print(f"   -> {r}\n")

        cases = [
            ("rk=True on device, page asks nothing", dict(transport="usb",
                 resident_key=True, user_verification=False), ""),
            ("rk=True device + uv=True device, page asks nothing",
             dict(transport="usb", resident_key=True, user_verification=True), ""),
            ("rk=False device + uv=False device, page asks rk",
             dict(transport="usb", resident_key=False, user_verification=False),
             "authenticatorSelection: { residentKey: 'required' }"),
            ("rk required on page", dict(transport="usb", resident_key=True,
                                         user_verification=False),
             "authenticatorSelection: { residentKey: 'required' }"),
            ("uv required on page", dict(transport="usb", resident_key=False,
                                         user_verification=True),
             "authenticatorSelection: { userVerification: 'required' }"),
            ("both rk+uv", dict(transport="usb", resident_key=True,
                               user_verification=True),
             "authenticatorSelection: { residentKey:'required', userVerification:'required' }"),
            ("internal transport", dict(transport="internal", resident_key=True,
                                        user_verification=True),
             "authenticatorSelection: { residentKey:'required' }"),
            ("presence not automatic", dict(transport="usb", resident_key=True,
                                            user_verification=True,
                                            automatic_presence=False),
             "authenticatorSelection: { residentKey:'required' }"),
        ]
        for label, opts, page in cases:
            print(f"== {label} ==")
            r = await one(b, label, opts, page)
            print(f"   -> {r}\n")

        await b.close_page()


if __name__ == "__main__":
    asyncio.run(main())
