# language: Python 3.12, file: diag_matrix.py, runtime: websockets
# *Narrow matrix: ctap2Version x residentKey x userVerification, one fresh
# *authenticator per case, reporting the exact CTAP-level error Chrome hits.*

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive_browser import PageSession, WAIT

RP = os.environ.get("RP_URL", "https://lab.example:8443")

JS = """
(async () => {
  const ch = await (await fetch('/api/challenge')).json();
  const s = ch.challenge.replace(/-/g,'+').replace(/_/g,'/');
  const t = atob(s+'==='.slice((s.length+3)%4));
  const a = new Uint8Array(t.length);
  for (let i=0;i<t.length;i++) a[i]=t.charCodeAt(i);
  try {
    const c = await Promise.race([
      navigator.credentials.create({
        publicKey: {
          challenge: a,
          rp: { id: 'lab.example', name: 'Lab RP' },
          user: { id: new Uint8Array([1,2,3,4,5,6,7,8]),
                  name: 'binda', displayName: 'Binda' },
          pubKeyCredParams: [{type:'public-key', alg:-7}],
          timeout: 8000,
        }
      }),
      new Promise((_,rej) => setTimeout(() => rej(new Error('client timeout')), 12000))
    ]);
    return 'OK';
  } catch (e) { return 'ERR ' + e.name; }
})()
"""


async def main():
    async with PageSession() as b:
        await b.open_page(RP)
        await b.evaluate("location.href", "location")
        print(f"{'ctap2':>9} {'rk':>5} {'uv':>5}  result")
        print("-" * 42)
        for version in ("ctap2_0", "ctap2_1", "ctap2_2"):
            for rk in (False, True):
                for uv in (False, True):
                    await b.add_authenticator(
                        transport="usb", resident_key=rk, user_verification=uv,
                        ctap2_version=version, automatic_presence=True,
                    )
                    out = await b.evaluate(WAIT.replace("@P", JS), "case")
                    print(f"{version:>9} {str(rk):>5} {str(uv):>5}  {out}")
                    await b.remove_authenticator()
        await b.close_page()


if __name__ == "__main__":
    asyncio.run(main())
