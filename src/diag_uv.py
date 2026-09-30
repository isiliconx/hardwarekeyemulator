# language: Python 3.12, file: diag_uv.py, runtime: websockets
# *UV-capable virtual authenticators are the one config that fails. CDP exposes
# *WebAuthn.setUserVerified for exactly this — test whether calling it after the
# *device is added clears the CTAP error Chromium reports (code 51 / status 3).*

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

        print("== UV device + explicit setUserVerified(True) ==")
        await b.add_authenticator(transport="usb", resident_key=True,
                                  user_verification=True, automatic_presence=True)
        await b.set_user_verified(True)
        print("   ->", await b.evaluate(WAIT.replace("@P", JS), "uv+setUserVerified"))
        await b.remove_authenticator()

        print("\n== UV device + hasMinPinLength=False explicit ==")
        await b.add_authenticator(transport="usb", resident_key=True,
                                  user_verification=True, automatic_presence=True)
        print("   ->", await b.evaluate(WAIT.replace("@P", JS), "uv repeat"))
        await b.remove_authenticator()

        print("\n== UV device, page does NOT require uv (device still UV-capable) ==")
        await b.add_authenticator(transport="usb", resident_key=True,
                                  user_verification=True, automatic_presence=True)
        await b.set_user_verified(False)
        print("   ->", await b.evaluate(WAIT.replace("@P", JS), "uv set false"))
        await b.set_user_verified(True)
        print("   ->", await b.evaluate(WAIT.replace("@P", JS), "uv set true"))
        await b.remove_authenticator()

        await b.close_page()


if __name__ == "__main__":
    asyncio.run(main())
