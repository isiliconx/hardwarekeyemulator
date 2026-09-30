# language: Python 3.12, file: drive_browser.py, runtime: websockets
# *Drives a real Chrome WebAuthn ceremony end to end: adds a virtual authenticator
# *that presents as a USB security key, opens the lab RP, runs the page's own
# *register()/auth(), and reports what Chrome actually sent to the relying party.*
# *
# *CRITICAL: virtual authenticators are scoped to the DevTools *session* that
# *created them. Adding one on the bridge's own session and then running the page
# *on a different session leaves the page with no authenticator, and the ceremony
# *hangs until timeout. Everything here therefore happens on ONE session.*

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chrome_bridge import ChromeBridge


class PageSession(ChromeBridge):
    """A bridge whose WebAuthn domain lives on the page's own session."""

    async def open_page(self, url: str, ignore_certs: bool = True):
        target = await self.call("Target.createTarget", {"url": "about:blank"})
        self.target_id = target["targetId"]
        attached = await self.call("Target.attachToTarget",
                                   {"targetId": self.target_id, "flatten": True})
        self.session_id = attached["sessionId"]

        await self.call("Page.enable", {}, session=self.session_id)
        await self.call("Runtime.enable", {}, session=self.session_id)
        if ignore_certs:
            await self.call("Security.enable", {}, session=self.session_id)
            await self.call("Security.setIgnoreCertificateErrors",
                            {"ignore": True}, session=self.session_id)

        # Enable WebAuthn *on the page session* — this is the line that makes the
        # whole thing work.
        await self.call("WebAuthn.enable", {"enableUI": False},
                        session=self.session_id)
        await self.call("Page.navigate", {"url": url}, session=self.session_id)
        return self.session_id

    async def evaluate(self, expr: str, label: str):
        """
        CDP Runtime.evaluate shape: {"result": {"result": {...}, "exceptionDetails": {...}}}.
        The payload is one level deeper than it looks, and an exception raised in
        the page lands in exceptionDetails — not in result. Getting either wrong
        silently yields a bare `{}` and looks like "no error".
        """
        res = await self.call("Runtime.evaluate", {
            "expression": expr,
            "awaitPromise": True,
            "returnByValue": True,
        }, session=self.session_id)

        exc = res.get("exceptionDetails")
        if exc:
            print(f"[driver] {label}: PAGE EXCEPTION "
                  f"{exc.get('exception', {}).get('description', exc.get('text'))}")
            return None

        out = res.get("result") or {}
        if out.get("subtype") == "error":
            print(f"[driver] {label}: EVAL ERROR {out.get('description')}")
            return None
        value = out.get("value")
        print(f"[driver] {label}: {json.dumps(value)[:500]}")
        return value

    async def close_page(self):
        try:
            await self.call("Target.closeTarget", {"targetId": self.target_id})
        except Exception:
            pass


WAIT = ("Promise.race([@P, new Promise(res => setTimeout(() => "
        "res('TIMEOUT: no authenticator responded'), 20000))])")


async def main():
    rp = os.environ.get("RP_URL", "https://lab.example:8443")

    async with PageSession() as b:
        await b.open_page(rp)
        print(f"[driver] page session {b.session_id[:12]} on {rp}")

        # Same session as the page — see the note at the top of the file.
        auth_id = await b.add_authenticator(
            transport="usb", resident_key=True, user_verification=True,
            automatic_presence=True,
        )
        print(f"[driver] virtual authenticator {auth_id} (transport=usb, rk, uv)")

        await asyncio.sleep(1)

        await b.evaluate("location.href + ' | ' + document.title", "location")
        await b.evaluate(
            "typeof PublicKeyCredential !== 'undefined' "
            "? 'WebAuthn API present' : 'MISSING'", "capability")

        print("\n[driver] --- registration ceremony ---")
        reg = await b.evaluate(
            f"{WAIT.replace('@P', 'reg()')}.then(() => "
            "document.getElementById('out').textContent)", "register")
        if reg and reg.strip().startswith("{"):
            try:
                for k, v in json.loads(reg).items():
                    print(f"[driver]   {k}: {v}")
            except Exception:
                pass

        creds = await b.credentials()
        print(f"[driver] credentials in authenticator: {len(creds)}")
        for c in creds:
            print(f"[driver]   rpId={c.get('rpId')} resident={c.get('isResidentCredential')} "
                  f"signCount={c.get('signCount')}")

        if creds:
            print("\n[driver] --- authentication ceremony ---")
            auth = await b.evaluate(
                f"{WAIT.replace('@P', 'auth()')}.then(() => "
                "document.getElementById('out').textContent)", "authenticate")
            if auth and auth.strip().startswith("{"):
                try:
                    for k, v in json.loads(auth).items():
                        print(f"[driver]   {k}: {v}")
                except Exception:
                    pass
            creds2 = await b.credentials()
            print(f"[driver] signCount after auth: {[c.get('signCount') for c in creds2]}")

        evts = [e["method"] for e in b.events if e["method"].startswith("WebAuthn.")]
        print(f"[driver] WebAuthn CDP events: {evts}")

        await b.remove_authenticator()
        await b.close_page()


if __name__ == "__main__":
    asyncio.run(main())
