#!/usr/bin/python3
"""
Keep a virtual FIDO2 authenticator attached to the real Chrome's blank tab and
STAY attached, so the key is present whenever the user clicks "add key".

Why a dedicated service: virtual authenticators are scoped to the DevTools
session that created them. A short-lived script that binds and exits takes the
device with it — the page then finds no key and hangs. So this stays resident,
holds the websocket open, and prints what it did.

  --persist : stay connected (default). Ctrl-C to release the key.
"""
import asyncio, json, sys, urllib.request, websockets

DEV = "http://127.0.0.1:9222"


async def main():
    persist = "--persist" in sys.argv or "-p" in sys.argv

    with urllib.request.urlopen(f"{DEV}/json/list", timeout=8) as r:
        targets = json.load(r)
    page = next((t for t in targets if t.get("type") == "page"), None)
    if not page:
        print("no page target"); sys.exit(1)
    print(f"attached to: {page['id']}  {page['url']}")

    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        nid = 0
        async def call(method, params=None, timeout=20):
            nonlocal nid
            nid += 1
            await ws.send(json.dumps({"id": nid, "method": method, "params": params or {}}))
            while True:
                # CDP frames are TEXT — recv() hands back a str, not a dict.
                raw = json.loads(await asyncio.wait_for(ws.recv(), timeout))
                if raw.get("method"):
                    continue
                if raw.get("id") == nid:
                    if "error" in raw:
                        raise RuntimeError(f"{method}: {raw['error']}")
                    return raw.get("result", {})

        # Enable on THIS session — the one holding the tab the user will use.
        await call("WebAuthn.enable", {"enableUI": False})
        print("WebAuthn domain enabled (enableUI=false)")

        auth_id = (await call("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2",
            "transport": "usb",
            "ctap2Version": "ctap2_2",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "hasLargeBlob": False,
            "hasCredBlob": False,
            "hasMinPinLength": False,
            "hasPrf": False,
            "automaticPresenceSimulation": True,
            "defaultBackupEligibility": False,
        }}))["authenticatorId"]
        print(f"virtual authenticator: {auth_id}  (transport=usb, rk, uv)")

        # MANDATORY. Without this the UV-capable device has no verified state and
        # Chromium fails every ceremony with CTAP 0x33 PIN_BLOCKED.
        await call("WebAuthn.setUserVerified",
                   {"authenticatorId": auth_id, "isUserVerified": True})
        print("setUserVerified(True) — 'touch' satisfied")

        res = await call("WebAuthn.getCredentials", {"authenticatorId": auth_id})
        print(f"credentials on key: {len(res.get('credentials', []))}")

        print("\nKEY IS LIVE. Switch to the Chrome window and click 'add key'.")
        print("If the page was already waiting, it will complete now.")
        print("Leave this process running. Ctrl-C to release the key.\n")

        if not persist:
            return

        # Stay resident. Report any credential the page registers, live.
        print("listening for WebAuthn events...")
        deadline_events = ["WebAuthn.credentialAdded", "WebAuthn.credentialAsserted",
                           "WebAuthn.credentialDeleted", "WebAuthn.credentialUpdated"]
        try:
            while True:
                raw = json.loads(await ws.recv())
                m = raw.get("method")
                if m in deadline_events:
                    p = raw.get("params", {})
                    c = p.get("credential", {})
                    print(f"  >> {m}: rpId={c.get('rpId')} "
                          f"signCount={c.get('signCount')} "
                          f"credId={p.get('credentialId','')[:24] or c.get('credentialId','')[:24]}")
                    if m == "WebAuthn.credentialAdded":
                        res = await call("WebAuthn.getCredentials",
                                         {"authenticatorId": auth_id})
                        print(f"     total credentials now: "
                              f"{len(res.get('credentials', []))}")
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\nreleasing key…")
        except websockets.ConnectionClosed:
            print("\ndevtools connection closed")
        except Exception as exc:
            print(f"\nlistener stopped: {type(exc).__name__}: {exc}")

asyncio.run(main())
