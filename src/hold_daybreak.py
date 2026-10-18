#!/usr/bin/env python3
"""
Daybreak one-command holder: Chrome virtual authenticator + AAGUID rewrite,
resident, for one tab in your real Chrome.

Why both: on a machine with no other authenticator (no uhid kernel support, no
USB key, no phone), the CDP *virtual authenticator* is what actually answers
the WebAuthn ceremony — but Chrome pins its AAGUID at
01020304050607080102030405060708 (measured on 154/155/158; no CDP option
exists), so registrations through it alone land in the "Passkey" bucket.
aaguid_shim.js rewrites the model the RP reads. This script holds both, on one
session, and prints the shim + WebAuthn events live.

  python3 src/hold_daybreak.py --tab chatgpt        # recommended: waits for a
                                                    # tab whose URL matches,
                                                    # then binds to it
  python3 src/hold_daybreak.py --mode aaguid       # keep the packed/x5c shape
  python3 src/hold_daybreak.py --profile 5-NFC-5.4  # a different model

Chrome must run with --remote-debugging-port=9222. Start this FIRST, open the
site, and do the enrollment IN THE TAB IT PRINTS. Reloads of that tab are
covered; closing it makes the holder rebind to the next matching tab.

Default mode is 'none' (recommended for OpenAI): the registration is
re-encoded as fmt 'none' — the shape password-manager passkeys send, which
OpenAI demonstrably accepts — carrying the YubiKey AAGUID, with no
contradictory certificate and no signature to fail verification. --mode aaguid
keeps the packed/x5c shape instead (the attestation signature then no longer
covers the modified authData).
"""
import argparse
import asyncio
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hold_aaguid import shim_source, usable
from vendor_profiles import get_profile

import websockets


async def find_tab(dev, needle):
    with urllib.request.urlopen(f"{dev}/json/list", timeout=8) as r:
        targets = json.load(r)
    pages = [t for t in targets if usable(t)]
    if needle:
        pages = [t for t in pages
                 if needle.lower() in (t.get("url") or "").lower()]
    return pages[0] if pages else None


def show(raw):
    method = raw.get("method")
    if method == "Runtime.consoleAPICalled":
        text = " ".join(str(a.get("value", "")) for a in
                        raw["params"].get("args", []))
        if "[hke]" in text:
            print(f"[page]      {text}", flush=True)
    elif method == "WebAuthn.credentialAdded":
        cred = raw["params"].get("credential", {})
        print(f"[webauthn]  credential added: rpId={cred.get('rpId')} "
              f"signCount={cred.get('signCount')}", flush=True)
    elif method == "WebAuthn.credentialAsserted":
        print("[webauthn]  credential asserted (sign-in worked)", flush=True)


async def hold(dev, page, source, model, aaguid, mode):
    """Attach authenticator + shim to one tab session and stay until it dies."""
    async with websockets.connect(page["webSocketDebuggerUrl"],
                                  max_size=None) as ws:
        nid = 0
        pending_events = []

        async def call(method, params=None, timeout=20):
            nonlocal nid
            nid += 1
            await ws.send(json.dumps({"id": nid, "method": method,
                                      "params": params or {}}))
            while True:
                raw = json.loads(await asyncio.wait_for(ws.recv(), timeout))
                if raw.get("method"):
                    pending_events.append(raw)
                    continue
                if raw.get("id") == nid:
                    if "error" in raw:
                        raise RuntimeError(f"{method}: {raw['error']}")
                    return raw.get("result", {})

        # *WebAuthn.enable is page-level; the authenticator is scoped to this
        # *session, which is why the enrollment must happen in this tab.*
        await call("Runtime.enable")
        await call("Page.enable")
        await call("WebAuthn.enable", {"enableUI": False})
        authenticator = (await call("WebAuthn.addVirtualAuthenticator",
                                   {"options": {
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
                                       "defaultBackupState": False,
                                   }}))["authenticatorId"]
        await call("WebAuthn.setUserVerified",
                   {"authenticatorId": authenticator, "isUserVerified": True})
        # *shim: every future navigation of this tab, plus the live document*
        await call("Page.addScriptToEvaluateOnNewDocument", {"source": source})
        await call("Runtime.evaluate", {"expression": source})
        for raw in pending_events:
            show(raw)

        print("[daybreak] virtual authenticator live (usb, rk, uv) — Chrome's "
              "own AAGUID is pinned, the shim corrects the model", flush=True)
        print(f"[daybreak] identity : {model}", flush=True)
        print(f"[daybreak] aaguid    : {aaguid}", flush=True)
        print(f"[daybreak] mode      : {mode}", flush=True)
        print(f"[daybreak] ENROLL IN THIS TAB: {page.get('url')}", flush=True)
        print("[daybreak] resident — reloads are covered; Ctrl-C to release.",
              flush=True)
        try:
            while True:
                raw = json.loads(await ws.recv())
                show(raw)
        except websockets.ConnectionClosed:
            print("[daybreak] tab closed — rebinding…", flush=True)


async def main():
    ap = argparse.ArgumentParser(
        description="Hold a Chrome virtual authenticator + the AAGUID shim "
                    "for one tab (Daybreak enrollment).")
    ap.add_argument("--dev", default="http://127.0.0.1:9222",
                    help="DevTools http endpoint of Chrome")
    ap.add_argument("--profile", default="yubikey",
                    help="vendor model (vendor_profiles.py name or alias)")
    ap.add_argument("--aaguid", default=None,
                    help="override: arbitrary AAGUID (32 hex chars)")
    ap.add_argument("--mode", default="none", choices=["aaguid", "none"],
                    help="'none' (default, recommended for OpenAI): fmt 'none' "
                         "re-encode; 'aaguid': keep packed/x5c shape")
    ap.add_argument("--tab", default=None,
                    help="bind to the first tab whose URL contains this "
                         "substring (e.g. 'chatgpt'); waits for it to appear")
    args = ap.parse_args()

    if args.aaguid:
        aaguid = args.aaguid.replace("-", "").lower()
        model = "custom AAGUID"
    else:
        profile = get_profile(args.profile)
        aaguid = profile.aaguid.replace("-", "").lower()
        model = f"{profile.model} [{profile.name}]"
    source = shim_source(aaguid, args.mode)

    print(f"[daybreak] identity : {model}")
    print(f"[daybreak] aaguid    : {aaguid}   mode: {args.mode}")

    waited = 0
    while True:
        page = await find_tab(args.dev, args.tab)
        if page is None:
            if waited == 0 or waited % 15 == 0:
                print(f"[daybreak] waiting for a tab matching {args.tab!r} "
                      "— open it now", flush=True)
            waited += 3
            await asyncio.sleep(3)
            continue
        try:
            await hold(args.dev, page, source, model, aaguid, args.mode)
        except KeyboardInterrupt:
            print("\n[daybreak] released")
            return
        except Exception as exc:
            print(f"[daybreak] session ended ({exc}); rebinding in 3s",
                  flush=True)
            await asyncio.sleep(3)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[daybreak] released")
