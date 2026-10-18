#!/usr/bin/env python3
"""
Hold an AAGUID-rewrite shim in a real Chrome over CDP — the Daybreak edition of
hold_virtual_key.py.

Why: Chrome's CDP *virtual authenticator* reports a FIXED AAGUID
(01020304050607080102030405060708; measured on Chrome 154/155/158 — there is no
addVirtualAuthenticator option to change it), so registrations made through
hold_virtual_key.py land in the "Passkey" bucket at RPs that classify by model.
This script instead leaves the browser's authenticator alone and rewrites the
AAGUID inside the attestationObject the page receives, so the RP reads the
vendor model you choose (default: YubiKey 5C NFC fw 5.7.4+).

Chrome must be running with --remote-debugging-port=9222. Then:

  python3 hold_aaguid.py                       # default model, stay resident
  python3 hold_aaguid.py --profile 5-NFC-5.4   # a different model
  python3 hold_aaguid.py --aaguid <32 hex>     # arbitrary AAGUID
  python3 hold_aaguid.py --mode none           # fmt:'none' re-encode
  python3 hold_aaguid.py --once                # inject and exit

Stay resident and newly opened tabs are shimmed automatically. Sign-in
(assertion) ceremonies are untouched — assertions carry no AAGUID.

Modes:
  aaguid (default) — swap the AAGUID bytes, keep fmt/x5c/sig. The packed
      attestation signature no longer covers the modified authData, so an RP
      that verifies attestation signatures will reject; use --mode none there.
  none — re-encode as fmt "none" (the shape software passkeys commonly send):
      no signature exists to fail, the AAGUID is the identity.
"""
import argparse
import asyncio
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_profiles import get_profile

import websockets

SHIM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aaguid_shim.js")
_call_id = 0


def usable(target) -> bool:
    url = target.get("url") or ""
    return (target.get("type") == "page"
            and not url.startswith("devtools://")
            and not url.startswith("chrome://")
            and not url.startswith("chrome-extension://")
            and not url.startswith("edge://"))


def shim_source(aaguid_hex: str, mode: str = "aaguid") -> str:
    with open(SHIM_PATH) as fh:
        body = fh.read()
    return (f'window.__HKE_AAGUID__ = "{aaguid_hex}";\n'
            f'window.__HKE_SHIM_MODE__ = "{mode}";\n'
            + body)


async def call(ws, method, params=None, timeout=20):
    global _call_id
    _call_id += 1
    msg_id = _call_id
    await ws.send(json.dumps({"id": msg_id, "method": method,
                             "params": params or {}}))
    while True:
        raw = json.loads(await asyncio.wait_for(ws.recv(), timeout))
        if raw.get("id") == msg_id:
            if "error" in raw:
                raise RuntimeError(f"{method}: {raw['error']}")
            return raw.get("result", {})


async def attach(target, source) -> bool:
    async with websockets.connect(target["webSocketDebuggerUrl"],
                                  max_size=None) as ws:
        await call(ws, "Page.enable", {})
        await call(ws, "Page.addScriptToEvaluateOnNewDocument",
                   {"source": source})
        await call(ws, "Runtime.enable", {})
        await call(ws, "Runtime.evaluate", {"expression": source})
    return True


async def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dev", default="http://127.0.0.1:9222",
                    help="DevTools http endpoint of the Chrome to attach to")
    ap.add_argument("--profile", default="yubikey",
                    help="vendor model (vendor_profiles.py name or alias)")
    ap.add_argument("--aaguid", default=None,
                    help="override: arbitrary AAGUID (32 hex chars)")
    ap.add_argument("--mode", default="aaguid", choices=["aaguid", "none"],
                    help="aaguid: swap bytes, keep fmt/x5c/sig (sig no longer "
                         "covers authData); none: re-encode as fmt 'none'")
    ap.add_argument("--once", action="store_true",
                    help="inject into open tabs and exit")
    args = ap.parse_args()

    if args.aaguid:
        aaguid = args.aaguid.replace("-", "").lower()
        model = "custom AAGUID"
    else:
        profile = get_profile(args.profile)
        aaguid = profile.aaguid.replace("-", "").lower()
        model = f"{profile.model} [{profile.name}]"
    source = shim_source(aaguid, args.mode)

    print(f"[hke] model : {model}")
    print(f"[hke] aaguid: {aaguid}")
    print(f"[hke] mode  : {args.mode}")
    if args.mode == "aaguid":
        print("[hke] note  : the attestation signature no longer covers the "
              "modified authData; if the site verifies packed signatures, "
              "rerun with --mode none")

    injected = set()
    async def sweep() -> int:
        with urllib.request.urlopen(f"{args.dev}/json/list", timeout=8) as r:
            targets = json.load(r)
        fresh = [t for t in targets if usable(t) and t["id"] not in injected]
        for target in fresh:
            try:
                await attach(target, source)
                injected.add(target["id"])
                print(f"[hke] shim attached: {(target.get('url') or '')[:90]}")
            except Exception as exc:
                print(f"[hke] attach failed for {(target.get('url') or '')[:60]}: {exc}")
        return len(fresh)

    await sweep()
    print(f"[hke] attached to {len(injected)} tab(s)")
    if args.once:
        print("[hke] done (--once)")
        return
    print("[hke] resident — new tabs are shimmed automatically. "
          "Ctrl-C to release.")
    try:
        while True:
            await asyncio.sleep(3)
            await sweep()
    except KeyboardInterrupt:
        print("\n[hke] released")


if __name__ == "__main__":
    asyncio.run(main())
