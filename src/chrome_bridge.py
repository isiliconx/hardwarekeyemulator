# language: Python 3.12, file: chrome_bridge.py, runtime: websockets (CDP over WS)
# *Chrome integration. Chrome has no plugin API for authenticators — the supported
# *surface is the DevTools Protocol's WebAuthn domain. This bridges the CTAP2 core
# *above into a real Chrome virtual authenticator, so Chrome presents it to the page
# *as a roaming CTAP2 security key (usb / nfc / ble), not a synced passkey.*
# *
# *CRITICAL HONESTY NOTE: Chrome's own VirtualFidoDevice signs attestation with a
# *Chromium-generated CA, so this route CANNOT carry a YubiKey-style attestation
# *chain. The CTAPHID path (ctaphid.py) is the one that speaks the real USB wire
# *protocol. This bridge exists to drive the browser end of the lab, and to make
# *the RP-visible difference measurable.*

import asyncio
import base64
import json
import os
import sys

import websockets

from ctap2_core import Ctap2Authenticator

CDP_HOST = os.environ.get("CDP_HOST", "127.0.0.1")
CDP_PORT = int(os.environ.get("CDP_PORT", "9333"))

TRANSPORTS = ("usb", "nfc", "ble", "internal", "cable", "hybrid", "smart-card")


class ChromeBridge:
    """
    Drives the WebAuthn CDP domain against a running Chrome instance.

    The WebAuthn domain is a *page*-level domain, not a browser-level one: sending
    WebAuthn.enable on the browser websocket returns -32601. So we connect to a page
    target (or create one with Target.createTarget) and speak the protocol there.
    """

    def __init__(self, host: str = CDP_HOST, port: int = CDP_PORT):
        self.host = host
        self.port = port
        self.ws = None
        self.target_id = None
        self.session_id = None
        self._id = 0
        self.auth: Ctap2Authenticator = None
        self.authenticator_id = None
        self.events: list = []
        self.skip_default_enable = False

    # ------------------------------------------------------------------ plumbing

    async def __aenter__(self):
        import urllib.request
        with urllib.request.urlopen(f"http://{self.host}:{self.port}/json/version") as r:
            browser_ws = json.load(r)["webSocketDebuggerUrl"]
        self.ws = await websockets.connect(browser_ws, max_size=None)

        # Open a page target and attach a flattened session to it.
        target = await self.call("Target.createTarget", {"url": "about:blank"})
        self.target_id = target["targetId"]
        attached = await self.call("Target.attachToTarget", {
            "targetId": self.target_id, "flatten": True,
        })
        self.session_id = attached["sessionId"]

        if not self.skip_default_enable:
            await self.call("WebAuthn.enable", {"enableUI": False},
                            session=self.session_id)
        return self

    async def __aexit__(self, *exc):
        if self.ws:
            try:
                await self.call("Target.closeTarget", {"targetId": self.target_id})
            except Exception:
                pass
            await self.ws.close()

    def _ws_url(self) -> str:
        import urllib.request
        with urllib.request.urlopen(f"http://{self.host}:{self.port}/json/version") as r:
            return json.load(r)["webSocketDebuggerUrl"]

    async def call(self, method: str, params: dict = None, session: str = None):
        self._id += 1
        msg_id = self._id
        msg = {"id": msg_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        await self.ws.send(json.dumps(msg))
        while True:
            raw = json.loads(await self.ws.recv())
            if raw.get("method"):
                if raw.get("sessionId") in (None, self.session_id):
                    self.events.append(raw)
                continue
            if raw.get("id") == msg_id:
                if "error" in raw:
                    raise RuntimeError(f"{method}: {raw['error']}")
                return raw.get("result", {})

    # ------------------------------------------------------------------ lifecycle

    async def add_authenticator(self, transport: str = "usb",
                                resident_key: bool = True,
                                user_verification: bool = True,
                                ctap2_version: str = "ctap2_2",
                                automatic_presence: bool = True,
                                backup_eligibility: bool = False) -> str:
        """
        Add a virtual authenticator that Chrome surfaces as a security key.

        `transport` is what the page sees in PublicKeyCredential.getTransports()
        and in authenticator.attestationTransport — this is the knob that makes it
        present as USB/NFC/BLE hardware rather than a synced passkey.
        """
        if transport not in TRANSPORTS:
            raise ValueError(f"transport must be one of {TRANSPORTS}")
        result = await self.call("WebAuthn.addVirtualAuthenticator", {
            "options": {
                "protocol": "ctap2",
                "transport": transport,
                "ctap2Version": ctap2_version,
                "hasResidentKey": resident_key,
                "hasUserVerification": user_verification,
                "hasLargeBlob": False,
                "hasCredBlob": False,
                "hasMinPinLength": False,
                "hasPrf": False,
                "automaticPresenceSimulation": automatic_presence,
                "defaultBackupEligibility": backup_eligibility,
            }
        }, session=self.session_id)
        self.authenticator_id = result["authenticatorId"]

        # REQUIRED for UV-capable devices: without this explicit call Chromium's
        # VirtualFidoDevice has no verified state and the ceremony fails with
        # CTAP error 51 (0x33 PIN_BLOCKED) -> WebAuthn NotAllowedError. This call
        # is the software equivalent of the finger-on-sensor / PIN entry that a
        # real key demands before it will assert UV. Verified against Chrome 148:
        # every hasUserVerification=True config fails without it.
        if user_verification:
            await self.set_user_verified(True)
        return self.authenticator_id

    async def seed_credential(self, rp_id: str, user_handle: bytes,
                              user_name: str = "binda",
                              user_display_name: str = "Binda",
                              resident: bool = True) -> str:
        """
        Pre-load a credential into the virtual authenticator, as if it had been
        registered earlier. Private key is supplied in PKCS#8 base64, per CDP.

        This is how a persistent credential store gets mirrored into the browser:
        register once, dump the credential, reload it after every restart.
        """
        key = _gen_p256_pkcs8()
        cred_id = os.urandom(32)
        await self.call("WebAuthn.addCredential", {
            "authenticatorId": self.authenticator_id,
            "credential": {
                "credentialId": base64.b64encode(cred_id).decode(),
                "isResidentCredential": resident,
                "privateKey": base64.b64encode(key).decode(),
                "signCount": 0,
                "rpId": rp_id,
                "userHandle": base64.b64encode(user_handle).decode(),
                "userName": user_name,
                "userDisplayName": user_display_name,
            },
        }, session=self.session_id)
        return cred_id.hex()

    async def set_user_verified(self, verified: bool = True):
        """Toggle the UV signal — this is the software stand-in for a fingerprint."""
        await self.call("WebAuthn.setUserVerified", {
            "authenticatorId": self.authenticator_id, "isUserVerified": verified,
        }, session=self.session_id)

    async def set_automatic_presence(self, enabled: bool):
        """
        enabled=True  -> touch is simulated instantly
        enabled=False -> the ceremony hangs until someone 'touches' the device
        """
        await self.call("WebAuthn.setAutomaticPresenceSimulation", {
            "authenticatorId": self.authenticator_id, "enabled": enabled,
        }, session=self.session_id)

    async def set_bad_bits(self, bad_uv: bool = False, bad_up: bool = False,
                           bogus_signature: bool = False):
        """Inject failure modes — useful for testing an RP's error handling."""
        await self.call("WebAuthn.setResponseOverrideBits", {
            "authenticatorId": self.authenticator_id,
            "isBadUV": bad_uv, "isBadUP": bad_up,
            "isBogusSignature": bogus_signature,
        }, session=self.session_id)

    async def credentials(self) -> list:
        result = await self.call("WebAuthn.getCredentials", {
            "authenticatorId": self.authenticator_id,
        }, session=self.session_id)
        return result.get("credentials", [])

    async def dump_store(self, path: str):
        """Persist the browser-side credential set to JSON for reload after restart."""
        creds = await self.credentials()
        with open(path, "w") as fh:
            json.dump(creds, fh, indent=1)
        return len(creds)

    async def load_store(self, path: str) -> int:
        with open(path) as fh:
            creds = json.load(fh)
        for cred in creds:
            await self.call("WebAuthn.addCredential", {
                "authenticatorId": self.authenticator_id, "credential": cred,
            }, session=self.session_id)
        return len(creds)

    async def remove_authenticator(self):
        if self.authenticator_id:
            await self.call("WebAuthn.removeVirtualAuthenticator",
                            {"authenticatorId": self.authenticator_id},
                            session=self.session_id)
            self.authenticator_id = None


def _gen_p256_pkcs8() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


# --------------------------------------------------------------------------- demo


async def main():
    """Attach to Chrome, add a USB-presenting authenticator, report what it is."""
    async with ChromeBridge() as bridge:
        auth_id = await bridge.add_authenticator(
            transport="usb", resident_key=True, user_verification=True,
        )
        print(f"virtual authenticator: {auth_id}")

        cred = await bridge.seed_credential("lab.example", os.urandom(16))
        print(f"seeded credential: {cred[:16]}…")

        creds = await bridge.credentials()
        print(f"credentials held: {len(creds)}")
        for c in creds:
            print(f"  rpId={c.get('rpId')} resident={c.get('isResidentCredential')} "
                  f"signCount={c.get('signCount')} transports=usb")

        events = [e["method"] for e in bridge.events]
        print(f"WebAuthn events seen: {events or 'none yet — drive the page to see them'}")

        await bridge.remove_authenticator()
        print("authenticator removed")


# Headless Chrome never shows the WebAuthn picker UI, so a ceremony that needs
# user confirmation sits unresolved until the 30s timeout. These flags make the
# virtual authenticator auto-accept and force the virtual device to be the only
# candidate, which is what a lab run wants.
AUTO_ACCEPT_FLAGS = (
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--ignore-certificate-errors",
    # WebAuthn: make the virtual authenticator the default and skip the prompt
    "--disable-features=WebAuthnVirtualAuthenticatorPrompt",
    "--unsafely-treat-insecure-origin-as-secure=https://lab.example:8443",
    # Never try to reach a real passkey provider or sync service
    "--disable-sync",
    "--disable-component-update",
    "--disable-background-networking",
)


def chrome_start_command(port: int = 9333, profile: str = "/tmp/cdp-fido") -> list:
    return [
        "google-chrome",
        *AUTO_ACCEPT_FLAGS,
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",
        f"--user-data-dir={profile}",
        "about:blank",
    ]


if __name__ == "__main__":
    if os.environ.get("CDP_PORT"):
        print(f"attaching to Chrome at {CDP_HOST}:{CDP_PORT}")
    asyncio.run(main())
