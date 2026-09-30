# FIDO2 / CTAP2 Hardware-Key Emulator — Lab Build

A software authenticator that speaks the **real FIDO2 / CTAP2 protocols**, registers
and authenticates against a live site through Chrome's actual WebAuthn stack, and
tells you exactly what a relying party can and cannot learn about it.

Built and verified on: Chrome 148.0.7778.96, Python 3.12, Linux 6.12.

---

## What actually runs here

| Test | Result |
|---|---|
| `selftest_hid.py` — CTAP2 core over real CTAPHID framing | **36 passed, 0 failed** |
| `selftest_e2e.py` — register → authenticate → RP verification | **21 passed, 0 failed** |
| `drive_browser.py` — live Chrome ceremony against the lab RP | **verified, signCount 1 → 2** |

Live browser run:

```
[driver] virtual authenticator 48c60fe7-… (transport=usb, rk, uv)
[driver] register: {"ok": true, "verified": true, "fmt": "packed",
                    "credential_id": "b7d8f5788d86e1d5…", "sign_count": 1}
[driver] authenticate: {"ok": true, "verified": true, "flags": "0x05", "sign_count": 2}
[driver] WebAuthn CDP events: ['WebAuthn.credentialAdded', 'WebAuthn.credentialAsserted']
```

`flags: 0x05` = UP (user present) + UV (user verified), set by a real authenticator
response that the RP verified.

---

## The honest answer to the hard part

A software authenticator **cannot** produce vendor-signed attestation. It can produce
a chain that is structurally perfect — real leaf, real signature, valid COSE key — and
still prove nothing, because it vouched for itself. `analyze_attestation.py` enumerates
every signal an RP has:

```
[REJECTABLE] attestation certificate is self-issued
             subject == issuer == CN=Batch Certificate,O=Chromium
[REJECTABLE] leaf certificate carries no id-fido-gen-ce-aaguid extension
             OID 1.3.6.1.4.1.45724.1.1.4 absent
[REJECTABLE] AAGUID is not a listed authenticator model
             aaguid=01020304050607080102030405060708 — no entry in FIDO MDS
[informational] packed signature verifies
```

Those first three are **one comparison each**. A site that pins FIDO MDS attestation
roots, or checks the AAGUID against the metadata blob, rejects this device at
registration — before any assertion is ever signed.

What the emulator *does* get right: everything an RP sees at the WebAuthn layer.
Key generation, COSE encoding, signature counters, resident/discoverable credentials,
UP/UV flags, clientDataHash binding, origin scoping, and the full CTAPHID wire format.

---

## Layout

| File | Role |
|---|---|
| `ctap2_core.py` | The authenticator. UP/UV gating, PIN, credential store, attestation modes |
| `ctaphid.py` | CTAPHID framing (64-byte reports, INIT/CONT/KEEPALIVE/PING) + transports |
| `ctaphid_server.py` | Serves CTAPHID on `/dev/hidg0` or TCP |
| `chrome_bridge.py` | DevTools Protocol WebAuthn domain — the Chrome integration |
| `drive_browser.py` | Drives a live ceremony end to end |
| `lab_server.py` | Local relying party over HTTPS with real RP verification |
| `rp_verify.py` | The RP side: challenge/origin/rpId/flags/counter/attestation |
| `analyze_attestation.py` | What an RP can learn from an attestation statement |
| `hid_gadget.sh` | USB HID gadget descriptor on the FIDO usage page |
| `selftest_hid.py`, `selftest_e2e.py` | Test suites |

---

## Setup

```bash
/usr/bin/python3 -m pip install --target ./libs cbor2 cryptography flask websockets
export PYTHONPATH=./libs
echo "127.0.0.1 lab.example" | sudo tee -a /etc/hosts
```

## Run it

**1. The relying party:**
```bash
python3 src/lab_server.py --port 8443
```

**2. Chrome, on a display** (the WebAuthn picker does not exist in headless):
```bash
xvfb-run -a --server-args="-screen 0 1280x900x24" \
  google-chrome --no-sandbox --remote-debugging-port=9333 \
    --remote-allow-origins='*' --ignore-certificate-errors \
    --disable-features=WebAuthnVirtualAuthenticatorPrompt \
    --unsafely-treat-insecure-origin-as-secure='https://lab.example:8443' \
    --user-data-dir=/tmp/cdp-fido about:blank
```

**3. Drive the ceremony:**
```bash
cd src && CDP_PORT=9333 python3 drive_browser.py
```

**4. Or serve CTAPHID over real USB:**
```bash
sudo ./src/hid_gadget.sh                    # builds the FIDO-usage-page gadget
python3 src/ctaphid_server.py --device /dev/hidg0
```

---

## Two findings worth keeping

**`WebAuthn.setUserVerified(True)` is mandatory for UV-capable devices.** Without it,
Chromium's `VirtualFidoDevice` has no verified state and every ceremony fails with
`CTAP error 51 (0x33 PIN_BLOCKED)` → `NotAllowedError`. Verified across a
3-version × rk × uv matrix: `hasUserVerification=True` alone was the sole trigger,
`hasResidentKey` was innocent. This call is the software stand-in for a finger on a
sensor — the emulator's version of the touch.

**Virtual authenticators are scoped to the DevTools session that created them.**
Add one on the bridge's session and run the page on another, and the page sees nothing
until the 30s timeout. Everything must happen on one session.

## Third, if you port this

**Packed attestation signs with the attestation certificate's key, not the
credential's** (WebAuthn §8.2) — only an empty `x5c` means self-attestation.
Verifying against the credential key rejects valid responses, including
Chromium's.

---

## What to watch

`authenticatorSelection` with `userVerification: 'required'` is the strictest path;
`--disable-features=WebAuthnVirtualAuthenticatorPrompt` plus `setUserVerified` is what
makes it pass headlessly. CTAP2 numeric keys differ per command — `makeCredential` and
`getAssertion` both start at key 1 with different meanings, and conflating them is the
classic CTAP implementation bug (both are spelled out in `ctap2_core.py`).
