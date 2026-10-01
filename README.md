# FIDO2 / CTAP2 Hardware-Key Emulator — Lab Build

A lab software authenticator with CTAP2 core operations, CTAPHID framing,
Linux UHID transport code, and a local WebAuthn relying party.

The September 30, 2026 repair was verified with automated tests on Windows.
Live Linux UHID, USB gadget, and browser/OS ceremonies have not been rerun for
this revision. Earlier browser results below are historical evidence only.

---

## What actually runs here

| Test | Result |
|---|---|
| `selftest_hid.py` — CTAP2 core over real CTAPHID framing | **36 passed, 0 failed** |
| `selftest_e2e.py` — register → authenticate → RP verification | **21 passed, 0 failed** |
| `selftest_uhid.py` — Linux UHID ABI packing, descriptor, CTAP2 core smoke test | **35 passed, 0 failed** |
| `pytest tests -q` — interoperability and security regressions | **44 passed, 0 failed** |
| `drive_browser.py` — historical Chrome virtual-authenticator ceremony | **not rerun for this revision** |

Historical browser run (before this repair):

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

Automated tests cover key generation, COSE encoding, signature counters,
credential scoping, UP/UV behavior, clientDataHash binding, exact origin checks,
attestation policy, and CTAPHID framing. This is a lab emulator, not a certified
hardware authenticator or a production relying-party service.

---

## Any browser: bind at the OS level with uhid

The DevTools path above needs Chrome and browser flags. To be **browser-agnostic**,
expose the authenticator as a **real HID device** on the FIDO usage page via
`/dev/uhid`. Every browser that speaks WebAuthn then discovers it natively — no flags,
no extension, no profile injection.

```bash
sudo modprobe uhid                      # once; needs CONFIG_INPUT_UHID=y
cd src
PYTHONPATH=../libs python3 uhid_ctap.py --store ./creds.json
```

Then open **any** browser, go to your site, choose "security key". Confirm the OS sees it:

```bash
lsusb | grep -i fido
cat /sys/class/hid/hidraw*/device/uevent | grep HID_NAME
```

**Why uhid rather than the USB gadget stack:** gadget mode needs a UDC (a real USB
device controller) and root on the host bus. `uhid` is a userspace HID driver — it
registers a virtual HID device through the normal input subsystem with no bus, no
root, and no browser cooperation. `uhid_ctap.py` declares the FIDO usage page
(`0xF1D0` / usage `0x01`), 64-byte reports, and the FIDO Alliance demo VID/PID
(`0xF1D0:0x0001`) — which is what makes the browser treat it as an authenticator.

**Verification status — read this before you rely on it.** The UHID ABI layer
(`UHID_CREATE2`, `UHID_INPUT2`, `UHID_OUTPUT`, descriptor packing, and event parsing)
is covered by `selftest_uhid.py` and the pytest regression suite. A live
`/dev/uhid` device was not available on the verification host, so the final kernel
handoff still needs confirmation on Linux with `CONFIG_INPUT_UHID=y`. The CTAP2 core, CTAPHID loopback, and RP registration/authentication paths pass
automated tests; this does not prove browser or kernel interoperability.

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
| `uhid_ctap.py` | **Any-browser path** — binds the key to the OS via `/dev/uhid` |
| `selftest_hid.py`, `selftest_e2e.py`, `selftest_uhid.py` | Scripted self-tests (92 checks total) |
| `tests/` | Pytest interoperability and security regressions |

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
credential's** (WebAuthn §8.2) — an absent `x5c` indicates self-attestation.
Verifying against the credential key rejects valid responses, including
Chromium's.

---

## What to watch

`authenticatorSelection` with `userVerification: 'required'` is the strictest path;
`--disable-features=WebAuthnVirtualAuthenticatorPrompt` plus `setUserVerified` is what
makes it pass headlessly. CTAP2 numeric keys differ per command — `makeCredential` and
`getAssertion` both start at key 1 with different meanings, and conflating them is the
classic CTAP implementation bug (both are spelled out in `ctap2_core.py`).


## Repair defaults and limits

- CTAPHID TCP listeners default to loopback; a remote bind requires `--allow-remote`.
- User presence prompts are required by default. `--no-touch-required` is an unsafe
  lab override. `--internal-uv` explicitly enables a software prompt, not biometric
  or hardware verification; without it, requests requiring UV fail closed.
- GetInfo advertises only `FIDO_2_0`; unsupported U2F messaging and UV are not
  advertised. CTAP status bytes and the 7,609-byte CTAPHID framing limit are
  regression-tested; incomplete messages expire after three seconds.
- Presence input is synchronous: waiting at the prompt blocks receipt of active
  CANCEL/INIT commands until the prompt completes. Idle CANCEL is ignored.
  Complete HID/browser conformance is not claimed; responsive in-flight cancellation
  requires a cancellable presence mechanism.
- PIN/UV protocols and credential management are unsupported. Multiple discoverable
  credentials for one RP require an allowList; ambiguous discovery is rejected until
  account selection or enumeration is implemented.
- Required attestation must chain to an explicitly SHA-256-pinned trust anchor.
  Certificate common names do not grant trust; self-attestation cannot satisfy this policy.
- The lab RP uses process-local locks and expiring, one-time server-side challenges.
  Run one server process; multiple workers require shared challenge and database storage.

To rerun the repair regression suite, install `pytest` and `fido2` in addition to
the runtime dependencies above, then run `python -m pytest tests -q` and each of
the three `src/selftest_*.py` scripts.
