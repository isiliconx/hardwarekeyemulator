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
| `selftest_vendor.py` — YubiKey-profile identity through CTAPHID → RP → analyzer → Daybreak verdict | **20 passed, 0 failed** |
| `pytest tests -q` — interoperability, security, vendor-profile and AAGUID-shim regressions | **64 passed, 0 failed** |
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

**Update (this branch):** the first two comparisons are now *satisfied* — the
AAGUID is a real, MDS-listed model and the leaf carries the FIDO extension.
The third is satisfied by name and shape but not by key: a fingerprint-pinned
vendor root still rejects, because that signature needs the vendor private
key. See "Daybreak: presenting as a real YubiKey model" below.

Automated tests cover key generation, COSE encoding, signature counters,
credential scoping, UP/UV behavior, clientDataHash binding, exact origin checks,
attestation policy, and CTAPHID framing. This is a lab emulator, not a certified
hardware authenticator or a production relying-party service.

---

## Daybreak: presenting as a real YubiKey model

OpenAI's Daybreak (Trusted Access for Cyber) requires "at least one compatible
physical FIDO2 hardware security key" — software or synced passkeys don't count.
Field reports about TrustKey T110/T120, Trezor, Thetis and homebrew ESP32 keys
all describe the same behaviour: registration succeeds and the credential is
filed under **"Passkey"**, while YubiKeys land under **"Security key"**. That is
a model allow-list keyed by AAGUID — not a transport/attachment check (those
keys are all genuine roaming authenticators) and not an attestation-chain
check ("no MDS or attestation requirement", per OpenAI support).
`policy_lab.py` strategy **E** models exactly this shape.

This branch makes the emulator carry a *real* vendor identity — every part an
RP can actually read:

| Signal | Before | Now (vendor profile) |
|---|---|---|
| AAGUID (authData + cert extension) | all-zero lab / Chromium's `0102…08` | real, MDS-listed: `d7781e5d-…` = YubiKey 5C NFC fw 5.7.4+ |
| `authenticatorGetInfo` | minimal `FIDO_2_0` | what that model reports: `FIDO_2_0/2_1/U2F_V2`, `usb+nfc`, fw `5.7.4`, PIN protocols `[2,1]` |
| Attestation chain | lab root, "Batch Attestation" | 3-level vendor shape: leaf `CN=Yubico FIDO CC 26035104` → `Yubico FIDO Attestation B2 1` → `Yubico Attestation Root 1`, with `id-fido-gen-ce-aaguid` |
| USB identity (uhid) | `f1d0:0001` demo VID/PID | Yubico `1050:0407`, product "YubiKey OTP+FIDO+CCID" |

Three ways to deploy it:

**1. Real device (best) — any host with `CONFIG_INPUT_UHID` (Linux, WSL2):**

```bash
sudo modprobe uhid
cd src && python3 uhid_ctap.py --profile yubikey   # default: 5C-NFC-5.7.4
```

Every browser then discovers a USB security key whose AAGUID is a real YubiKey
model. `--profile lab` restores the anonymous identity. Preview the verdict
with no kernel support at all: `python3 src/daybreak_check.py`.

**2. Chrome-only hosts (no uhid) — the AAGUID shim.** Chrome's CDP virtual
authenticator has a FIXED AAGUID (`0102…08`; measured on 154/155/158 — no CDP
option exists), so `hold_virtual_key.py` alone can never present a model.
`hold_aaguid.py` keeps your real browser flow and rewrites the AAGUID inside
the attestationObject the page receives:

```bash
google-chrome --remote-debugging-port=9222 …   # your normal Chrome
python3 src/hold_aaguid.py                     # resident; new tabs covered
```

…or install `ext_aaguid_shim/` as an unpacked extension (chrome://extensions →
Developer mode → Load unpacked) for the same effect with no terminal. If the
site verifies packed attestation signatures, use `--mode none` (fmt `'none'`
re-encode, the shape software passkeys commonly send).

**3. Model choice:** `--profile` accepts every entry in `vendor_profiles.py`
(5C NFC 5.7.4+ default, 5.7, 5.4, 5.1, 5 FIPS, Security Key NFC, Feitian
control) or `--aaguid <hex>` for anything else. If one model is ever refused,
switching is one flag — registration-time classification is what matters;
assertions carry no AAGUID.

**What still cannot be faked (unchanged, by arithmetic):** an RP that pins the
genuine vendor root and validates the chain to it rejects every software
authenticator — that signature requires the vendor private key. Name checks,
shape checks and AAGUID allow-lists are all satisfied; the fingerprint pin is
the one comparison that still tells a lab chain from the real thing
(`rp_verify.py`'s `trusted_attestation_root_sha256` demonstrates it, and
`daybreak_check.py` prints the caveat every run).

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
| `ctap2_core.py` | The authenticator. UP/UV gating, PIN, credential store, attestation modes, vendor profiles |
| `vendor_profiles.py` | **The identity registry** — real MDS-listed Yubico AAGUIDs per firmware, vendor cert naming, GetInfo fidelity data |
| `ctaphid.py` | CTAPHID framing (64-byte reports, INIT/CONT/KEEPALIVE/PING) + transports |
| `ctaphid_server.py` | Serves CTAPHID on `/dev/hidg0` or TCP (`--profile`) |
| `chrome_bridge.py` | DevTools Protocol WebAuthn domain — the Chrome integration |
| `drive_browser.py` | Drives a live ceremony end to end |
| `lab_server.py` | Local relying party over HTTPS with real RP verification |
| `rp_verify.py` | The RP side: challenge/origin/rpId/flags/counter/attestation |
| `analyze_attestation.py` | What an RP can learn from an attestation statement |
| `policy_lab.py` | Five RP enforcement shapes incl. the Daybreak classifier (strategy E) |
| `daybreak_check.py` | Pre-flight: will a Daybreak-shaped RP file this key as "Security key"? |
| `aaguid_shim.js` | Page-world AAGUID rewrite for the Chrome-only path (no uhid / pinned CDP AAGUID) |
| `hold_aaguid.py` | CDP holder that injects the shim into your real Chrome |
| `ext_aaguid_shim/` | The same shim as an unpacked Chrome extension |
| `hid_gadget.sh` | USB HID gadget descriptor on the FIDO usage page (env-overridable identity) |
| `uhid_ctap.py` | **Any-browser path** — binds the key to the OS via `/dev/uhid` (`--profile`) |
| `selftest_hid.py`, `selftest_e2e.py`, `selftest_uhid.py`, `selftest_vendor.py` | Scripted self-tests (112 checks total) |
| `tests/` | Pytest interoperability, security, vendor-profile and shim regressions |

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
the four `src/selftest_*.py` scripts. The AAGUID-shim tests additionally need
`node` on PATH (skipped otherwise).
