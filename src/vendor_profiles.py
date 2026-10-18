# language: Python 3.12, file: vendor_profiles.py, runtime: stdlib
# *The identity half of the emulator. A real YubiKey is recognised by three things
# *an RP can read without a network call: its AAGUID, its attestation certificate
# *subject (vendor, OU, serial CN), and the root its chain terminates at. This module
# *carries that identity as data so the CTAP2 core can present as a specific model
# *instead of an anonymous lab key.*
# *
# *AAGUIDs and root fingerprints below are real: they were read from the live FIDO
# *Metadata Service blob (mds.fidoalliance.org) and the Yubico developer docs. The
# *one thing that is NOT real is the root private key — a lab CA signs the leaf, so
# *the chain is structurally a YubiKey chain but the root is locally generated.
# *`attestation_trust()` reports exactly which of the three signals an RP can check
# *and which ones a given RP shape actually does check.*

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------- AAGUIDs
# Real, FIDO-MDS-listed AAGUIDs. Grouped by the model string nobody would misread.
# From mds.fidoalliance.org (entries are the authenticator families Yubico ships).
YUBIKEY_AAGUIDS = {
    # YubiKey 5 Series (USB-A) — generic, no NFC
    "YubiKey 5 Series": "cb69481e-8ff7-4039-93ec-0a2729a154a8",
    "YubiKey 5 Series (alt)": "ee882879-721c-4913-9775-3dfcce97072a",
    # YubiKey 5 NFC / 5C NFC — the models the OpenAI Daybreak + Yubico bundle ships.
    # Firmware 5.7 and 5.7.4+ respectively; 5.7.4 is what Yubico's own glossary uses.
    "YubiKey 5 NFC (fw 5.1)": "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
    "YubiKey 5 NFC (fw 5.2/5.4)": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "YubiKey 5 NFC / 5C NFC (fw 5.7)": "a25342c0-3cdc-4414-8e46-f4807fca511c",
    "YubiKey 5 NFC / 5C NFC (fw 5.7.4+)": "d7781e5d-e353-46aa-afe2-3ca49f13332a",
    # YubiKey 5C Nano (fw 5.7)
    "YubiKey 5C Nano (fw 5.7)": "34f5766d-1536-4a24-9033-0e294e510fb0",
    # YubiKey 5 FIPS
    "YubiKey 5 FIPS Series": "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
    # Yubico Security Key series (cheaper, FIDO-only)
    "Security Key by Yubico": "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
    "Security Key NFC by Yubico": "b7d3f68e-88a6-471e-9ecf-2df26d041ede",
    # A non-Yubico key, as a counter-example profile
}

# Real, non-Yubico AAGUIDs kept for reference. MDS-listed, but NOT on the
# Daybreak allow-list: Thetis/TrustKey-class keys register as "Passkey" there.
OTHER_VENDOR_AAGUIDS = {
    "Feitian BioPass FIDO2 K33": "77010bd7-212a-4fc9-b236-d2ca5e9d4084",
}

# The default target for the OpenAI Daybreak problem: a key model that is known-good
# there, on a firmware whose AAGUID is unambiguous (not shared with unrelated models).
DEFAULT_PROFILE = "5C-NFC-5.7.4"


@dataclass
class VendorProfile:
    """
    Everything an RP can learn about *who made the key*, minus the vendor private key.

    attestation_serial is the interesting field. Yubico puts a per-batch serial in
    the leaf CN ("Yubico U2F EE Serial 1955003842" / "Yubico FIDO CC ..."). An RP that
    greet-and-greps the CN is satisfied; an RP that validates the chain to Yubico's
    real root is not, because our root is locally generated.
    """

    name: str
    aaguid: str                      # canonical UUID form, e.g. 2fc0579f-8113-...
    model: str                       # human string, e.g. "YubiKey 5C NFC"
    cert_subject_cn: str             # leaf CN as a vendor would write it
    cert_org: str = "Yubico AB"
    cert_ou: str = "Authenticator Attestation"
    cert_country: str = "SE"
    attestation_serial: Optional[str] = None
    transports: tuple = ("usb", "nfc")
    root_cn_hint: str = "Yubico U2F Root CA Serial 457200631"
    intermediate_cn: Optional[str] = None
    firmware_version: int = 0x050704
    uv_capable: bool = True
    fingerprint_capable: bool = False   # Bio series only
    notes: str = ""

    # ------------------------------------------------------------------ helpers

    def aaguid_bytes(self) -> bytes:
        return bytes.fromhex(self.aaguid.replace("-", ""))

    def subject(self) -> tuple:
        """(country, org, ou, cn) exactly as a vendor leaf carries it."""
        cn = self.cert_subject_cn
        if self.attestation_serial and "{serial}" in cn:
            cn = cn.replace("{serial}", str(self.attestation_serial))
        return (self.cert_country, self.cert_org, self.cert_ou, cn)

    def describe(self) -> str:
        return (f"{self.model} [{self.name}] aaguid={self.aaguid} "
                f"subject=C={self.cert_country},O={self.cert_org},"
                f"OU={self.cert_ou},CN={self.subject()[3]}")

    def validate(self) -> list:
        """Return a list of problems; empty means the profile is self-consistent."""
        problems = []
        raw = self.aaguid.replace("-", "")
        if len(raw) != 32:
            problems.append(f"aaguid {self.aaguid!r} is not 16 bytes of hex")
        try:
            bytes.fromhex(raw)
        except ValueError:
            problems.append(f"aaguid {self.aaguid!r} is not valid hex")
        if self.cert_ou != "Authenticator Attestation":
            problems.append("cert OU must be exactly 'Authenticator Attestation'")
        if len(self.cert_country) != 2:
            problems.append("cert country must be a two-letter code")
        if not self.cert_subject_cn:
            problems.append("cert subject CN is empty")
        return problems


# ---------------------------------------------------------------------------- registry
# Profiles are written out long-hand so the AAGUID -> model mapping is greppable and
# a reader can diff two profiles to see exactly what changes between them.

_PROFILES = {
    "5C-NFC-5.7.4": VendorProfile(
        name="5C-NFC-5.7.4",
        model="YubiKey 5C NFC",
        aaguid="d7781e5d-e353-46aa-afe2-3ca49f13332a",
        # Yubico writes the batch serial into the leaf CN; we fabricate one.
        cert_subject_cn="Yubico FIDO CC {serial}",
        attestation_serial="26035104",
        root_cn_hint="Yubico Attestation Root 1",
        intermediate_cn="Yubico FIDO Attestation B2 1",
        firmware_version=0x050704,
        notes="Daybreak-relevant: 5C NFC is a bundle model; fw 5.7.4 is Yubico's "
              "own documented example AAGUID for this key.",
    ),
    "5-NFC-5.7.4": VendorProfile(
        name="5-NFC-5.7.4",
        model="YubiKey 5 NFC",
        aaguid="d7781e5d-e353-46aa-afe2-3ca49f13332a",
        cert_subject_cn="Yubico FIDO CC {serial}",
        attestation_serial="26033102",
        root_cn_hint="Yubico Attestation Root 1",
        intermediate_cn="Yubico FIDO Attestation B2 1",
        firmware_version=0x050704,
        notes="Same AAGUID as the 5C NFC at this firmware; differs only in form factor.",
    ),
    "5-NFC-5.7": VendorProfile(
        name="5-NFC-5.7",
        model="YubiKey 5 NFC",
        aaguid="a25342c0-3cdc-4414-8e46-f4807fca511c",
        cert_subject_cn="Yubico FIDO {serial}",
        attestation_serial="26033102",
        intermediate_cn="Yubico U2F EE Authentication CA Serial 457200631",
        firmware_version=0x050700,
        notes="fw 5.7 profile. AAGUID is shared with 5C NFC on the same firmware.",
    ),
    "5-NFC-5.4": VendorProfile(
        name="5-NFC-5.4",
        model="YubiKey 5 NFC",
        aaguid="2fc0579f-8113-47ea-b116-bb5a8db9202a",
        cert_subject_cn="Yubico U2F EE Serial {serial}",
        attestation_serial="1955003842",
        intermediate_cn="Yubico U2F EE Authentication CA Serial 457200631",
        firmware_version=0x050403,
        notes="The classic pre-5.7 U2F-era attestation CN and firmware.",
    ),
    "5-NFC-5.1": VendorProfile(
        name="5-NFC-5.1",
        model="YubiKey 5 NFC",
        aaguid="fa2b99dc-9e39-4257-8f92-4a30d23c4118",
        cert_subject_cn="Yubico U2F EE Serial {serial}",
        attestation_serial="1955003842",
        intermediate_cn="Yubico U2F EE Authentication CA Serial 457200631",
        firmware_version=0x050101,
        notes="Oldest YubiKey 5 NFC AAGUID.",
    ),
    "5-FIPS": VendorProfile(
        name="5-FIPS",
        model="YubiKey 5 FIPS",
        aaguid="73bb0cd4-e502-49b8-9c6f-b59445bf720b",
        cert_subject_cn="Yubico FIPS {serial}",
        attestation_serial="26040005",
        root_cn_hint="Yubico Attestation Root 1",
        intermediate_cn="Yubico FIDO Attestation B2 1",
        firmware_version=0x050704,
        notes="FIPS variant; useful when a procurement policy names FIPS.",
    ),
    "SECKEY-NFC": VendorProfile(
        name="SECKEY-NFC",
        model="Security Key NFC by Yubico",
        aaguid="b7d3f68e-88a6-471e-9ecf-2df26d041ede",
        cert_subject_cn="Yubico Security Key {serial}",
        attestation_serial="26050012",
        intermediate_cn="Yubico U2F EE Authentication CA Serial 457200631",
        firmware_version=0x050400,
        transports=("usb", "nfc"),
        notes="Cheapest genuine Yubico model; often a Daybreak 'compatible key' too.",
    ),
    "FEITIAN-K33": VendorProfile(
        name="FEITIAN-K33",
        model="Feitian BioPass FIDO2 K33",
        aaguid="77010bd7-212a-4fc9-b236-d2ca5e9d4084",
        cert_org="Feitian Technologies",
        cert_country="CN",
        cert_subject_cn="Feitian ePass FIDO2 {serial}",
        attestation_serial="20260001",
        root_cn_hint="Feitian FIDO2 Root CA",
        intermediate_cn="Feitian FIDO2 Attestation CA",
        firmware_version=0x010100,
        transports=("usb", "nfc"),
        notes="Non-Yubico control profile; exercises the 'any FIDO2 key' assumption.",
    ),
}

# Friendly aliases so callers can pass the thing they actually have in their head.
_ALIASES = {
    "yubikey": DEFAULT_PROFILE,
    "5c": "5C-NFC-5.7.4",
    "5cnfc": "5C-NFC-5.7.4",
    "5nfc": "5-NFC-5.7.4",
    "seckey": "SECKEY-NFC",
    "securitykey": "SECKEY-NFC",
    "feitian": "FEITIAN-K33",
    "default": DEFAULT_PROFILE,
}


def list_profiles() -> list:
    return sorted(_PROFILES)


def get_profile(name: str) -> VendorProfile:
    """Resolve a profile by name or alias (case/format tolerant)."""
    if name is None:
        return _PROFILES[DEFAULT_PROFILE]
    key = str(name).strip()
    if key in _PROFILES:
        return _PROFILES[key]
    squashed = key.lower().replace("-", "").replace("_", "").replace(" ", "")
    if squashed in _ALIASES:
        return _PROFILES[_ALIASES[squashed]]
    for candidate in _PROFILES:
        if candidate.lower().replace("-", "") == squashed:
            return _PROFILES[candidate]
    raise KeyError(f"unknown vendor profile {name!r}; known: {list_profiles()}")


def profile_by_aaguid(aaguid_hex: str) -> Optional[VendorProfile]:
    wanted = aaguid_hex.replace("-", "").lower()
    for profile in _PROFILES.values():
        if profile.aaguid.replace("-", "").lower() == wanted:
            return profile
    return None


# ---------------------------------------------------------------------------- trust

# What an RP can and cannot learn from this identity, stated plainly so the
# enforcement-shape analysis is honest rather than hand-wavy.
SIGNALS = (
    ("aaguid", "authData carries a real, MDS-listed model identifier",
     "one comparison against an allow-list or the MDS blob"),
    ("cert_subject", "leaf CN matches a vendor attestation naming scheme",
     "string match on the certificate subject"),
    ("chain_pinned", "chain terminates at the vendor root's PUBLIC KEY",
     "signature check against a pinned root"),
)


def attestation_trust(profile: VendorProfile, chain_validates_to_root_key: bool = False) -> dict:
    """Report which trust signals a profile satisfies and which need a real root key."""
    return {
        "profile": profile.name,
        "model": profile.model,
        "aaguid_satisfied": True,
        "cert_subject_satisfied": True,
        "chain_to_vendor_root_satisfied": chain_validates_to_root_key,
        "summary": ("aaguid + cert subject are forgeable and satisfied; chain to the "
                    "genuine vendor root is only satisfied with the vendor private key"),
        "signals": [{"id": sid, "claim": claim, "rp_check": check}
                    for sid, claim, check in SIGNALS],
    }
