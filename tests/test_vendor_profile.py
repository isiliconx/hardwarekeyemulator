import base64
import hashlib
import json
import os
import sys
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctap2_core import Ctap2Authenticator, parse_attested_credential_id
from policy_lab import (DAYBREAK_ALLOWLIST, classify_daybreak,
                        parse_attestation)
from rp_verify import POLICY, RpError, verify_registration
from vendor_profiles import (DEFAULT_PROFILE, YUBIKEY_AAGUIDS, get_profile,
                             list_profiles, profile_by_aaguid)

RP_ID = "example.com"
ORIGIN = "https://example.com"
YUBIKEY_5C_NFC = "d7781e5de35346aaafe23ca49f13332a"
CHROMIUM_VIRTUAL = "01020304050607080102030405060708"


def client_data(challenge):
    return json.dumps({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": ORIGIN, "crossOrigin": False,
    }).encode()


def make_registration(auth):
    challenge = os.urandom(32)
    cd = client_data(challenge)
    resp = auth.make_credential({
        1: hashlib.sha256(cd).digest(),
        2: {"id": RP_ID, "name": "Example"},
        3: {"id": os.urandom(16), "name": "alice", "displayName": "Alice"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True, "uv": True},
    })
    return {"fmt": resp[1], "authData": resp[2], "attStmt": resp[3]}, cd, challenge


def chain_verifies_internally(x5c):
    certs = [x509.load_der_x509_certificate(der) for der in x5c]
    for child, parent in zip(certs, certs[1:]):
        assert child.issuer == parent.subject
        public = parent.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(child.signature, child.tbs_certificate_bytes,
                          padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            public.verify(child.signature, child.tbs_certificate_bytes,
                          ec.ECDSA(child.signature_hash_algorithm))


def test_profile_registry_resolves_and_validates():
    names = list_profiles()
    assert "5C-NFC-5.7.4" in names
    assert "FEITIAN-K33" in names
    for name in names:
        profile = get_profile(name)
        assert profile.name == name
        assert profile.validate() == []
        assert len(profile.aaguid_bytes()) == 16
    assert get_profile("yubikey").name == DEFAULT_PROFILE == "5C-NFC-5.7.4"
    assert get_profile("5cnfc").name == "5C-NFC-5.7.4"
    assert profile_by_aaguid(YUBIKEY_5C_NFC).name == "5C-NFC-5.7.4"
    with pytest.raises(KeyError):
        get_profile("no-such-profile")


def test_daybreak_allowlist_covers_yubico_models_only():
    for aaguid in YUBIKEY_AAGUIDS.values():
        assert aaguid.replace("-", "").lower() in DAYBREAK_ALLOWLIST
    assert CHROMIUM_VIRTUAL not in DAYBREAK_ALLOWLIST
    assert "0" * 32 not in DAYBREAK_ALLOWLIST


def test_vendor_registration_carries_model_identity(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                              profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    att, cd, challenge = make_registration(auth)

    assert att["authData"][37:53] == bytes.fromhex(YUBIKEY_5C_NFC)

    x5c = att["attStmt"]["x5c"]
    assert len(x5c) == 3                       # leaf -> batch CA -> root
    chain_verifies_internally(x5c)

    leaf = x509.load_der_x509_certificate(x5c[0])
    subject = leaf.subject.rfc4514_string()
    assert "OU=Authenticator Attestation" in subject
    assert "O=Yubico AB" in subject
    assert "C=SE" in subject
    assert leaf.subject != leaf.issuer         # batch leaf, not self-issued

    ext = leaf.extensions.get_extension_for_oid(
        x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"))
    assert not ext.critical
    assert ext.value.value == b"\x04\x10" + bytes.fromhex(YUBIKEY_5C_NFC)

    # packed attestation signature verifies under the leaf key (WebAuthn 8.2)
    leaf.public_key().verify(
        att["attStmt"]["sig"],
        att["authData"] + hashlib.sha256(cd).digest(),
        ec.ECDSA(hashes.SHA256()))


def test_vendor_get_info_matches_a_real_yubikey(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                              profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    info = auth.get_info()
    assert info[3] == bytes.fromhex(YUBIKEY_5C_NFC)
    assert "FIDO_2_1" in info[1] and "U2F_V2" in info[1]
    assert info[9] == ["usb", "nfc"]
    assert info[6] == [2, 1]
    assert info[4]["plat"] is False
    assert info[4]["clientPin"] is False
    assert info[4]["uv"] is True
    assert info[0x0D] == 4
    assert info[0x0E] == 0x050704


def test_lab_identity_stays_minimal_with_no_profile(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), uv_gate=lambda: True)
    info = auth.get_info()
    assert info[1] == ["FIDO_2_0"]
    assert info[3] == b"\x00" * 16
    assert "clientPin" not in info[4]
    assert 9 not in info and 0x0D not in info and 0x0E not in info


def test_daybreak_classifier_separates_lab_from_vendor(tmp_path):
    outcomes = {}
    for label, kwargs in (
            ("lab", {}),
            ("vendor", {"profile": "5C-NFC-5.7.4"}),
            ("chromium", {"aaguid": bytes.fromhex(CHROMIUM_VIRTUAL)}),
    ):
        auth = Ctap2Authenticator(str(tmp_path / f"{label}.json"),
                                 uv_gate=lambda: True, **kwargs)
        att, cd, _ = make_registration(auth)
        parsed = parse_attestation(att["authData"], att["fmt"], att["attStmt"])
        outcomes[label] = classify_daybreak(parsed)

    assert outcomes["vendor"]["label"] == "Security key"
    assert outcomes["vendor"]["counts_as_hardware_key"] is True
    assert outcomes["vendor"]["model"] == "YubiKey 5 NFC / 5C NFC (fw 5.7.4+)"
    assert outcomes["lab"]["label"] == "Passkey"
    assert outcomes["lab"]["counts_as_hardware_key"] is False
    assert outcomes["chromium"]["label"] == "Passkey"


def test_backup_eligible_credential_never_counts_as_hardware(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                              profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    att, cd, _ = make_registration(auth)
    parsed = parse_attestation(att["authData"], att["fmt"], att["attStmt"])
    parsed["flags"] |= 0x08                     # force BE on
    verdict = classify_daybreak(parsed)
    assert verdict["counts_as_hardware_key"] is False
    assert verdict["label"] == "Passkey"


def test_rp_verify_accepts_vendor_registration_by_default(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                              profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    att, cd, challenge = make_registration(auth)
    reg = verify_registration(RP_ID, cd, att, challenge, expected_origin=ORIGIN)
    assert reg["aaguid"] == bytes.fromhex(YUBIKEY_5C_NFC)


def test_strict_pinned_root_policy_still_rejects(tmp_path):
    # Honesty check: without the vendor private key the chain cannot terminate
    # at a pinned trust anchor, so an RP requiring attestation must reject.
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                              profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    att, cd, challenge = make_registration(auth)
    with pytest.raises(RpError):
        verify_registration(RP_ID, cd, att, challenge, expected_origin=ORIGIN,
                            policy={**POLICY, "require_attestation": True})


def test_identity_switch_regenerates_ca_but_keeps_credentials(tmp_path):
    store = str(tmp_path / "creds.json")
    lab = Ctap2Authenticator(store, uv_gate=lambda: True)
    lab_att, _, _ = make_registration(lab)
    old_leaf = x509.load_der_x509_certificate(lab_att["attStmt"]["x5c"][0])

    vendor = Ctap2Authenticator(store, profile="5C-NFC-5.7.4", uv_gate=lambda: True)
    assert len(vendor.list_credentials()) == 1          # credential survived
    assert vendor.get_info()[3] == bytes.fromhex(YUBIKEY_5C_NFC)

    new_att, _, _ = make_registration(vendor)
    new_leaf = x509.load_der_x509_certificate(new_att["attStmt"]["x5c"][0])
    assert new_leaf.subject != old_leaf.subject         # identity regenerated

    # the pre-switch credential still authenticates with the new identity loaded
    cid = parse_attested_credential_id(lab_att["authData"])
    assertion = vendor.get_assertion({
        1: RP_ID, 2: os.urandom(32),
        3: [{"type": "public-key", "id": cid}],
        5: {"uv": True},
    })
    assert assertion[1]["id"] == cid


def test_restart_adopts_stored_vendor_identity(tmp_path):
    store = str(tmp_path / "creds.json")
    first = Ctap2Authenticator(store, profile="5-NFC-5.4", uv_gate=lambda: True)
    assert first.get_info()[3] == bytes.fromhex(
        "2fc0579f811347eab116bb5a8db9202a")
    make_registration(first)

    restarted = Ctap2Authenticator(store)              # no profile argument
    assert restarted._resolved_profile.name == "5-NFC-5.4"
    assert restarted.get_info()[3] == bytes.fromhex(
        "2fc0579f811347eab116bb5a8db9202a")


def test_explicit_aaguid_override_beats_profile(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "c.json"), profile="5C-NFC-5.7.4",
                              aaguid=bytes.fromhex(
                                  "2fc0579f811347eab116bb5a8db9202a"),
                              uv_gate=lambda: True)
    att, _, _ = make_registration(auth)
    assert att["authData"][37:53] == bytes.fromhex(
        "2fc0579f811347eab116bb5a8db9202a")
    leaf = x509.load_der_x509_certificate(att["attStmt"]["x5c"][0])
    assert "Yubico" in leaf.subject.rfc4514_string()   # naming from the profile


def test_uhid_transport_carries_yubico_usb_identity():
    import uhid_ctap
    assert uhid_ctap.YUBICO_VENDOR_ID == 0x1050
    assert uhid_ctap.YUBICO_PRODUCT_ID == 0x0407
    assert uhid_ctap.YUBICO_PRODUCT_NAME == "YubiKey OTP+FIDO+CCID"

    transport = uhid_ctap.UhidTransport(name=uhid_ctap.YUBICO_PRODUCT_NAME,
                                        vendor=uhid_ctap.YUBICO_VENDOR_ID,
                                        product=uhid_ctap.YUBICO_PRODUCT_ID,
                                        version=0x050704)
    event = uhid_ctap.uhid_create2_event(
        name=transport.name, phys=transport.phys, uniq=transport.uniq,
        bus=uhid_ctap.BUS_USB, vendor=transport.vendor,
        product=transport.product, version=transport.version, country=0,
        report_descriptor=uhid_ctap.REPORT_DESCRIPTOR)
    vendor, product = struct.unpack_from("=II", event, 264)
    assert vendor == 0x1050 and product == 0x0407
