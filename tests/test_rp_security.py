import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctap2_core import Ctap2Authenticator
from rp_verify import RpError, verify_registration

RP_ID = "example.com"
ORIGIN = "https://example.com"


def client_data(challenge: bytes, origin=ORIGIN, cross_origin=False):
    return json.dumps({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": origin,
        "crossOrigin": cross_origin,
    }).encode()


def registration(auth, client_json):
    response = auth.make_credential({
        1: hashlib.sha256(client_json).digest(),
        2: {"id": RP_ID, "name": "Example"},
        3: {"id": os.urandom(16), "name": "alice"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True, "uv": True},
    })
    return {"fmt": response[1], "authData": response[2], "attStmt": response[3]}


def replace_attestation_leaf(auth, response, *, ou="Authenticator Attestation", include_aaguid=True, aaguid_critical=False):
    original = x509.load_der_x509_certificate(response["attStmt"]["x5c"][0])
    root = x509.load_der_x509_certificate(auth._ca.root_cert_der)
    root_key = serialization.load_pem_private_key(
        auth._ca.root_key_pem.encode(), password=None
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Vendor"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Authenticator"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.subject)
        .public_key(original.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(original.not_valid_before_utc)
        .not_valid_after(original.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if include_aaguid:
        extension = original.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
        )
        builder = builder.add_extension(extension.value, critical=aaguid_critical)
    response["attStmt"]["x5c"][0] = builder.sign(
        root_key, hashes.SHA256()
    ).public_bytes(serialization.Encoding.DER)


def test_registration_requires_exact_expected_origin(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="none", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    malicious = client_data(challenge, origin="https://evil.example.com")
    response = registration(auth, malicious)

    with pytest.raises(RpError, match="origin"):
        verify_registration(
            RP_ID,
            malicious,
            response,
            challenge,
            expected_origin=ORIGIN,
        )


def test_registration_rejects_cross_origin_ceremony(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="none", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    crossed = client_data(challenge, cross_origin=True)
    response = registration(auth, crossed)

    with pytest.raises(RpError, match="cross-origin"):
        verify_registration(
            RP_ID,
            crossed,
            response,
            challenge,
            expected_origin=ORIGIN,
        )


def trusted_attestation_policy(response):
    root_der = response["attStmt"]["x5c"][-1]
    root = x509.load_der_x509_certificate(root_der)
    return {
        "require_attestation": True,
        "trusted_attestation_root_sha256": [
            root.fingerprint(hashes.SHA256()).hex()
        ],
    }


def test_attestation_rejects_invalid_subject_profile(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="packed_x5c", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    replace_attestation_leaf(auth, response, ou="Wrong OU")

    with pytest.raises(RpError, match="subject"):
        verify_registration(
            RP_ID, data, response, challenge, expected_origin=ORIGIN,
            policy=trusted_attestation_policy(response),
        )


def test_attestation_aaguid_extension_is_optional(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="packed_x5c", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    replace_attestation_leaf(auth, response, include_aaguid=False)

    result = verify_registration(
        RP_ID, data, response, challenge, expected_origin=ORIGIN,
        policy=trusted_attestation_policy(response),
    )
    assert result["attestation_verified"] is True


def test_attestation_accepts_pinned_root_supplied_out_of_band(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="packed_x5c", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    root_der = response["attStmt"]["x5c"].pop()
    root = x509.load_der_x509_certificate(root_der)
    fingerprint = root.fingerprint(hashes.SHA256()).hex()

    result = verify_registration(
        RP_ID,
        data,
        response,
        challenge,
        expected_origin=ORIGIN,
        policy={
            "require_attestation": True,
            "trusted_attestation_root_sha256": [fingerprint],
            "trusted_attestation_root_certificates": [root_der],
        },
    )

    assert result["attestation_verified"] is True


def test_attestation_requires_pinned_root_fingerprint_not_common_name(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"), attestation_mode="packed_x5c", uv_gate=lambda: True
    )
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)

    with pytest.raises(RpError, match="fingerprint"):
        verify_registration(
            RP_ID,
            data,
            response,
            challenge,
            expected_origin=ORIGIN,
            policy={
                "require_attestation": True,
                "trusted_attestation_cns": ["Batch Certificate"],
            },
        )

    root = x509.load_der_x509_certificate(response["attStmt"]["x5c"][-1])
    fingerprint = root.fingerprint(hashes.SHA256()).hex()
    result = verify_registration(
        RP_ID,
        data,
        response,
        challenge,
        expected_origin=ORIGIN,
        policy={
            "require_attestation": True,
            "trusted_attestation_root_sha256": [fingerprint],
        },
    )
    assert result["attestation_verified"] is True


def test_required_attestation_rejects_self_without_trusted_chain(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"),
                             attestation_mode="packed_self", uv_gate=lambda: True)
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    with pytest.raises(RpError):
        verify_registration(RP_ID, data, response, challenge, expected_origin=ORIGIN,
                            policy={"require_attestation": True})


def test_attestation_rejects_critical_aaguid_extension(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), uv_gate=lambda: True)
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    replace_attestation_leaf(auth, response, aaguid_critical=True)
    with pytest.raises(RpError):
        verify_registration(RP_ID, data, response, challenge, expected_origin=ORIGIN,
                            policy=trusted_attestation_policy(response))


def test_attestation_rejects_sub_ca_below_pathlen_zero(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), uv_gate=lambda: True)
    challenge = os.urandom(32)
    data = client_data(challenge)
    response = registration(auth, data)
    old = x509.load_der_x509_certificate(response["attStmt"]["x5c"][0])
    root = x509.load_der_x509_certificate(auth._ca.root_cert_der)
    root_key = serialization.load_pem_private_key(auth._ca.root_key_pem.encode(), password=None)
    upper_key = ec.generate_private_key(ec.SECP256R1())
    lower_key = ec.generate_private_key(ec.SECP256R1())
    upper_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Upper")])
    lower_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lower")])
    def issue(subject, issuer, public_key, signer, ca, path_length=None):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(old.not_valid_before_utc).not_valid_after(old.not_valid_after_utc)
                .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
                .sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    upper = issue(upper_name, root.subject, upper_key.public_key(), root_key, True, 0)
    lower = issue(lower_name, upper_name, lower_key.public_key(), upper_key, True)
    leaf = issue(old.subject, lower_name, old.public_key(), lower_key, False)
    response["attStmt"]["x5c"] = [leaf, lower, upper, auth._ca.root_cert_der]
    with pytest.raises(RpError):
        verify_registration(RP_ID, data, response, challenge, expected_origin=ORIGIN,
                            policy=trusted_attestation_policy(response))
