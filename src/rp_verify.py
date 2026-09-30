# language: Python 3.12, file: rp_verify.py, runtime: cryptography + cbor2
# *relying-party side. This is the code a real site runs — the thing the emulator
# *has to survive. If verify_* passes here with the RP's policy checks enabled,
# *the credential is indistinguishable from a hardware key at this layer.*

from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Optional

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from ctap2_core import FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV

# Relying-party policy knobs — these are the checks that separate a synced
# passkey from a roaming/hardware authenticator.
POLICY = {
    "require_user_verification": True,
    "require_user_presence": True,
    "require_attestation": False,      # set True to demand an attestation chain
    "rejected_aaguids": [],            # FIDO MDS revocations live here
    "rejected_cert_common_names": [],  # deny-list vendors outright
    "require_backup_eligibility": False,
    # When require_attestation is on, the attestation root must terminate at a
    # *recognised* FIDO attestation CA. A locally generated root is not, and that
    # is the check that actually stops a software authenticator.
    "trusted_attestation_cns": [],
}

# Attestation roots/issuers that appear in genuine vendor attestation chains.
# A real RP gets these from the FIDO Alliance Metadata Service (blob) rather than
# hardcoding them; the shapes are the same.
KNOWN_FIDO_ATTESTATION_ISSUERS = {
    "Yubico U2F EE",
    "Yubico U2F EE Serial",
    "Yubico Unified Attestation",
    "Yubico",
    "Google Hardware Attestation",
    "Microsoft Corporation",
    "Feitian Technologies",
    "SoloKeys",
    "Nitrokey",
}


class RpError(Exception):
    pass


def verify_registration(
    rp_id: str,
    client_data: bytes,
    attestation_response: dict,
    expected_challenge: bytes,
    policy: dict = None,
) -> dict:
    """
    Verify an authenticatorMakeCredential response (WebAuthn §7.1).

    client_data is the raw serialized ClientDataJSON — the RP hashes it itself and
    checks type/challenge/origin, exactly as a real backend does.
    """
    policy = {**POLICY, **(policy or {})}
    client_data_hash = hashlib.sha256(client_data).digest()

    _check_client_data(client_data, expected_challenge, "webauthn.create")

    auth_data = attestation_response["authData"]
    flags = auth_data[32]
    _check_registration_flags(flags, policy)

    rp_id_hash = auth_data[:32]
    if rp_id_hash != hashlib.sha256(rp_id.encode()).digest():
        raise RpError("rpIdHash does not match this relying party")

    # attested credential data
    aaguid = auth_data[37:53]
    cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
    credential_id = auth_data[55:55 + cred_id_len]
    rest = auth_data[55 + cred_id_len:]
    cose = cbor2.loads(rest)
    public_key = _cose_to_public_key(cose)

    fmt = attestation_response["fmt"]
    att_stmt = attestation_response.get("attStmt") or {}
    _verify_attestation_statement(fmt, att_stmt, auth_data + client_data_hash, public_key,
                                  aaguid, policy)

    return {
        "credential_id": credential_id,
        "aaguid": aaguid,
        "public_key_der": public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "sign_count": struct.unpack(">I", auth_data[33:37])[0],
        "flags": flags,
        "fmt": fmt,
        "attestation_verified": fmt != "none" and policy["require_attestation"],
        "backup_eligible": bool(flags & FLAG_BE),
        "backup_state": bool(flags & FLAG_BS),
    }


def verify_assertion(
    rp_id: str,
    client_data: bytes,
    assertion_response: dict,
    stored_public_key_der: bytes,
    stored_sign_count: int,
    expected_challenge: bytes,
    policy: dict = None,
) -> dict:
    """
    Verify an authenticatorGetAssertion response (WebAuthn §7.2).

    Returns the new sign count. Raises RpError on any failure.
    """
    policy = {**POLICY, **(policy or {})}
    client_data_hash = hashlib.sha256(client_data).digest()
    _check_client_data(client_data, expected_challenge, "webauthn.get")

    credential_id = assertion_response[1]
    auth_data = assertion_response[2]
    signature = assertion_response[3]
    user = assertion_response.get(4)
    number_of_credentials = assertion_response.get(5)

    flags = auth_data[32]
    if not flags & FLAG_UP and policy["require_user_presence"]:
        raise RpError("UP flag not set — no user presence signal")
    if policy["require_user_verification"] and not flags & FLAG_UV:
        raise RpError("UV flag not set but RP requires user verification")
    if flags & FLAG_AT:
        raise RpError("assertion authData must not carry attested credential data")

    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise RpError("rpIdHash does not match this relying party")

    new_count = struct.unpack(">I", auth_data[33:37])[0]
    # Per WebAuthn §7.2 step 21: if both counts are non-zero and do not increase,
    # the authenticator may be cloned.
    if stored_sign_count and new_count and new_count <= stored_sign_count:
        raise RpError(
            f"signature counter did not increase ({stored_sign_count} -> {new_count}) "
            "— possible cloned authenticator"
        )

    public_key = serialization.load_der_public_key(stored_public_key_der)
    try:
        public_key.verify(signature, auth_data + client_data_hash, ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise RpError(f"assertion signature failed verification: {exc}")

    return {
        "credential_id": credential_id,
        "sign_count": new_count,
        "user_handle": user.get("id") if user else None,
        "number_of_credentials": number_of_credentials,
    }


# --------------------------------------------------------------------------- internals


def _check_client_data(client_data: bytes, expected_challenge: bytes, expected_type: str):
    try:
        parsed = json.loads(client_data.decode())
    except Exception as exc:
        raise RpError(f"clientData is not valid JSON: {exc}")
    if parsed.get("type") != expected_type:
        raise RpError(
            f"expected ceremony {expected_type!r}, got {parsed.get('type')!r}"
        )
    import base64
    challenge = base64.urlsafe_b64decode(parsed["challenge"] + "==")
    if challenge != expected_challenge:
        raise RpError("clientData challenge does not match the challenge we issued")


def _check_registration_flags(flags: int, policy: dict):
    if not flags & FLAG_AT:
        raise RpError("AT flag missing from registration authData")
    if policy["require_user_presence"] and not flags & FLAG_UP:
        raise RpError("UP flag not set but RP requires user presence")
    if policy["require_user_verification"] and not flags & FLAG_UV:
        raise RpError("UV flag not set but RP requires user verification")
    if policy["require_backup_eligibility"] and not flags & FLAG_BE:
        raise RpError("BE flag not set but RP requires a backup-eligible credential")


def _cose_to_public_key(cose: dict) -> ec.EllipticCurvePublicKey:
    kty = cose[1]
    if kty != 2:
        raise RpError(f"unsupported COSE key type {kty} (only EC2 handled here)")
    crv = cose[-1]
    curves = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}
    if crv not in curves:
        raise RpError(f"unsupported COSE curve {crv}")
    x = int.from_bytes(cose[-2], "big")
    y = int.from_bytes(cose[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, curves[crv]()).public_key()


def _verify_attestation_statement(fmt: str, stmt: dict, signed_data: bytes,
                                  credential_key, aaguid: bytes, policy: dict):
    """
    Verify a packed/none attestation statement (WebAuthn §8.2).

    The subtle spec rule: with `x5c` present the signature is made by the
    *attestation certificate's* key, not the credential key. Only when x5c is
    empty is it self-attestation and the credential key signs. Chromium's virtual
    authenticator is the canonical example — it presents a self-signed leaf and
    signs with that leaf's key, which is why a verifier that checks the credential
    key rejects a perfectly valid response.
    """
    if fmt == "none":
        if policy["require_attestation"]:
            raise RpError("RP requires attestation, authenticator returned fmt=none")
        return

    if fmt != "packed":
        raise RpError(f"unsupported attestation format {fmt!r}")

    if "sig" not in stmt:
        raise RpError("packed attestation without a signature")
    alg = stmt.get("alg")
    if alg != -7:
        raise RpError(f"unsupported packed alg {alg}")

    x5c = stmt.get("x5c") or []

    if x5c:
        leaf = x509.load_der_x509_certificate(x5c[0])
        signing_key = leaf.public_key()
        chain_kind = "x5c"
    else:
        signing_key = credential_key
        chain_kind = "self"

    try:
        signing_key.verify(stmt["sig"], signed_data, ECDSA(hashes.SHA256()))
    except InvalidSignature:
        which = ("attestation certificate" if chain_kind == "x5c"
                 else "credential")
        raise RpError(
            f"attestation signature does not verify against the {which} key"
        )
    except Exception as exc:
        raise RpError(f"attestation signature could not be checked: {exc}")

    if chain_kind == "x5c" and policy["require_attestation"]:
        cn = _common_name(leaf)
        if cn in policy["rejected_cert_common_names"]:
            raise RpError(f"attestation certificate CN {cn!r} is on the deny-list")
        if leaf.subject == leaf.issuer:
            # Self-issued single-cert chain. Legitimate for Chromium's virtual
            # authenticator, never for vendor hardware — the RP decides whether
            # it trusts that certificate by name.
            if policy["trusted_attestation_cns"] and cn not in policy["trusted_attestation_cns"]:
                raise RpError(
                    f"attestation certificate {cn!r} is self-issued and is not a "
                    "trusted FIDO attestation CA"
                )
        elif len(x5c) > 1:
            root = x509.load_der_x509_certificate(x5c[-1])
            if leaf.issuer != root.subject:
                raise RpError("attestation chain does not terminate at the presented root")
            issuer_cn = _common_name(root) or _common_name(leaf) or ""
            trusted = policy["trusted_attestation_cns"] or KNOWN_FIDO_ATTESTATION_ISSUERS
            if issuer_cn not in trusted:
                raise RpError(
                    f"attestation root {issuer_cn!r} is not a trusted FIDO attestation CA "
                    "— this authenticator vouched for itself, so it cannot be "
                    "treated as hardware-backed"
                )
        return

    # self-attestation: spec requires an all-zero AAGUID
    if chain_kind == "self" and aaguid != b"\x00" * 16:
        raise RpError(
            "self-attestation presented with a non-zero AAGUID — spec violation, "
            "and a cheap signal an RP can check"
        )


def _common_name(cert) -> Optional[str]:
    vals = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return vals[0].value if vals else None
