# language: Python 3.12, file: analyze_attestation.py, runtime: cryptography + cbor2
# *The honest answer to the hard part of the brief.*
# *A software authenticator cannot mint a vendor-signed attestation. It can mint a
# *self-signed chain that *looks* structurally identical. This tool prints exactly
# *what an RP can and cannot learn from an attestation statement — which is the
# *difference between "impersonate a key" and "be rejected in one line of code".*

from __future__ import annotations

import base64
import json
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

# AAGUIDs of real, FIDO-MDS-listed authenticator families. An RP that pins or
# deny-lists AAGUIDs resolves the whole question without touching the network.
# Genuine vendor attestation roots — real RPs load these from the FIDO MDS blob.
KNOWN_FIDO_ATTESTATION_ISSUERS = {
    "Yubico U2F EE", "Yubico U2F EE Serial", "Yubico Unified Attestation",
    "Yubico", "Google Hardware Attestation", "Microsoft Corporation",
    "Feitian Technologies", "SoloKeys", "Nitrokey",
}

KNOWN_AAGUIDS = {
    "00000000000000000000000000000000": "self-attestation (AAGUID must be all-zero)",
    "ee882879721776c68f8f4249af2df5e": "Yubico YubiKey 5 series",
    "fa2b99dc9c939b41de6b2a6d56024f0b": "Yubico YubiKey 5 FIPS",
    "cb69481e8a7f005a397e0088faf85d65": "Yubico Security Key",
    "d8522d9f575b486688a9ba99fa02f35b": "Yubico YubiKey 5 NFC",
    "b93fd961-f2e6-462f-b122-82002247de78": "Google Titan / Chrome (internal)",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello hardware-backed",
    "adce0002-35bc-c60a-648b-0b25f1f05503": "Chromium virtual authenticator",
}


def _fmt_bytes(b) -> str:
    if isinstance(b, str):
        b = b.encode() if not b.startswith("b") else eval(b)
    return b.hex()


def inspect(attestation_response: dict, auth_data: bytes, client_data_hash: bytes) -> dict:
    """Walk a packed/none attestation and report every signal an RP could use."""
    fmt = attestation_response.get("fmt")
    stmt = attestation_response.get("attStmt") or {}
    findings: list = []
    x5c = stmt.get("x5c") or []

    aaguid = auth_data[37:53]
    aaguid_hex = aaguid.hex()

    report = {
        "fmt": fmt,
        "aaguid": aaguid_hex,
        "aaguid_known": aaguid_hex in KNOWN_AAGUIDS,
        "aaguid_identity": KNOWN_AAGUIDS.get(aaguid_hex, "UNRECOGNISED / not in FIDO MDS"),
        "attestation_chain_length": len(x5c),
    }

    if fmt == "none":
        findings.append({
            "signal": "attestation statement is empty",
            "what_rp_sees": "fmt='none' — authenticator declined to attest",
            "rp_can_reject": True,
            "how": "Most RPs treat fmt=none as acceptable for privacy; a security-conscious "
                   "RP simply refuses to register keys that skip attestation.",
        })
        report["findings"] = findings
        return report

    if fmt == "packed":
        leaf = x509.load_der_x509_certificate(x5c[0]) if x5c else None
        if leaf is not None:
            report["leaf_subject"] = leaf.subject.rfc4514_string()
            report["leaf_issuer"] = leaf.issuer.rfc4514_string()
            report["leaf_cn"] = _cn(leaf)
            report["leaf_is_self_issued"] = leaf.subject == leaf.issuer
            report["leaf_validity_days"] = (leaf.not_valid_after_utc
                                            - leaf.not_valid_before_utc).days
            report["leaf_is_ca"] = _is_ca(leaf)
            report["leaf_has_fido_extension"] = _has_fido_aaguid(leaf)

            if report["leaf_is_self_issued"]:
                findings.append({
                    "signal": "attestation certificate is self-issued",
                    "what_rp_sees": f"subject == issuer == {report['leaf_subject']}",
                    "rp_can_reject": True,
                    "how": "Compare subject against issuer. A YubiKey batch certificate is "
                           "issued by Yubico's CA, so they differ. A locally generated CA "
                           "signs itself, so they match. One attribute comparison.",
                })

            if not report["leaf_has_fido_extension"]:
                findings.append({
                    "signal": "leaf certificate carries no id-fido-gen-ce-aaguid extension",
                    "what_rp_sees": "OID 1.3.6.1.4.1.45724.1.1.4 absent",
                    "rp_can_reject": True,
                    "how": "Real vendor attestation certs embed the AAGUID as an X.509 "
                           "extension. An emulator that only fills the CBOR aaguid field "
                           "leaves this empty.",
                })

            # The decisive one: is the attestation root an actual FIDO CA?
            root = x509.load_der_x509_certificate(x5c[-1]) if len(x5c) > 1 else None
            if root is not None:
                root_cn = _cn(root)
                report["root_cn"] = root_cn
                report["root_is_trusted_fido_ca"] = root_cn in KNOWN_FIDO_ATTESTATION_ISSUERS
                if not report["root_is_trusted_fido_ca"]:
                    findings.append({
                        "signal": "attestation chain terminates at an untrusted self-made CA",
                        "what_rp_sees": f"root CN={root_cn!r} — not a recognised FIDO "
                                        "attestation root (Yubico, Google, Microsoft, ...)",
                        "rp_can_reject": True,
                        "how": "The chain can be structurally perfect — correct leaf, real "
                               "signature, FIDO extension present — and still prove nothing, "
                               "because the root is one this process generated itself. An RP "
                               "that pins FIDO MDS attestation roots rejects it here.",
                    })

            if not report["aaguid_known"]:
                findings.append({
                    "signal": "AAGUID is not a listed authenticator model",
                    "what_rp_sees": f"aaguid={aaguid_hex} — no entry in FIDO MDS",
                    "rp_can_reject": True,
                    "how": "Download the FIDO Metadata Service blob and check membership, or "
                           "maintain an allow-list. This is the single highest-value check.",
                })
        elif not x5c:
            findings.append({
                "signal": "self-attestation carries no certificate chain",
                "what_rp_sees": "packed with x5c=[] — the key vouched for itself",
                "rp_can_reject": True,
                "how": "WebAuthn explicitly permits this, but an RP that requires "
                       "attestation can reject it outright.",
            })

        # Signature check: with x5c present the signature is by the *attestation
        # certificate* key, not the credential key (WebAuthn §8.2). Chromium's
        # virtual authenticator signs with its self-signed leaf.
        try:
            if x5c:
                signing_key = x509.load_der_x509_certificate(x5c[0]).public_key()
                report["signature_signed_by"] = "attestation certificate (x5c leaf)"
            else:
                signing_key = _pubkey_from_authdata(auth_data)
                report["signature_signed_by"] = "credential key (self-attestation)"
            signing_key.verify(stmt["sig"], auth_data + client_data_hash,
                               ECDSA(hashes.SHA256()))
            report["self_signature_valid"] = True
            findings.append({
                "signal": "packed signature verifies",
                "what_rp_sees": f"valid signature over authData||clientDataHash, "
                                f"signed by the {report['signature_signed_by']}",
                "rp_can_reject": False,
                "how": "This proves nothing about hardware origin — a software key signs "
                       "its own attestation perfectly well. It only catches tampering.",
            })
        except Exception as exc:
            report["self_signature_valid"] = False
            report["signature_error"] = str(exc)

    report["findings"] = findings
    report["verdict"] = _verdict(report)
    return report


def _verdict(report: dict) -> str:
    rejectable = [f for f in report.get("findings", []) if f["rp_can_reject"]]
    if not rejectable:
        return "indistinguishable from hardware at the attestation layer"
    return (f"{len(rejectable)} signal(s) let an RP reject this in one comparison: "
            + "; ".join(f["signal"] for f in rejectable))


def _cn(cert) -> str:
    vals = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return vals[0].value if vals else "<none>"


def _is_ca(cert) -> bool:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return ext.value.ca
    except x509.ExtensionNotFound:
        return False


def _has_fido_aaguid(cert) -> bool:
    oid = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
        return True
    except x509.ExtensionNotFound:
        return False


def _pubkey_from_authdata(auth_data: bytes):
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    cose = cbor2.loads(auth_data[55 + cred_id_len:])
    crv = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}[cose[-1]]
    x = int.from_bytes(cose[-2], "big")
    y = int.from_bytes(cose[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, crv()).public_key()
