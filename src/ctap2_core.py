# language: Python 3.12, file: ctap2_core.py, runtime: cryptography + cbor2
# *the actual CTAP2 authenticator state machine — shared by every transport below.*
# *this is where UP/UV gating, pinUvAuth, and the credential store actually live,*
# *so "is this a software authenticator" is decided by policy in ONE place, not per transport.*

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- constants

CTAP2_ERR = {
    0x00: "CTAP2_OK",
    0x01: "CTAP1_ERR_INVALID_COMMAND",
    0x02: "CTAP1_ERR_INVALID_PARAMETER",
    0x03: "CTAP1_ERR_INVALID_LENGTH",
    0x04: "CTAP1_ERR_INVALID_SEQ",
    0x05: "CTAP1_ERR_TIMEOUT",
    0x06: "CTAP1_ERR_CHANNEL_BUSY",
    0x0A: "CTAP1_ERR_LOCK_REQUIRED",
    0x0B: "CTAP1_ERR_INVALID_CHANNEL",
    0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
    0x12: "CTAP2_ERR_INVALID_CBOR",
    0x14: "CTAP2_ERR_MISSING_PARAMETER",
    0x15: "CTAP2_ERR_LIMIT_EXCEEDED",
    0x16: "CTAP2_ERR_UNSUPPORTED_EXTENSION",
    0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED",
    0x21: "CTAP2_ERR_PROCESSING",
    0x22: "CTAP2_ERR_INVALID_CREDENTIAL",
    0x23: "CTAP2_ERR_USER_ACTION_PENDING",
    0x24: "CTAP2_ERR_OPERATION_PENDING",
    0x25: "CTAP2_ERR_NO_OPERATIONS",
    0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
    0x27: "CTAP2_ERR_OPERATION_DENIED",
    0x28: "CTAP2_ERR_KEY_STORE_FULL",
    0x2B: "CTAP2_ERR_NO_OPERATION_PENDING",
    0x2C: "CTAP2_ERR_UNSUPPORTED_OPTION",
    0x2D: "CTAP2_ERR_INVALID_OPTION",
    0x2E: "CTAP2_ERR_KEEPALIVE_CANCEL",
    0x2F: "CTAP2_ERR_NO_CREDENTIALS",
    0x30: "CTAP2_ERR_USER_ACTION_TIMEOUT",
    0x31: "CTAP2_ERR_NOT_ALLOWED",
    0x32: "CTAP2_ERR_PIN_INVALID",
    0x33: "CTAP2_ERR_PIN_BLOCKED",
    0x34: "CTAP2_ERR_PIN_AUTH_INVALID",
    0x35: "CTAP2_ERR_PIN_AUTH_BLOCKED",
    0x36: "CTAP2_ERR_PIN_NOT_SET",
    0x37: "CTAP2_ERR_PUAT_REQUIRED",
    0x38: "CTAP2_ERR_PIN_POLICY_VIOLATION",
    0x39: "CTAP2_ERR_REQUEST_TOO_LARGE",
    0x3A: "CTAP2_ERR_ACTION_TIMEOUT",
    0x3B: "CTAP2_ERR_UP_REQUIRED",
    0x3C: "CTAP2_ERR_UV_BLOCKED",
    0x7F: "CTAP1_ERR_OTHER",
}

# authenticator data flag bits
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80

ALG_ES256 = -7
ALG_RS256 = -257
ALG_EDDSA = -8
ALG_ES384 = -35
ALG_ES512 = -36

COSE_KTY_EC2 = 2
COSE_KTY_RSA = 3
COSE_KTY_OKP = 1

MIN_PIN_LEN = 4
MAX_PIN_RETRY = 8
MAX_UV_RETRY = 8


class CtapError(Exception):
    """Carries a CTAP2 status byte so transports can serialise it verbatim."""

    def __init__(self, code: int, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{CTAP2_ERR.get(code, hex(code))}{': ' + detail if detail else ''}")


def err_name(code: int) -> str:
    return CTAP2_ERR.get(code, hex(code))


# CTAP2 integer map keys. makeCredential and getAssertion reuse low key numbers
# for different fields, so each command gets its own map.
MAKE_CREDENTIAL_KEYS = {
    0x01: "clientDataHash", 0x02: "rp", 0x03: "user",
    0x04: "pubKeyCredParams", 0x05: "excludeList", 0x06: "extensions",
    0x07: "options", 0x08: "pinUvAuthParam", 0x09: "pinUvAuthProtocol",
}
GET_ASSERTION_KEYS = {
    0x01: "rpId", 0x02: "clientDataHash", 0x03: "allowList",
    0x04: "extensions", 0x05: "options", 0x06: "pinUvAuthParam",
    0x07: "pinUvAuthProtocol",
}


def normalize_params(req: dict, keymap: dict) -> dict:
    """Accept either CTAP2 numeric keys or friendly names; return friendly names."""
    out = {}
    for k, v in req.items():
        if isinstance(k, int):
            name = keymap.get(k)
            if name is not None:
                out[name] = v
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- crypto helpers


def _aes_cbc(key: bytes, data: bytes, iv: bytes, decrypt: bool = False) -> bytes:
    # *FIDO uses AES-256-CBC with a zero IV throughout — no padding on the plaintext side.*
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = c.decryptor() if decrypt else c.encryptor()
    return e.update(data) + e.finalize()


def _hkdf_32(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _ctap_cbor_encode(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


# --------------------------------------------------------------------------- credential records


@dataclass
class Credential:
    """One WebAuthn credential, persisted by the store."""

    credential_id: bytes
    rp_id: str
    user_handle: bytes
    user_name: str
    user_display_name: str
    private_key_pem: str          # PKCS#8, P-256 — what CDP's addCredential also wants
    alg: int = ALG_ES256
    sign_count: int = 0
    is_resident: bool = True
    backup_eligible: bool = False
    backup_state: bool = False
    cred_protect: str = "userVerificationOptional"
    cred_lg: Optional[str] = None
    cred_blob: Optional[bytes] = None
    hmac_secret: Optional[bytes] = None     # non-UV half of the hmac-secret seed
    created_ts: float = field(default_factory=time.time)

    def private_key(self) -> ec.EllipticCurvePrivateKey:
        return serialization.load_pem_private_key(
            self.private_key_pem.encode(), password=None
        )

    def public_key_der(self) -> bytes:
        return self.private_key().public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def cose_key(self) -> dict:
        """COSE_Key CBOR for the credential public key (EC2 / P-256 / ES256)."""
        numbers = self.private_key().public_key().public_numbers()
        return {
            1: COSE_KTY_EC2,
            3: ALG_ES256,
            -1: 1,                 # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }

    def rp_id_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()


def _credential_to_json(c: Credential) -> dict:
    """Credential -> JSON-safe dict. Bytes fields become hex; everything else passes."""
    out = {}
    for field, value in c.__dict__.items():
        if isinstance(value, bytes):
            out[field] = value.hex()
        elif value is None or isinstance(value, (str, int, float, bool)):
            out[field] = value
        else:
            out[field] = str(value)
    return out


def _credential_from_json(d: dict) -> Credential:
    fields = {}
    for field, value in d.items():
        if field in ("credential_id", "user_handle", "cred_blob", "hmac_secret"):
            fields[field] = bytes.fromhex(value) if value else None
        else:
            fields[field] = value
    return Credential(**fields)


# --------------------------------------------------------------------------- attestation CA


@dataclass
class AttestationCa:
    """
    A local attestation chain. Deliberately NOT a real vendor CA — the analyser exists
    precisely to show an RP can tell the difference. See analyze_attestation.py.

    The root is a real self-signed CA; the leaf is issued *by* that root and wraps
    the credential public key, exactly as a packed/x5c attestation should. It is a
    **local** CA, so its root is not in any trust store — which is the honest answer
    to the "can this pass as a YubiKey" question: no, and rp_verify says so out loud.
    """

    root_cert_der: bytes
    root_key_pem: str
    aaguid: bytes
    root_subject: str = ""

    @staticmethod
    def generate(common_name: str, aaguid: bytes) -> "AttestationCa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509_name(common_name)
        cert = (
            x509_builder()
            .subject_name(subject)
            .issuer_name(subject)          # self-signed root
            .public_key(key.public_key())
            .serial_number(0x476F4F4C46444)
            .not_valid_before(_epoch(1500000000))
            .not_valid_after(_epoch(1500000000 + 60 * 60 * 24 * 365 * 10))
            .add_extension(basic_constraints_ca(), critical=True)
            .sign(key, hashes.SHA256())
        )
        return AttestationCa(
            root_cert_der=cert.public_bytes(serialization.Encoding.DER),
            root_key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            aaguid=aaguid,
            root_subject=subject.rfc4514_string(),
        )

    def issue_leaf(self, credential_pub_der: bytes, serial: int) -> bytes:
        """
        Batch attestation certificate: subject = credential key, issuer = our root.
        Carries the FIDO AAGUID extension (1.3.6.1.4.1.45724.1.1.4) the way vendor
        certificates do, so the only remaining tell is that the issuer is not a
        recognised vendor — which is exactly the check an RP must make.
        """
        key = serialization.load_pem_private_key(self.root_key_pem.encode(), password=None)
        root = _certlib().load_der_x509_certificate(self.root_cert_der)
        return (
            x509_builder()
            .subject_name(x509_name("Batch Attestation"))
            .issuer_name(root.subject)        # issued BY the root, not itself
            .public_key(serialization.load_der_public_key(credential_pub_der))
            .serial_number(serial)
            .not_valid_before(_epoch(1500000000))
            .not_valid_after(_epoch(1500000000 + 60 * 60 * 24 * 90))
            .add_extension(basic_constraints_ca(), critical=False)
            .add_extension(fido_aaguid_extension(self.aaguid), critical=False)
            .sign(key, hashes.SHA256())
        ).public_bytes(serialization.Encoding.DER)


def _epoch(ts: int):
    """cryptography >= 42 wants datetime, not struct_time."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _certlib():
    from cryptography import x509

    return x509


def x509_name(cn: str):
    x = _certlib()
    return x.Name([
        x.NameAttribute(x.oid.NameOID.COUNTRY_NAME, "US"),
        x.NameAttribute(x.oid.NameOID.ORGANIZATION_NAME, "Lab"),
        x.NameAttribute(x.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x.NameAttribute(x.oid.NameOID.COMMON_NAME, cn),
    ])


def x509_builder():
    x = _certlib()
    return x.CertificateBuilder()


def basic_constraints_ca():
    x = _certlib()
    return x.BasicConstraints(ca=True, path_length=None)


def fido_aaguid_extension(aaguid: bytes):
    """
    id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4) — vendor attestation certs carry
    the authenticator model here as a DER OCTET STRING. Omitting it is one of the
    cheapest tells an RP can read off the leaf.
    """
    x = _certlib()
    return x.UnrecognizedExtension(
        x.oid.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
        _der_octet_string(aaguid),
    )


def _der_octet_string(data: bytes) -> bytes:
    """Minimal DER TLV encoder for OCTET STRING (tag 0x04)."""
    def tlv(tag: int, payload: bytes) -> bytes:
        length = len(payload)
        if length < 0x80:
            return bytes([tag, length]) + payload
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(encoded)]) + encoded + payload

    return tlv(0x04, data)


# --------------------------------------------------------------------------- the authenticator


@dataclass
class Ctap2Authenticator:
    """
    One software authenticator. `up_gate` and `uv_gate` are the load-bearing fields:
    a real key proves presence with a finger and verifies identity with a secret in
    silicon. Here both are callables, so the operator decides what "presence" costs.
    """

    store_path: str
    aaguid: bytes = b"\x00" * 16
    attestation_mode: str = "packed_x5c"   # none | packed_self | packed_x5c
    up_gate: Callable[[], bool] = lambda: True
    uv_gate: Callable[[], bool] = lambda: True
    _credentials: dict = field(default_factory=dict)
    _pin: Optional[bytes] = None
    _pin_hash: Optional[bytes] = None
    _pin_retries: int = MAX_PIN_RETRY
    _uv_retries: int = MAX_UV_RETRY
    _ca: Optional[AttestationCa] = None
    _uv_blocked: bool = False
    pin_uv_auth_protocols: tuple = (2, 1)

    # ---------------------------------------------------------------- lifecycle

    def __post_init__(self):
        self.load()

    def load(self):
        if os.path.exists(self.store_path):
            import json
            from base64 import b64decode

            with open(self.store_path) as fh:
                blob = json.load(fh)
            self._pin_hash = b64decode(blob["pin_hash"]) if blob.get("pin_hash") else None
            self._pin_retries = blob.get("pin_retries", MAX_PIN_RETRY)
            self._uv_retries = blob.get("uv_retries", MAX_UV_RETRY)
            self._uv_blocked = blob.get("uv_blocked", False)
            self._credentials = {bytes.fromhex(k): _credential_from_json(v)
                                for k, v in blob["credentials"].items()}
            if blob.get("ca_cert"):
                self._ca = AttestationCa(
                    root_cert_der=b64decode(blob["ca_cert"]),
                    root_key_pem=blob["ca_key"],
                    aaguid=b64decode(blob["aaguid"]),
                )
        if self._ca is None:
            self._ca = AttestationCa.generate("Batch Certificate", self.aaguid)

    def save(self):
        """Atomic write — a half-flushed credential store means unregistered keys."""
        import json
        from base64 import b64encode

        os.makedirs(os.path.dirname(os.path.abspath(self.store_path)) or ".", exist_ok=True)
        payload = {
            "pin_hash": b64encode(self._pin_hash).decode() if self._pin_hash else None,
            "pin_retries": self._pin_retries,
            "uv_retries": self._uv_retries,
            "uv_blocked": self._uv_blocked,
            "aaguid": b64encode(self._ca.aaguid).decode(),
            "ca_cert": b64encode(self._ca.root_cert_der).decode(),
            "ca_key": self._ca.root_key_pem,
            "credentials": {cid.hex(): _credential_to_json(c)
                            for cid, c in self._credentials.items()},
        }
        tmp = self.store_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.store_path)

    # ---------------------------------------------------------------- PIN

    def set_pin(self, pin: str):
        if len(pin) < MIN_PIN_LEN:
            raise CtapError(0x38, "pin too short")
        self._pin = pin.encode()
        self._pin_hash = hashlib.sha256(self._pin).digest()[:16]
        self._pin_retries = MAX_PIN_RETRY
        self.save()

    def verify_pin(self, pin: str) -> bool:
        if self._pin_hash is None:
            raise CtapError(0x36, "pin not set")
        got = hashlib.sha256(pin.encode()).digest()[:16]
        ok = hmac.compare_digest(got, self._pin_hash)
        if ok:
            self._pin_retries = MAX_PIN_RETRY
        else:
            self._pin_retries -= 1
            if self._pin_retries == 0:
                raise CtapError(0x33, "pin blocked")
        self.save()
        return ok

    # ---------------------------------------------------------------- user verification

    def _uv(self) -> None:
        """Internal UV. Real hardware reads a finger; here the gate decides."""
        if self._uv_blocked:
            raise CtapError(0x3C, "uv blocked")
        if not self.uv_gate():
            self._uv_retries -= 1
            if self._uv_retries == 0:
                self._uv_blocked = True
                self.save()
            raise CtapError(0x3C, "uv failed")

    def _up(self) -> None:
        if not self.up_gate():
            raise CtapError(0x3B, "up required")

    # ---------------------------------------------------------------- CTAP commands

    def get_info(self) -> dict:
        return {
            1:  [ALG_ES256, ALG_RS256, ALG_EDDSA],
            2:  32,                                  # maxMsgSize
            3:  1,                                   # pinUvAuthProtocols count
            4:  list(self.pin_uv_auth_protocols),
            5:  MAX_PIN_RETRY,
            6:  MAX_UV_RETRY,
            7:  64,                                  # maxCredentialIdLength
            8:  32,                                  # maxCredentialIdLength (legacy slot)
            9:  [{"type": "public-key", "alg": ALG_ES256}],   # algorithms
            0x0A: [{"id": "hmac-secret", "version": 2},
                   {"id": "credBlob", "version": 1}],       # extensions
            0x0B: 3,                                 # maxAuthenticatorConfigLength
            0x0C: {"rk": True, "up": True, "clientPin": self._pin is not None, "pinUvAuthToken": True},
            0x0D: 2,                                 # maxUvAttemptsPerMakeCredential
            0x0E: 1,
        }

    def reset(self):
        self._credentials.clear()
        self._pin = None
        self._pin_hash = None
        self._pin_retries = MAX_PIN_RETRY
        self._uv_retries = MAX_UV_RETRY
        self._uv_blocked = False
        self.save()

    def list_credentials(self, rp_id: Optional[str] = None) -> list:
        creds = self._credentials.values()
        if rp_id is not None:
            creds = [c for c in creds if c.rp_id == rp_id]
        return list(creds)

    def add_credential(self, cred: Credential):
        self._credentials[cred.credential_id] = cred
        self.save()

    def make_credential(self, req: dict) -> dict:
        req = normalize_params(req, MAKE_CREDENTIAL_KEYS)
        client_data_hash = req["clientDataHash"]
        rp = req["rp"]
        user = req["user"]
        rp_id = rp["id"]
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        pub_key_param = req.get("pubKeyCredParams", [])

        options = req.get("options") or {}
        pin_auth = req.get("pinUvAuthParam")

        # rk / uv / credProtect all live under `options` (key 0x07), not at the
        # top level — reading them off the request root silently yields rk=False.
        want_rk = bool(options.get("rk", False))
        want_uv = bool(options.get("uv", True))

        if not any(p.get("alg") == ALG_ES256 for p in pub_key_param):
            raise CtapError(0x26, "no ES256 offered")
        for ex in req.get("excludeList", []):
            ex_id = ex.get("id")
            if isinstance(ex_id, str):
                ex_id = bytes.fromhex(ex_id)
            if ex_id and ex_id in self._credentials:
                raise CtapError(0x19, "credential already exists for this user")

        self._up()
        uv = self._pin is not None or want_uv
        if uv:
            self._uv()

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        cred = Credential(
            credential_id=os.urandom(32),
            rp_id=rp_id,
            user_handle=bytes.fromhex(user["id"]),
            user_name=user.get("name", ""),
            user_display_name=user.get("displayName", ""),
            private_key_pem=pem,
            sign_count=0,
            is_resident=want_rk,
            cred_protect=req.get("credProtect", "userVerificationOptional"),
            cred_lg=req.get("credBlob"),
            hmac_secret=os.urandom(32),
        )
        self._credentials[cred.credential_id] = cred

        flags = FLAG_AT | FLAG_UP
        if uv:
            flags |= FLAG_UV
        if cred.backup_eligible:
            flags |= FLAG_BE
        if cred.backup_state:
            flags |= FLAG_BS

        att_data = build_auth_data(
            rp_id_hash, flags, cred.sign_count, aaguid=self._ca.aaguid,
            credential_id=cred.credential_id, cose_key=cred.cose_key(),
        )
        fmt, att_stmt = self._attest(att_data + client_data_hash, cred)
        self.save()

        # NOTE: per CTAP2.1 §6.1.2 the response map carries only
        # fmt / authData / attStmt / epAtt / largeBlobKey. The credential ID is
        # NOT a response field — it is the trailing bytes of authData, which the
        # client parses out. Putting it in the map would be a spec violation.
        return {
            "fmt": fmt,
            "authData": att_data,
            "attStmt": att_stmt,
            "epAtt": False,
            "largeBlobKey": None,
        }

    def _attest(self, auth_data_with_hash: bytes, cred: Credential):
        if self.attestation_mode == "none":
            return "none", {}
        key = cred.private_key()
        if self.attestation_mode == "packed_self":
            # *spec: self-attestation requires an all-zero AAGUID — we key the AAGUID at 0*
            sig = key.sign(auth_data_with_hash, ec.ECDSA(hashes.SHA256()))
            return "packed", {
                "alg": ALG_ES256,
                "sig": sig,
                "x5c": [],
            }
        leaf = self._ca.issue_leaf(cred.public_key_der(), serial=len(self._credentials))
        sig = key.sign(auth_data_with_hash, ec.ECDSA(hashes.SHA256()))
        return "packed", {
            "alg": ALG_ES256,
            "sig": sig,
            "x5c": [leaf, self._ca.root_cert_der],
        }

    def get_assertion(self, req: dict) -> dict:
        req = normalize_params(req, GET_ASSERTION_KEYS)
        client_data_hash = req["clientDataHash"]
        rp_id_hash = hashlib.sha256(req["rpId"].encode()).digest()
        allow = req.get("allowList") or []

        if allow:
            # allowList entries arrive as CBOR byte strings; match on the credential
            # ID and enforce that the credential is scoped to this rpId.
            matches = []
            for entry in allow:
                cid = entry.get("id")
                if isinstance(cid, str):
                    cid = bytes.fromhex(cid)
                if cid and cid in self._credentials and self._credentials[cid].rp_id_hash() == rp_id_hash:
                    matches.append(self._credentials[cid])
            if not matches:
                raise CtapError(0x2F, "no credential in allowList for this rpId")
            cred = matches[0]
        else:
            resident = [c for c in self._credentials.values() if c.rp_id_hash() == rp_id_hash]
            if not resident:
                raise CtapError(0x2F, "no resident credential for rpId")
            self._up()
            cred = self._select_credential(resident)

        if len(cred.rp_id_hash()) != 32 or cred.rp_id_hash() != rp_id_hash:
            raise CtapError(0x22, "rpId mismatch")

        self._up()
        opts = req.get("options") or {}
        uv = self._pin is not None or bool(opts.get("uv", True))
        if uv:
            self._uv()

        cred.sign_count += 1
        flags = FLAG_UP
        if uv:
            flags |= FLAG_UV
        if cred.backup_eligible:
            flags |= FLAG_BE
        if cred.backup_state:
            flags |= FLAG_BS

        user_sel = req.get("user")
        # CTAP2.1 §6.2: response keys are 1=credentialId, 2=authData, 3=signature,
        # 4=user, 5=numberOfCredentials. The user entity is public data, so it
        # travels as bytes — NOT hex strings the way makeCredential receives it.
        resp_user = None
        if cred.is_resident or user_sel is not None:
            resp_user = {
                "id": cred.user_handle,
                "name": cred.user_name,
                "displayName": cred.user_display_name,
            }
        att_data = build_auth_data(rp_id_hash, flags, cred.sign_count)
        sig = cred.private_key().sign(
            att_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )
        out = {
            1: cred.credential_id,
            2: att_data,
            3: sig,
            4: resp_user,
            5: len([c for c in self._credentials.values()
                    if c.rp_id_hash() == rp_id_hash]),
        }
        self.save()
        return out

    def _select_credential(self, resident: list) -> Credential:
        # *a real key with 2 accounts shows a picker; the gate is where that UI plugs in.*
        if len(resident) == 1:
            return resident[0]
        self._up()
        return resident[0]

    def get_key_agreement(self) -> dict:
        key = ec.generate_private_key(ec.SECP256R1())
        self._ecdh_key = key
        return {
            1: ALG_ES256,   # kty EC2
            3: ALG_ES256,   # alg
            -1: 1,
            -2: key.public_key().public_numbers().x.to_bytes(32, "big"),
            -3: key.public_key().public_numbers().y.to_bytes(32, "big"),
        }

    def get_pin_token(self, pin_protocol: int, key_agreement_cbor: bytes) -> dict:
        if self._pin is None:
            raise CtapError(0x36, "pin not set")
        pub = parse_cose_public(key_agreement_cbor)
        x = self._ecdh_key.exchange(ec.ECDH(), pub)
        shared = x.to_bytes(32, "big")
        try:
            self.verify_pin(self._pin.decode())
        except CtapError:
            raise CtapError(0x33 if self._pin_retries == 0 else 0x31, "pin rejected")
        pin_token_enc = os.urandom(16)
        if pin_protocol == 1:
            pin_token = hmac.new(self._pin_hash, pin_token_enc, hashlib.sha256).digest()[:16]
        else:
            hkdf = _hkdf_32(shared, b"\x00" * 32, b"CTAP2 HMAC key")
            pin_token = hmac.new(
                hkdf, self._pin_hash + pin_token_enc, hashlib.sha256
            ).digest()[:16]
        return {
            1: pin_protocol,
            2: pin_token_enc.hex(),
            3: shared.hex(),
        }

    def get_pin_uv_token_using_uv(self, permissions: int, rp_id: str, permissions_rp_id: str) -> dict:
        if self._uv_blocked:
            raise CtapError(0x3C, "uv blocked")
        self._uv()
        hmac_key = os.urandom(32)
        token = os.urandom(32)
        return {"1": token.hex(), "2": permissions, "3": rp_id}

    def info(self) -> dict:
        return {
            "credentials": len(self._credentials),
            "rp_ids": sorted({c.rp_id for c in self._credentials.values()}),
            "pin_set": self._pin is not None,
            "pin_retries": self._pin_retries,
            "uv_blocked": self._uv_blocked,
            "aaguid": self._ca.aaguid.hex(),
            "attestation_mode": self.attestation_mode,
            "up_gate": getattr(self.up_gate, "__name__", "lambda"),
            "uv_gate": getattr(self.uv_gate, "__name__", "lambda"),
        }


# --------------------------------------------------------------------------- authData / COSE helpers


def build_auth_data(rp_id_hash: bytes, flags: int, counter: int,
                    aaguid: Optional[bytes] = None,
                    credential_id: Optional[bytes] = None,
                    cose_key: Optional[dict] = None,
                    attested_user: Optional[dict] = None) -> bytes:
    """
    Assemble authenticator data (CTAP2.1 §6.1).

    Registration form, when credential_id + cose_key are present:
        rpIdHash[32] | flags[1] | signCount[4] | aaguid[16] |
        credentialIdLength[2] | credentialId | credentialPublicKey (COSE CBOR)

    Assertion form is just rpIdHash | flags | signCount — the asserted user
    entity travels in the response map, *not* in authData.
    """
    out = bytearray()
    out += rp_id_hash
    out += struct.pack(">B", flags)
    out += struct.pack(">I", counter)
    if credential_id is not None and cose_key is not None:
        out += aaguid or b"\x00" * 16
        out += struct.pack(">H", len(credential_id)) + credential_id
        out += _ctap_cbor_encode(cose_key)
    return bytes(out)


def parse_attested_credential_id(auth_data: bytes) -> bytes:
    """
    Pull the credential ID out of authenticator data (CTAP2.1 §6.1.1).

    Layout: rpIdHash[32] | flags[1] | counter[4] | aaguid[16] |
            credIdLen[2] | credId[credIdLen] | COSE key
    The credential ID only exists when the AT flag is set.
    """
    if len(auth_data) < 55 or not (auth_data[32] & FLAG_AT):
        raise ValueError("authData carries no attested credential data")
    cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
    start, end = 55, 55 + cred_id_len
    if len(auth_data) < end:
        raise ValueError("authData truncated inside credential ID")
    return auth_data[start:end]


def parse_cose_public(cbor_bytes: bytes) -> ec.EllipticCurvePublicKey:
    d = cbor2.loads(cbor_bytes)
    x = int.from_bytes(d[-2], "big")
    y = int.from_bytes(d[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
