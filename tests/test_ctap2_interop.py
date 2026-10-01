import os
import sys
from pathlib import Path

import pytest
from fido2.ctap2 import Info

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctap2_core import (
    Ctap2Authenticator,
    CtapError,
    FLAG_UV,
    parse_attested_credential_id,
)
from ctaphid import CtapHidDeviceSide, LoopbackTransport


def make_request(*, resident=True, uv=False):
    return {
        1: os.urandom(32),
        2: {"id": "example.com", "name": "Example"},
        3: {"id": os.urandom(16), "name": "alice", "displayName": "Alice"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": resident, "uv": uv},
    }


def test_get_info_uses_ctap_integer_schema(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    info = auth.get_info()

    assert info[1] == ["FIDO_2_0"]
    assert info[3] == bytes(16)
    assert info[4]["rk"] is True
    assert isinstance(info[5], int)
    assert 6 not in info
    assert 9 not in info
    assert 0x0D not in info
    assert "clientPin" not in info[4]
    parsed = Info.from_dict(info)
    assert parsed.versions == ["FIDO_2_0"]
    assert parsed.algorithms == [{"type": "public-key", "alg": -7}]
    assert parsed.transports == []
    assert parsed.max_creds_in_list == 64
    assert parsed.max_cred_id_length == 64
    assert parsed.min_pin_length == 4


def test_make_credential_accepts_binary_user_handle_and_returns_integer_keys(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    response = auth.make_credential(make_request())

    assert set(response).issuperset({1, 2, 3})
    assert response[1] == "none"
    assert response[3] == {}
    credential_id = parse_attested_credential_id(response[2])
    assert len(credential_id) == 32
    assert auth.list_credentials("example.com")[0].user_handle


def test_uv_is_not_asserted_without_explicit_internal_verification(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    response = auth.make_credential(make_request(uv=False))
    assert response[2][32] & FLAG_UV == 0

    with pytest.raises(CtapError) as exc:
        auth.make_credential(make_request(uv=True))
    assert exc.value.code == 0x2C


def test_internal_uv_sets_flag_only_after_gate_succeeds(tmp_path):
    auth = Ctap2Authenticator(
        str(tmp_path / "creds.json"),
        attestation_mode="none",
        uv_gate=lambda: True,
    )
    response = auth.make_credential(make_request(uv=True))
    assert response[2][32] & FLAG_UV


def test_nonresident_credentials_require_allow_list(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    request = make_request(resident=False)
    response = auth.make_credential(request)
    credential_id = parse_attested_credential_id(response[2])

    with pytest.raises(CtapError) as exc:
        auth.get_assertion({1: "example.com", 2: os.urandom(32), 5: {"uv": False}})
    assert exc.value.code == 0x2E

    assertion = auth.get_assertion({
        1: "example.com",
        2: os.urandom(32),
        3: [{"type": "public-key", "id": credential_id}],
        5: {"uv": False},
    })
    assert assertion[1] == {"type": "public-key", "id": credential_id}


def test_exclude_list_is_scoped_to_the_requested_rp(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    response = auth.make_credential(make_request())
    credential_id = parse_attested_credential_id(response[2])

    other_rp_request = make_request()
    other_rp_request[2] = {"id": "other.example", "name": "Other"}
    other_rp_request[5] = [{"type": "public-key", "id": credential_id}]
    auth.make_credential(other_rp_request)

    same_rp_request = make_request()
    same_rp_request[5] = [{"type": "public-key", "id": credential_id}]
    with pytest.raises(CtapError) as exc:
        auth.make_credential(same_rp_request)
    assert exc.value.code == 0x19


def test_persisted_aaguid_is_used_by_get_info_after_restart(tmp_path):
    store = str(tmp_path / "creds.json")
    expected_aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    first = Ctap2Authenticator(store, aaguid=expected_aaguid, attestation_mode="none")
    first.make_credential(make_request())

    restarted = Ctap2Authenticator(store, attestation_mode="none")
    response = restarted.make_credential(make_request())

    assert restarted.get_info()[3] == expected_aaguid
    assert response[2][37:53] == expected_aaguid


def test_ctap_command_numbers_do_not_alias_destructive_operations(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    auth.make_credential(make_request(resident=True))
    side = CtapHidDeviceSide(LoopbackTransport(), auth, verbose=False)

    for command in (0x06, 0x0A):
        with pytest.raises(CtapError) as exc:
            side._dispatch_ctap2(command, {})
        assert exc.value.code == 0x01

    with pytest.raises(CtapError) as exc:
        side._dispatch_ctap2(0x08, {})
    assert exc.value.code == 0x30

    assert len(auth.list_credentials()) == 1
    side._dispatch_ctap2(0x07, {})
    assert auth.list_credentials() == []


def test_assertion_uses_standard_descriptor_and_hides_names_without_uv(tmp_path):
    from fido2.ctap2 import AssertionResponse
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    created = auth.make_credential(make_request())
    cid = parse_attested_credential_id(created[2])
    result = auth.get_assertion({1: "example.com", 2: bytes(32)})
    parsed = AssertionResponse.from_dict(result)
    assert parsed.credential == {"type": "public-key", "id": cid}
    assert set(result[4]) == {"id"}
    assert 5 not in result


def test_nonresident_assertion_omits_optional_user_and_count(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    created = auth.make_credential(make_request(resident=False))
    cid = parse_attested_credential_id(created[2])
    result = auth.get_assertion({1: "example.com", 2: bytes(32),
                                3: [{"type": "public-key", "id": cid}]})
    assert result[1] == {"type": "public-key", "id": cid}
    assert 4 not in result
    assert 5 not in result


def test_multiple_discoverable_credentials_do_not_silently_select_first(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    auth.make_credential(make_request())
    auth.make_credential(make_request())
    with pytest.raises(CtapError) as exc:
        auth.get_assertion({1: "example.com", 2: bytes(32)})
    assert exc.value.code == 0x27


def test_standard_status_names_match_python_fido2():
    from fido2.ctap import CtapError as ReferenceError
    from ctap2_core import err_name
    for status in ReferenceError.ERR:
        if 0x2B <= int(status) <= 0x3C:
            assert err_name(int(status)).endswith(status.name)


def test_get_info_does_not_advertise_unimplemented_uv(tmp_path):
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    assert "uv" not in auth.get_info()[4]
    assert 0x0E not in auth.get_info()


def test_upstream_policy_demo_uses_repaired_core_api(tmp_path, monkeypatch):
    import policy_lab
    def isolated_auth(**kwargs):
        kwargs["store_path"] = str(tmp_path / "creds.json")
        return Ctap2Authenticator(**kwargs)
    monkeypatch.setattr("ctap2_core.Ctap2Authenticator", isolated_auth)
    auth_data, statement, data = policy_lab.build_demo_attestation()
    assert auth_data[32] & FLAG_UV
    assert statement["x5c"]
    assert data
