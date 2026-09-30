import os
import struct
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctap2_core import Ctap2Authenticator
from ctaphid import (
    CMD_CBOR,
    CMD_INIT,
    CONT_PACKET,
    CTAPHID_BROADCAST,
    CtapHidDevice,
    CtapHidDeviceSide,
    LoopbackTransport,
    pack_reports,
    parse_report,
)


def test_initial_frames_set_command_high_bit_and_continuations_do_not():
    payload = os.urandom(200)
    frames = pack_reports(0x01020304, CMD_CBOR, payload)

    assert frames[0][4] == 0x80 | CMD_CBOR
    assert frames[1][4] == 0
    assert frames[2][4] == 1

    channel, command, byte_count, first_data = parse_report(frames[0])
    assert channel == 0x01020304
    assert command == CMD_CBOR
    assert byte_count == len(payload)
    assert first_data == payload[:57]

    channel, sequence, byte_count, continuation = parse_report(frames[1])
    assert channel == 0x01020304
    assert sequence == 0
    assert byte_count == -1
    assert continuation == payload[57 : 57 + CONT_PACKET]


def test_standard_init_is_single_round_trip_and_echoes_nonce(tmp_path):
    authenticator = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host_transport = LoopbackTransport().open()
    device_transport = host_transport.peer().open()
    side = CtapHidDeviceSide(device_transport, authenticator, verbose=False)
    threading.Thread(target=side.serve_forever, daemon=True).start()

    host = CtapHidDevice(host_transport, verbose=False)
    channel = host.init_sequence()

    assert channel not in (0, CTAPHID_BROADCAST)


def test_init_response_has_standard_17_byte_shape(tmp_path):
    authenticator = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host_transport = LoopbackTransport().open()
    device_transport = host_transport.peer().open()
    side = CtapHidDeviceSide(device_transport, authenticator, verbose=False)
    threading.Thread(target=side.serve_forever, daemon=True).start()

    nonce = os.urandom(8)
    for frame in pack_reports(CTAPHID_BROADCAST, CMD_INIT, nonce):
        host_transport.write(frame)

    response = host_transport.read_exact(64, timeout=1)
    channel, command, byte_count, data = parse_report(response)
    assert channel == CTAPHID_BROADCAST
    assert command == CMD_INIT
    assert byte_count == 17
    assert data[:8] == nonce
    allocated = struct.unpack(">I", data[8:12])[0]
    assert allocated not in (0, CTAPHID_BROADCAST)
    assert len(data[12:17]) == 5
    assert data[16] & 0x08  # NMSG: U2F/CTAPHID_MSG is unsupported.


def test_allocated_init_aborts_partial_message_and_reuses_channel(tmp_path):
    from ctaphid import CMD_PING
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host = LoopbackTransport()
    side = CtapHidDeviceSide(host.peer(), auth, verbose=False)
    side._handle(pack_reports(CTAPHID_BROADCAST, CMD_INIT, b"12345678")[0])
    _, _, _, response = parse_report(host.read_exact(64, timeout=1))
    channel = struct.unpack(">I", response[8:12])[0]
    side._handle(pack_reports(channel, CMD_PING, bytes(100))[0])
    side._handle(pack_reports(channel, CMD_INIT, b"87654321")[0])
    cid, command, length, data = parse_report(host.read_exact(64, timeout=1))
    assert (cid, command, length) == (channel, CMD_INIT, 17)
    assert data[:8] == b"87654321"
    assert struct.unpack(">I", data[8:12])[0] == channel
    side._handle(pack_reports(channel, CMD_PING, b"ping")[0])
    assert parse_report(host.read_exact(64, timeout=1))[3] == b"ping"


def test_host_key_agreement_does_not_reset_credentials(tmp_path):
    import cbor2
    from ctap2_core import CtapError
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    auth.make_credential({1: bytes(32), 2: {"id": "example.com"},
                          3: {"id": b"alice"}, 4: [{"alg": -7}], 7: {"rk": True}})
    side = CtapHidDeviceSide(LoopbackTransport(), auth, verbose=False)
    class DirectHost(CtapHidDevice):
        def ctap2(self, command, params=b"", timeout=60):
            try:
                return 0, side._dispatch_ctap2(command, cbor2.loads(params) if params else {})
            except CtapError as exc:
                return exc.code, {}
    status, _ = DirectHost(LoopbackTransport()).get_key_agreement()
    assert len(auth.list_credentials()) == 1
    assert status == 0x01


def test_client_pin_uses_standard_subcommand_key():
    import cbor2
    class CaptureHost(CtapHidDevice):
        def ctap2(self, command, params=b"", timeout=60):
            return command, cbor2.loads(params)
    command, params = CaptureHost(LoopbackTransport()).client_pin(2, {1: 1})
    assert command == 0x06
    assert params == {1: 1, 2: 2}


def test_oversize_ctaphid_messages_are_rejected(tmp_path):
    import pytest
    from ctaphid import CMD_ERROR, CMD_PING, CtapHidError
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host = LoopbackTransport()
    side = CtapHidDeviceSide(host.peer(), auth, verbose=False)
    side._handle(pack_reports(CTAPHID_BROADCAST, CMD_INIT, b"12345678")[0])
    host.read_exact(64, timeout=1)
    oversized = struct.pack(">IBH", 1, 0x80 | CMD_PING, 7610) + bytes(57)
    side._handle(oversized)
    _, command, _, data = parse_report(host.read_exact(64, timeout=1))
    assert (command, data) == (CMD_ERROR, b"\x03")
    assert side.channels[1]["cmd"] is None
    with pytest.raises(CtapHidError):
        pack_reports(1, CMD_PING, bytes(7610))


def test_partial_ctaphid_message_expires_and_channel_is_reusable(tmp_path, monkeypatch):
    import ctaphid
    from ctaphid import CMD_ERROR, CMD_PING
    now = [0.0]
    monkeypatch.setattr(ctaphid.time, "monotonic", lambda: now[0])
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host = LoopbackTransport()
    side = CtapHidDeviceSide(host.peer(), auth, verbose=False)
    side._handle(pack_reports(CTAPHID_BROADCAST, CMD_INIT, b"12345678")[0])
    host.read_exact(64, timeout=1)
    side._handle(pack_reports(1, CMD_PING, bytes(100))[0])
    now[0] = 10.0
    side._handle(pack_reports(1, CMD_PING, b"ready")[0])
    _, command, _, data = parse_report(host.read_exact(64, timeout=1))
    assert (command, data) == (CMD_ERROR, b"\x05")
    assert parse_report(host.read_exact(64, timeout=1))[3] == b"ready"


def test_reset_rejects_extraneous_parameters_before_deleting_credentials(tmp_path):
    import cbor2
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    auth.make_credential({1: bytes(32), 2: {"id": "example.com"},
                          3: {"id": b"alice"}, 4: [{"alg": -7}]})
    host = LoopbackTransport()
    side = CtapHidDeviceSide(host.peer(), auth, verbose=False)
    side._ctap2(1, b"\x07" + cbor2.dumps({1: "unexpected"}))
    assert len(auth.list_credentials()) == 1
    assert parse_report(host.read_exact(64, timeout=1))[3][0] == 0x03


def test_idle_cancel_does_not_receive_a_response(tmp_path):
    from ctaphid import CMD_CANCEL
    auth = Ctap2Authenticator(str(tmp_path / "creds.json"), attestation_mode="none")
    host = LoopbackTransport()
    side = CtapHidDeviceSide(host.peer(), auth, verbose=False)
    side._handle(pack_reports(CTAPHID_BROADCAST, CMD_INIT, b"12345678")[0])
    host.read_exact(64, timeout=1)
    side._handle(pack_reports(1, CMD_CANCEL, b"")[0])
    side._handle(pack_reports(99, CMD_CANCEL, b"")[0])
    assert not host.q_in
