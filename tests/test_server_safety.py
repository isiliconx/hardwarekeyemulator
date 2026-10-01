import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctaphid import CtapHidDeviceSide, HidTransport
from ctaphid_server import SocketServerTransport, resolve_listen_address


class DisconnectedTransport(HidTransport):
    def open(self):
        return self

    def close(self):
        pass

    def write(self, data: bytes):
        pass

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        raise ConnectionError("client disconnected")


def test_fatal_transport_disconnect_escapes_device_loop():
    side = CtapHidDeviceSide(DisconnectedTransport(), object(), verbose=False)
    with pytest.raises(ConnectionError):
        side.serve_forever()


def test_tcp_listener_defaults_to_loopback():
    assert resolve_listen_address("4444", allow_remote=False) == ("127.0.0.1", 4444)
    assert resolve_listen_address("127.0.0.1:4444", allow_remote=False) == (
        "127.0.0.1",
        4444,
    )


def test_ipv6_loopback_listener_uses_ipv6_socket(monkeypatch):
    created = []

    class FakeSocket:
        def __init__(self, family, sock_type):
            created.append((family, sock_type))

        def setsockopt(self, *args):
            pass

        def bind(self, address):
            assert address == ("::1", 4444)

        def listen(self, backlog):
            assert backlog == 4

    monkeypatch.setattr(socket, "socket", FakeSocket)
    SocketServerTransport("::1", 4444).open()
    assert created == [(socket.AF_INET6, socket.SOCK_STREAM)]


def test_non_loopback_listener_requires_explicit_opt_in():
    with pytest.raises(ValueError, match="allow-remote"):
        resolve_listen_address("0.0.0.0:4444", allow_remote=False)
    assert resolve_listen_address("0.0.0.0:4444", allow_remote=True) == (
        "0.0.0.0",
        4444,
    )
