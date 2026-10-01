# language: Python 3.12, file: ctaphid_server.py, runtime: stdlib + cbor2
# *Device side of the USB authenticator. Serves CTAPHID on /dev/hidg0 (real gadget),
# *or on a TCP port for a lab box / VM, using the same state machine.*
# *
# *   PYTHONPATH=../libs python3 ctaphid_server.py --device /dev/hidg0
# *   PYTHONPATH=../libs python3 ctaphid_server.py --listen 127.0.0.1:4444
# *
# *This is the "browser sees a security key" half: speak CTAPHID to this port and
# *you are talking to a real USB security key's wire protocol.*

import argparse
import socket
import sys
import threading

from ctap2_core import Ctap2Authenticator
from ctaphid import (
    CtapHidDeviceSide, HidTransport, LinuxHidGadgetTransport, REPORT_SIZE,
)


class SocketServerTransport(HidTransport):
    """
    One connection at a time, framing fixed-size reports off a TCP stream.

    Reports are exactly 64 bytes on the wire, so read_exact needs no delimiter —
    but real FIDO clients (and fido2-token over TCP bridges) sometimes pad, so we
    reassemble strictly by length rather than trusting message boundaries.
    """

    def __init__(self, host: str, port: int, max_clients: int = 1):
        super().__init__()
        self.host, self.port = host, port
        self.srv = None
        self.conn = None
        self.max_clients = max_clients

    def open(self):
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self.srv = socket.socket(family, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((self.host, self.port))
        self.srv.listen(4)
        print(f"[server] listening on {self.host}:{self.port} "
              f"(CTAPHID, {REPORT_SIZE}-byte reports)", flush=True)
        return self

    def close(self):
        if self.conn:
            self.conn.close()
        if self.srv:
            self.srv.close()

    def accept(self, timeout: float = 30.0):
        self.srv.settimeout(timeout)
        conn, addr = self.srv.accept()
        conn.settimeout(None)
        self.conn = conn
        print(f"[server] client connected from {addr[0]}:{addr[1]}", flush=True)
        return conn

    def write(self, data: bytes):
        if self.conn:
            self.conn.sendall(data)

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        if not self.conn:
            raise ConnectionError("no client connected")
        self.conn.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("client disconnected")
            buf += chunk
        return bytes(buf)


def serve(transport, auth, verbose=True):
    """Serve one client at a time until the transport closes."""
    while not getattr(transport, "stop", None):
        if hasattr(transport, "accept"):
            try:
                transport.accept(timeout=60)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
        side = CtapHidDeviceSide(transport, auth, verbose=verbose)
        try:
            side.serve_forever()
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"[server] client ended: {exc}", flush=True)
        if hasattr(transport, "close"):
            transport.close()
            if hasattr(transport, "open"):
                transport.open()
    print("[server] stopped", flush=True)


def resolve_listen_address(value: str, allow_remote: bool = False) -> tuple[str, int]:
    """Parse host:port, defaulting to loopback and rejecting remote binds."""
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        host = host or "127.0.0.1"
    else:
        host, port_text = "127.0.0.1", value
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise ValueError("non-loopback listeners require --allow-remote")
    return host, port


def main():
    ap = argparse.ArgumentParser(description="CTAPHID authenticator server")
    ap.add_argument("--device", default="/dev/hidg0",
                    help="Linux HID gadget device (needs hid_gadget.sh)")
    ap.add_argument("--listen", help="[host:]port for CTAPHID over TCP; defaults to loopback")
    ap.add_argument("--allow-remote", action="store_true",
                    help="allow an unauthenticated non-loopback TCP listener")
    ap.add_argument("--store", default="./creds.json",
                    help="credential store path (persisted across restarts)")
    ap.add_argument("--attestation", default="packed_x5c",
                    choices=["none", "packed_self", "packed_x5c"])
    ap.add_argument("--aaguid", default="00" * 16,
                    help="16-byte AAGUID (hex) — all-zero means self-attestation")
    ap.set_defaults(touch_required=True)
    ap.add_argument("--no-touch-required", dest="touch_required", action="store_false",
                    help="UNSAFE: approve user presence without an operator gesture")
    ap.add_argument("--internal-uv", action="store_true",
                    help="assert software user verification after the presence prompt")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    presence_gate = _presence_gate(args.touch_required)
    auth = Ctap2Authenticator(
        store_path=args.store,
        attestation_mode=args.attestation,
        aaguid=bytes.fromhex(args.aaguid),
        up_gate=presence_gate,
        uv_gate=presence_gate if args.internal_uv else None,
    )
    print(f"[server] store={args.store} attestation={args.attestation} "
          f"aaguid={args.aaguid}", flush=True)

    if args.listen:
        try:
            host, port = resolve_listen_address(args.listen, args.allow_remote)
        except ValueError as exc:
            ap.error(str(exc))
        transport = SocketServerTransport(host, port).open()
    else:
        transport = LinuxHidGadgetTransport(args.device)
        try:
            transport.open()
        except Exception as exc:
            print(f"[server] cannot open {args.device}: {exc}", flush=True)
            return 1
        print(f"[server] serving CTAPHID on {args.device}", flush=True)

    try:
        serve(transport, auth, verbose=not args.quiet)
    except KeyboardInterrupt:
        print("\n[server] interrupted", flush=True)
    return 0


def _presence_gate(interactive: bool):
    """User-presence policy. A real key needs a finger; this is the substitute."""
    if not interactive:
        return lambda: True

    def gate() -> bool:
        try:
            ans = input("[presence] touch required — press Enter, or 'n' to refuse: ")
        except EOFError:
            return False
        return not ans.strip().lower().startswith("n")

    return gate


if __name__ == "__main__":
    sys.exit(main())
