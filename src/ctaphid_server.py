# language: Python 3.12, file: ctaphid_server.py, runtime: stdlib + cbor2
# *Device side of the USB authenticator. Serves CTAPHID on /dev/hidg0 (real gadget),
# *or on a TCP port for a lab box / VM, using the same state machine.*
# *
# *   PYTHONPATH=../libs python3 ctaphid_server.py --device /dev/hidg0
# *   PYTHONPATH=../libs python3 ctaphid_server.py --listen 0.0.0.0:4444
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
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


def main():
    ap = argparse.ArgumentParser(description="CTAPHID authenticator server")
    ap.add_argument("--device", default="/dev/hidg0",
                    help="Linux HID gadget device (needs hid_gadget.sh)")
    ap.add_argument("--listen", help="host:port to serve CTAPHID over TCP instead")
    ap.add_argument("--store", default="./creds.json",
                    help="credential store path (persisted across restarts)")
    ap.add_argument("--attestation", default="packed_x5c",
                    choices=["none", "packed_self", "packed_x5c"])
    ap.add_argument("--aaguid", default="00" * 16,
                    help="16-byte AAGUID (hex) — all-zero means self-attestation")
    ap.add_argument("--touch-required", action="store_true",
                    help="require an interactive presence gesture (Ctrl-C to refuse)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    auth = Ctap2Authenticator(
        store_path=args.store,
        attestation_mode=args.attestation,
        aaguid=bytes.fromhex(args.aaguid),
        up_gate=_presence_gate(args.touch_required),
    )
    print(f"[server] store={args.store} attestation={args.attestation} "
          f"aaguid={args.aaguid}", flush=True)

    if args.listen:
        host, _, port = args.listen.rpartition(":")
        transport = SocketServerTransport(host or "0.0.0.0", int(port)).open()
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
            return True
        return not ans.strip().lower().startswith("n")

    return gate


if __name__ == "__main__":
    sys.exit(main())
