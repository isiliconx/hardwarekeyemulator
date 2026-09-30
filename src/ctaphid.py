# language: Python 3.12, file: ctaphid.py, runtime: stdlib + cbor2
# *CTAPHID transport — the same framing a real USB security key speaks.*
# *channel allocation, INIT, CANCEL, KEEPALIVE, PING, and 64-byte report fragmentation.*
# *this is what makes the emulator look like a USB authenticator on the bus, not a passkey.*

from __future__ import annotations

import os
import struct
import threading
import time
from typing import Optional

import cbor2

# CTAPHID command bytes (FIDO CTAP2 rev 2.1 table 39)
CMD_PING = 0x01
CMD_MSG = 0x03
CMD_LOCK = 0x04
CMD_INIT = 0x06
CMD_WINK = 0x08
CMD_CBOR = 0x10
CMD_CANCEL = 0x11
CMD_KEEPALIVE = 0x3B
CMD_ERROR = 0x3F

CTAPHID_BROADCAST = 0xFFFFFFFF

# CTAPHID report layout (CTAP2 rev 2.1 §11.2):
#   INIT frame : cid[4] | cmd[1] | bcnt[2] | data[57]   -> 64 bytes
#   CONT frame : cid[4] | 0x80|seq[1] | data[59]       -> 64 bytes
REPORT_SIZE = 64
INIT_PACKET = REPORT_SIZE - 7      # 57 bytes of data in the first frame
CONT_PACKET = REPORT_SIZE - 5      # 59 bytes in each continuation frame
DEVICE_VERSION = (2, 0, 0x0001)    # CTAP 2.0, build 1

KEEPALIVE_PROCESSING = 0x01
KEEPALIVE_USER_ACTION_PENDING = 0x02

# CTAP2 numeric map keys. NOTE: these differ per command — makeCredential and
# getAssertion both start at key 1 with *different* meanings. Conflating them is
# the classic CTAP implementation bug, so each map is spelled out separately.
MAKE_CREDENTIAL_KEYS = {
    0x01: "clientDataHash",
    0x02: "rp",
    0x03: "user",
    0x04: "pubKeyCredParams",
    0x05: "excludeList",
    0x06: "extensions",
    0x07: "options",
    0x08: "pinUvAuthParam",
    0x09: "pinUvAuthProtocol",
    0x0A: "enterpriseAttestation",
}

GET_ASSERTION_KEYS = {
    0x01: "rpId",
    0x02: "clientDataHash",
    0x03: "allowList",
    0x04: "extensions",
    0x05: "options",
    0x06: "pinUvAuthParam",
    0x07: "pinUvAuthProtocol",
}

CLIENT_PIN_KEYS = {
    0x01: "pinUvAuthProtocol",
    0x02: "subCommand",
    0x03: "keyAgreement",
    0x04: "pinUvAuthParam",
    0x05: "newPinEnc",
    0x06: "pinHashEnc",
}


class CtapHidError(Exception):
    pass


def parse_report(rep: bytes):
    """Unpack one 64-byte report.

    Returns (channel, cmd, bcnt, data). For a CONT frame bcnt is -1 and `data`
    carries the raw continuation bytes; the caller tracks accumulation itself.
    """
    if len(rep) != REPORT_SIZE:
        raise CtapHidError(f"short report: {len(rep)} != {REPORT_SIZE}")
    channel = struct.unpack(">I", rep[0:4])[0]
    cmd = rep[4]
    if cmd & 0x80:
        return channel, cmd, -1, rep[5:]
    bcnt = struct.unpack(">H", rep[5:7])[0]
    return channel, cmd, bcnt, rep[7:7 + bcnt]


def pack_reports(channel: int, cmd: int, payload: bytes) -> list:
    """Split a message into one INIT frame plus zero or more CONT frames."""
    cid = struct.pack(">I", channel & 0xFFFFFFFF)
    frames = [
        cid + struct.pack(">B", cmd) + struct.pack(">H", len(payload))
        + payload[:INIT_PACKET].ljust(INIT_PACKET, b"\x00")
    ]
    rest, seq = payload[INIT_PACKET:], 0
    while rest:
        frames.append(
            cid + struct.pack(">B", 0x80 | (seq & 0x7F))
            + rest[:CONT_PACKET].ljust(CONT_PACKET, b"\x00")
        )
        rest = rest[CONT_PACKET:]
        seq += 1
    return frames


# --------------------------------------------------------------------------- carriers


class HidTransport:
    """Abstract byte pipe carrying 64-byte HID reports."""

    def __init__(self):
        self._lock = threading.Lock()

    def open(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def write(self, data: bytes):
        raise NotImplementedError

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        raise NotImplementedError


class LinuxHidGadgetTransport(HidTransport):
    """
    Real USB HID gadget via configfs. The kernel exposes the host-visible side as
    /dev/hidg0; hid_gadget.sh (shipped alongside) builds the descriptor so the
    device enumerates on the FIDO usage page (0xF1D0).
    """

    def __init__(self, device: str = "/dev/hidg0"):
        super().__init__()
        self.device = device
        self.fh = None

    def open(self):
        if not os.path.exists(self.device):
            raise CtapHidError(
                f"{self.device} missing — mount configfs and run hid_gadget.sh as root"
            )
        self.fh = open(self.device, "r+b", buffering=0)
        return self

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None

    def write(self, data: bytes):
        with self._lock:
            self.fh.write(data)

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        deadline = time.time() + timeout
        buf = bytearray()
        while len(buf) < n:
            if time.time() > deadline:
                raise CtapHidError(f"hid read timeout after {len(buf)}/{n} bytes")
            chunk = self.fh.read(n - len(buf))
            if chunk:
                buf += chunk
            else:
                time.sleep(0.001)
        return bytes(buf)


class SocketHidTransport(HidTransport):
    """CTAPHID over a TCP stream — lab box, VM, or an SSH-forwarded remote hidg."""

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host, self.port = host, port
        self.sock = None

    def open(self):
        import socket
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        return self

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def write(self, data: bytes):
        self.sock.sendall(data)

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        self.sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise CtapHidError("hid socket closed mid-report")
            buf += chunk
        return bytes(buf)


class LoopbackTransport(HidTransport):
    """Two CTAPHID endpoints in one process. Same bytes, no root required."""

    def __init__(self):
        super().__init__()
        self.q_in: list = []
        self.q_out: list = []
        self._cv = threading.Condition()

    def open(self):
        return self

    def close(self):
        with self._cv:
            self._cv.notify_all()

    def write(self, data: bytes):
        with self._cv:
            self.q_out.append(data)
            self._cv.notify_all()

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        deadline = time.time() + timeout
        with self._cv:
            while not self.q_in:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise CtapHidError("loopback read timeout")
                self._cv.wait(remaining)
            report = self.q_in.pop(0)
        return report

    def peer(self) -> "LoopbackTransport":
        p = LoopbackTransport()
        p.q_in, p.q_out = self.q_out, self.q_in
        p._cv = self._cv
        return p


# --------------------------------------------------------------------------- host side


class CtapHidDevice:
    """Host-side CTAPHID client: what a browser/driver would talk to a real key."""

    def __init__(self, transport: HidTransport, verbose: bool = True):
        self.t = transport
        self.verbose = verbose
        self.channel = 0
        self.channel_id: bytes = b""
        self.state = {"cmd": None, "bcnt": -1, "buf": bytearray()}
        self.locked = False

    def _log(self, *a):
        if self.verbose:
            print("[ctaphid]", *a, flush=True)

    def _tx(self, cmd: int, payload: bytes = b"", channel: Optional[int] = None):
        for frame in pack_reports(self.channel if channel is None else channel, cmd, payload):
            self.t.write(frame)

    def _rx(self, timeout: float, expect_channel: Optional[int] = None,
            pin_channel: bool = False) -> tuple:
        """
        Read one complete message, transparently absorbing CONT frames.

        `expect_channel` filters traffic; `pin_channel` additionally locks the
        session to the channel of the first frame (INIT does this, because the
        device answers a channel-claim INIT on the new channel, not broadcast).
        """
        deadline = time.time() + timeout
        st = self.state
        while True:
            rep = self.t.read_exact(REPORT_SIZE, timeout=max(0.05, deadline - time.time()))
            channel, cmd, bcnt, data = parse_report(rep)
            if st["cmd"] is None:
                if expect_channel is not None and channel != expect_channel \
                        and not pin_channel:
                    continue
                if pin_channel:
                    self.channel = channel
            elif channel != self.channel:
                continue

            st["buf"] += data
            if bcnt >= 0:
                st["cmd"], st["bcnt"] = cmd, bcnt
            if st["bcnt"] >= 0 and len(st["buf"]) >= st["bcnt"]:
                out_cmd = st["cmd"]
                out = bytes(st["buf"][:st["bcnt"]])
                st.update({"cmd": None, "bcnt": -1, "buf": bytearray()})
                return out_cmd, out

    def request(self, cmd: int, payload: bytes = b"", timeout: float = 30.0) -> bytes:
        """
        Send one CTAPHID message and return the payload of its reply.

        Per CTAP2.1 the device may emit KEEPALIVE(processing) /
        KEEPALIVE(user_action_pending) *before* the real response, so keep reading
        until something other than a keepalive comes back.
        """
        self._tx(cmd, payload)
        deadline = time.time() + timeout
        while True:
            out_cmd, out = self._rx(max(0.05, deadline - time.time()))
            if out_cmd == CMD_ERROR:
                code = struct.unpack(">H", out[:2])[0] if len(out) >= 2 else -1
                raise CtapHidError(f"CTAPHID_ERROR code={code}")
            if out_cmd == CMD_KEEPALIVE:
                status = out[0] if out else 0
                self._log(f"keepalive status={status} — device is waiting on user action")
                if status in (KEEPALIVE_PROCESSING, KEEPALIVE_USER_ACTION_PENDING):
                    continue
                raise CtapHidError(f"unexpected KEEPALIVE status {status}")
            return out

    # ------------------------------------------------------------------ handshake

    def init_sequence(self) -> int:
        """
        Broadcast INIT(8-byte nonce) to learn the device nonce, then INIT again
        carrying nonce | 16-byte CID to claim a channel. A real key does this in
        firmware; here the identity stays inspectable from userspace.
        """
        self._tx(CMD_INIT, os.urandom(8), channel=CTAPHID_BROADCAST)
        cmd, data = self._rx(10, expect_channel=CTAPHID_BROADCAST)
        if cmd != CMD_INIT or len(data) < 12:
            raise CtapHidError(f"bad INIT reply: cmd=0x{cmd:02x} len={len(data)}")
        nonce = data[:8]
        major, minor, build = data[8], data[9], struct.unpack(">H", data[10:12])[0]
        self._log(f"device init: nonce={nonce.hex()} ctap={major}.{minor} build={build}")

        cid = os.urandom(16)
        self._tx(CMD_INIT, nonce + cid, channel=CTAPHID_BROADCAST)
        cmd2, data2 = self._rx(10, expect_channel=CTAPHID_BROADCAST, pin_channel=True)
        channel = self.channel          # pinned to whatever the device claimed
        if cmd2 != CMD_INIT:
            raise CtapHidError("expected CMD_INIT on channel claim")
        if data2[:8] != nonce:
            raise CtapHidError("INIT nonce mismatch — device not spec-compliant")
        if channel == CTAPHID_BROADCAST:
            raise CtapHidError("device echoed broadcast instead of claiming a channel")
        self.channel_id = cid
        self._log(f"channel allocated: 0x{channel:08x}")
        return channel

    # ------------------------------------------------------------------ commands

    def ping(self, payload: bytes = b"pong", timeout: float = 10.0) -> bytes:
        return self.request(CMD_PING, payload, timeout)

    def wink(self) -> bytes:
        return self.request(CMD_WINK, b"")

    def get_info(self, timeout: float = 10.0) -> dict:
        # CTAPHID_CBOR responses are prefixed with a 1-byte CTAP2 status.
        _, info = self.ctap2(0x04, b"", timeout)
        return info

    def ctap2(self, command: int, params: bytes = b"", timeout: float = 60.0):
        """CTAP2 command byte | CBOR params -> (status byte, response map)."""
        raw = self.request(CMD_CBOR, bytes([command]) + params, timeout)
        status = raw[0]
        payload = cbor2.loads(raw[1:]) if len(raw) > 1 else {}
        return status, payload

    def make_credential(self, params: dict, timeout: float = 60.0):
        return self.ctap2(0x01, cbor2.dumps(params, canonical=True), timeout)

    def get_assertion(self, params: dict, timeout: float = 60.0):
        return self.ctap2(0x02, cbor2.dumps(params, canonical=True), timeout)

    def get_key_agreement(self):
        return self.ctap2(0x07, b"")

    def client_pin(self, subcommand: int, params: dict = None):
        payload = {1: subcommand}
        if params:
            payload.update(params)
        return self.ctap2(0x06, cbor2.dumps(payload, canonical=True), timeout=30.0)


# --------------------------------------------------------------------------- device side


class CtapHidDeviceSide:
    """The gadget end: serves CTAPHID to whatever host is talking to it."""

    def __init__(self, transport: HidTransport, authenticator, verbose: bool = True):
        self.t = transport
        self.auth = authenticator
        self.verbose = verbose
        self.channels: dict = {}
        self.next_channel = 1
        self.stop = threading.Event()
        self.stats = {"init": 0, "ping": 0, "cbor": 0, "errors": 0}

    def _log(self, *a):
        if self.verbose:
            print("[device]", *a, flush=True)

    def serve_forever(self):
        self._log("serving CTAPHID")
        while not self.stop.is_set():
            try:
                rep = self.t.read_exact(REPORT_SIZE, timeout=1.0)
            except Exception:
                continue
            try:
                self._handle(rep)
            except Exception as exc:
                self.stats["errors"] += 1
                self._log(f"dispatch error: {exc}")

    # ------------------------------------------------------------------ receive

    def _handle(self, rep: bytes):
        channel, cmd, bcnt, data = parse_report(rep)
        if channel == CTAPHID_BROADCAST and cmd == CMD_INIT:
            self._init(data)
            return
        st = self.channels.setdefault(
            channel, {"cmd": None, "bcnt": -1, "buf": bytearray()}
        )
        st["buf"] += data
        if bcnt >= 0:
            st["cmd"], st["bcnt"] = cmd, bcnt
        if st["bcnt"] >= 0 and len(st["buf"]) >= st["bcnt"]:
            payload = bytes(st["buf"][:st["bcnt"]])
            # Capture the command from the INIT frame *before* clearing state —
            # a CONT frame's cmd byte is 0x80|seq, not the real command.
            real_cmd = st["cmd"] if st["cmd"] is not None else cmd
            st.update({"cmd": None, "bcnt": -1, "buf": bytearray()})
            self._dispatch(channel, real_cmd, payload, st)

    def _init(self, data: bytes):
        """
        Spec §11.2.9: an 8-byte payload is a nonce probe; nonce|16-byte CID claims
        a channel on the first four CID bytes.
        """
        self.stats["init"] += 1
        nonce, cid = data[:8], data[8:24]
        version = struct.pack(">BBH", *DEVICE_VERSION)
        if len(cid) == 16:
            channel = struct.unpack(">I", cid[:4])[0]
            if channel == CTAPHID_BROADCAST:
                channel = self.next_channel
                self.next_channel += 1
            for frame in pack_reports(channel, CMD_INIT, nonce + version):
                self.t.write(frame)
            self.channels[channel] = {"cmd": None, "bcnt": -1, "buf": bytearray()}
            self._log(f"channel claimed: 0x{channel:08x}")
        else:
            for frame in pack_reports(CTAPHID_BROADCAST, CMD_INIT, os.urandom(8) + version):
                self.t.write(frame)
            self._log("nonce probe")

    # ------------------------------------------------------------------ dispatch

    def _dispatch(self, channel: int, cmd: int, payload: bytes, st: dict):
        if cmd == CMD_PING:
            self.stats["ping"] += 1
            self._reply(channel, CMD_PING, payload)
        elif cmd == CMD_WINK:
            self._reply(channel, CMD_WINK, b"")
        elif cmd == CMD_CANCEL:
            self._reply(channel, CMD_CANCEL, b"")
        elif cmd == CMD_LOCK:
            self.locked = len(payload) == 1 and payload[0] == 0
            self._reply(channel, CMD_LOCK, b"")
        elif cmd == CMD_CBOR:
            self._ctap2(channel, payload)
        else:
            self._reply(channel, CMD_ERROR, struct.pack(">H", 0x01))

    def _ctap2(self, channel: int, payload: bytes):
        self.stats["cbor"] += 1
        if not payload:
            self._reply(channel, CMD_ERROR, struct.pack(">H", 0x01))
            return
        command, raw_params = payload[0], payload[1:]
        try:
            req = cbor2.loads(raw_params) if raw_params else {}
        except Exception:
            self._reply(channel, CMD_ERROR, struct.pack(">H", 0x12))
            return

        # CTAP2.1 says: emit KEEPALIVE(user_action_pending) while waiting for touch.
        needs_touch = command in (0x01, 0x02)
        if needs_touch:
            self._keepalive(channel, KEEPALIVE_USER_ACTION_PENDING)

        try:
            body = self._dispatch_ctap2(command, req)
            self._reply(channel, CMD_CBOR, bytes([0x00]) + cbor2.dumps(body, canonical=True))
        except Exception as exc:
            code = getattr(exc, "code", 0x7F)
            from ctap2_core import err_name
            self._log(f"ctap2 0x{command:02x} -> {err_name(code)}")
            self._reply(channel, CMD_CBOR, bytes([code]) + cbor2.dumps({}, canonical=True))

    def _dispatch_ctap2(self, command: int, req: dict):
        from ctap2_core import CtapError
        a = self.auth
        if command == 0x04:
            return a.get_info()
        if command == 0x01:
            return a.make_credential(_ctap_params(req, MAKE_CREDENTIAL_KEYS))
        if command == 0x02:
            return a.get_assertion(_ctap_params(req, GET_ASSERTION_KEYS))
        if command == 0x06:
            return a.client_pin(req)
        if command == 0x07:
            return a.get_key_agreement()
        if command == 0x08:
            rp_id = _s(req.get(2))
            perms_rp = _s(req.get(3), rp_id)
            return a.get_pin_uv_token_using_uv(req[1], rp_id, perms_rp)
        if command == 0x0A:
            return a.reset()
        raise CtapError(0x2C, f"unsupported command 0x{command:02x}")

    # ------------------------------------------------------------------ transmit

    def _keepalive(self, channel: int, status: int):
        for frame in pack_reports(channel, CMD_KEEPALIVE, bytes([status])):
            self.t.write(frame)

    def _reply(self, channel: int, cmd: int, payload: bytes):
        for frame in pack_reports(channel, cmd, payload):
            self.t.write(frame)


def _ctap_params(req: dict, keymap: dict) -> dict:
    """
    Normalise a CTAP2 integer-keyed CBOR map into the string keys ctap2_core uses.

    The wire format is numeric (1=clientDataHash, 2=rp, ...); the core works in
    names. `keymap` is per-command because CTAP2 reuses low key numbers for
    different fields in different commands.
    """
    out = {}
    for k, v in req.items():
        if isinstance(k, int):
            name = keymap.get(k)
            if name is None:
                continue
            out[name] = v
        else:
            out[k] = v
    return out


def _s(v, default=None):
    if v is None:
        return default
    return v.decode() if isinstance(v, bytes) else v
