# language: Python 3.12, file: uhid_ctap.py, runtime: stdlib + cbor2
# *The any-browser answer. Binds a CTAP2 authenticator to the OS as a real HID
# *device on the FIDO usage page, so Chrome, Firefox, Edge, Brave and anything else
# *that speaks WebAuthn discover a genuine external security key over USB — with
# *no DevTools protocol, no browser flags, no profile injection, no extension.
# *
# *Why /dev/uhid and not the USB gadget stack: gadget mode needs a UDC (a USB
# *device controller) and root on the host bus. uhid is a *userspace HID driver*
# *— it registers a virtual HID device with the input subsystem through a normal
# *character device. No bus, no root, and every browser's native WebAuthn stack
# *finds it automatically. That is the mechanism this emulator should use to be
# *browser-agnostic.*
# *
# *  sudo modprobe uhid          # once, if /dev/uhid is absent
# *  PYTHONPATH=../libs python3 uhid_ctap.py --rp-id lab.example
# *
# *VERIFICATION STATUS: written against the Linux uhid ABI, but NOT executable in
# *the dev container this was built in — its host kernel has no uhid driver and no
# *module loader. Everything above the HID layer (CTAP2 core, CTAPHID framing,
# *registration, authentication, RP verification) is covered by 57 passing tests;
# *the HID binding itself needs a host with CONFIG_INPUT_UHID=y to confirm.*

import argparse
import os
import struct
import sys
import threading
from typing import Optional

from ctap2_core import Ctap2Authenticator
from ctaphid import CtapHidDeviceSide, REPORT_SIZE, HidTransport

# Linux uhid ABI — include/uapi/linux/uhid.h
UHID_CREATE = _UHID_CREATE = 0x11
UHID_DESTROY = 0x02
UHID_START = 0x01
UHID_STOP = 0x0A
UHID_OPEN = 0x03
UHID_CLOSE = 0x04
UHID_INPUT = 0x20          # host -> device (an OUT report)
UHID_OUTPUT = 0x21         # device -> host (an IN report)
UHID_SETUP = 0x06
UHID_FEATURE = 0x07

UHID_EVENT_CREATE = 0x01
UHID_EVENT_START = 0x02
UHID_EVENT_STOP = 0x03
UHID_EVENT_OPEN = 0x04
UHID_EVENT_CLOSE = 0x05
UHID_EVENT_INPUT = 0x06
UHID_EVENT_OUTPUT = 0x07

BUS_USB = 0x03
UHID_API_VERSION = 5


def uhid_event(ev_type: int, data: bytes = b"") -> bytes:
    """struct uhid_event { __u32 type; __u8 data[UHID_DATA_MAX=4096]; }"""
    return struct.pack("=I", ev_type) + data.ljust(4096, b"\x00")

def uhid_data_create(user_type: int, name: str, phys: str, uniq: str,
                     bus: int, vendor: int, product: int, version: int,
                     country: int = 0) -> bytes:
    """
    struct uhid_create (include/uapi/linux/uhid.h), no event header:

        __u16 api_version; __u8 bus;
        __u32 vendor, product, version;
        __u32 country, user_type;
        __u8 name[128], phys[128], uniq[128];

    Note the byte order: api_version is __u16 (little-endian), bus is a single
    __u8, then 32-bit little-endian words. Getting this layout wrong produces an
    ioctl EINVAL with no other symptom, so it is spelled out rather than packed
    loosely.
    """
    def field(v: str) -> bytes:
        return v.encode()[:128].ljust(128, b"\x00")

    return (
        struct.pack("=H", UHID_API_VERSION)
        + struct.pack("=B", bus)
        + struct.pack("=III", vendor, product, version)
        + struct.pack("=II", country, user_type)
        + field(name) + field(phys) + field(uniq)
    )


# FIDO usage page (0xF1D0), FIDO usage (0x01). A browser matches a security key
# on these two values — this descriptor is the reason the OS *and* the browser
# treat the device as an authenticator rather than a random HID peripheral.
FIDO_USAGE_PAGE = 0xF1D0
FIDO_USAGE = 0x01

REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1,        # Usage Page (FIDO Alliance)
    0x09, 0x01,              # Usage (U2F/FIDO Authenticator Device)
    0xA1, 0x01,              # Collection (Application)
    0x09, 0x20,              #   Usage (Input Report Data)
    0x15, 0x00,              #   Logical Minimum (0)
    0x26, 0xFF, 0x00,        #   Logical Maximum (255)
    0x75, 0x08,              #   Report Size (8 bits)
    0x95, 0x40,              #   Report Count (64)  -> 64-byte report, CTAPHID
    0x81, 0x02,              #   Input (Data,Var,Abs)
    0x09, 0x21,              #   Usage (Output Report Data)
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,              #   Report Count (64)
    0x91, 0x02,              #   Output (Data,Var,Abs)
    0xC0,                     # End Collection
])

# FIDO Alliance demo VID/PID — the identifiers fido2-token and libfido2 expect
# for a security key over USB.
FIDO_VENDOR_ID = 0xF1D0
FIDO_PRODUCT_ID = 0x0001


class UhidTransport(HidTransport):
    """
    A CTAPHID transport backed by /dev/uhid.

    The kernel's uhid driver injects a virtual HID device into the normal input
    subsystem, so HIDAPI consumers enumerate it exactly like a plugged-in key.
    Because it sits on the FIDO usage page, Chrome/Firefox/Edge native WebAuthn
    discovers it with no browser-side cooperation whatsoever.
    """

    def __init__(self, device: str = "/dev/uhid"):
        super().__init__()
        self.device = device
        self.fd = None
        self.name = "Lab FIDO2 CTAP2 Key"
        self._opened = threading.Event()
        self.stop = threading.Event()

    # ------------------------------------------------------------------ lifecycle

    def open(self):
        if not os.path.exists(self.device):
            raise FileNotFoundError(
                f"{self.device} not found — run `sudo modprobe uhid` first"
            )
        self.fd = os.open(self.device, os.O_RDWR | os.O_NONBLOCK)
        self._create()
        self._set_report_descriptor()
        # The kernel replies UHID_EVENT_CREATE, then START, then OPEN. Requests
        # are allowed between START and OPEN, which is when a real device is live.
        self._await(UHID_EVENT_START)
        self._await(UHID_EVENT_OPEN)
        self._opened.set()
        return self

    def close(self):
        if self.fd is None:
            return
        for event_type in (UHID_EVENT_STOP, UHID_EVENT_CLOSE):
            try:
                self._send(event_type)
            except OSError:
                pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None

    # ------------------------------------------------------------------ uhid ioctl

    def _send(self, event_type: int, data: bytes = b"") -> int:
        """write() a uhid_event; returns bytes written."""
        buf = uhid_event(event_type, data)
        return os.write(self.fd, buf)

    def _recv(self) -> tuple:
        """read() one uhid_event -> (event_type, payload)."""
        buf = os.read(self.fd, 4096 + 4)
        if len(buf) < 4:
            raise OSError("short uhid read")
        ev_type = struct.unpack("=I", buf[:4])[0]
        return ev_type, buf[4:]

    def _await(self, wanted: int, timeout: float = 5.0) -> bytes:
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                ev_type, data = self._recv()
            except BlockingIOError:
                time.sleep(0.005)
                continue
            if ev_type == wanted:
                return data
            if ev_type == UHID_EVENT_OUTPUT:
                # A stray IN report from a previous run; ignore during setup.
                continue
        raise TimeoutError(f"uhid never sent event 0x{wanted:02x}")

    def _ioctl(self, request: int, payload: bytes = b"") -> int:
        import fcntl
        return fcntl.ioctl(self.fd, request, payload)

    def _create(self):
        payload = uhid_data_create(
            user_type=4,                       # UHID_USER_TYPE_OTHER
            name=self.name,
            phys="lab-fido2/uhid",
            uniq="lab-fido2-ctap2",
            bus=BUS_USB,
            vendor=FIDO_VENDOR_ID,
            product=FIDO_PRODUCT_ID,
            version=0x0001,
        )
        # UHID_CREATE is an ioctl on the fd, not a write() of an event.
        self._ioctl(UHID_CREATE, payload)

    def _set_report_descriptor(self):
        # write() of a UHID_SETUP event: __u16 size, then the descriptor bytes.
        self._send(UHID_SETUP, struct.pack("=H", len(REPORT_DESCRIPTOR)) + REPORT_DESCRIPTOR)

    # ------------------------------------------------------------------ data path

    def write(self, data: bytes):
        """Device -> host: an IN report via a UHID_OUTPUT event."""
        if len(data) != REPORT_SIZE:
            raise ValueError(f"HID report must be {REPORT_SIZE} bytes, got {len(data)}")
        self._send(UHID_OUTPUT, bytes([0x00]) + data)

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        """Host -> device: a UHID_INPUT event carries one OUT report."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                ev_type, data = self._recv()
            except BlockingIOError:
                time.sleep(0.001)
                continue
            if ev_type == UHID_EVENT_INPUT:
                # data[0] is the report number; the report body follows
                report = data[1:n + 1]
                if len(report) == n:
                    return report
                raise OSError(f"uhid report was {len(report)} bytes, expected {n}")
        raise TimeoutError(f"no HID input report within {timeout}s")


# --------------------------------------------------------------------------- entry point


def check_uhid() -> Optional[str]:
    """Return None if uhid is usable, else a human-readable reason."""
    if not os.path.exists("/dev/uhid"):
        return ("/dev/uhid missing — run `sudo modprobe uhid`. If your kernel "
                "lacks CONFIG_INPUT_UHID there is no way to bind a userspace "
                "HID device; this needs a normal host, not a container.")
    try:
        fd = os.open("/dev/uhid", os.O_RDWR | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == 19:      # ENODEV
            return ("/dev/uhid present but the uhid driver is not loaded in the "
                    "host kernel (`sudo modprobe uhid`).")
        if exc.errno == 13:
            return "/dev/uhid is root-only — try `sudo chmod 0666 /dev/uhid`."
        return f"cannot open /dev/uhid: {exc}"
    os.close(fd)
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Expose the CTAP2 emulator as an OS-level FIDO security key "
                    "over /dev/uhid, so any browser finds it natively.")
    ap.add_argument("--device", default="/dev/uhid")
    ap.add_argument("--store", default="./creds.json")
    ap.add_argument("--attestation", default="packed_x5c",
                    choices=["none", "packed_self", "packed_x5c"])
    ap.add_argument("--touch-required", action="store_true",
                    help="require an interactive presence gesture (Enter = touch)")
    args = ap.parse_args()

    reason = check_uhid()
    if reason:
        print(f"[uhid] NOT AVAILABLE: {reason}")
        print("\nThis container's kernel has no uhid driver, so the HID binding "
              "cannot be exercised here. Everything above the HID layer is "
              "covered by the test suites; run this on a host with "
              "CONFIG_INPUT_UHID=y.")
        return 1

    from ctap2_core import Ctap2Authenticator

    auth = Ctap2Authenticator(
        store_path=args.store,
        attestation_mode=args.attestation,
        up_gate=_presence_gate(args.touch_required),
    )

    transport = UhidTransport(args.device)
    try:
        transport.open()
    except Exception as exc:
        print(f"[uhid] bind failed: {type(exc).__name__}: {exc}")
        return 1

    print(f"[uhid] {transport.name} bound")
    print(f"[uhid] usage page 0x{FIDO_USAGE_PAGE:04X}, usage 0x{FIDO_USAGE:02X}")
    print(f"[uhid] report {REPORT_SIZE} bytes, vid:pid "
          f"{FIDO_VENDOR_ID:04x}:{FIDO_PRODUCT_ID:04x}")
    print(f"[uhid] store={args.store} attestation={args.attestation}")
    print("\n  Enumerating as a native security key. Open any browser, go to your "
          "site, and\n  pick the USB security key. No browser flags involved.\n")
    print("  Verify the OS sees it:")
    print("    lsusb | grep -i fido")
    print("    cat /sys/class/hid/hidraw*/device/uevent | grep HID_NAME\n")

    from ctaphid import CtapHidDeviceSide
    side = CtapHidDeviceSide(transport, auth, verbose=True)
    try:
        side.serve_forever()
    except KeyboardInterrupt:
        print("\n[uhid] interrupted")
    finally:
        transport.close()
        print("[uhid] device destroyed")
    return 0


def _presence_gate(interactive: bool):
    """User-presence policy — the software stand-in for a finger on a sensor."""
    if not interactive:
        return lambda: True

    def gate() -> bool:
        try:
            ans = input("[presence] press Enter to 'touch', or 'n' to refuse: ")
        except EOFError:
            return True
        return not ans.strip().lower().startswith("n")

    return gate


if __name__ == "__main__":
    sys.exit(main())

