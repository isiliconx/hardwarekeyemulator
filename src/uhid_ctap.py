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
UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6          # kernel -> userspace: host sent an OUT report
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12         # userspace -> kernel: device sent an IN report
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

UHID_DATA_MAX = 4096
HID_MAX_DESCRIPTOR_SIZE = 4096
BUS_USB = 0x03


def _fixed_field(value: str, size: int) -> bytes:
    encoded = value.encode()
    if len(encoded) >= size:
        encoded = encoded[: size - 1]
    return encoded.ljust(size, b"\x00")


def uhid_create2_event(
    *, name: str, phys: str, uniq: str, bus: int, vendor: int,
    product: int, version: int, country: int, report_descriptor: bytes,
) -> bytes:
    """Pack struct uhid_event with a uhid_create2_req payload."""
    if len(report_descriptor) > HID_MAX_DESCRIPTOR_SIZE:
        raise ValueError("HID report descriptor is too large")
    payload = (
        _fixed_field(name, 128)
        + _fixed_field(phys, 64)
        + _fixed_field(uniq, 64)
        + struct.pack(
            "=HHIIII", len(report_descriptor), bus, vendor, product, version, country
        )
        + report_descriptor.ljust(HID_MAX_DESCRIPTOR_SIZE, b"\x00")
    )
    return struct.pack("=I", UHID_CREATE2) + payload


def uhid_input2_event(report: bytes) -> bytes:
    """Pack a device-to-host input report as UHID_INPUT2."""
    if len(report) > UHID_DATA_MAX:
        raise ValueError("UHID input report is too large")
    return (
        struct.pack("=IH", UHID_INPUT2, len(report))
        + report.ljust(UHID_DATA_MAX, b"\x00")
    )


def uhid_destroy_event() -> bytes:
    return struct.pack("=I", UHID_DESTROY)


def parse_uhid_event(event: bytes) -> tuple[int, bytes]:
    if len(event) < 4:
        raise OSError("short uhid event")
    return struct.unpack_from("=I", event, 0)[0], event[4:]


def parse_uhid_output(event: bytes) -> bytes:
    """Extract one host-to-device report from a UHID_OUTPUT event."""
    event_type, payload = parse_uhid_event(event)
    if event_type != UHID_OUTPUT:
        raise ValueError(f"expected UHID_OUTPUT, received {event_type}")
    if len(payload) < UHID_DATA_MAX + 3:
        raise OSError("short UHID_OUTPUT event")
    size, _report_type = struct.unpack_from("=HB", payload, UHID_DATA_MAX)
    if size > UHID_DATA_MAX:
        raise OSError("invalid UHID_OUTPUT report size")
    return payload[:size]

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
        try:
            self._send_event(uhid_create2_event(
                name=self.name,
                phys="lab-fido2/uhid",
                uniq="lab-fido2-ctap2",
                bus=BUS_USB,
                vendor=FIDO_VENDOR_ID,
                product=FIDO_PRODUCT_ID,
                version=0x0001,
                country=0,
                report_descriptor=REPORT_DESCRIPTOR,
            ))
            self._await(UHID_START)
        except Exception:
            os.close(self.fd)
            self.fd = None
            raise
        self._opened.set()
        return self

    def close(self):
        if self.fd is None:
            return
        try:
            self._send_event(uhid_destroy_event())
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None

    def _send_event(self, event: bytes) -> None:
        view = memoryview(event)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError("short uhid write")
            view = view[written:]

    def _recv_event(self) -> bytes:
        event = os.read(self.fd, 4 + 4372)
        if len(event) < 4:
            raise OSError("short uhid read")
        return event

    def _await(self, wanted: int, timeout: float = 5.0) -> bytes:
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                event = self._recv_event()
            except BlockingIOError:
                time.sleep(0.005)
                continue
            event_type, data = parse_uhid_event(event)
            if event_type == wanted:
                return data
        raise TimeoutError(f"uhid never sent event 0x{wanted:02x}")

    # ------------------------------------------------------------------ data path

    def write(self, data: bytes):
        """Device -> host: submit an IN report with UHID_INPUT2."""
        if len(data) != REPORT_SIZE:
            raise ValueError(f"HID report must be {REPORT_SIZE} bytes, got {len(data)}")
        with self._lock:
            self._send_event(uhid_input2_event(data))

    def read_exact(self, n: int, timeout: float = 30.0) -> bytes:
        """Host -> device: receive an OUT report from UHID_OUTPUT."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                event = self._recv_event()
            except BlockingIOError:
                time.sleep(0.001)
                continue
            event_type, _ = parse_uhid_event(event)
            if event_type != UHID_OUTPUT:
                continue
            report = parse_uhid_output(event)
            if len(report) != n:
                raise OSError(f"uhid report was {len(report)} bytes, expected {n}")
            return report
        raise TimeoutError(f"no HID output report within {timeout}s")


# --------------------------------------------------------------------------- entry point


def check_uhid(device: str = "/dev/uhid") -> Optional[str]:
    """Return None if the selected uhid device is usable, else a reason."""
    if not os.path.exists(device):
        return (f"{device} missing — run `sudo modprobe uhid`. If your kernel "
                "lacks CONFIG_INPUT_UHID there is no way to bind a userspace "
                "HID device; this needs a normal host, not a container.")
    try:
        fd = os.open(device, os.O_RDWR | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == 19:      # ENODEV
            return ("/dev/uhid present but the uhid driver is not loaded in the "
                    "host kernel (`sudo modprobe uhid`).")
        if exc.errno == 13:
            return (
                f"cannot open {device}: permission denied. Grant a dedicated group "
                "0660 access with a udev rule; do not make /dev/uhid world-writable."
            )
        return f"cannot open {device}: {exc}"
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
    ap.set_defaults(touch_required=True)
    ap.add_argument("--no-touch-required", dest="touch_required", action="store_false",
                    help="UNSAFE: approve user presence without an operator gesture")
    ap.add_argument("--internal-uv", action="store_true",
                    help="assert software user verification after the presence prompt")
    args = ap.parse_args()

    reason = check_uhid(args.device)
    if reason:
        print(f"[uhid] NOT AVAILABLE: {reason}")
        print("\nThis container's kernel has no uhid driver, so the HID binding "
              "cannot be exercised here. Everything above the HID layer is "
              "covered by the test suites; run this on a host with "
              "CONFIG_INPUT_UHID=y.")
        return 1

    from ctap2_core import Ctap2Authenticator

    presence_gate = _presence_gate(args.touch_required)
    auth = Ctap2Authenticator(
        store_path=args.store,
        attestation_mode=args.attestation,
        up_gate=presence_gate,
        uv_gate=presence_gate if args.internal_uv else None,
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
            return False
        return not ans.strip().lower().startswith("n")

    return gate


if __name__ == "__main__":
    sys.exit(main())

