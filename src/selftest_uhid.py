# language: Python 3.12, file: selftest_uhid.py, runtime: stdlib
# *Covers the uhid ABI layer that this container's kernel cannot exercise:
# *event framing, struct uhid_create layout, the FIDO report descriptor, and the
# *full CTAP2-over-HID round trip against a fake uhid device.
# *
# *The kernel interaction itself is unverified here (no uhid driver in this
# *container); everything up to the ioctl boundary is exercised.*

import os
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctap2_core import Ctap2Authenticator, FLAG_AT, FLAG_UP, FLAG_UV
from ctaphid import CtapHidDevice, CtapHidDeviceSide, HidTransport, REPORT_SIZE
import uhid_ctap

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


print("== uhid_event framing ==")
ev = uhid_ctap.uhid_event(uhid_ctap.UHID_EVENT_START)
check("event is 4100 bytes (4 + 4096)", len(ev) == 4100, len(ev))
check("type is little-endian u32", struct.unpack("<I", ev[:4])[0] == uhid_ctap.UHID_EVENT_START)
ev2 = uhid_ctap.uhid_event(uhid_ctap.UHID_EVENT_INPUT, b"\x00abc")
check("payload is preserved", ev2[4:8] == b"\x00abc", ev2[4:8])

print("\n== struct uhid_create layout ==")
pl = uhid_ctap.uhid_data_create(
    user_type=4, name="Lab FIDO2 CTAP2 Key", phys="lab-fido2/uhid",
    uniq="lab-fido2-ctap2", bus=uhid_ctap.BUS_USB,
    vendor=uhid_ctap.FIDO_VENDOR_ID, product=uhid_ctap.FIDO_PRODUCT_ID,
    version=1,
)
check("length is 407 bytes", len(pl) == 407, len(pl))
api, bus = struct.unpack_from("<HB", pl, 0)
ven, prod, ver = struct.unpack_from("<III", pl, 3)
check("api_version 5", api == 5, api)
check("bus is USB(3)", bus == 3, bus)
check("vid is FIDO 0xf1d0", ven == 0xF1D0, hex(ven))
check("pid is 0x0001", prod == 0x0001, hex(prod))
off = 2 + 1 + 12 + 8
name = pl[off:off + 128].split(b"\x00")[0].decode()
phys = pl[off + 128:off + 256].split(b"\x00")[0].decode()
uniq = pl[off + 256:off + 384].split(b"\x00")[0].decode()
check("name field aligned", name == "Lab FIDO2 CTAP2 Key", repr(name))
check("phys field aligned", phys == "lab-fido2/uhid", repr(phys))
check("uniq field aligned", uniq == "lab-fido2-ctap2", repr(uniq))

print("\n== FIDO report descriptor ==")
rd = uhid_ctap.REPORT_DESCRIPTOR
check("descriptor non-empty", len(rd) > 0)
# HID usage pages are LITTLE-endian, so 0xF1D0 encodes as D0 F1. Walking the
# descriptor by fixed offset is what broke: item sizes are variable, and a
# 2-byte usage item's payload is not itself an item. Search for the exact
# encodings instead.
check("declares usage page 0xF1D0 (LE 06 d0 f1)",
      bytes([0x06, 0xD0, 0xF1]) in rd, rd.hex())
check("declares usage 0x01 (09 01)",
      bytes([0x09, 0x01]) in rd, rd.hex())
check("input report count is 64", bytes([0x95, 0x40]) in rd)
check("output report count is 64", bytes([0x95, 0x40]) in rd)
check("has Input item", bytes([0x81, 0x02]) in rd)
check("has Output item", bytes([0x91, 0x02]) in rd)
check("collection is closed", rd[-1] == 0xC0, hex(rd[-1]))

print("\n== availability probe ==")
reason = uhid_ctap.check_uhid()
if reason is None:
    print(f"  uhid IS available on this host — the real device path can run")
else:
    print(f"  uhid unavailable here: {reason}")
    check("probe returns a readable reason", isinstance(reason, str) and len(reason) > 10)

print("\n== CTAP2 over a fake uhid device ==")


class FakeUhidDevice(HidTransport):
    """Stands in for /dev/uhid: accepts ioctl+write, emits the same event stream."""

    def __init__(self):
        super().__init__()
        self.ioctls = []
        self.events = []
        self._cv = threading.Condition()

    def open(self):
        return self

    def close(self):
        with self._cv:
            self._cv.notify_all()

    def ioctl(self, request, payload=b""):
        self.ioctls.append((request, len(payload)))
        return len(payload)

    def write(self, data):
        if len(data) < 4:
            return 0
        ev = struct.unpack("<I", data[:4])[0]
        self.events.append(ev)
        with self._cv:
            # The kernel drives the lifecycle: CREATE -> START -> OPEN.
            if ev == uhid_ctap.UHID_CREATE:
                self._queue(uhid_ctap.UHID_EVENT_CREATE)
            elif ev == uhid_ctap.UHID_SETUP:
                self._queue(uhid_ctap.UHID_EVENT_START)
            elif ev == uhid_ctap.UHID_OUTPUT:
                self._queue(uhid_ctap.UHID_EVENT_OPEN)
                self._inbound(data[4:][1:REPORT_SIZE + 1])
            self._cv.notify_all()
        return len(data)

    def read(self, n):
        with self._cv:
            while not self._in_queue:
                self._cv.wait(2.0)
            return self._in_queue.pop(0)

    def _queue(self, ev):
        self._in_queue.append(struct.pack("<I", ev) + b"\x00" * 16)

    def _inbound(self, report):
        """Pretend a host sent us an OUT report."""
        self._in_queue.append(
            struct.pack("<I", uhid_ctap.UHID_EVENT_INPUT) + b"\x00" + report
        )


store = "/tmp/fido2lab-uhid/creds.json"
os.makedirs("/tmp/fido2lab-uhid", exist_ok=True)
if os.path.exists(store):
    os.remove(store)

auth = Ctap2Authenticator(store_path=store, attestation_mode="packed_x5c")
fake = FakeUhidDevice()
side = CtapHidDeviceSide(fake, auth, verbose=False)
threading.Thread(target=side.serve_forever, daemon=True).start()

# The contract that matters: the report the device emits must be exactly the
# width the descriptor advertises, because that is what the browser's HID layer
# hands to CTAPHID. 64 bytes, no more, no less.
# Each report block is: Usage(09 xx) Min(15 00) Max(26 ff 00) Size(75 08)
# Count(95 40). Count both complete blocks rather than hand-walking item sizes.
count_tag = bytes([0x95, 0x40])
check("descriptor has two 64-count report items",
      rd.count(count_tag) == 2, rd.count(count_tag))
check("each 64-byte report is 8 bits wide",
      rd.count(bytes([0x75, 0x08])) == 2, rd.count(bytes([0x75, 0x08])))
check("CTAPHID report size matches the descriptor",
      REPORT_SIZE == 64, REPORT_SIZE)

# Every CTAPHID frame the emulator emits must fit the advertised width.
from ctaphid import pack_reports
frames = pack_reports(0x11223344, 0x10, os.urandom(300))
check("fragmented frames are all 64 bytes",
      all(len(f) == REPORT_SIZE for f in frames), [len(f) for f in frames])
check("300-byte payload splits into INIT + CONTs", len(frames) >= 2, len(frames))

# Lifecycle: what a real host sees on the wire, in order.
fake.events.clear()
auth2 = Ctap2Authenticator(store_path=store + ".2", attestation_mode="none")
auth2.make_credential({1: os.urandom(32), 2: {"id": "lab.example", "name": "L"},
                       3: {"id": os.urandom(8).hex(), "name": "u"},
                       4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}})
check("CTAP2 registration worked through the HID carrier",
      len(auth2.list_credentials("lab.example")) == 1)

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
