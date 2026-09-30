# Static/self-contained checks for the Linux UHID ABI packing and FIDO descriptor.

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctap2_core import Ctap2Authenticator, parse_attested_credential_id
from ctaphid import REPORT_SIZE, pack_reports
import uhid_ctap

ok = fail = 0


def check(name, condition, extra=""):
    global ok, fail
    if condition:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


print("== Linux UHID event numbers ==")
expected = {
    "UHID_DESTROY": 1,
    "UHID_START": 2,
    "UHID_STOP": 3,
    "UHID_OPEN": 4,
    "UHID_CLOSE": 5,
    "UHID_OUTPUT": 6,
    "UHID_CREATE2": 11,
    "UHID_INPUT2": 12,
}
for name, value in expected.items():
    check(f"{name}={value}", getattr(uhid_ctap, name) == value)

print("\n== UHID_CREATE2 packing ==")
create = uhid_ctap.uhid_create2_event(
    name="Lab FIDO2 CTAP2 Key",
    phys="lab-fido2/uhid",
    uniq="lab-fido2-ctap2",
    bus=uhid_ctap.BUS_USB,
    vendor=uhid_ctap.FIDO_VENDOR_ID,
    product=uhid_ctap.FIDO_PRODUCT_ID,
    version=1,
    country=0,
    report_descriptor=uhid_ctap.REPORT_DESCRIPTOR,
)
check("CREATE2 event type", struct.unpack_from("=I", create, 0)[0] == 11)
check("name field", create[4:132].split(b"\0", 1)[0] == b"Lab FIDO2 CTAP2 Key")
check("phys field", create[132:196].split(b"\0", 1)[0] == b"lab-fido2/uhid")
check("uniq field", create[196:260].split(b"\0", 1)[0] == b"lab-fido2-ctap2")
rd_size, bus = struct.unpack_from("=HH", create, 260)
vendor, product, version, country = struct.unpack_from("=IIII", create, 264)
check("descriptor size", rd_size == len(uhid_ctap.REPORT_DESCRIPTOR), rd_size)
check("USB bus", bus == 3, bus)
check("FIDO demo VID", vendor == 0xF1D0, hex(vendor))
check("FIDO demo PID", product == 1, product)
check("device version", version == 1, version)
check("country code", country == 0, country)
check("descriptor embedded", create[280:280 + rd_size] == uhid_ctap.REPORT_DESCRIPTOR)

print("\n== input/output event packing ==")
report = bytes(range(REPORT_SIZE))
input2 = uhid_ctap.uhid_input2_event(report)
check("INPUT2 event type", struct.unpack_from("=I", input2, 0)[0] == 12)
check("INPUT2 report size", struct.unpack_from("=H", input2, 4)[0] == REPORT_SIZE)
check("INPUT2 payload", input2[6:6 + REPORT_SIZE] == report)
output = (
    struct.pack("=I", uhid_ctap.UHID_OUTPUT)
    + report.ljust(uhid_ctap.UHID_DATA_MAX, b"\0")
    + struct.pack("=HB", REPORT_SIZE, 2)
)
check("OUTPUT parser", uhid_ctap.parse_uhid_output(output) == report)
check("DESTROY event", uhid_ctap.uhid_destroy_event() == struct.pack("=I", 1))

print("\n== FIDO HID descriptor and CTAPHID reports ==")
rd = uhid_ctap.REPORT_DESCRIPTOR
check("usage page 0xF1D0", bytes([0x06, 0xD0, 0xF1]) in rd)
check("FIDO usage 0x01", bytes([0x09, 0x01]) in rd)
check("input and output reports", rd.count(bytes([0x95, 0x40])) == 2)
check("collection closed", rd[-1] == 0xC0)
frames = pack_reports(0x11223344, 0x10, os.urandom(300))
check("all CTAPHID frames are 64 bytes", all(len(f) == 64 for f in frames))
check("initial frame has command bit", frames[0][4] == 0x90)
check("continuation starts at sequence zero", frames[1][4] == 0)

print("\n== CTAP2 core smoke test ==")
with tempfile.TemporaryDirectory() as directory:
    store = os.path.join(directory, "creds.json")
    auth = Ctap2Authenticator(store_path=store, attestation_mode="none")
    response = auth.make_credential({
        1: os.urandom(32),
        2: {"id": "lab.example", "name": "Lab"},
        3: {"id": os.urandom(16), "name": "user"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": True},
    })
    credential_id = parse_attested_credential_id(response[2])
    check("integer response keys", set(response).issuperset({1, 2, 3}))
    check("credential persisted", len(auth.list_credentials("lab.example")) == 1)
    check("credential ID is 32 bytes", len(credential_id) == 32)

print("\n== availability probe ==")
reason = uhid_ctap.check_uhid()
check("probe returns None or a reason", reason is None or isinstance(reason, str))
if reason:
    print(f"  INFO  {reason}")

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
