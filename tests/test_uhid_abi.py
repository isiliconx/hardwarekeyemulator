import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import uhid_ctap


def test_uhid_event_numbers_match_linux_uapi():
    assert uhid_ctap.UHID_DESTROY == 1
    assert uhid_ctap.UHID_START == 2
    assert uhid_ctap.UHID_STOP == 3
    assert uhid_ctap.UHID_OPEN == 4
    assert uhid_ctap.UHID_CLOSE == 5
    assert uhid_ctap.UHID_OUTPUT == 6
    assert uhid_ctap.UHID_CREATE2 == 11
    assert uhid_ctap.UHID_INPUT2 == 12


def test_create2_event_embeds_descriptor_and_device_identity():
    event = uhid_ctap.uhid_create2_event(
        name="Test Key",
        phys="test/uhid",
        uniq="test-key",
        bus=uhid_ctap.BUS_USB,
        vendor=0xF1D0,
        product=1,
        version=1,
        country=0,
        report_descriptor=uhid_ctap.REPORT_DESCRIPTOR,
    )

    assert struct.unpack_from("=I", event, 0)[0] == uhid_ctap.UHID_CREATE2
    assert event[4:132].split(b"\0", 1)[0] == b"Test Key"
    assert event[132:196].split(b"\0", 1)[0] == b"test/uhid"
    assert event[196:260].split(b"\0", 1)[0] == b"test-key"
    rd_size, bus = struct.unpack_from("=HH", event, 260)
    assert rd_size == len(uhid_ctap.REPORT_DESCRIPTOR)
    assert bus == uhid_ctap.BUS_USB
    assert event[280 : 280 + rd_size] == uhid_ctap.REPORT_DESCRIPTOR


def test_input2_event_sends_device_report_to_host():
    report = bytes(range(64))
    event = uhid_ctap.uhid_input2_event(report)
    assert struct.unpack_from("=I", event, 0)[0] == uhid_ctap.UHID_INPUT2
    assert struct.unpack_from("=H", event, 4)[0] == 64
    assert event[6:70] == report


def test_output_event_parser_reads_host_report():
    report = bytes(reversed(range(64)))
    payload = report.ljust(4096, b"\0") + struct.pack("=HB", len(report), 2)
    event = struct.pack("=I", uhid_ctap.UHID_OUTPUT) + payload
    assert uhid_ctap.parse_uhid_output(event) == report
