#!/bin/bash
# shell: bash, file: hid_gadget.sh, target: Linux kernel with CONFIG_USB_CONFIGFS_F_HID
#
# Builds a USB HID gadget that enumerates on the FIDO usage page so ctaphid.py can
# speak real CTAPHID to it over /dev/hidg0. Root required (configfs + usbfs).
#
#   modprobe libcomposite
#   ./hid_gadget.sh            # start
#   ./hid_gadget.sh stop       # tear down
#
# PHYSICAL NOTE: this presents the gadget on the *same* machine's USB bus. For a
# box that enumerates to a *host*, put this on a second machine (or a USB/IP-like
# forward) and point SocketHidTransport at it.

set -euo pipefail

GADGET_DIR="/sys/kernel/config/usb_gadget/fido_key"
HIDG=/dev/hidg0
PID=fido

usage() { echo "usage: $0 [start|stop]"; exit 1; }
[ $# -ge 1 ] || usage

teardown() {
  echo "==> tearing down"
  [ -d "$GADGET_DIR" ] || exit 0
  echo 0 > "$GADGET_DIR/UDC" 2>/dev/null || true
  rm -f "$GADGET_DIR/os_desc/1"/* 2>/dev/null || true
  rm -f "$GADGET_DIR/strings/0x409"/* 2>/dev/null || true
  # configs/functions must be empty before the gadget dir can be removed
  for f in "$GADGET_DIR"/configs/*/*; do
    rmdir "$(dirname "$f")" 2>/dev/null || true
  done
  for f in "$GADGET_DIR"/functions/*; do
    rmdir "$f" 2>/dev/null || true
  done
  rmdir "$GADGET_DIR/configs" "$GADGET_DIR/functions" "$GADGET_DIR/strings" \
        "$GADGET_DIR/os_desc" "$GADGET_DIR" 2>/dev/null || true
}

case "$1" in
  stop)
    teardown
    exit 0
    ;;
  start) ;;
  *) usage ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

echo "==> loading modules"
modprobe libcomposite || true

if [ ! -d /sys/kernel/config/usb_gadget ]; then
  echo "configfs not mounted — trying"
  mount -t configfs none /sys/kernel/config 2>/dev/null || true
fi
[ -d /sys/kernel/config/usb_gadget ] || { echo "configfs unavailable"; exit 1; }

teardown

echo "==> creating gadget"
mkdir -p "$GADGET_DIR"
cd "$GADGET_DIR"

# idVendor 0xf1d0 / idProduct 0x0001 — the FIDO Alliance's own demo VID/PID,
# so hosts enumerate it as a FIDO device rather than a generic HID.
echo 0xf1d0 > idVendor
echo 0x0001 > idProduct
echo 0x0100 > bcdDevice
echo 0x0100 > bcdUSB

mkdir -p strings/0x409
echo "Lab FIDO2 CTAPHID Key" > strings/0x409/serialnumber
echo "Lab Security Key" > strings/0x409/product
echo "Lab Instruments" > strings/0x409/manufacturer

mkdir -p os_desc
echo 1 > os_desc/bDeviceClass
echo 1 > os_desc/bDeviceSubClass
echo 0x06 > os_desc/bDeviceProtocol
echo -1 > os_desc/iManufacturer
echo -1 > os_desc/iProduct
echo -1 > os_desc/iSerialNumber

mkdir -p configs/c.1/strings/0x409
echo "FIDO Config" > configs/c.1/strings/0x409/configuration
echo 120 > configs/c.1/MaxPower          # 240 mA
echo 0x0a > configs/c.1/MaxPower         # fall back to a legal value

mkdir -p functions/hid.usb
# FIDO usage page (0xF1D0), FIDO usage (0x01), 64-byte input/output reports.
# This is what makes lsusb/lsusb-devices report a security key.
printf '\x06\xd0\xf1\x09\x01\xa1\x01\x85\x01\x75\x08\x95\x40\x81\x02\x85\x01\x75\x08\x95\x40\x91\x02' \
  > functions/hid.usb/report_desc
echo 64 > functions/hid.usb/report_length

ln -s functions/hid.usb configs/c.1/

echo "==> binding to UDC"
UDC=$(ls /sys/class/udc 2>/dev/null | head -1 || true)
if [ -z "$UDC" ]; then
  echo "no UDC available (no USB controller / not a gadget-capable port)"
  echo "gadget files created at $GADGET_DIR but not bound"
  exit 2
fi
echo "$UDC" > UDC

sleep 1
[ -c "$HIDG" ] || { echo "$HIDG not created — check dmesg"; exit 3; }

echo
echo "gadget bound to UDC $UDC"
echo "  vid:pid  0f1d:0001 (FIDO Alliance demo VID/PID)"
echo "  usage    FIDO page 0xF1D0 / usage 0x01"
echo "  report   64 bytes, CTAPHID framing"
echo "  device   $HIDG"
echo
echo "start the device with:"
echo "  PYTHONPATH=../libs python3 ctaphid_server.py --device $HIDG"
