# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact observed HID framing; no generic commands, COMPLETE or memory writes."""
import functools
import struct
import sys
import time

from .image import require
from .profiles import by_getv
from .stubs import core_stub, read_stub, hold_stub, release_stub

BOOT = (0x352D, 0x1101)
APP = (0x3532, 0xA0A3)
QUERY = bytes.fromhex("0000000004000001") + b"getv"


def start_frame(header, image):
    require(len(header) == 52 and len(image) == 440, "Invalid START frame components")
    checksum = functools.reduce(int.__xor__, struct.unpack("<110I", image), 0)
    return header + image + struct.pack("<I", checksum)


def data_frame(sequence, page):
    require(1 <= sequence <= 117 and len(page) == 512, "Invalid application DATA page")
    return bytes([2, sequence, 0, 0x73, 0, 2, 1, 0x77]) + page


def shared_open(hid_module):
    """macOS hidapi seizes (opens exclusively) by default; the stock application keeps its
    vendor collection on the keyboard interface, which the system already holds."""
    if sys.platform == "darwin":
        import ctypes
        try:
            ctypes.CDLL(hid_module.__file__).hid_darwin_set_open_exclusive(0)
        except (AttributeError, OSError):
            pass  # hidapi builds without the switch keep their default


class HIDTransport:
    def __init__(self, header, enter_stock=False, wait_seconds=30, hid_module=None, resume_holder=False, profile=None):
        if hid_module is None:
            import hid as hid_module
            shared_open(hid_module)
        self.hid = hid_module
        self.header = header
        self.handle = None
        self.path = None
        self.enter_stock = enter_stock
        self.wait_seconds = wait_seconds
        self.version = None
        self.resume_holder = resume_holder
        # Bootloader revision: from GETV, or given for a held session (GETV would end it).
        self.profile = profile
        require(not resume_holder or profile is not None, "A held session needs the backup's bootloader profile")

    def open(self):
        deadline = time.monotonic() + self.wait_seconds
        entered = False
        while True:
            boots, apps = self.hid.enumerate(*BOOT), self.hid.enumerate(*APP)
            require(len(boots) <= 1, "Multiple matching bootloaders; disconnect other boards")
            if boots:
                require(not apps, "Other matching application interfaces remain connected")
                self.path = boots[0]["path"]
                self.handle = self.hid.device()
                self.handle.open_path(self.path)
                if self.resume_holder:
                    # A recovery holder is already inside native BDC. GETV
                    # would exit that state. Fence with bounded read-only
                    # holder replies instead; core and the boot SHA are checked
                    # again by Session before ANY programming command.
                    for attempt in range(3):
                        try:
                            self.hold_once()
                            self.version = "held-session; boot hash checked before DATA"
                            return self.version
                        except (OSError, ValueError):
                            if attempt == 2:
                                raise
                            self.close()
                            time.sleep(0.02)
                self.version = self.get_version()
                return self.version
            if self.enter_stock and not entered:
                vendors = [d for d in apps if d.get("usage_page") == 0xFF00 and d.get("serial_number") == "rankednova"]
                require(len(apps) == 6 and len(vendors) == 1, "Automatic entry requires the original six-interface Nova application")
                app = self.hid.device()
                try:
                    app.open_path(vendors[0]["path"])
                    require(app.write(bytes.fromhex("04a501") + bytes(61)) == 64, "Short stock boot-entry transfer")
                finally:
                    app.close()
                entered = True
            if time.monotonic() >= deadline:
                raise TimeoutError("Bootloader not found. For QMK, hold Esc while reconnecting; stock needs --enter-stock.")
            time.sleep(0.1)

    def _send(self, frame):
        require(self.handle is not None, "HID handle is not open")
        for offset in range(0, len(frame), 64):
            require(self.handle.write(b"\0" + frame[offset:offset + 64].ljust(64, b"\0")) == 65, "Short HID write; no automatic retry")

    def _read(self, timeout=10000):
        result = bytes(self.handle.read(65, timeout))
        if len(result) == 65 and result[0] == 0:
            result = result[1:]
        require(len(result) == 64, "Short or timed-out HID reply")
        return result

    def get_version(self):
        self._send(QUERY)
        reply = self._read(2000)
        require(reply[:16] == bytes.fromhex("0000000010000001") + b"version:", "Unrecognized bootloader version response")
        version = reply[16:24].hex()
        profile = by_getv(version)
        require(self.profile in (None, profile), "Bootloader revision differs from the expected one")
        self.profile = profile
        return version

    def _reply(self, packet, sequence, length):
        result = self._read()
        require(result[:4] == bytes([packet, sequence, 0, 0x73]) and result[6:8] == b"\x01\x77", "Mismatched native reply")
        require(int.from_bytes(result[4:6], "little") == length, "Native reply length mismatch")
        return result[8:8 + length]

    def start(self, image, reply_length):
        self._send(start_frame(self.header, image))
        return self._reply(1, 0, reply_length)

    def core(self, mask):
        before, after, cpuid, iser, systick = struct.unpack("<5I", self.start(core_stub(mask, self.profile), 20))
        require(cpuid == 0x410CC200 and iser == 0 and systick & 3 == 0, "Unsupported core or active IRQ/SysTick state")
        require(after == 1, "Core interrupt mask is not preserved")
        if not mask:
            require(before == 1, "Core interrupt state changed during programming")
        return dict(before=before, after=after, cpuid=hex(cpuid), nvic_iser=iser, systick=systick)

    def read(self, address, length, metadata=False):
        output = bytearray()
        for current in range(address, address + length, 56):
            count = min(56, address + length - current)
            output.extend(self.start(read_stub(current, count, metadata, self.profile), count))
        return bytes(output)

    def begin_programming(self, loader):
        require(self.start(loader, 1) == b"\x04", "Bounded loader START rejected")

    def data(self, sequence, page):
        self._send(data_frame(sequence, page))
        require(self._reply(2, sequence, 1) == b"\x04", "Application DATA rejected")

    def hold_once(self):
        if self.handle is None:
            matches = [d for d in self.hid.enumerate(*BOOT) if d["path"] == self.path]
            require(len(matches) == 1, "Original bootloader path unavailable; refusing another board")
            self.handle = self.hid.device()
            self.handle.open_path(self.path)
        require(self.start(hold_stub(self.profile), 6) == bytes.fromhex(self.profile.holder_proof[1]), "Read-only recovery holder reply mismatch")

    def release(self):
        require(self.start(release_stub(self.profile), 1) == b"\x04", "Verified-image release rejected")
        # GETV terminates this native programming session. Its expected native
        # result is a NACK5 followed by reset, not a normal version reply. USB
        # can disconnect before hidapi delivers that reply. Enumeration is the
        # independent completion check performed by Session.
        self._send(QUERY)
        try:
            self._read(1000)
        except (OSError, ValueError):
            pass

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def wait_application(self, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            apps, boots = self.hid.enumerate(*APP), self.hid.enumerate(*BOOT)
            if apps and not boots:
                return dict(application_interfaces=len(apps), bootloader_interfaces=0)
            time.sleep(0.1)
        raise TimeoutError("Image verified, but application enumeration was not observed; use Esc recovery")
