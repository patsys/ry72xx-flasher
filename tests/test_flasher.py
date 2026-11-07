# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Public, vendor-data-free host tests. No physical USB calls are made."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import os
import time
import threading
import unittest
from unittest.mock import patch

from ry72xx_flasher import image
from ry72xx_flasher.image import START, END, FLASH_SIZE, digest, parse_hex, xor_words
from ry72xx_flasher import profiles
import dataclasses
from ry72xx_flasher.session import Session
from ry72xx_flasher.transport import HIDTransport, start_frame
from ry72xx_flasher.stubs import hold_stub, release_stub, read_stub, core_stub
from ry72xx_flasher.cli import main, restored_image, queue_recovery
from ry72xx_flasher.loader import extract_capture, patch_vendor, load_profile
from ry72xx_flasher.nvm_audit import audit_nvm_backup


def record(address, kind, data=b""):
    data = bytes(data)
    body = bytes([len(data)]) + address.to_bytes(2, "big") + bytes([kind]) + data
    return ":" + (body + bytes([-sum(body) & 255])).hex().upper()


def valid_hex():
    data = struct.pack("<40I", 0x20001000, *([0x20A1] * 39)) + b"\x70\x47"
    return "\n".join([record(START + offset, 0, data[offset:offset + 16]) for offset in range(0, len(data), 16)] + [record(0, 5, (0x20A1).to_bytes(4, "big")), record(0, 1)])



def fake_profile(flash):
    """Test-only bootloader profile whose identity is the fake flash's boot region."""
    return dataclasses.replace(profiles.V105, name="fake", boot_sha=digest(bytes(flash[:START])))


def supported(profile):
    return patch("ry72xx_flasher.profiles.PROFILES", (profile,))


def valid_metadata(length=0xE908, stored=0x25A4F084):
    """512-byte info-flash metadata block with a valid application entry and header XOR."""
    words = [0] * 128
    words[7:11] = [1, START, length, stored]
    block = bytearray(b"".join(w.to_bytes(4, "little") for w in words))
    block[0x1FC:0x200] = xor_words(bytes(block[:0x1FC])).to_bytes(4, "little")
    return bytes(block)

class ImageTests(unittest.TestCase):
    def reject(self, text):
        with self.assertRaises(ValueError):
            parse_hex(text)

    def test_valid_vectors_and_entry(self):
        parsed = parse_hex(valid_hex())
        self.assertEqual(parsed.entry, 0x20A1)
        self.assertEqual(len(parsed.data), 162)


    def test_checksum(self):
        text = valid_hex()
        self.reject(text.replace(text[20], "0" if text[20] != "0" else "1", 1))

    def test_truncated_and_invalid_records(self):
        for text in [":00", ":GG", "hello", "", valid_hex()[:-1], valid_hex().replace(":10", ":11", 1)]:
            with self.subTest(text=text[:12]):
                self.reject(text)

    def test_missing_or_repeated_eof(self):
        self.reject("\n".join(valid_hex().splitlines()[:-1]))
        self.reject(valid_hex() + "\n" + record(0, 1))

    def test_overlap_rejected_even_if_identical(self):
        lines = valid_hex().splitlines()
        self.reject("\n".join([lines[0], *lines]))

    def test_protected_and_outside_addresses(self):
        for address in [0, START - 1, END, 0x1FFFF]:
            with self.subTest(address=address):
                self.reject(record(0, 4, (address >> 16).to_bytes(2, "big")) + "\n" + record(address & 65535, 0, b"\0") + "\n" + valid_hex())
        self.reject(record(0, 4, b"\x40\0") + "\n" + record(START, 0, b"\0") + "\n" + record(0, 1))

    def test_segment_and_linear_extensions(self):
        self.assertEqual(parse_hex(record(0, 4, b"\0\0") + "\n" + valid_hex()).data, parse_hex(valid_hex()).data)
        self.assertEqual(parse_hex(record(0, 2, b"\0\0") + "\n" + valid_hex()).data, parse_hex(valid_hex()).data)
        self.assertEqual(parse_hex(valid_hex().replace(record(0, 5, b"\0\0\x20\xa1"), record(0, 3, b"\0\0\x20\xa1"))).entry, 0x20A1)

    def test_bad_stack_and_vectors(self):
        lines = valid_hex().splitlines()
        for stack in [0, 0x20000004, 0x20001004, 0x20002000]:
            payload = struct.pack("<4I", stack, 0x20A1, 0x20A1, 0x20A1)
            self.reject("\n".join([record(START, 0, payload), *lines[1:]]))
        for reset in [0, 0x20A0, 0x2001, 0x1001, 0x40000001]:
            self.reject("\n".join([record(START, 0, struct.pack("<4I", 0x20001000, reset, 0x20A1, 0x20A1)), *lines[1:]]))

    def test_entry_must_agree(self):
        self.reject(valid_hex().replace(record(0, 5, b"\0\0\x20\xa1"), record(0, 5, b"\0\0\x20\xa3")))

    def test_unsupported_or_malformed_record(self):
        for line in [record(0, 6, b"\0" * 4), record(1, 1), record(1, 4, b"\0\0"), record(0, 4, b"\0")]:
            self.reject(line + "\n" + valid_hex())


class NvmAuditTests(unittest.TestCase):
    # Synthetic boot region accepted through a test profile; no vendor bootloader bytes are needed.
    BOOT = bytes((i * 7 + 3) & 255 for i in range(START))

    def setUp(self):
        patcher = supported(fake_profile(self.BOOT))
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_backup(self, folder, candidate_fill=0xFF):
        flash = bytearray([0xFF]) * FLASH_SIZE
        flash[:0x2000] = self.BOOT
        flash[0xF8 * 512:0x100 * 512] = bytes([candidate_fill]) * (8 * 512)
        metadata = bytes([0xFF]) * 512
        (folder / "before_flash.bin").write_bytes(flash)
        (folder / "before_metadata.bin").write_bytes(metadata)
        (folder / "result.json").write_text(json.dumps({
            "format": 1,
            "boot_verified": True,
            "probe_only": True,
            "write_started": False,
            "passed": True,
            "released": True,
            "before_flash_sha256": digest(flash),
            "before_metadata_sha256": digest(metadata),
        }), encoding="utf-8")

    def test_blank_candidate_is_reported_without_permitting_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.make_backup(folder)
            result = audit_nvm_backup(folder)
            self.assertTrue(result["candidate_erased"])
            self.assertFalse(result["write_permitted"])
            self.assertEqual(result["candidate_bytes"], 4 * 1024)
            self.assertTrue(result["candidate_permission_bits_enabled"])

    def test_nonblank_candidate_is_reported_as_not_erased(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.make_backup(folder, candidate_fill=0x00)
            self.assertFalse(audit_nvm_backup(folder)["candidate_erased"])

    def test_rejects_non_probe_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.make_backup(folder)
            manifest = json.loads((folder / "result.json").read_text(encoding="utf-8"))
            manifest["probe_only"] = False
            (folder / "result.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                audit_nvm_backup(folder)


class FakeTransport:
    def __init__(self, fail_page=None, corrupt=None, bad_metadata=False, bad_boot=False):
        self.flash = bytearray((i * 19 + 7) & 255 for i in range(FLASH_SIZE))
        self.original = bytes(self.flash)
        self.metadata = valid_metadata()
        self.profile = fake_profile(self.original)
        self.events = []
        self.fail_page = fail_page
        self.corrupt = corrupt
        self.bad_metadata = bad_metadata
        self.bad_boot = bad_boot
        self.written = 0

    def open(self):
        self.events.append("open")
        return "a1050000a1040000"

    def core(self, mask):
        self.events.append(("core", mask))
        return dict(after=1, cpuid="0x410cc200")

    def read(self, address, length, metadata=False):
        if metadata:
            return bytes([self.metadata[0] ^ 1]) + self.metadata[1:] if self.bad_metadata and self.written == 117 else self.metadata
        if self.bad_boot and address == 0 and length == START:
            return bytes(START)
        result = bytes(self.flash[address:address + length])
        if self.written == 117 and self.corrupt is not None and address <= self.corrupt < address + length:
            offset = self.corrupt - address
            result = result[:offset] + bytes([result[offset] ^ 1]) + result[offset + 1:]
        return result

    def begin_programming(self, loader):
        self.events.append("loader")

    def data(self, sequence, page):
        self.events.append(("data", sequence))
        if sequence == self.fail_page:
            raise TimeoutError("Injected DATA timeout")
        self.written = sequence
        address = START + (sequence - 1) * 512
        self.flash[address:address + 512] = page

    def release(self):
        self.events.append("release")

    def close(self):
        self.events.append("close")

    def wait_application(self):
        self.events.append("application")
        return dict(application_interfaces=2, bootloader_interfaces=0)

    def hold_once(self):
        self.events.append("hold")


class SessionTests(unittest.TestCase):
    def run_fake(self, transport, output):
        def recovery(session):
            transport.hold_once()
        with supported(transport.profile):
            return Session(transport, b"x" * 440, output, notify=lambda _: None, recover=recovery).run(parse_hex(valid_hex()))

    def test_success_full_backup_readback_and_protected_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            output = Path(temporary) / "session"
            result = self.run_fake(transport, output)
            self.assertTrue(result["passed"] and result["verified"] and result["released"])
            self.assertEqual(transport.written, 117)
            self.assertEqual(bytes(transport.flash[:START]), transport.original[:START])
            self.assertEqual(bytes(transport.flash[END:]), transport.original[END:])
            self.assertEqual((output / "before_flash.bin").read_bytes(), transport.original)
            self.assertEqual((output / "after_flash.bin").read_bytes(), bytes(transport.flash))
            self.assertTrue(result["hidden_metadata_unchanged"] and result["outside_application_unchanged"])
            self.assertLess(transport.events.index("release"), transport.events.index("application"))

    def test_failure_at_first_middle_and_last_page_holds_without_release(self):
        for page in [1, 57, 117]:
            with self.subTest(page=page), tempfile.TemporaryDirectory() as temporary:
                transport = FakeTransport(fail_page=page)
                output = Path(temporary) / "session"
                with self.assertRaises(TimeoutError):
                    self.run_fake(transport, output)
                result = json.loads((output / "result.json").read_text())
                self.assertFalse(result["verified"] or result["released"])
                self.assertNotIn("release", transport.events)
                self.assertIn("hold", transport.events)
                self.assertEqual([e for e in transport.events if isinstance(e, tuple) and e[0] == "data"], [("data", i) for i in range(1, page + 1)])

    def test_any_readback_corruption_blocks_release(self):
        for address in [0, START + 30, END + 10, FLASH_SIZE - 1]:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as temporary:
                transport = FakeTransport(corrupt=address)
                with self.assertRaises(ValueError):
                    self.run_fake(transport, Path(temporary) / "session")
                self.assertNotIn("release", transport.events)
                self.assertIn("hold", transport.events)

    def test_metadata_mismatch_blocks_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(bad_metadata=True)
            with self.assertRaises(ValueError):
                self.run_fake(transport, Path(temporary) / "session")
            self.assertNotIn("release", transport.events)

    def test_unknown_boot_rejected_before_programming(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(bad_boot=True)
            with self.assertRaises(ValueError):
                self.run_fake(transport, Path(temporary) / "session")
            self.assertNotIn("loader", transport.events)
            self.assertNotIn("hold", transport.events)
            self.assertEqual(transport.written, 0)

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            with self.assertRaises(FileExistsError):
                self.run_fake(transport, Path(temporary))
            self.assertFalse(transport.events)

    def test_read_only_probe_never_starts_programming(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            with supported(transport.profile):
                result = Session(transport, b"x" * 440, Path(temporary) / "probe", notify=lambda _: None).run()
            self.assertTrue(result["passed"] and result["probe_only"])
            self.assertFalse(result["write_started"])
            self.assertEqual(transport.written, 0)
            self.assertNotIn("loader", transport.events)
            self.assertEqual(bytes(transport.flash), transport.original)

    def test_backup_failure_before_erase(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            with patch("ry72xx_flasher.session.durable_write", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    self.run_fake(transport, Path(temporary) / "session")
            self.assertEqual(transport.written, 0)
            self.assertNotIn("loader", transport.events)

    def test_log_failure_after_ack_stops_additional_pages(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            original_save = Session.save
            def failing_save(session):
                if transport.written:
                    raise OSError("log disk full after first ACK")
                original_save(session)
            with patch.object(Session, "save", failing_save), self.assertRaises(OSError):
                self.run_fake(transport, Path(temporary) / "session")
            self.assertEqual(transport.written, 1)
            self.assertNotIn("release", transport.events)
            self.assertIn("hold", transport.events)

    def test_release_failure_is_not_misreported_as_unverified_programming(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            transport.release = lambda: (_ for _ in ()).throw(OSError("exit transfer failed"))
            output = Path(temporary) / "session"
            with self.assertRaises(OSError):
                self.run_fake(transport, output)
            result = json.loads((output / "result.json").read_text())
            self.assertTrue(result["verified"])
            self.assertFalse(result["released"] or result["passed"])
            self.assertNotIn("hold", transport.events)

    def test_transient_windows_journal_lock_does_not_repeat_programming(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            original_replace = Path.replace
            attempts = []
            def temporarily_locked(path, target):
                attempts.append(1)
                if len(attempts) <= 2:
                    raise PermissionError("simulated transient Windows rename-sharing denial")
                return original_replace(path, target)
            with patch.object(Path, "replace", temporarily_locked):
                result = self.run_fake(transport, Path(temporary) / "session")
            self.assertTrue(result["passed"])
            self.assertEqual([e for e in transport.events if isinstance(e, tuple) and e[0] == "data"], [("data",i) for i in range(1,118)])

    @unittest.skipUnless(os.name == "nt", "Windows file-sharing regression")
    def test_real_windows_reader_lock_is_retried_without_usb(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            output = Path(temporary) / "session"
            output.mkdir()
            session = Session(transport,b"x"*440,output)
            session.save()
            handle = kernel.CreateFileW(str(output/'result.json'),0x80000000,3,None,3,0,None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            thread = threading.Thread(target=lambda: (time.sleep(.08),kernel.CloseHandle(handle)))
            thread.start()
            try:
                started = time.monotonic()
                session.save()
                self.assertGreaterEqual(time.monotonic()-started,.05)
            finally:
                thread.join()
            self.assertFalse(transport.events)

    def test_explicit_recovery_restores_before_image_on_same_open_transport(self):
        class FailsOnce(FakeTransport):
            def data(self, sequence, page):
                if self.fail_page == sequence:
                    self.fail_page = None
                    self.events.append(("injected_failure",sequence))
                    raise TimeoutError("one transient programming failure")
                super().data(sequence,page)
        with tempfile.TemporaryDirectory() as temporary:
            transport = FailsOnce(fail_page=3)
            output = Path(temporary)/'session'
            def recovery(session):
                queue_recovery(output)
                Session.keepalive(session)
            with supported(transport.profile):
                session = Session(transport,b'x'*440,output,notify=lambda _:None,recover=recovery)
                with self.assertRaises(TimeoutError):
                    session.run(parse_hex(valid_hex()))
            self.assertTrue(session.log['recovery_restored'])
            self.assertFalse(session.log['verified'] or session.log['passed'])
            self.assertEqual(bytes(transport.flash),transport.original)
            self.assertEqual(transport.events.count('open'),1)
            self.assertEqual(transport.events.count('release'),1)
            self.assertTrue(json.loads(Path(session.log['recovery_restore_result']).read_text())['passed'])


class FakeHandle:
    def __init__(self, replies=(), short=False):
        self.replies = list(replies)
        self.writes = []
        self.short = short

    def write(self, report):
        self.writes.append(report)
        return len(report) - int(self.short)

    def read(self, *args):
        return self.replies.pop(0) if self.replies else b""

    def close(self):
        pass

    def open_path(self, path):
        self.path = path


class FakeHID:
    def __init__(self, boots, apps=(), handle=None):
        self.boots, self.apps = boots, apps
        self.handle = handle or FakeHandle()

    def enumerate(self, vid, pid):
        return self.boots if vid == 0x352D else self.apps

    def device(self):
        return self.handle


class TransportTests(unittest.TestCase):
    def transport(self, replies=(), short=False):
        transport = HIDTransport(bytes(52), hid_module=FakeHID([]), wait_seconds=0, profile=profiles.V105)
        transport.handle = FakeHandle(replies, short)
        return transport

    def test_no_device_and_multiple_devices(self):
        with self.assertRaises(TimeoutError):
            HIDTransport(bytes(52), hid_module=FakeHID([]), wait_seconds=0).open()
        for boots, apps in [([dict(path=b"a"), dict(path=b"b")], []), ([dict(path=b"a")], [dict(path=b"app")])]:
            with self.assertRaises(ValueError):
                HIDTransport(bytes(52), hid_module=FakeHID(boots, apps), wait_seconds=0).open()

    def test_resume_holder_uses_read_only_probe_not_getv(self):
        reply = bytes.fromhex("0100007306000177fff706f933e0") + bytes(50)
        handle = FakeHandle([reply])
        transport = HIDTransport(bytes(52), hid_module=FakeHID([dict(path=b"original")], handle=handle), wait_seconds=0, resume_holder=True, profile=profiles.V105)
        self.assertIn("held-session", transport.open())
        self.assertEqual(transport.path, b"original")
        self.assertEqual(len(handle.writes), 8)
        self.assertFalse(any(report[1:13] == bytes.fromhex("0000000004000001") + b"getv" for report in handle.writes))

    def test_supported_version_and_zero_report_id(self):
        reply = bytes.fromhex("0000000010000001") + b"version:" + bytes.fromhex("a1050000a1040000") + bytes(40)
        for data in [reply, b"\0" + reply]:
            self.assertEqual(self.transport([data]).get_version(), "a1050000a1040000")

    def test_version_rejection(self):
        for reply in [bytes(64), bytes.fromhex("0000000010000001") + b"version:" + bytes(48)]:
            with self.assertRaises(ValueError):
                self.transport([reply]).get_version()

    def test_short_writes_and_reads(self):
        with self.assertRaises(ValueError):
            self.transport(short=True).get_version()
        for reply in [b"", bytes(63), bytes(66)]:
            with self.assertRaises(ValueError):
                self.transport([reply]).get_version()

    def test_start_fragmentation_and_checksum(self):
        reply = bytes.fromhex("010000730100017704") + bytes(55)
        transport = self.transport([reply])
        stub = bytes(range(220)) * 2
        self.assertEqual(transport.start(stub, 1), b"\x04")
        self.assertEqual(len(transport.handle.writes), 8)
        self.assertTrue(all(len(report) == 65 and report[0] == 0 for report in transport.handle.writes))
        assembled = b"".join(report[1:] for report in transport.handle.writes)
        self.assertEqual(assembled[:496], start_frame(bytes(52), stub))
        self.assertEqual(assembled[496:], bytes(16))

    def test_data_framing_and_range(self):
        reply = bytes.fromhex("027500730100017704") + bytes(55)
        transport = self.transport([reply])
        transport.data(117, b"x" * 512)
        self.assertEqual(len(transport.handle.writes), 9)
        frame = b"".join(report[1:] for report in transport.handle.writes)
        self.assertEqual(frame[:8], bytes.fromhex("0275007300020177"))
        for sequence, data in [(0, bytes(512)), (118, bytes(512)), (1, bytes(511))]:
            with self.assertRaises(ValueError):
                self.transport().data(sequence, data)

    def test_bad_ack_sequence_length_and_status(self):
        for reply in [bytes.fromhex("020200730100017704") + bytes(55), bytes.fromhex("02010073020001770400") + bytes(54), bytes.fromhex("020100730100017702") + bytes(55)]:
            with self.assertRaises(ValueError):
                self.transport([reply]).data(1, bytes(512))

    def test_core_state_guard(self):
        for values in [(0,1,0x410CC200,0,4), (1,1,0x410CC200,0,4)]:
            reply = bytes.fromhex("0100007314000177") + struct.pack("<5I", *values) + bytes(36)
            self.assertEqual(self.transport([reply]).core(True)["after"], 1)
        for values in [(0,0,0x410CC200,0,4), (1,1,0,0,4), (1,1,0x410CC200,1,4), (1,1,0x410CC200,0,7)]:
            reply = bytes.fromhex("0100007314000177") + struct.pack("<5I", *values) + bytes(36)
            with self.assertRaises(ValueError):
                self.transport([reply]).core(True)

    def test_verified_release_accepts_native_exit_nack_or_disconnect(self):
        start_ack = bytes.fromhex("010000730100017704") + bytes(55)
        for final_reply in [bytes.fromhex("000000730100017705") + bytes(55), b""]:
            transport = self.transport([start_ack, final_reply])
            transport.release()
            self.assertEqual(transport.handle.writes[-1][1:13], bytes.fromhex("0000000004000001") + b"getv")
        transport = self.transport([start_ack])
        original_read = transport.handle.read
        calls = []
        def disconnecting_read(*args):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("device detached after verified exit")
            return original_read(*args)
        transport.handle.read = disconnecting_read
        transport.release()


class StubAndCLITests(unittest.TestCase):
    def test_authored_holder_and_release_match_validated_instructions(self):
        self.assertEqual(digest(hold_stub()), "1c04bf5c4c9ae72885acfd8a62dc948219bb36c4cbc7a12ea3106367a0ebf871")
        self.assertEqual(digest(release_stub()), "57332cb094949feeba32c44fa829bb57069eaef61d92bceab161601737af4323")
        self.assertEqual(digest(core_stub(True)), "59c5de29b7d3673cd3ccfc6f20cc141f03205cd3f8349d7c1caf6c9507d2bf6c")
        self.assertEqual(digest(core_stub(False)), "b6b4988d8ba802c0b0b6ca701045c0aca7221e38daa0ea2af4fbe7bc72b730fd")

    def test_read_probe_boundaries(self):
        for address, length, metadata in [(-1,1,False), (0x20000,1,False), (0,0,False), (0,57,False), (0x100005FC,4,True), (0x100007FC,8,True), (0x10000600,3,True)]:
            with self.assertRaises(ValueError):
                read_stub(address, length, metadata)

    def test_check_image_has_no_hid_or_profile_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "app.hex"
            path.write_text(valid_hex())
            with patch("ry72xx_flasher.cli.load_profile", side_effect=AssertionError("unexpected profile access")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--file", str(path), "--check-image"]), 0)

    def test_invalid_image_is_rejected_before_profile_or_hardware(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.hex"
            path.write_text(":bad")
            with patch("ry72xx_flasher.cli.load_profile", side_effect=AssertionError("unexpected profile access")), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--file", str(path)]), 1)

    def test_restore_accepts_only_integrity_checked_application_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            before = bytes((i * 19 + 7) & 255 for i in range(FLASH_SIZE))
            metadata = bytes(512)
            manifest = dict(format=1, boot_verified=True, before_flash_sha256=digest(before), before_metadata_sha256=digest(metadata))
            (folder / "before_flash.bin").write_bytes(before)
            (folder / "before_metadata.bin").write_bytes(metadata)
            (folder / "result.json").write_text(json.dumps(manifest))
            with supported(fake_profile(before)):
                restored = restored_image(folder)
                self.assertEqual(min(restored.data), START)
                self.assertEqual(max(restored.data), END - 1)
                self.assertEqual(bytes(restored.data[i] for i in range(START, END)), before[START:END])
                (folder / "before_metadata.bin").write_bytes(bytes([1]) + metadata[1:])
                with self.assertRaises(ValueError):
                    restored_image(folder)
                (folder / "before_metadata.bin").write_bytes(metadata)
                (folder / "before_flash.bin").write_bytes(before[:-1] + bytes([before[-1] ^ 1]))
                with self.assertRaises(ValueError):
                    restored_image(folder)


class LoaderTests(unittest.TestCase):
    def test_unknown_vendor_bytes_are_not_patched(self):
        for data in [b"", bytes(439), bytes(440), bytes(441)]:
            with self.assertRaises(ValueError):
                patch_vendor(data)

    def test_profile_format_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            for value in [dict(format=2), dict(format=1, header=bytes(52).hex(), loader=bytes(440).hex())]:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_profile(path)

    def test_capture_truncation_and_link_type(self):
        header = bytes.fromhex("d4c3b2a1") + bytes(16) + (249).to_bytes(4, "little")
        for data in [b"", bytes(24), header, header + bytes(8), header + struct.pack("<4I", 0,0,100,100)]:
            with self.assertRaises(ValueError):
                extract_capture(data)

    def test_capture_cannot_supply_arbitrary_loader(self):
        header = bytes.fromhex("d4c3b2a1") + bytes(16) + (249).to_bytes(4, "little")
        frame = bytearray(bytes.fromhex("01000073e8010177") + bytes(488))
        struct.pack_into("<I", frame, 48, 440)
        packets = bytearray()
        for offset in range(0,496,64):
            usb = bytearray(27)
            struct.pack_into("<H", usb, 0, 27)
            usb[21:23] = bytes([4,1])
            struct.pack_into("<I", usb, 23, 64)
            packet = usb + frame[offset:offset+64].ljust(64,b"\0")
            packets.extend(struct.pack("<4I",0,0,len(packet),len(packet)) + packet)
        with self.assertRaises(ValueError):
            extract_capture(header + packets)


if __name__ == "__main__":
    unittest.main()


V107_DUMP = Path(__file__).resolve().parents[3] / "flash_controller_research" / "v107_dump"


class BootRevisionTests(unittest.TestCase):
    def test_getv_selects_profile_and_rejects_others(self):
        for version, profile in [("a1050000a1040000", profiles.V105), ("a1070000a1040000", profiles.V107)]:
            reply = bytes.fromhex("0000000010000001") + b"version:" + bytes.fromhex(version) + bytes(40)
            transport = HIDTransport(bytes(52), hid_module=FakeHID([]), wait_seconds=0)
            transport.handle = FakeHandle([reply])
            self.assertEqual(transport.get_version(), version)
            self.assertIs(transport.profile, profile)
        reply = bytes.fromhex("0000000010000001") + b"version:" + bytes.fromhex("a1070000a1040000") + bytes(40)
        transport = HIDTransport(bytes(52), hid_module=FakeHID([]), wait_seconds=0, profile=profiles.V105)
        transport.handle = FakeHandle([reply])
        with self.assertRaises(ValueError):
            transport.get_version()

    def test_loader_selection_per_revision(self):
        from ry72xx_flasher.cli import select_loader
        header, loader = select_loader("authored", None)
        self.assertEqual(len(header), 52)
        self.assertNotEqual(loader(profiles.V105), loader(profiles.V107))
        self.assertEqual(digest(loader(profiles.V107)), "66c95355137e042e808d5a0e8e325894365b3d869b54fd372b0b10f1b67cb58a")
        with patch("ry72xx_flasher.cli.load_profile", return_value=(bytes(52), b"c" * 440)):
            header, loader = select_loader("profile", Path("unused"))
        self.assertEqual(loader(profiles.V105), b"c" * 440)
        with self.assertRaises(ValueError):
            loader(profiles.V107)

    @unittest.skipUnless((V107_DUMP / "flash_pass1.bin").exists(), "v1.0.7 dump not present")
    def test_checksum_word_on_real_v107_dump(self):
        from ry72xx_flasher.image import with_boot_checksum, CHECKSUM_WORD
        flash = (V107_DUMP / "flash_pass1.bin").read_bytes()
        metadata = (V107_DUMP / "info_pass1.bin").read_bytes()[0x600:0x800]
        result, old, new = with_boot_checksum(flash, metadata)
        self.assertEqual((result, old), (flash, new), "the stock application already passes: no change")
        image = parse_hex(valid_hex())
        corrected, old, new = with_boot_checksum(image.overlay(flash), metadata)
        self.assertEqual(xor_words(corrected[START:START + 0xE908]), 0x25A4F084)
        changed = [i for i in range(FLASH_SIZE) if corrected[i] != image.overlay(flash)[i]]
        self.assertTrue(all(CHECKSUM_WORD <= i < CHECKSUM_WORD + 4 for i in changed))
        broken = bytearray(metadata)
        broken[0x24] ^= 4
        with self.assertRaises(ValueError):
            with_boot_checksum(flash, bytes(broken))

    def test_session_on_v107_profile_writes_checksummed_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport()
            transport.profile = dataclasses.replace(profiles.V107, boot_sha=digest(transport.original[:START]))
            seen = []
            with supported(transport.profile):
                result = Session(transport, lambda profile: seen.append(profile) or b"y" * 440,
                                 Path(temporary) / "s", notify=lambda _: None).run(parse_hex(valid_hex()))
            self.assertEqual(seen, [transport.profile])
            self.assertEqual(result["boot_profile"], "v1.0.7")
            self.assertEqual(xor_words(bytes(transport.flash[START:START + 0xE908])), 0x25A4F084)
            self.assertIn("boot_checksum_word", result)
