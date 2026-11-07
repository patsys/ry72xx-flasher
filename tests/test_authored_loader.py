# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unicorn checks of the authored RAM loader's admission rules and controller use.

The controller is emulated as RAM with an immediately clearing busy bit; these
tests do not prove physical programming. MeasuredController additionally models the
behaviour measured on a v1.0.7 unit (flash_controller_research, 2026-11-07): the first
STATUS read after the start bit shows 0x1, busy (0x3) follows, a start while busy is
ignored and the running operation completes with the ADDRESS/DATA present at its end.
Requires the `unicorn` package.
"""
from pathlib import Path
import struct
import unittest
import unittest.mock

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PRIMASK
except ImportError:  # pragma: no cover
    Uc = None

LOADER = Path(__file__).resolve().parents[1] / "src" / "ry72xx_flasher" / "ry72xx_loader.bin"
CTX, PAYLOAD, CTRL = 0x20000324, 0x2000032C, 0x40013000
STACK, RETURN = 0x2000F000, 0x2000E000
ERASE, PROGRAM, META_ERASE, META_PROGRAM, INIT = 0x24, 0x6C, 0xDA, 0xFC, 0x13A


@unittest.skipIf(Uc is None, "unicorn not installed")
class AuthoredLoader(unittest.TestCase):
    loader = LOADER
    hold_return = 0x849

    def call(self, entry, r0=0, r1=PAYLOAD, r4=CTX, length=512, primask=1, flash_fill=0x00, measured=False):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        for base, size in [(0, 0x20000), (0x20000000, 0x10000), (0x40013000, 0x1000)]:
            u.mem_map(base, size)
        u.mem_write(0, bytes([flash_fill]) * 0x20000)
        u.mem_write(0x20000000, self.loader.read_bytes())
        u.mem_write(0x20000214, struct.pack("<I", 1))
        u.mem_write(CTX + 4, struct.pack("<H", length))
        u.mem_write(PAYLOAD, b"".join(struct.pack("<I", 0x11110000 + i) for i in range(128)))
        u.mem_write(RETURN, b"\xfe\xe7")  # b . : return trap
        u.mem_write(STACK, b"\xaa" * 64)
        writes = []
        state = dict(pending=None, delay=0, busy=0)

        def complete(uc):
            word = struct.unpack("<I", uc.mem_read(CTRL + 4, 4))[0]
            if state["pending"] == 2:
                uc.mem_write((word >> 7) * 512, b"\xff" * 512)
            elif state["pending"] == 1:
                uc.mem_write(word * 4, bytes(uc.mem_read(CTRL + 8, 4)))
            state["pending"] = None

        def on_status_read(uc, access, address, size, value, data):
            if state["delay"]:
                state["delay"] -= 1
                uc.mem_write(CTRL + 0x10, struct.pack("<I", 1))
            elif state["busy"]:
                state["busy"] -= 1
                uc.mem_write(CTRL + 0x10, struct.pack("<I", 3))
            else:
                if state["pending"] is not None:
                    complete(uc)
                uc.mem_write(CTRL + 0x10, struct.pack("<I", 0))

        def on_write_measured(uc, access, address, size, value, data):
            if CTRL <= address < CTRL + 0x1000:
                writes.append((address - CTRL, value))
                if address == CTRL + 0x10 and value & 1 and state["pending"] is None:
                    state.update(pending=struct.unpack("<I", uc.mem_read(CTRL, 4))[0], delay=1, busy=240)

        def on_write(uc, access, address, size, value, data):
            if CTRL <= address < CTRL + 0x1000:
                writes.append((address - CTRL, value))
                if address == CTRL + 0x00:  # emulate the command on CPU flash
                    word = struct.unpack("<I", uc.mem_read(CTRL + 4, 4))[0]
                    if value == 2:
                        uc.mem_write((word >> 7) * 512, b"\xff" * 512)
                    elif value == 1:
                        uc.mem_write(word * 4, bytes(uc.mem_read(CTRL + 8, 4)))

        if measured:
            u.hook_add(UC_HOOK_MEM_WRITE, on_write_measured)
            u.hook_add(UC_HOOK_MEM_READ, on_status_read, begin=CTRL + 0x10, end=CTRL + 0x13)
        else:
            u.hook_add(UC_HOOK_MEM_WRITE, on_write)
            # Commands complete instantly here; the start bit reads back clear (hardware ends at 0x0).
            u.hook_add(UC_HOOK_MEM_READ, lambda uc, *a: uc.mem_write(CTRL + 0x10, struct.pack("<I", struct.unpack("<I", uc.mem_read(CTRL + 0x10, 4))[0] & ~1)),
                       begin=CTRL + 0x10, end=CTRL + 0x13)
        for register, value in [(UC_ARM_REG_R0, r0), (UC_ARM_REG_R1, r1), (UC_ARM_REG_R4, r4),
                                (UC_ARM_REG_SP, STACK), (UC_ARM_REG_LR, RETURN | 1), (UC_ARM_REG_PRIMASK, primask)]:
            u.reg_write(register, value)
        u.emu_start(0x20000000 + entry | 1, RETURN, count=20_000_000)
        self.assertEqual(u.reg_read(UC_ARM_REG_SP), STACK, "stack must balance")
        self.assertEqual(u.reg_read(UC_ARM_REG_R4), r4, "r4 must be preserved")
        return u, u.reg_read(UC_ARM_REG_R0), writes

    def stack_word(self, u, offset):
        return struct.unpack("<I", u.mem_read(STACK + offset, 4))[0]

    def test_image_size(self):
        self.assertEqual(len(self.loader.read_bytes()), 440)

    def test_erase_admitted_page(self):
        for page in (16, 80, 132):
            u, status, writes = self.call(ERASE, page)
            self.assertEqual(status, 0)
            self.assertIn((0x04, page << 7), writes)
            self.assertIn((0x00, 2), writes)
            self.assertEqual(bytes(u.mem_read(page * 512, 512)), b"\xff" * 512)
            self.assertEqual(bytes(u.mem_read(page * 512 - 4, 4)), b"\0" * 4, "neighbouring page untouched")
            self.assertEqual(self.stack_word(u, 60), self.hold_return, "outer saved return held at the USB bootstrap")
            gate = [v for a, v in writes if a == 0xD0 + (page >> 5) * 4]
            self.assertEqual(gate[0], 1 << (page & 31))
            self.assertEqual(gate[-1] & (1 << (page & 31)), 0, "page gate closed again")
            self.assertEqual(u.reg_read(UC_ARM_REG_PRIMASK), 1)

    def test_program_admitted_page(self):
        u, status, writes = self.call(PROGRAM, 40, flash_fill=0xFF)
        self.assertEqual(status, 0)
        expected = b"".join(struct.pack("<I", 0x11110000 + i) for i in range(128))
        self.assertEqual(bytes(u.mem_read(40 * 512, 512)), expected)
        self.assertEqual(sum(1 for a, v in writes if a == 0x00 and v == 1), 128)
        self.assertEqual(self.stack_word(u, 8), 0xAAAAAAAA, "only the last page ends the DATA state")

    def test_program_page_on_measured_controller(self):
        # Regression for the hardware failure "every other program word left erased".
        u, status, writes = self.call(PROGRAM, 40, flash_fill=0xFF, measured=True)
        self.assertEqual(status, 0)
        expected = b"".join(struct.pack("<I", 0x11110000 + i) for i in range(128))
        self.assertEqual(bytes(u.mem_read(40 * 512, 512)), expected)

    def test_erase_on_measured_controller(self):
        u, status, _ = self.call(ERASE, 80, measured=True)
        self.assertEqual(status, 0)
        self.assertEqual(bytes(u.mem_read(80 * 512, 512)), b"\xff" * 512)

    def test_last_page_clears_data_active(self):
        u, status, _ = self.call(PROGRAM, 132, flash_fill=0xFF)
        self.assertEqual(status, 0)
        self.assertEqual(self.stack_word(u, 8), 0)

    def test_rejections_touch_no_controller(self):
        cases = [
            (ERASE, dict(r0=15)), (ERASE, dict(r0=133)), (ERASE, dict(r0=0xFA)), (ERASE, dict(r0=0)),
            (ERASE, dict(r0=40, r4=CTX + 4)), (ERASE, dict(r0=40, length=511)), (ERASE, dict(r0=40, length=513)),
            (PROGRAM, dict(r0=15)), (PROGRAM, dict(r0=133)), (PROGRAM, dict(r0=0xFF)),
            (PROGRAM, dict(r0=40, r1=PAYLOAD + 4)), (PROGRAM, dict(r0=40, r4=0x20000000)),
            (PROGRAM, dict(r0=40, length=1024)),
            (META_ERASE, dict(r0=0x80)), (META_PROGRAM, dict(r0=0x10000600)),
        ]
        for entry, args in cases:
            with self.subTest(entry=hex(entry), **args):
                u, status, writes = self.call(entry, **args)
                self.assertEqual(status, 2)
                self.assertEqual(writes, [])
                self.assertEqual(self.stack_word(u, 60), 0xAAAAAAAA)
                self.assertEqual(self.stack_word(u, 8), 0xAAAAAAAA)

    def test_init_timing_matches_controller_formula(self):
        u, status, writes = self.call(INIT, 48_000_000)
        self.assertEqual(status, 0)
        registers = dict(writes)
        mhz = 48
        self.assertEqual(registers, {0x10: 0, 0x14: 0x207, 0x18: 0x0B, 0x20: 0x40, 0x24: 0x137,
                                     0x28: 0x144 * mhz // 0x30, 0x30: 0x104, 0x38: 0x114,
                                     0x3C: 0x34BC0 * mhz // 0x30, 0x40: 0x15F900 * mhz // 0x30, 0x4C: 6})
        self.assertEqual(bytes(u.mem_read(0x20000214, 4)), b"\0" * 4, "plaintext DATA flag cleared")

    def test_init_rejects_absurd_clock(self):
        _, status, writes = self.call(INIT, 0x9000_0000)
        self.assertEqual(status, 2)
        self.assertEqual(writes, [])

    def test_timeout_reports_three(self):
        # A controller whose busy bit never clears must time out, not hang.
        loader = LOADER.read_bytes()
        emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        for base, size in [(0, 0x20000), (0x20000000, 0x10000), (0x40013000, 0x1000)]:
            emu.mem_map(base, size)
        emu.mem_write(0x20000000, loader)
        emu.mem_write(CTRL + 0x10, struct.pack("<I", 2))
        emu.mem_write(RETURN, b"\xfe\xe7")
        emu.reg_write(UC_ARM_REG_SP, STACK)
        emu.reg_write(UC_ARM_REG_LR, RETURN | 1)
        emu.emu_start(0x20000000 | 1, RETURN, count=50_000_000)
        self.assertEqual(emu.reg_read(UC_ARM_REG_R0), 3)


class AuthoredLoaderV107(AuthoredLoader):
    """Same checks on the v1.0.7 image; it differs only in the USB bootstrap re-entry."""
    loader = LOADER.with_name("ry72xx_loader_v107.bin")
    hold_return = 0x86B


class AuthoredHeader(unittest.TestCase):
    def test_header_selects_plaintext_mode_and_satisfies_native_checks(self):
        from ry72xx_flasher.loader import authored, AUTHORED_SHA
        from ry72xx_flasher.image import digest
        header, loader = authored()
        self.assertEqual(digest(loader), AUTHORED_SHA["ry72xx_loader.bin"])
        self.assertEqual(len(header), 52)
        self.assertEqual(header[:8], bytes.fromhex("01000073e8010177"))  # START, payload 0x1e8
        self.assertEqual(header[0x20:0x30], bytes(16), "zero encrypted field -> no decryption")
        length, revision = struct.unpack_from("<II", header, 8)
        w0, w1, w2, w3 = struct.unpack_from("<IIII", header, 0x10)
        self.assertEqual(struct.unpack_from("<H", header, 2)[0] * 4, length)
        self.assertEqual(w0, length)
        self.assertEqual(w2 & 0xFFFF, revision)
        self.assertEqual(struct.unpack_from("<I", header, 48)[0], 440)

    def test_packaged_loader_hash_is_enforced(self):
        from ry72xx_flasher import loader as module
        with unittest.mock.patch.object(module, "AUTHORED_SHA", {"ry72xx_loader.bin": "0" * 64}):
            with self.assertRaises(ValueError):
                module.authored()


if __name__ == "__main__":
    unittest.main()
