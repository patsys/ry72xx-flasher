# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unicorn checks of every START stub against each bootloader revision's native frame.

The frame is the measured one: LR into the init entry, the START handler's saved
return at saved_offset and the dispatcher's saved return at outer_offset. A stub
must act only on its own revision's frame and stay inert on the other one.
"""
import struct
import unittest

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
except ImportError:  # pragma: no cover
    Uc = None

from ry72xx_flasher import profiles, stubs
from ry72xx_flasher.image import digest

CTX, STACK, CALLBACK = 0x20000324, 0x2000F000, 0x2000E000
TAIL = 0x20000141


def machine(image, flash):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    u.mem_map(0, 0x20000)
    u.mem_map(0x20000000, 0x10000)
    u.mem_map(0xE0000000, 0x100000)
    u.mem_write(0, flash)
    u.mem_write(0x20000000, image)
    u.mem_write(CALLBACK, b"\x70\x47")
    u.mem_write(CTX + 0x214, struct.pack("<I", CALLBACK | 1))
    u.mem_write(0xE000ED00, struct.pack("<I", 0x410CC200))
    return u


def init(u, profile, outer):
    """Native call of the START init entry with `profile`'s frame; returns writes and stack words."""
    u.mem_write(STACK, bytes(128))
    u.mem_write(STACK + profile.saved_offset, struct.pack("<I", profile.saved))
    u.mem_write(STACK + profile.outer_offset, struct.pack("<I", outer))
    u.mem_write(profile.incoming_lr & ~1, b"\xfe\xe7")
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_LR, profile.incoming_lr)
    writes = []
    hook = u.hook_add(UC_HOOK_MEM_WRITE, lambda uc, a, address, size, value, d: writes.append(address))
    u.emu_start(0x2000013A | 1, profile.incoming_lr & ~1, count=2000)
    u.hook_del(hook)
    words = lambda offset: struct.unpack("<I", u.mem_read(STACK + offset, 4))[0]
    return writes, words, u.reg_read(UC_ARM_REG_R0)


def tail(u, profile):
    u.mem_write(profile.resume, b"\xfe\xe7")
    u.reg_write(UC_ARM_REG_R4, CTX)
    u.reg_write(UC_ARM_REG_SP, STACK + 0x200)
    u.emu_start(TAIL, profile.resume, count=100000)
    assert u.reg_read(UC_ARM_REG_PC) == profile.resume
    length = struct.unpack("<H", u.mem_read(CTX + 4, 2))[0]
    return bytes(u.mem_read(CTX + 8, length))


@unittest.skipIf(Uc is None, "unicorn not installed")
class Profiles(unittest.TestCase):
    flash = bytes(range(256)) * 512

    def other(self, profile):
        return profiles.V107 if profile is profiles.V105 else profiles.V105

    def test_lookup(self):
        self.assertIs(profiles.by_getv("a1070000a1040000"), profiles.V107)
        self.assertIs(profiles.by_boot_sha(profiles.V105.boot_sha), profiles.V105)
        with self.assertRaises(ValueError):
            profiles.by_getv("a1060000a1040000")

    def test_read_stub_per_revision(self):
        for profile in profiles.PROFILES:
            with self.subTest(profile=profile.name):
                u = machine(stubs.read_stub(0x1040, 12, profile=profile), self.flash)
                writes, word, _ = init(u, profile, profile.normal_return)
                self.assertEqual(writes, [STACK + profile.saved_offset])
                self.assertEqual(word(profile.saved_offset), TAIL)
                self.assertEqual(tail(u, profile), bytes(u.mem_read(0x1040, 12)))
                u = machine(stubs.read_stub(0x1040, 12, profile=self.other(profile)), self.flash)
                writes, word, _ = init(u, profile, profile.normal_return)
                self.assertEqual(writes, [], "a stub for another revision must stay inert")

    def test_core_stub_per_revision(self):
        for profile in profiles.PROFILES:
            with self.subTest(profile=profile.name):
                u = machine(stubs.core_stub(True, profile=profile), self.flash)
                init(u, profile, profile.normal_return)
                before, after, cpuid, _, _ = struct.unpack("<5I", tail(u, profile))
                self.assertEqual(cpuid, 0x410CC200)

    def test_hold_and_release_per_revision(self):
        for profile in profiles.PROFILES:
            with self.subTest(profile=profile.name):
                hold = stubs.build_hold(profile)
                for outer in (profile.normal_return, profile.hold_return):
                    u = machine(hold, self.flash)
                    _, word, _ = init(u, profile, outer)
                    self.assertEqual(word(profile.outer_offset), profile.hold_return)
                    self.assertEqual(word(profile.saved_offset), TAIL)
                    address, proof = profile.holder_proof
                    self.assertEqual(tail(u, profile), bytes(u.mem_read(address, 6)))
                u = machine(hold, self.flash)
                writes, _, _ = init(u, profile, 0x1234)
                self.assertEqual(writes, [], "unknown dispatcher return: holder inert")
                u = machine(hold, self.flash)
                writes, _, _ = init(u, self.other(profile), self.other(profile).normal_return)
                self.assertEqual(writes, [], "other revision: holder inert")

                release = stubs.build_release(profile)
                for outer in (profile.normal_return, profile.hold_return):
                    u = machine(release, self.flash)
                    _, word, status = init(u, profile, outer)
                    self.assertEqual((word(profile.outer_offset), status), (profile.normal_return, 0))
                    self.assertEqual(word(profile.saved_offset), profile.saved, "release does not redirect")
                u = machine(release, self.flash)
                _, _, status = init(u, profile, 0x1234)
                self.assertEqual(status, 2)
                u = machine(release, self.flash)
                writes, _, status = init(u, self.other(profile), self.other(profile).normal_return)
                self.assertEqual((writes, status), ([], 2))

    def test_pinned_images(self):
        for profile in profiles.PROFILES:
            with self.subTest(profile=profile.name):
                self.assertEqual(stubs.hold_stub(profile), stubs.build_hold(profile))
                self.assertEqual(stubs.release_stub(profile), stubs.build_release(profile))


if __name__ == "__main__":
    unittest.main(verbosity=2)
