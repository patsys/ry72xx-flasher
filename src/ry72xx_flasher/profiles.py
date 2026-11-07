# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Supported bootloader revisions and the native identities the RAM stubs rely on.

A board is accepted only when GETV and the SHA-256 of its whole boot region
(0x0000..0x1FFF) both name the same profile. Every value below was read from
the bootloader code of a real unit; the v1.0.7 values were additionally
measured live with register-only timing probes before any stub used them.

  incoming_lr     return address of the native call into the START init entry
  saved_offset    stack offset (from the init entry) of the START handler's saved
                  return into the packet dispatcher; saved = that return
  resume          dispatcher point after a reply (memset of the context, loop)
  outer_offset    stack offset (from the init entry) of the dispatcher's saved
                  return into the USB main path
  hold_return     USB bootstrap re-entry: the session stays in the bootloader
  normal_return   the original dispatcher return (normal_return - hold_return
                  is 0x36 in both revisions)
  holder_proof    native code bytes (bl 0x22c; b exit) returned by the holder
"""
from dataclasses import dataclass

from .image import require


@dataclass(frozen=True)
class BootProfile:
    name: str
    getv: str
    boot_sha: str
    incoming_lr: int
    saved_offset: int
    saved: int
    resume: int
    outer_offset: int
    hold_return: int
    normal_return: int
    holder_proof: tuple
    loader_resource: str


V105 = BootProfile(
    name="v1.0.5", getv="a1050000a1040000",
    boot_sha="e46c6d9300a13f4d2eea7c16584d24ea6e4e1b83815e5f84f389d4aeb0915f62",
    incoming_lr=0x1021, saved_offset=52, saved=0xCC3, resume=0xE70,
    outer_offset=116, hold_return=0x849, normal_return=0x87F,
    holder_proof=(0x101C, "fff706f933e0"), loader_resource="ry72xx_loader.bin")

# START handler frame +8 (add sp,#0x2c at 0xf88); dispatcher identical except +0x24.
V107 = BootProfile(
    name="v1.0.7", getv="a1070000a1040000",
    boot_sha="eae819e411e7a1d336f75567e0aa7b2e432311694ae73ecdce4c417d548f3c01",
    incoming_lr=0x1049, saved_offset=60, saved=0xCE7, resume=0xE94,
    outer_offset=124, hold_return=0x86B, normal_return=0x8A1,
    holder_proof=(0x1044, "fff7f2f843e0"), loader_resource="ry72xx_loader_v107.bin")

PROFILES = (V105, V107)


def by_getv(version):
    matches = [profile for profile in PROFILES if profile.getv == version]
    require(len(matches) == 1, f"Unsupported bootloader version {version}")
    return matches[0]


def by_boot_sha(sha):
    matches = [profile for profile in PROFILES if profile.boot_sha == sha]
    require(len(matches) == 1, "Unsupported bootloader bytes")
    return matches[0]
