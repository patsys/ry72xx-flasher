# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Supported bootloader revisions and the native identities the RAM stubs rely on.

A bootloader is accepted only when the first GETV word and the SHA-256 of its
whole boot region (0x0000..0x1FFF) both name the same profile. The second GETV
word is the board ID from the info-flash metadata (+0x2C); it selects a Board. Every value below was read from
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


V105 = BootProfile(
    name="v1.0.5", getv="a1050000",
    boot_sha="e46c6d9300a13f4d2eea7c16584d24ea6e4e1b83815e5f84f389d4aeb0915f62",
    incoming_lr=0x1021, saved_offset=52, saved=0xCC3, resume=0xE70,
    outer_offset=116, hold_return=0x849, normal_return=0x87F,
    holder_proof=(0x101C, "fff706f933e0"))

# START handler frame +8 (add sp,#0x2c at 0xf88); dispatcher identical except +0x24.
V107 = BootProfile(
    name="v1.0.7", getv="a1070000",
    boot_sha="eae819e411e7a1d336f75567e0aa7b2e432311694ae73ecdce4c417d548f3c01",
    incoming_lr=0x1049, saved_offset=60, saved=0xCE7, resume=0xE94,
    outer_offset=124, hold_return=0x86B, normal_return=0x8A1,
    holder_proof=(0x1044, "fff7f2f843e0"))

PROFILES = (V105, V107)


@dataclass(frozen=True)
class Board:
    """A keyboard on this bootloader, named by the board ID in the info-flash metadata.

    board_id        metadata word +0x2C, reported as GETV bytes 16..17
    app_usb         VID/PID of the stock application (--enter-stock, enumeration)
    stock_serial    serial number of the stock application's vendor collection
    app_end         exclusive end of the writable application pages; equals the
                    metadata application range (start +0x20, length +0x24)
                    rounded up to whole pages
    settings_pages  first and last page of the stock settings in the backup
    """
    name: str
    board_id: int
    app_usb: tuple
    stock_serial: str
    app_end: int
    settings_pages: tuple

    @property
    def last_page(self):
        return self.app_end // 512 - 1


NOVA_N60 = Board(name="Ranked Nova N60", board_id=0xA104, app_usb=(0x3532, 0xA0A3),
                 stock_serial="rankednova", app_end=0x10A00, settings_pages=(0xD5, 0xDF))
# Stock application 0x2000..0x12EBC (metadata length 0x10EBC), settings 0x1A000..0x1D9FF.
G65 = Board(name="Ranked G65", board_id=0xA102, app_usb=(0x3532, 0xA0C2),
            stock_serial="RYMicro", app_end=0x13000, settings_pages=(0xD0, 0xEC))

BOARDS = (NOVA_N60, G65)


def by_getv(version):
    require(len(version) == 16, f"Unsupported bootloader version {version}")
    matches = [profile for profile in PROFILES if profile.getv == version[:8]]
    require(len(matches) == 1, f"Unsupported bootloader version {version}")
    return matches[0]


def board_by_getv(version):
    require(len(version) == 16, f"Unsupported bootloader version {version}")
    return board_by_id(int(version[8:12], 16))


def board_by_id(board_id):
    matches = [board for board in BOARDS if board.board_id == board_id]
    require(len(matches) == 1, f"Unsupported board ID {board_id:#06x}")
    return matches[0]


def board_by_metadata(metadata):
    require(len(metadata) == 512, "Full metadata block required")
    return board_by_id(int.from_bytes(metadata[0x2C:0x30], "little"))


def by_boot_sha(sha):
    matches = [profile for profile in PROFILES if profile.boot_sha == sha]
    require(len(matches) == 1, "Unsupported bootloader bytes")
    return matches[0]
