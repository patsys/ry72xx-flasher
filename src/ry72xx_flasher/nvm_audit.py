# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline gate for a read-only full-flash backup before NVM experiments."""
import json
from pathlib import Path

from .image import FLASH_SIZE, digest, require
from .profiles import by_boot_sha

PAGE_SIZE = 512
STOCK_CONFIG_FIRST_PAGE = 0xD5
STOCK_CONFIG_LAST_PAGE = 0xDF
QMK_CANDIDATE_FIRST_PAGE = 0xF8
QMK_CANDIDATE_LAST_PAGE = 0xFF


def audit_nvm_backup(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    flash = (folder / "before_flash.bin").read_bytes()
    metadata = (folder / "before_metadata.bin").read_bytes()
    require(manifest.get("format") == 1 and manifest.get("boot_verified") is True,
            "Backup manifest is not verified")
    require(manifest.get("probe_only") is True and manifest.get("write_started") is False,
            "Expected a read-only probe backup")
    require(manifest.get("passed") is True and manifest.get("released") is True,
            "Read-only probe did not finish and return to the application")
    require(len(flash) == FLASH_SIZE and digest(flash) == manifest.get("before_flash_sha256"),
            "Full-flash backup size or digest mismatch")
    by_boot_sha(digest(flash[:0x2000]))
    require(len(metadata) == 512 and digest(metadata) == manifest.get("before_metadata_sha256"),
            "Hidden metadata backup size or digest mismatch")

    candidate_start = QMK_CANDIDATE_FIRST_PAGE * PAGE_SIZE
    candidate_end = (QMK_CANDIDATE_LAST_PAGE + 1) * PAGE_SIZE
    candidate = flash[candidate_start:candidate_end]
    stock_start = STOCK_CONFIG_FIRST_PAGE * PAGE_SIZE
    stock_end = (STOCK_CONFIG_LAST_PAGE + 1) * PAGE_SIZE
    stock = flash[stock_start:stock_end]
    permission_words = [int.from_bytes(metadata[0x50 + group * 4:0x54 + group * 4], "little") for group in range(8)]
    candidate_permissions = {
        page: bool(permission_words[page >> 5] & (1 << (page & 31)))
        for page in range(QMK_CANDIDATE_FIRST_PAGE, QMK_CANDIDATE_LAST_PAGE + 1)
    }
    return {
        "read_only_backup_verified": True,
        "candidate_pages": f"0x{QMK_CANDIDATE_FIRST_PAGE:02X}-0x{QMK_CANDIDATE_LAST_PAGE:02X}",
        "candidate_address_range": f"0x{candidate_start:05X}..0x{candidate_end - 1:05X}",
        "candidate_bytes": len(candidate),
        "candidate_sha256": digest(candidate),
        "candidate_erased": all(byte == 0xFF for byte in candidate),
        "candidate_permission_bits_enabled": all(candidate_permissions.values()),
        "candidate_permission_pages_disabled": [f"0x{page:02X}" for page, enabled in candidate_permissions.items() if not enabled],
        "preserved_vendor_pages": "0xE0-0xF7",
        "preserved_vendor_region_sha256": digest(flash[0xE0 * PAGE_SIZE:0xF8 * PAGE_SIZE]),
        "stock_settings_pages": f"0x{STOCK_CONFIG_FIRST_PAGE:02X}-0x{STOCK_CONFIG_LAST_PAGE:02X}",
        "stock_settings_sha256": digest(stock),
        "stock_settings_erased": all(byte == 0xFF for byte in stock),
        "flash_sha256": digest(flash),
        "metadata_sha256": digest(metadata),
        "write_permitted": False,
        "note": "A blank readback is necessary but not sufficient; controller permissions and backend tests remain required.",
    }
