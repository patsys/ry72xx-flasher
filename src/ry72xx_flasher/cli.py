# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Console entry point used by QMK's normal flash target."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from . import __version__
from .image import Image, START, FLASH_SIZE, digest, parse_hex, require
from .loader import authored, load_profile, setup
from .profiles import NOVA_N60, V105, board_by_metadata, by_boot_sha


def restored_image(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    before = (folder / "before_flash.bin").read_bytes()
    metadata = (folder / "before_metadata.bin").read_bytes()
    require(manifest.get("format") == 1 and manifest.get("boot_verified") is True, "Not a supported verified backup manifest")
    require(len(before) == FLASH_SIZE and digest(before) == manifest.get("before_flash_sha256"), "Backup flash digest mismatch")
    require(len(metadata) == 512 and digest(metadata) == manifest.get("before_metadata_sha256"), "Backup metadata digest mismatch")
    by_boot_sha(digest(before[:START]))
    # Only the backed-up board's application pages are restored. Device-specific
    # protected data are checked and preserved from the CURRENT same-session backup, never copied.
    end = board_by_metadata(metadata).app_end
    return Image(dict(enumerate(before[START:end], START)), boot_checksum=False)


def select_loader(kind, config):
    """START header and a function (bootloader profile, board) -> 440-byte RAM loader."""
    if kind == "authored":
        # One plaintext START header for every revision; the loader image is per revision and board.
        return authored()[0], lambda profile, board: authored(profile, board)[1]
    header, captured = load_profile(config)

    def loader(profile, board):
        # The capture-derived patch encodes v1.0.5 dispatcher returns and the Nova N60 page bound.
        require(profile is V105 and board is NOVA_N60, "Capture-derived loader profiles support the Nova N60 on bootloader v1.0.5 only")
        return captured
    return header, loader


def queue_recovery(folder):
    folder = Path(folder)
    restored_image(folder)
    manifest = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    require(not manifest.get("released") and not manifest.get("verified"), "Session is already verified/released; use normal --restore if needed")
    from .session import durable_write
    request = dict(format=1, action="restore-before", before_flash_sha256=manifest["before_flash_sha256"])
    durable_write(folder / "restore.request", json.dumps(request).encode("utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded application-only RY7203 flasher (Ranked Nova N60, G65); no bootloader/settings programming")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--mcu", choices=["RY7203"], default="RY7203")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", type=Path, help="Program a validated Intel HEX application image")
    mode.add_argument("--restore", type=Path, help="Restore application pages from a verified local backup directory")
    mode.add_argument("--setup-capture", type=Path, help="Extract and bound the loader from your own original USBPcap update capture")
    mode.add_argument("--probe", action="store_true", help="Read and verify two full backups, without programming; return to the existing application")
    mode.add_argument("--audit-nvm-backup", type=Path, help="Audit E0-FF and stock settings pages in a completed read-only --probe backup; no USB access")
    mode.add_argument("--recover", type=Path, help="Request pre-flash restoration in an already-running error holder; this command opens no HID handle")
    parser.add_argument("--config", type=Path, default=Path.home() / ".config/ry72xx-flasher/loader.json",
                        help="Capture-derived loader profile, used only with --loader profile")
    parser.add_argument("--loader", choices=["authored", "profile"], default="authored",
                        help="authored (default): packaged open-source loader and plaintext START header; "
                             "profile: loader extracted from your own vendor capture")
    parser.add_argument("--check-image", action="store_true", help="Validate --file only; do not load HID or access a device")
    parser.add_argument("--enter-stock", action="store_true", help="Allow the known original application mode-switch command")
    parser.add_argument("--resume-holder", action="store_true", help="Restore a verified backup from an already-active recovery holder, without GETV boot exit")
    parser.add_argument("--wait", type=float, default=30, help="Bootloader wait deadline in seconds, 0..600")
    parser.add_argument("--output", type=Path, help="New private backup/result directory; must not already exist")
    args = parser.parse_args(argv)
    try:
        require(0 <= args.wait <= 600, "Wait deadline must be between zero and 600 seconds")
        require(not args.resume_holder or args.restore is not None, "--resume-holder requires --restore")
        if args.audit_nvm_backup:
            from .nvm_audit import audit_nvm_backup
            print(json.dumps(audit_nvm_backup(args.audit_nvm_backup), indent=2))
            return 0
        if args.recover:
            require(not args.check_image and not args.enter_stock, "Recovery request does not enter or query USB")
            queue_recovery(args.recover)
            print("Restoration request queued. Keep the original holder running; its output reports verification. This request command does not access USB.")
            return 0
        if args.setup_capture:
            require(not args.check_image, "--check-image requires --file")
            setup(args.setup_capture, args.config)
            print(f"Validated local loader profile saved to {args.config}. Do not publish this vendor-derived file.")
            return 0
        if args.file:
            image = parse_hex(args.file.read_text(encoding="ascii"))
        elif args.restore:
            require(not args.check_image, "--check-image requires --file")
            image = restored_image(args.restore)
        else:
            require(not args.check_image, "--check-image requires --file")
            image = None
        if args.check_image:
            print(json.dumps(dict(passed=True, bytes=len(image.data), lowest_address=hex(min(image.data)), highest_address=hex(max(image.data)), hardware_access=False)))
            return 0
        header, loader = select_loader(args.loader, args.config)
        held = held_board = None
        if args.resume_holder:
            held = by_boot_sha(digest((Path(args.restore) / "before_flash.bin").read_bytes()[:START]))
            held_board = board_by_metadata((Path(args.restore) / "before_metadata.bin").read_bytes())
        # Import HID only after complete image/profile validation.
        from .transport import HIDTransport
        from .session import Session
        output = args.output or Path.home() / ".local/state/ry72xx-flasher" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        print(f"{'Read-only probe' if args.probe else 'Application-only flash'} requested. Backups/results: {output}", flush=True)
        transport = HIDTransport(header, enter_stock=args.enter_stock, wait_seconds=args.wait, resume_holder=args.resume_holder, profile=held, board=held_board)
        result = Session(transport, loader, output, notify=lambda message: print(message, flush=True)).run(image)
        print(json.dumps(dict(passed=result["passed"], verified=result["verified"], result_file=str(output / "result.json"))), flush=True)
        return 0
    except (ValueError, OSError, TimeoutError, KeyError, json.JSONDecodeError) as error:
        print(f"ry72xx-flasher: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; no automatic reset or additional DATA requested.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
