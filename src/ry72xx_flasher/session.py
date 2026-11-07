# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Backup-before-write transaction with full readback and explicit recovery."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from .image import Image, START, END, FLASH_SIZE, digest, require, with_boot_checksum
from .profiles import by_boot_sha
from . import __version__


def durable_write(path, data):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class Session:
    def __init__(self, transport, loader, output, notify=print, recover=None, retain_error_handle=False):
        """loader: the 440-byte RAM loader, or a function of the bootloader profile returning it."""
        self.transport = transport
        self.loader = loader
        self.output = Path(output)
        self.notify = notify
        self.recover = recover or self.keepalive
        self.retain_error_handle = retain_error_handle
        self.log = dict(format=1, version=__version__, created_at=datetime.now(timezone.utc).isoformat(),
                        no_complete_command=True, write_started=False, verified=False,
                        released=False, boot_verified=False, pages=[])
        self.log["host_sources"] = {
            path.name: digest(path.read_bytes())
            for path in sorted(Path(__file__).parent.glob("*.py"))
        }

    def save(self):
        temporary = self.output / "result.tmp"
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(self.log, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows readers/AV/indexers can briefly deny rename sharing. Retry
        # only this filesystem operation, never a USB DATA/program operation.
        for attempt in range(10):
            try:
                temporary.replace(self.output / "result.json")
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.02)

    def save_best_effort(self):
        try:
            self.save()
        except OSError as error:
            self.notify(f"Could not persist error log: {error}")

    def snapshot(self, name):
        data = bytearray()
        for address in range(0, FLASH_SIZE, 4096):
            chunk = self.transport.read(address, 4096)
            require(len(chunk) == 4096, "Short flash backup/readback")
            data.extend(chunk)
            if address % 0x4000 == 0 or address + 4096 == FLASH_SIZE:
                self.notify(f"{name}: {address + 4096}/{FLASH_SIZE} bytes")
        durable_write(self.output / name, data)
        return bytes(data)

    def run(self, image=None, reuse_open=False):
        self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.save()
        try:
            if reuse_open:
                self.transport.hold_once()
                self.log["boot_version"] = getattr(self.transport, "version", "active recovery holder")
            else:
                self.log["boot_version"] = self.transport.open()
            self.log["core_before_backup"] = self.transport.core(True)
            boot = self.transport.read(0, START)
            profile = self.transport.profile
            require(len(boot) == START and profile is not None and digest(boot) == profile.boot_sha, "Unsupported bootloader; no DATA sent")
            loader = self.loader(profile) if callable(self.loader) else self.loader
            require(len(loader) == 440, "RAM loader must be 440 bytes")
            self.log["boot_profile"] = profile.name
            self.log["boot_verified"] = True
            self.save()
            before = self.snapshot("before_flash.bin")
            metadata = self.transport.read(0x10000600, 512, metadata=True)
            require(len(metadata) == 512, "Short hidden metadata backup")
            durable_write(self.output / "before_metadata.bin", metadata)
            self.log["probe_only"] = image is None
            expected = before if image is None else image.overlay(before)
            if image is not None and image.boot_checksum:
                expected, old_word, new_word = with_boot_checksum(expected, metadata)
                self.log["boot_checksum_word"] = dict(address=hex(START + 0x1C), image=hex(old_word), written=hex(new_word))
            durable_write(self.output / "expected_flash.bin", expected)
            self.log.update(before_flash_sha256=digest(before), before_metadata_sha256=digest(metadata),
                            expected_flash_sha256=digest(expected), target_application_sha256=digest(expected[START:END]),
                            loader_sha256=digest(loader))
            self.save()
            # Read persisted backup files back before the first possible erase.
            require((self.output / "before_flash.bin").read_bytes() == before and
                    (self.output / "before_metadata.bin").read_bytes() == metadata and
                    (self.output / "expected_flash.bin").read_bytes() == expected, "Backup persistence verification failed")
            if image is not None:
                self.log["core_before_data"] = self.transport.core(True)
                self.transport.begin_programming(loader)
                for index in range(117):
                    page = expected[START + index * 512:START + (index + 1) * 512]
                    self.log["write_started"] = True
                    self.save()
                    self.transport.data(index + 1, page)
                    self.log["pages"].append(dict(sequence=index + 1, address=START + index * 512, sha256=digest(page)))
                    self.save()
                    if index == 0 or (index + 1) % 16 == 0 or index == 116:
                        self.notify(f"Programmed {index + 1}/117 application pages")
            self.log["core_before_readback"] = self.transport.core(False)
            after = self.snapshot("after_flash.bin")
            after_metadata = self.transport.read(0x10000600, 512, metadata=True)
            durable_write(self.output / "after_metadata.bin", after_metadata)
            self.log["core_after_readback"] = self.transport.core(False)
            self.log.update(whole_flash_matches_expected=after == expected,
                            bootloader_unchanged=after[:START] == before[:START],
                            outside_application_unchanged=after[:START] + after[END:] == before[:START] + before[END:],
                            hidden_metadata_unchanged=after_metadata == metadata,
                            after_flash_sha256=digest(after), after_metadata_sha256=digest(after_metadata))
            self.save()
            require(after == expected and after_metadata == metadata, "Readback mismatch; refusing application release")
            self.log["verified"] = True
            self.save()
            self.transport.release()
            self.log["released"] = True
            self.save()
            self.transport.close()
            self.log["final_state"] = self.transport.wait_application()
            self.log["passed"] = True
            self.save()
            return self.log
        except BaseException as error:
            self.log.update(passed=False, error=f"{type(error).__name__}: {error}")
            self.save_best_effort()
            if self.log["boot_verified"] and not self.log["verified"]:
                self.recover(self)
            raise
        finally:
            if not (self.retain_error_handle and self.log["boot_verified"] and not self.log["verified"]):
                self.transport.close()

    @staticmethod
    def keepalive(session):
        session.notify(f"FLASH ERROR: no automatic programming retry. Read-only recovery keepalive is running. Keep USB power connected. To request restoration of this session's pre-flash application without closing HID, run: ry72xx-flasher --recover \"{session.output}\". Ctrl-C stops the holder and can end recovery.")
        while True:
            try:
                session.transport.hold_once()
                session.log["recovery_keepalives"] = session.log.get("recovery_keepalives", 0) + 1
                session.save_best_effort()
                request_path = session.output / "restore.request"
                if request_path.exists():
                    try:
                        request = json.loads(request_path.read_text(encoding="utf-8"))
                        require(request.get("format") == 1 and request.get("action") == "restore-before", "Invalid recovery action")
                        require(request.get("before_flash_sha256") == session.log.get("before_flash_sha256"), "Recovery request names another backup")
                        before = (session.output / "before_flash.bin").read_bytes()
                        metadata = (session.output / "before_metadata.bin").read_bytes()
                        require(len(before) == FLASH_SIZE and digest(before) == session.log["before_flash_sha256"], "Recovery backup changed")
                        require(by_boot_sha(digest(before[:START])) is session.transport.profile and len(metadata) == 512 and digest(metadata) == session.log["before_metadata_sha256"], "Recovery identity/metadata backup changed")
                    except (ValueError, OSError, KeyError) as error:
                        session.log["recovery_request_error"] = str(error)
                        session.save_best_effort()
                    else:
                        # Only an explicit local request can start this separate
                        # rollback transaction. It does not retry the failed
                        # target or release an unverified application.
                        consumed = session.output / datetime.now(timezone.utc).strftime("restore.request.consumed_%Y%m%dT%H%M%S_%fZ")
                        request_path.replace(consumed)
                        output = session.output / datetime.now(timezone.utc).strftime("recovery_restore_%Y%m%dT%H%M%S_%fZ")
                        session.notify(f"Explicit pre-flash restoration requested; same HID handle. Results: {output}")
                        restoration = Session(session.transport, session.loader, output, notify=session.notify,
                                              recover=lambda failed: failed.transport.hold_once(), retain_error_handle=True)
                        try:
                            restoration.run(Image(dict(enumerate(before[START:END], START)), boot_checksum=False), reuse_open=True)
                        except Exception as error:
                            session.log["recovery_restore_error"] = str(error)
                            session.log["recovery_restore_result"] = str(output / "result.json")
                            session.save_best_effort()
                            if restoration.log["verified"]:
                                session.notify("Restoration content verified, but release/enumeration failed; see its result log. No further automatic programming.")
                                return
                            session.notify("Restoration attempt failed; returning to read-only holder. Another restoration requires a new explicit --recover request.")
                            continue
                        session.log["recovery_restored"] = True
                        session.log["recovery_restore_result"] = str(output / "result.json")
                        session.save_best_effort()
                        session.notify("Pre-flash application restoration verified. Original target flash remains reported as failed.")
                        return
            except KeyboardInterrupt:
                session.notify("Recovery holder stopped by user; no reset or further DATA sent.")
                return
            except Exception as error:
                session.log["recovery_last_error"] = str(error)
                session.save_best_effort()
                session.transport.close()
            time.sleep(0.25)
