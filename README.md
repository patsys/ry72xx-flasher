# ry72xx-flasher

Experimental Python 3 host tool for the **observed Ranked Nova N60 ISO RY7203
bootloader revisions**, not a generic programmer for every RY72xx part.

## Supported bootloader revisions

A board is accepted only when its GETV reply and the SHA-256 of its whole boot
region (`0x0000..0x1fff`) name the same entry in `profiles.py`; any other
revision is refused before a RAM stub or DATA packet is sent.

| Revision | GETV | Boot SHA-256 | Status |
|---|---|---|---|
| `ry72xx_boot_usb_v1.0.5` | `a1050000a1040000` | `e46c6d93…` | read, probe and application flashing validated on hardware |
| `ry72xx_boot_usb_v1.0.7` | `a1070000a1040000` | `eae819e4…` | read path, core check and scratch-page flash diagnostics validated on hardware; release/flash validated in emulation only |

The revisions share the START framing, loader entry ABI and the packet
dispatcher (relocated by `+0x24`, same stack frame). They differ in the START
handler frame (`+8` bytes), the native return addresses the stubs verify, and
the USB bootstrap re-entry; the per-revision values are documented in
`profiles.py`. The authored loader is built once per revision
(`ry72xx_loader.bin`, `ry72xx_loader_v107.bin`), differing only in that
re-entry address. Capture-derived loader profiles remain v1.0.5 only.

**Application checksum.** Before starting the application the bootloader can
verify the XOR of all 32-bit words of `0x2000 + length` against the info-flash
metadata (`0x10000624` length, `0x10000628` value). v1.0.7 always performs that
check; v1.0.5 skips it while the info-flash patch list is valid. For a new
image the flasher therefore sets the reserved Cortex-M0 vector entry 7
(`0x201c`, never fetched by the core) so the check passes, using the length and
value read from the board's own metadata. The metadata is never written.
Restoring a backup writes it byte-exact, without this adjustment.

It writes only CPU application addresses `0x2000..0x109ff` (117 pages of 512
bytes). Bootloader, settings/calibration and hidden metadata are excluded by
both host checks and a bounded RAM loader. It backs up the full 128 KiB CPU flash
and the separate 512-byte metadata window, persists and checks those files
before programming, then compares the entire flash and metadata before release.
No COMPLETE command is sent. Settings changes remain volatile in the QMK port.

## Install

Use Python 3.10 or newer in a dedicated environment:

```sh
python -m venv .venv
# Activate the environment using your shell's normal activation command.
python -m pip install .
ry72xx-flasher --version
```

Runtime dependencies are `hidapi` and `keystone-engine`; no disassembler,
emulator, vendor firmware dump or encryption key is bundled or required to run
the host tool. The supplied loader profile described below is required.

## One-time loader setup

This repository contains **no vendor loader binary**. The observed controller
programming code has not been established as redistributable. Obtain your own
original vendor update capture from hardware/firmware you are authorized to use.
The currently supported input is little-endian USBPcap PCAP with the observed
496-byte START frame and its original 440-byte loader. PCAPNG and other loader
revisions are rejected. Setup does not access the keyboard:

```sh
ry72xx-flasher --setup-capture your_original_update.pcap
```

Setup validates known header/loader hashes and the loader's XOR checksum, applies
the documented application-only bounds and native handoff patch, and verifies
the resulting loader's exact validated instruction hash. It saves a private
local profile at `~/.config/ry72xx-flasher/loader.json`. Use `--config PATH` to
choose another location. **Do not publish the profile, capture or backups.**

The package's source and patch logic are GPL-3.0-or-later. This license does not
relicense the user's vendor binary. A profile is not distributed with a wheel.

## Check and flash

For a read-only live check, `--probe` reads the full flash and metadata twice,
verifies they agree, and returns to the existing application. It sends authored
RAM read/hold/release code but no programming loader or DATA:

```sh
ry72xx-flasher --probe --enter-stock
```

Validate a QMK-generated Intel HEX without USB access:

```sh
ry72xx-flasher --mcu RY7203 --file firmware.hex --check-image
```

The parser checks record checksums, overlaps, extensions, entry point, complete
vector table, stack alignment and application address bounds. It supports the
start-segment record emitted by GNU objcopy as well as start-linear records.
Binary files without address metadata are intentionally unsupported.

Enter the preserved bootloader before flashing. On the tested QMK port, hold
Esc while reconnecting. With the original stock application, `--enter-stock`
allows the previously observed stock mode-switch command; it requires exactly
the original six-interface Nova application and does not send that command to
QMK firmware. Multiple matching boards are rejected.

```sh
ry72xx-flasher --mcu RY7203 --file firmware.hex
# Initial stock-to-QMK migration, when the original application is running:
ry72xx-flasher --mcu RY7203 --file firmware.hex --enter-stock
```

**The file forms above program firmware**, after validation and backup. There
is no separate confirmation prompt. `--check-image` is the explicit offline mode.
The default bootloader wait deadline is 30 seconds (`--wait 0..600`).

The QMK RY7203 platform's make integration invokes this external command:

```sh
qmk flash -kb ranked/nova_n60 -km default
make ranked/nova_n60:default:flash
```

For an external userspace, configure that userspace and select its keymap, such
as `neo2_via`. Put the installed flasher environment's scripts directory on PATH,
or use QMK's `RY72XX_FLASHER`/`PROGRAM_CMD` override. Raw-file autodetection through
`qmk flash firmware.hex` is not integrated into QMK's separate discovery backend;
use the keyboard/keymap command or invoke this tool directly.

## Backup and stock restore

Every flash creates a new private directory under
`~/.local/state/ry72xx-flasher/`, or the unused directory specified by `--output`.
It contains `result.json`, `before_flash.bin`, `before_metadata.bin`, expected
flash bytes and final readback. Existing directories/files are never overwritten.
Do not delete the original stock backup after migrating to QMK.

To restore the application from a backup produced by this tool:

```sh
# Enter the preserved bootloader, then:
ry72xx-flasher --restore /path/to/original-stock-backup
```

Restore validates the backup's hashes and supported bootloader. It writes only
its saved application pages, preserving the current session's bootloader,
settings and hidden metadata. It does not restore those protected regions.

## Errors and recovery

Short transfers, mismatched ACKs and verification errors never cause an automatic
programming retry. Transient Windows journal rename-sharing errors receive a
bounded filesystem-only retry; this never repeats a USB DATA command. After an
unverified write fails, a read-only RAM holder services the original bootloader
path. Keep the original process and USB power connected. From a second terminal,
explicitly request restoration of that session's verified pre-flash backup:

```sh
ry72xx-flasher --recover /path/to/failed-session-directory
```

This command only validates the local backup and queues a request file; it opens
no HID handle. The original holder validates and consumes the request, then
performs a separate backup/restore/readback transaction using the same open HID
handle. It never retries or continues the failed target image. Verification of
the restoration is reported in its own result file; the original target attempt
remains failed. A failed restoration returns to the read-only holder and requires
another explicit request for any further programming.

A second board is never opened as a substitute. Ctrl-C stops the holder but can
end the recovery opportunity. Host failure, cable removal and power loss can
defeat recovery. **Power-loss recovery has not been established.** Advanced
`--restore BACKUP --resume-holder` is available when handing off an already-held
session after its original host process has stopped; it must not run concurrently
with another HID client. Prefer the same-process `--recover` method.

Once the image has passed complete readback, failure to enumerate is reported
separately from content verification. Try the documented Esc-held boot entry
and restore a verified backup. A programming-session exit GETV can produce a
native NACK5 or USB disconnect; normal application enumeration is checked after
that exit, rather than interpreting it as a normal version query.

## Tests and support limits

```sh
python -m unittest discover -s tests -v
python -O -m unittest discover -s tests -v
```

Public tests use synthetic flash and fake HID handles; no vendor data or live
device is used. They cover image parsing, protected ranges, identity ambiguity,
short/invalid transfers, backup failures, DATA failures, readback corruption,
metadata preservation, guarded release and failure recovery. Production guards
use explicit exceptions, so `python -O` does not remove them.

Native-bootloader emulation and physical validation results belong in the
contribution evidence and must name the exact package/source/image hashes.
Windows hidapi is the initial live-test environment. Linux/macOS transport and
permissions are not yet physically tested. No generic USB driver replacement is
required or performed by this tool. The stock keyboard uses HID.
