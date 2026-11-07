# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble ry72xx_loader.S into the packaged 440-byte RAM image.

Usage: python build_loader.py [--check]   (builds every packaged revision variant)
Requires arm-none-eabi-as/ld/objcopy on PATH (or ARM_TOOLCHAIN_BIN).
--check rebuilds into a temporary file and fails if the packaged image differs.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "ry72xx_loader.S"
PACKAGE = HERE.parent / "src" / "ry72xx_flasher"
# Packaged image -> assembler symbols (bootloader revision specific values, see profiles.py).
VARIANTS = {
    PACKAGE / "ry72xx_loader.bin": {},
    PACKAGE / "ry72xx_loader_v107.bin": {"HOLD_RETURN": 0x86B},
}


def tool(name):
    base = os.environ.get("ARM_TOOLCHAIN_BIN")
    return str(Path(base) / f"arm-none-eabi-{name}") if base else f"arm-none-eabi-{name}"


def build(output, symbols):
    with tempfile.TemporaryDirectory() as work:
        obj, elf = Path(work) / "loader.o", Path(work) / "loader.elf"
        defsyms = [f"--defsym={name}={value:#x}" for name, value in symbols.items()]
        subprocess.run([tool("as"), "-mcpu=cortex-m0", "-mthumb", *defsyms, "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run([tool("ld"), "-nostdlib", "-Ttext=0x20000000", "-e", "ry72xx_loader", "-o", str(elf), str(obj)], check=True)
        subprocess.run([tool("objcopy"), "-O", "binary", "-j", ".text", str(elf), str(output)], check=True)
    image = Path(output).read_bytes()
    if len(image) != 440:
        raise SystemExit(f"Loader must be exactly 440 bytes, got {len(image)}")
    return image


def main():
    for packaged, symbols in VARIANTS.items():
        if "--check" in sys.argv:
            with tempfile.TemporaryDirectory() as work:
                image = build(Path(work) / "loader.bin", symbols)
            if image != packaged.read_bytes():
                raise SystemExit(f"Packaged {packaged.name} does not match ry72xx_loader.S")
            print(f"packaged {packaged.name} matches source", hashlib.sha256(image).hexdigest())
            continue
        image = build(packaged, symbols)
        print(packaged, len(image), hashlib.sha256(image).hexdigest())


if __name__ == "__main__":
    main()
