# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Loader selection: the packaged authored loader, or a user's own capture.

The default is the authored loader (`ry72xx_loader.bin`, built from
`loader/ry72xx_loader.S` in this repository) with an authored START header.
The header selects the bootloader's plaintext mode: its 16-byte encrypted
parameter field is zero, so the bootloader copies the plain parameter block
instead of decrypting it, and DATA payloads are taken as plaintext. Every field
is a protocol value (frame type, lengths, bootloader revision); no vendor key,
ciphertext or vendor code is included.

The capture-derived profile path is kept for comparison and recovery; it never
bundles or downloads vendor loader code.
"""
import functools
from importlib import resources
import json
from pathlib import Path
import struct

from .image import digest, require
from .profiles import V105

# Packaged loader image per bootloader revision (loader/build_loader.py); differ only in HOLD_RETURN.
AUTHORED_SHA = {
    "ry72xx_loader.bin": "22487f077007401c86c417094cc4aa2599b8afcb2fdb5f20730eb94e28ee9741",
    "ry72xx_loader_v107.bin": "66c95355137e042e808d5a0e8e325894365b3d869b54fd372b0b10f1b67cb58a",
}
CLEAR_LENGTH = 0x1CC00          # 0x7300 * 4; checked against header bytes 2..3
BOOT_REVISION = 0xA104          # second GETV word, a1040000 in v1.0.5 and v1.0.7
AUTHORED_HEADER = (
    bytes.fromhex("01000073e8010177")                      # START, payload 0x1e8
    + struct.pack("<II", CLEAR_LENGTH, BOOT_REVISION)       # plain header fields
    + struct.pack("<IIII", CLEAR_LENGTH, 0, 0x3A42 << 16 | BOOT_REVISION, 0)  # plain parameter block
    + bytes(16)                                             # zero: no encrypted parameters
    + struct.pack("<I", 440)                                # RAM image length
)

VENDOR_SHA = "fbf8d711262615c1fcfa7abad885e124032be8990da9af01f6e31a20da762ae8"
HEADER_SHA = "3a555131918325b6d55eef48d7b2299ab872bfa1b6caa4659458db6ced1a2fc5"
PATCHED_SHA = "e4c466571f03c5ece7ae4417c281dd9be3787d659945633acec7cfb92dae3a8c"


def extract_capture(blob):
    require(len(blob) >= 24 and blob[:4] == bytes.fromhex("d4c3b2a1"), "Require little-endian USBPcap PCAP")
    require(struct.unpack_from("<I", blob, 20)[0] == 249, "Unsupported capture link type")
    reports = []
    position = 24
    while position < len(blob):
        require(position + 16 <= len(blob), "Truncated PCAP packet header")
        size = struct.unpack_from("<I", blob, position + 8)[0]
        end = position + 16 + size
        require(end <= len(blob), "Truncated PCAP packet")
        packet = blob[position + 16:end]
        position = end
        if len(packet) == 91 and struct.unpack_from("<H", packet)[0] == 27 and packet[16] == 0 and packet[21:23] == bytes([4, 1]) and struct.unpack_from("<I", packet, 23)[0] == 64:
            reports.append(packet[27:])
    for index, report in enumerate(reports):
        if report[:8] != bytes.fromhex("01000073e8010177"):
            continue
        frame = b"".join(reports[index:index + 8])[:496]
        require(len(frame) == 496 and struct.unpack_from("<I", frame, 48)[0] == 440, "Malformed START capture")
        header, vendor = frame[:52], frame[52:492]
        require(digest(header) == HEADER_SHA and digest(vendor) == VENDOR_SHA, "Unsupported vendor loader or header revision")
        require(struct.unpack_from("<I", frame, 492)[0] == functools.reduce(int.__xor__, struct.unpack("<110I", vendor), 0), "Loader checksum mismatch")
        return header, vendor
    raise ValueError("Supported START frame not found")


def patch_vendor(vendor):
    require(len(vendor) == 440 and digest(vendor) == VENDOR_SHA, "Unsupported vendor loader")
    from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    stub = bytearray(vendor)

    def patch(offset, source, size):
        code = bytes(ks.asm(source, 0x20000000 + offset)[0])
        require(len(code) == size, "Unexpected patch assembly size")
        stub[offset:offset + size] = code

    patch(0x24, "movs r3,#0; b #0x200000de", 4)
    patch(0x6C, "movs r3,#1; b #0x200000de", 4)
    patch(0xDA, "movs r0,#2; bx lr", 4)
    patch(0xFC, "movs r0,#2; bx lr", 4)
    # Disable special metadata operations and guard every native page operation.
    # Page16..132 = CPU application2000..109ff; fixed512-byte context/source.
    patch(0xDE, """
        cmp r0,#16; blo #0x200000da; cmp r0,#132; bhi #0x200000da;
        ldr r2,[pc,#0x3c]; cmp r4,r2; bne #0x200000da;
        ldrh r2,[r4,#4]; subs r2,#255; subs r2,#255; subs r2,#2;
        bne #0x200000da; cmp r3,#0; beq #0x20000100; b #0x2000010e
    """, 30)
    patch(0x100, """
        push {r3,r4,r5,r6,r7,lr}; mov r4,r0;
        movs r2,#0x84; lsls r2,#4; adds r2,#9; str r2,[sp,#84];
        b #0x20000028
    """, 14)
    patch(0x10E, """
        ldr r2,[pc,#0x18]; cmp r1,r2; bne #0x200000da;
        push {r1,r2,r3,r4,r5,r6,r7,lr}; mov r7,r0; b #0x20000130
    """, 12)
    patch(0x11A, """
        ldr r1,[pc,#0x10]; movs r2,#0; str r2,[r1];
        push {r4,r5,r6,lr}; b #0x2000013c
    """, 10)
    struct.pack_into("<III", stub, 0x124, 0x20000324, 0x2000032C, 0x20000214)
    patch(0x130, "cmp r0,#132; bne #0x20000070; movs r2,#0; str r2,[sp,#40]; b #0x20000070", 10)
    patch(0x13A, "b #0x2000011a", 2)
    require(digest(stub) == PATCHED_SHA, "Bounded loader does not match validated v3 instructions")
    return bytes(stub)


def setup(capture, destination):
    header, vendor = extract_capture(Path(capture).read_bytes())
    patched = patch_vendor(vendor)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists(), "Loader profile already exists; choose another path")
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(dict(format=1, header=header.hex(), loader=patched.hex(), source_capture_sha256=digest(Path(capture).read_bytes())), stream, indent=2)
    destination.chmod(0o600)


def authored(profile=V105):
    """Return the authored (header, loader) pair for a bootloader revision after checking the packaged hash."""
    loader = resources.files(__package__).joinpath(profile.loader_resource).read_bytes()
    require(len(loader) == 440 and digest(loader) == AUTHORED_SHA[profile.loader_resource], "Packaged authored loader changed; rebuild and re-validate")
    require(len(AUTHORED_HEADER) == 52, "Authored START header must be 52 bytes")
    return AUTHORED_HEADER, loader


def load_profile(path):
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    require(profile.get("format") == 1, "Unsupported loader profile format")
    header, loader = bytes.fromhex(profile["header"]), bytes.fromhex(profile["loader"])
    require(len(header) == 52 and digest(header) == HEADER_SHA, "Loader profile header changed")
    require(len(loader) == 440 and digest(loader) == PATCHED_SHA, "Loader profile executable changed")
    return header, loader
