# Copyright 2026 patsys
# SPDX-License-Identifier: GPL-3.0-or-later
"""Authored bounded RAM probes, generated from readable Thumb source."""
from functools import lru_cache
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

from .image import digest, require
from .profiles import V105, V107

BASE = 0x20000000
ENTRIES = (0, 0x24, 0x6C, 0xDA, 0xFC, 0x13A)


def identity_check(profile, fail):
    """Branch to `fail` unless called natively: LR and the START handler's saved return."""
    lr, saved = profile.incoming_lr, profile.saved
    return f"""
    mov r0,lr; movs r2,#{lr >> 8}; lsls r2,#8; adds r2,#{lr & 0xFF};
    cmp r0,r2; bne {fail}; ldr r0,[sp,#{profile.saved_offset}];
    movs r2,#{saved >> 8}; lsls r2,#8; adds r2,#{saved & 0xFF}; cmp r0,r2; bne {fail};"""


def redirect(profile):
    """Saved return := 0x20000141, the stub tail at 0x140 (runs with the native context in r4)."""
    return f"movs r2,#0x20; lsls r2,#24; adds r2,#255; adds r2,#66; str r2,[sp,#{profile.saved_offset}];"


def guard(profile):
    return identity_check(profile, "done") + "\n    " + redirect(profile) + "\ndone: movs r0,#0; bx lr\n"


def send(profile):
    resume = profile.resume | 1
    return f"""
    strh r1,[r4,#4]; mov r0,r4; adds r0,#255; adds r0,#255; adds r0,#2;
    ldr r0,[r0,#20]; blx r0;
    movs r3,#{resume >> 8}; lsls r3,#8; adds r3,#{resume & 0xFF}; bx r3
"""


GUARD = guard(V105)
SEND = send(V105)


def assemble(source, offset):
    return bytes(Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm(source, BASE + offset)[0])


def blank():
    image = bytearray(b"\x70\x47" * 220)
    for offset in ENTRIES:
        image[offset:offset + 4] = b"\0\x20\x70\x47"
    image[0x13A:0x13C] = assemble("b #0x20000080", 0x13A)
    return image


def place(image, offset, source, end):
    code = assemble(source, offset)
    require(offset + len(code) <= end, "RAM stub source exceeds its bounded section")
    image[offset:offset + len(code)] = code


def mov32(register, value):
    octets = value.to_bytes(4, "big")
    parts = [f"movs {register},#{octets[0]}"]
    for byte in octets[1:]:
        parts.extend([f"lsls {register},#8", f"adds {register},#{byte}"])
    return "; ".join(parts)


@lru_cache(maxsize=64)
def read_stub(address, length, metadata=False, profile=V105):
    if metadata:
        require(0x10000600 <= address and address + length <= 0x10000800 and address % 4 == length % 4 == 0, "Metadata read outside observed window")
    else:
        require(0 <= address and address + length <= 0x20000, "Read outside CPU flash")
    require(1 <= length <= 56, "Read reply must fit its native buffer")
    image = blank()
    place(image, 0x80, guard(profile), 0xDA)
    if metadata:
        tail = mov32("r0", address) + f""";
            mov r2,r4; adds r2,#8; movs r1,#{length // 4};
        loop: ldr r3,[r0]; str r3,[r2]; adds r0,#4; adds r2,#4;
            subs r1,#1; bne loop; movs r1,#{length};
        """ + send(profile)
    else:
        tail = mov32("r0", address) + f""";
            mov r2,r4; adds r2,#8; movs r1,#{length};
        loop: ldrb r3,[r0]; strb r3,[r2]; adds r0,#1; adds r2,#1;
            subs r1,#1; bne loop; movs r1,#{length};
        """ + send(profile)
    place(image, 0x140, tail, 440)
    return bytes(image)


@lru_cache(maxsize=4)
def core_stub(mask, profile=V105):
    image = blank()
    place(image, 0x80, guard(profile), 0xDA)
    tail = "mov r2,r4; adds r2,#8; .byte 0xef,0xf3,0x10,0x80; str r0,[r2]; "
    if mask:
        tail += "cpsid i; "
    tail += ".byte 0xef,0xf3,0x10,0x80; str r0,[r2,#4]; "
    for offset, address in [(8, 0xE000ED00), (12, 0xE000E100), (16, 0xE000E010)]:
        tail += mov32("r0", address) + f"; ldr r0,[r0]; str r0,[r2,#{offset}]; "
    tail += "movs r1,#20; " + send(profile)
    place(image, 0x140, tail, 440)
    return bytes(image)


# The holder and release stubs act on the dispatcher's saved return (outer_offset):
# hold_return keeps a session in the bootloader, normal_return (= hold + 0x36) lets the
# dispatcher end it. Their images are pinned per bootloader revision.
HOLD_DIGESTS = {
    V105.name: "1c04bf5c4c9ae72885acfd8a62dc948219bb36c4cbc7a12ea3106367a0ebf871",
    V107.name: "3af57af79f8c1d902ab3a58f1c545a0f532eb82ed435c29e61148c3cc08883af",
}
RELEASE_DIGESTS = {
    V105.name: "57332cb094949feeba32c44fa829bb57069eaef61d92bceab161601737af4323",
    V107.name: "4461e98ea033ea7280031960d1456025cf7f9479480d571c4a078d78531bb622",
}


def outer_check(profile, fail, label):
    hold = profile.hold_return
    require(profile.normal_return - hold == 0x36, "Unexpected hold/normal return spacing")
    return f"""
    ldr r0,[sp,#{profile.outer_offset}]; movs r2,#{hold >> 8}; lsls r2,#8; adds r2,#{hold & 0xFF};
    cmp r0,r2; beq {label}; adds r2,#0x36; cmp r0,r2; bne {fail};"""


def build_hold(profile):
    address, proof = profile.holder_proof
    image = bytearray(read_stub(address, len(proof) // 2, profile=profile))
    source = identity_check(profile, "done") + outer_check(profile, "done", "hold") + f""" subs r2,#0x36;
    hold: str r2,[sp,#{profile.outer_offset}]; """ + redirect(profile) + """
    done: movs r0,#0; bx lr
    """
    place(image, 0x80, source, 0xDA)
    return bytes(image)


def build_release(profile):
    image = blank()
    source = identity_check(profile, "fail") + outer_check(profile, "fail", "release") + f""" b done;
    release: adds r2,#0x36; str r2,[sp,#{profile.outer_offset}];
    done: movs r0,#0; bx lr;
    fail: movs r0,#2; bx lr
    """
    place(image, 0x80, source, 0xDA)
    return bytes(image)


@lru_cache(maxsize=2)
def hold_stub(profile=V105):
    image = build_hold(profile)
    require(digest(image) == HOLD_DIGESTS[profile.name], "Holder differs from validated instructions")
    return image


@lru_cache(maxsize=2)
def release_stub(profile=V105):
    image = build_release(profile)
    require(digest(image) == RELEASE_DIGESTS[profile.name], "Release differs from validated instructions")
    return image
