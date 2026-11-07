@ Copyright 2026 patsys
@ SPDX-License-Identifier: GPL-3.0-or-later
@
@ Authored RAM programming loader for the Nova RY7203 bootloader
@ (ry72xx_boot_usb_v1.0.5, GETV a1050000a1040000, and v1.0.7, GETV
@ a1070000a1040000). The two revisions share the entry ABI, the packet
@ dispatcher (relocated by +0x24, same frame) and the native context; only the
@ USB bootstrap re-entry differs, so HOLD_RETURN is set per image at assembly
@ time (build_loader.py): v1.0.5 0x849, v1.0.7 0x86B.
@
@ The bootloader copies this 440-byte image to 0x20000000 after a START frame
@ and calls fixed entry points in it:
@
@   0x000  start the queued flash-controller operation and wait for it
@   0x024  erase one 512-byte page          r0 = page
@   0x06C  program one 512-byte page        r0 = page, r1 = source words
@   0x0DA  metadata erase                   rejected (returns 2)
@   0x0FC  metadata program                 rejected (returns 2)
@   0x13A  initialise                       r0 = core clock in Hz
@
@ Return value 0 is acknowledged by the bootloader (ACK 4); anything else is a
@ NACK. Every page operation is admitted only for application pages 16..132
@ (CPU 0x2000..0x109FF), the native packet context 0x20000324 with a 512-byte
@ payload, and, for programming, the payload buffer 0x2000032C. Bootloader,
@ settings, wear-leveling and hidden metadata pages are never touched.
@
@ Two stack writes keep the native session usable for the host's in-session
@ readback (see ry72xx-flasher README, "Session handoff"):
@   - before each admitted erase, the outer saved return becomes HOLD_RETURN, so a
@     native error or timeout re-enters the USB bootstrap instead of jumping
@     into a partially written application;
@   - after the last page is admitted for programming, the outer DATA-active
@     local is cleared, so later read-only START frames are accepted.
@ The host restores the original return only after full readback verification.
@
@ Flash controller (0x40013000): +0x00 command (1 program word, 2 erase page),
@ +0x04 word address (page << 7 | word), +0x08 data, +0x10 status (bit0 start,
@ bit1 busy), +0xD0 per-page write gate bitmap, timing registers +0x14..+0x4C.

    .syntax unified
    .cpu cortex-m0
    .thumb

    .equ CTRL,              0x40013000
    .equ CTRL_COMMAND,      0x00
    .equ CTRL_ADDRESS,      0x04
    .equ CTRL_DATA,         0x08
    .equ CTRL_STATUS,       0x10
    .equ CTRL_GATE,         0x400130D0
    .equ CMD_PROGRAM,       1
    .equ CMD_ERASE,         2
    .equ PACKET_CONTEXT,    0x20000324
    .equ PACKET_PAYLOAD,    0x2000032C
    .equ PLAINTEXT_FLAG,    0x20000214
    .equ FIRST_PAGE,        16
    .equ LAST_PAGE,         132
    .ifndef HOLD_RETURN
    .equ HOLD_RETURN,       0x849
    .endif
    .equ TIMEOUT_POLLS,     0x100000
    .equ ST_OK,             0
    .equ ST_REJECTED,       2
    .equ ST_TIMEOUT,        3

    .text
    .global ry72xx_loader
ry72xx_loader:

@ ---------------------------------------------------------------- 0x000
    .org 0x000
entry_start_wait:
    b       flash_go

@ udiv: r0 = r0 / r1 (unsigned, r1 != 0). Clobbers r1-r3.
udiv:
    movs    r2, #0
    movs    r3, #1
1:  cmp     r1, r0
    bhs     2f
    lsls    r1, r1, #1
    lsls    r3, r3, #1
    b       1b
2:  cmp     r0, r1
    blo     3f
    subs    r0, r0, r1
    orrs    r2, r3
3:  lsrs    r1, r1, #1
    lsrs    r3, r3, #1
    bne     2b
    mov     r0, r2
    bx      lr

@ ---------------------------------------------------------------- 0x024
    .org 0x024
entry_erase:
    push    {r4-r7, lr}             @ sp = caller sp - 20
    movs    r3, #0
    bl      admit
    bne     reject
    ldr     r2, =HOLD_RETURN
    str     r2, [sp, #80]           @ caller sp + 60: outer saved return
    mov     r5, r0
    bl      gate_open
    ldr     r1, =CTRL
    lsls    r2, r5, #7
    str     r2, [r1, #CTRL_ADDRESS]
    movs    r2, #CMD_ERASE
    str     r2, [r1, #CTRL_COMMAND]
    bl      flash_go
close_and_return:
    bl      gate_close
    b       finish
reject:
    movs    r0, #ST_REJECTED
finish:
    pop     {r4-r7, pc}

@ scale: r0 = r0 * MHz(r4) / 48; returns r3 = CTRL. Clobbers r1, r2.
scale:
    push    {lr}
    muls    r0, r4
    movs    r1, #48
    bl      udiv
    ldr     r3, =CTRL
    pop     {pc}
    .ltorg

@ ---------------------------------------------------------------- 0x06C
    .org 0x06C
entry_program:
    push    {r4-r7, lr}             @ sp = caller sp - 20
    movs    r3, #1
    bl      admit
    bne     reject
    cmp     r0, #LAST_PAGE
    bne     1f
    movs    r2, #0
    str     r2, [sp, #28]           @ caller sp + 8: end native DATA-active state
1:  mov     r5, r0
    bl      gate_open               @ keeps r1 (source)
    movs    r3, #0                  @ word index
2:  push    {r1, r3}
    ldr     r2, [r1]
    ldr     r1, =CTRL
    str     r2, [r1, #CTRL_DATA]
    lsls    r2, r5, #7
    orrs    r2, r3
    str     r2, [r1, #CTRL_ADDRESS]
    movs    r2, #CMD_PROGRAM
    str     r2, [r1, #CTRL_COMMAND]
    bl      flash_go
    pop     {r1, r3}
    cmp     r0, #ST_OK
    bne     close_and_return
    adds    r1, r1, #4
    adds    r3, r3, #1
    cmp     r3, #128
    blo     2b
    b       close_and_return

@ flash_go: start the queued operation and wait until STATUS bits 1:0 clear.
@ Returns r0 = 0, or 3 on timeout (2^20 polls). Clobbers r1-r3.
@ Measured on hardware (scratch page, 2026-11-07): the first STATUS read right
@ after setting the start bit returns 0x1 - busy (bit 1) is not raised yet, it
@ reads 0x3 from the next read until the operation ends with 0x0. Polling
@ bit 1 alone therefore reported completion at once, and the next word's
@ DATA/ADDRESS redirected the running operation (every other program word left
@ erased). The start bit (bit 0) stays set until completion, so both bits are
@ polled. The short delay before the start is kept from the earlier image.
flash_go:
    ldr     r1, =CTRL
    movs    r3, #32
0:  subs    r3, #1
    bne     0b
    ldr     r2, [r1, #CTRL_STATUS]
    movs    r3, #1
    orrs    r2, r3
    str     r2, [r1, #CTRL_STATUS]
    lsls    r3, r3, #20
1:  ldr     r2, [r1, #CTRL_STATUS]
    lsls    r2, r2, #30             @ bits 1:0 (busy, start) -> 31:30
    beq     2f
    subs    r3, #1
    bne     1b
    movs    r0, #ST_TIMEOUT
    bx      lr
2:  movs    r0, #ST_OK
    bx      lr
    .ltorg

@ ---------------------------------------------------------------- 0x0DA
    .org 0x0DA
entry_metadata_erase:
    movs    r0, #ST_REJECTED
    bx      lr

@ gate_open: r5 page -> r6 gate word address, r7 page bit, r4 saved PRIMASK.
@ Masks interrupts and opens only this page's write gate. Clobbers r2.
gate_open:
    lsrs    r6, r5, #5
    lsls    r6, r6, #2
    ldr     r2, =CTRL_GATE
    adds    r6, r6, r2
    movs    r2, #31
    ands    r2, r5
    movs    r7, #1
    lsls    r7, r7, r2
    mrs     r4, primask
    cpsid   i
    str     r7, [r6]
    bx      lr
    .ltorg

@ ---------------------------------------------------------------- 0x0FC
    .org 0x0FC
entry_metadata_program:
    movs    r0, #ST_REJECTED
    bx      lr

@ admit: r0 page, r1 source, r3 = 1 for program, r4 native context.
@ Returns Z set when admitted. Clobbers r2 only.
admit:
    cmp     r0, #FIRST_PAGE
    blo     9f
    cmp     r0, #LAST_PAGE
    bhi     9f
    ldr     r2, =PACKET_CONTEXT
    cmp     r4, r2
    bne     9f
    ldrh    r2, [r4, #4]
    subs    r2, #255
    subs    r2, #255
    cmp     r2, #2                  @ payload length exactly 512
    bne     9f
    cmp     r3, #0
    beq     8f
    movs    r2, #8
    adds    r2, r2, r4              @ payload buffer follows the context header
    cmp     r1, r2
    bx      lr                      @ Z from source comparison
8:  cmp     r3, r3                  @ Z set: admitted erase
9:  bx      lr                      @ Z clear on every rejection path

@ gate_close: clear only this page's gate bit, restore PRIMASK. Keeps r0.
gate_close:
    ldr     r2, [r6]
    bics    r2, r7
    str     r2, [r6]
    msr     primask, r4
    bx      lr
    .ltorg

@ ---------------------------------------------------------------- 0x13A
    .org 0x13A
entry_init:
    push    {r4, lr}
    ldr     r1, =PLAINTEXT_FLAG
    movs    r2, #0
    str     r2, [r1]                @ DATA payloads are plaintext
    lsrs    r2, r0, #27             @ reject clocks >= 134 MHz; bounds udiv
    bne     8f
    ldr     r1, =1000000
    bl      udiv                    @ r0 = MHz
    mov     r4, r0
    ldr     r3, =CTRL
    movs    r2, #0
    str     r2, [r3, #CTRL_STATUS]
    movs    r1, #0x81
    lsls    r1, r1, #2
    adds    r1, #3                  @ 0x207
    str     r1, [r3, #0x14]
    movs    r2, #0x0B
    str     r2, [r3, #0x18]
    movs    r2, #0x40
    str     r2, [r3, #0x20]
    subs    r1, #0xD0               @ 0x137
    str     r1, [r3, #0x24]
    movs    r0, #0x51
    lsls    r0, r0, #2              @ 0x144
    bl      scale
    str     r0, [r3, #0x28]
    movs    r2, #0x41
    lsls    r2, r2, #2              @ 0x104
    str     r2, [r3, #0x30]
    adds    r2, #0x10               @ 0x114
    str     r2, [r3, #0x38]
    ldr     r0, =0x34BC0
    bl      scale
    str     r0, [r3, #0x3C]
    ldr     r0, =0x15F900
    bl      scale
    str     r0, [r3, #0x40]
    movs    r2, #6
    str     r2, [r3, #0x4C]
    movs    r0, #ST_OK
    pop     {r4, pc}
8:  movs    r0, #ST_REJECTED
    pop     {r4, pc}
    .ltorg

    .org 0x1B8                      @ exact native image size: 440 bytes
