//! Early fault handler used before the kernel's real exception vectors
//! are installed. Catches any synchronous/async fault during the boot
//! window (page table building, exitBootServices, switchStackAndCall,
//! kEntry prologue) and dumps ESR_EL1, FAR_EL1, ELR_EL1 to the PL011
//! UART at physical 0x09000000, then halts.
//!
//! Install via installEarlyVbar() from the bootloader before any code
//! that might fault. The kernel's exceptions.install() later overwrites
//! VBAR_EL1 with the real handler.
//!
//! ARM ARM D1.10.2: exception vector table must be 2KB aligned.

pub fn installEarlyVbar() void {
    const addr: u64 = @intFromPtr(&earlyVbarTable);
    asm volatile (
        \\msr vbar_el1, %[addr]
        \\isb
        :
        : [addr] "r" (addr),
        : .{ .memory = true }
    );
}

export fn earlyVbarTable() align(2048) callconv(.naked) noreturn {
    asm volatile (
    // 16 vector entries × 0x80 bytes each = 0x800 (2KB) total.
    // Each entry just branches to the shared handler.
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        \\  b 10f
        \\  .balign 0x80
        // Shared fault handler.
        // x10 = UART base, x1 = value being printed, x0 = scratch byte,
        // x2/x3 = hex loop scratch. No stack, no memory except UART.
        \\10:
        \\  mov x10, #0x09000000
        // Marker: "!F\n"
        \\  mov w0, #0x21
        \\  str w0, [x10]
        \\  mov w0, #0x46
        \\  str w0, [x10]
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "E="
        \\  mov w0, #0x45
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mrs x1, esr_el1
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "F="
        \\  mov w0, #0x46
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mrs x1, far_el1
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "L="
        \\  mov w0, #0x4C
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mrs x1, elr_el1
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "S=" (SP at fault time — before exception entry SP is preserved)
        \\  mov w0, #0x53
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mov x1, sp
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // Halt forever.
        \\30:
        \\  wfi
        \\  b 30b
        // Hex printer: prints x1 as 16 hex nibbles to UART at x10.
        // No stack: bl/ret uses x30 only, no nested calls.
        \\20:
        \\  mov x2, #60
        \\21:
        \\  lsr x3, x1, x2
        \\  and x3, x3, #0xF
        \\  cmp x3, #10
        \\  b.lt 22f
        \\  add x3, x3, #0x37
        \\  b 23f
        \\22:
        \\  add x3, x3, #0x30
        \\23:
        \\  str w3, [x10]
        \\  subs x2, x2, #4
        \\  b.ge 21b
        \\  ret
    );
}
