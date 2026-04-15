//! Early fault handler used before the kernel's real exception vectors
//! are installed. Catches any synchronous/async fault during the boot
//! window (exitBootServices, switchStackAndCall, kEntry, arch.init up
//! until exceptions.install()) and dumps ESR_EL1, FAR_EL1, ELR_EL1, SP
//! to the PL011 UART at physical 0x09000000, then halts.
//!
//! Install via installEarlyVbar() from the bootloader after any code
//! that UEFI's own exception paths rely on (i.e., after exitBootServices).
//! The kernel's exceptions.install() later overwrites VBAR_EL1 with the
//! real handler.
//!
//! The UART MMIO page must be identity-mapped into the kernel page
//! tables via mapUart() before the handler can fire, otherwise the
//! first `str` to 0x09000000 would itself translation-fault and cause
//! infinite handler recursion.
//!
//! ARM ARM D1.10.2: exception vector table must be 2KB aligned.

const std = @import("std");
const zag = @import("zag");

const paging = zag.arch.aarch64.paging;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const pl011_phys: u64 = 0x09000000;

pub fn installEarlyVbar() void {
    const addr: u64 = @intFromPtr(&earlyVbarTable);
    asm volatile (
        \\msr vbar_el1, %[addr]
        \\isb
        :
        : [addr] "r" (addr),
        : .{ .memory = true });
}

/// Map the PL011 UART MMIO page into the kernel's TTBR1 physmap range
/// as Device memory so the handler's UART writes always have a valid
/// translation, independent of UEFI's TTBR0 identity mapping (which is
/// invalidated once a user process writes TTBR0).
pub fn mapUart(
    addr_space_root: VAddr,
    allocator: std.mem.Allocator,
) !void {
    const perms: MemoryPerms = .{
        .write_perm = .write,
        .execute_perm = .no_execute,
        .cache_perm = .not_cacheable,
        .global_perm = .global,
        .privilege_perm = .kernel,
    };
    try paging.mapPageBoot(
        addr_space_root,
        PAddr.fromInt(pl011_phys),
        VAddr.fromInt(pl011_phys),
        .page4k,
        perms,
        allocator,
    );
}

export fn earlyVbarTable() align(2048) callconv(.naked) noreturn {
    asm volatile (
    // 16 vector entries × 0x80 bytes each = 0x800 (2KB) total.
    // Each entry branches to the shared handler.
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
        // Save caller's LR (x30) and FP (x29) before bl clobbers them.
        \\  mov x11, x30
        \\  mov x12, x29
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
        // "S="
        \\  mov w0, #0x53
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mov x1, sp
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "R=" caller's LR at time of fault
        \\  mov w0, #0x52
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mov x1, x11
        \\  bl 20f
        \\  mov w0, #0x0A
        \\  str w0, [x10]
        // "P=" caller's FP at time of fault
        \\  mov w0, #0x50
        \\  str w0, [x10]
        \\  mov w0, #0x3D
        \\  str w0, [x10]
        \\  mov x1, x12
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
