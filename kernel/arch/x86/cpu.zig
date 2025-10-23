//! CPU utilities for x86-64.
//!
//! Provides register snapshots and small privileged helpers used by the kernel,
//! including `hlt` loops, `invlpg`, reading `cr2`, and reloading segment
//! selectors after GDT setup. All functions assume CPL0 (ring 0).

const paging = @import("paging.zig");

const VAddr = paging.VAddr;

/// Snapshot of general-purpose registers saved/restored by interrupt/exception glue.
///
/// Layout matches the push/pop order used by our stubs so it can be copied
/// verbatim to/from the stack. All fields are 64-bit.
pub const Registers = packed struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
};

/// Halts the CPU in a tight loop (low-power wait until interrupt).
///
/// Never returns.
pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn outb(
    value: u8,
    port: u16,
) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

/// Invalidates the TLB entry for `vaddr`.
///
/// Arguments:
/// - `vaddr`: virtual address whose page translation should be dropped
pub fn invlpg(vaddr: VAddr) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr.addr),
        : .{ .memory = true });
}

/// Reads `cr2` and returns the last page-fault linear address.
///
/// Returns:
/// - `VAddr` of the most recent page-faulting linear address.
pub fn read_cr2() VAddr {
    var addr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (addr),
    );
    return VAddr.fromInt(addr);
}

/// Reloads CS/DS/ES/SS using known ring-0 selectors in the current GDT.
///
/// Assumes:
/// - Code selector = `0x08`
/// - Data selectors (DS/ES/SS) = `0x10`
pub fn reloadSegments() void {
    asm volatile (
        \\pushq $0x08
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%ss
        ::: .{ .memory = true });
}

pub fn setWriteProtect(enable: bool) void {
    var cr0: u64 = 0;
    asm volatile ("mov %%cr0, %[out]"
        : [out] "=r" (cr0),
    );
    const wp_bit: u64 = 1 << 16;
    if (enable) {
        cr0 |= wp_bit;
    } else {
        cr0 &= ~wp_bit;
    }
    asm volatile ("mov %[in], %%cr0"
        :
        : [in] "r" (cr0),
        : .{ .memory = true });
}
