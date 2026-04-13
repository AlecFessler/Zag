//! Arch-neutral primitives for deliberately triggering synchronous CPU
//! exceptions from test children. The exact fault reason observed by the
//! kernel differs by arch (e.g. x86 #UD vs aarch64 undefined instruction),
//! but each helper produces a synchronous exception suitable for tests
//! that want to verify fault-delivery semantics rather than exact x86
//! mnemonics.

const builtin = @import("builtin");

/// Dereference a null pointer to trigger a page/translation fault.
///
/// Uses a volatile load so the optimizer cannot elide it. On both x86_64
/// and aarch64 a load from virtual address 0 produces a synchronous
/// memory fault delivered to the process fault handler.
pub inline fn nullDeref() void {
    const p: *allowzero volatile u8 = @ptrFromInt(0);
    _ = p.*;
}

/// Trigger a breakpoint-style fault. `int3` on x86, `brk #0` on aarch64.
pub inline fn breakpoint() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => unreachable,
    }
}

/// Trigger an illegal-instruction fault. `ud2` on x86, `udf #0` on aarch64.
pub inline fn illegalInstruction() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("ud2" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("udf #0" ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// CPU relaxation hint inside spin loops. `pause` on x86, `yield` on aarch64.
pub inline fn cpuPause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => unreachable,
    }
}

/// Trigger a general-protection-style fault by executing a privileged
/// instruction from userspace. On x86 this is `cli`; on aarch64 we read
/// `sctlr_el1` from EL0 which raises an exception.
pub inline fn privilegedInstruction() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("cli"),
        .aarch64 => asm volatile ("mrs x0, sctlr_el1" ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// Read the current stack pointer.
pub inline fn readStackPointer() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm ("mov %%rsp, %[sp]"
            : [sp] "=r" (-> u64),
        ),
        .aarch64 => asm ("mov %[sp], sp"
            : [sp] "=r" (-> u64),
        ),
        else => unreachable,
    };
}

/// Trigger an alignment-check fault.
///
/// On x86 this sets the AC flag in RFLAGS and does a misaligned load.
/// On aarch64 from EL0 we rely on the SP alignment check: setting SP to a
/// non-16-aligned value and then executing an instruction that references
/// SP (any memory op) raises an SP alignment fault.
///
/// This helper does not return — it is intended to be the last thing a
/// test child executes before faulting.
pub inline fn alignmentFault() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\pushfq
            \\orq $0x40000, (%%rsp)
            \\popfq
            \\movq %%rsp, %%rax
            \\addq $1, %%rax
            \\movq (%%rax), %%rbx
        ),
        .aarch64 => asm volatile (
        // Misalign SP then touch memory via SP — raises SP alignment fault
        // at EL0 when SCTLR_EL1.SA0 is set (the kernel sets it).
            \\mov x9, sp
            \\sub x9, x9, #1
            \\mov sp, x9
            \\ldr x10, [sp]
        ),
        else => unreachable,
    }
    unreachable;
}
