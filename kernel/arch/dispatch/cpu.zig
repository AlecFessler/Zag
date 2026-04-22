const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const BootInfo = zag.boot.protocol.BootInfo;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

/// Number of general-purpose registers saved in a fault snapshot.
/// x86-64: 15 (rax-r15 minus rsp). aarch64: 31 (x0-x30).
pub const fault_gpr_count: usize = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.fault_gpr_count,
    .aarch64 => aarch64.interrupts.fault_gpr_count,
    else => unreachable,
};

/// Size of the register portion of a FaultMessage: ip + flags + sp + GPRs.
pub const fault_regs_size: usize = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.fault_regs_size,
    .aarch64 => aarch64.interrupts.fault_regs_size,
    else => unreachable,
};

/// Total size of a FaultMessage written to userspace (32-byte header + regs).
pub const fault_msg_size: usize = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.fault_msg_size,
    .aarch64 => aarch64.interrupts.fault_msg_size,
    else => unreachable,
};

/// Architecture-neutral snapshot of a faulted thread's registers.
/// Used by fault delivery to serialize register state without the
/// generic kernel referencing arch-specific register names.
pub const FaultRegSnapshot = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.FaultRegSnapshot,
    .aarch64 => aarch64.interrupts.FaultRegSnapshot,
    else => unreachable,
};

pub const ArchCpuContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.ArchCpuContext,
    .aarch64 => aarch64.interrupts.ArchCpuContext,
    else => unreachable,
};

pub const PageFaultContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.PageFaultContext,
    .aarch64 => aarch64.interrupts.PageFaultContext,
    else => unreachable,
};

/// Apply a modified register snapshot from userspace to a faulted thread's
/// saved context. Reverse of serializeFaultRegs. The caller is responsible
/// for SMAP (userAccessBegin/End) around the buffer read.
pub fn applyFaultRegs(ctx: *ArchCpuContext, snapshot: FaultRegSnapshot) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.applyFaultRegs(ctx, snapshot),
        .aarch64 => aarch64.interrupts.applyFaultRegs(ctx, snapshot),
        else => unreachable,
    }
}

pub fn serializeFaultRegs(ctx: *const ArchCpuContext) FaultRegSnapshot {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.serializeFaultRegs(ctx),
        .aarch64 => aarch64.interrupts.serializeFaultRegs(ctx),
        else => unreachable,
    };
}

pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.interrupts.prepareThreadContext(kstack_top, ustack_top, entry, arg),
        .aarch64 => return aarch64.interrupts.prepareThreadContext(kstack_top, ustack_top, entry, arg),
        else => unreachable,
    }
}

pub fn switchTo(thread: *Thread) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.switchTo(thread),
        .aarch64 => aarch64.interrupts.switchTo(thread),
        else => unreachable,
    }
}

pub fn cc() std.builtin.CallingConvention {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .x86_64_sysv = .{} },
        .aarch64 => .{ .aarch64_aapcs = .{} },
        else => unreachable,
    };
}

/// Called by the kernel entry point after the bootloader has already set SP
/// to the kernel stack (via switchStackAndCall). Jumps to the trampoline
/// with boot_info as the first argument.
pub inline fn kEntry(boot_info: *BootInfo, ktrampoline: *const fn (*BootInfo) callconv(cc()) noreturn) noreturn {
    // The bootloader already switched SP. Just tail-call the trampoline.
    ktrampoline(boot_info);
}

/// Switch SP to a new stack and call a function. Used by the bootloader to
/// switch from the UEFI stack (which may be invalid after exitBootServices)
/// to the kernel stack before entering the kernel.
pub inline fn switchStackAndCall(stack_top: VAddr, arg: u64, entry: u64) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\movq %[sp], %%rsp
                \\movq %%rsp, %%rbp
                \\movq %[arg], %%rdi
                \\jmp *%[entry]
                :
                : [sp] "r" (stack_top.addr),
                  [arg] "r" (arg),
                  [entry] "r" (entry),
                : .{ .rsp = true, .rbp = true, .rdi = true });
        },
        .aarch64 => {
            // Follow Linux arm64's rule: MAIR_EL1 is only ever written
            // with the MMU disabled. We stay on UEFI's MAIR here —
            // changing it while the MMU is on and stale WB cache lines
            // may exist at our physical pages produces "constrained
            // unpredictable" reads on Cortex-A72 KVM (head.S:85-131,
            // proc.S:__cpu_setup). Our kernel-side page tables use
            // attr_indx=1 which under UEFI's MAIR is Normal NC — that
            // is slower but correct. If/when the kernel needs Write-
            // Back performance, it must perform the proper MMU-off →
            // clean → MAIR write → MMU-on cycle from its own code.
            //
            // Mask IRQ/FIQ/SError so no stale firmware interrupt can
            // reach its VBAR between here and the kernel installing
            // its real exception vectors.
            asm volatile (
                \\msr daifset, #0x7
                \\isb
                \\mov sp, %[sp]
                \\mov x0, %[arg]
                \\br %[entry]
                :
                : [sp] "r" (stack_top.addr),
                  [arg] "r" (arg),
                  [entry] "r" (entry),
                : .{ .x0 = true, .memory = true });
        },
        else => unreachable,
    }
    unreachable;
}

/// Spin-loop hint. Reduces power and inter-core memory traffic while
/// busy-waiting on an atomic.
pub inline fn cpuRelax() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
        else => unreachable,
    }
}

pub fn halt() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.halt(),
        .aarch64 => aarch64.cpu.halt(),
        else => unreachable,
    }
}

/// Align a stack pointer for the target architecture's calling convention.
/// x86-64: 16-byte aligned minus 8 (simulates the return address push by `call`).
/// aarch64: 16-byte aligned (SP must be 16-byte aligned at all times).
pub fn alignStack(stack_top: VAddr) VAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.alignStack(stack_top),
        .aarch64 => aarch64.cpu.alignStack(stack_top),
        else => unreachable,
    };
}
