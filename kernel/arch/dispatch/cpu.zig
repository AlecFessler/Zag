const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const BootInfo = zag.boot.protocol.BootInfo;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.proc.process.Process;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

// --- Fault / context types ---------------------------------------------

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

// --- Calling convention / entry ----------------------------------------

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

// --- Control primitives ------------------------------------------------

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

// --- Interrupt enable state (CPU IF / DAIF) ----------------------------

pub fn enableInterrupts() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.enableInterrupts(),
        .aarch64 => aarch64.cpu.enableInterrupts(),
        else => unreachable,
    }
}

pub fn saveAndDisableInterrupts() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.saveAndDisableInterrupts(),
        .aarch64 => aarch64.cpu.saveAndDisableInterrupts(),
        else => unreachable,
    };
}

pub fn restoreInterrupts(state: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.restoreInterrupts(state),
        .aarch64 => aarch64.cpu.restoreInterrupts(state),
        else => unreachable,
    }
}

// --- User-memory access gate (SMAP / PAN) ------------------------------

/// Temporarily allow kernel access to user pages.
/// x86: STAC (clear AC flag, disabling SMAP).
/// aarch64: clear PSTATE.PAN (disabling Privileged Access Never).
pub inline fn userAccessBegin() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.stac(),
        .aarch64 => aarch64.cpu.panDisable(),
        else => unreachable,
    }
}

/// Re-enable kernel protection from user page access.
/// x86: CLAC (set AC flag, enabling SMAP).
/// aarch64: set PSTATE.PAN (enabling Privileged Access Never).
pub inline fn userAccessEnd() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.clac(),
        .aarch64 => aarch64.cpu.panEnable(),
        else => unreachable,
    }
}

// --- Interrupt controller (APIC / GIC) ---------------------------------

pub fn unmaskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq),
        .aarch64 => aarch64.irq.unmaskIrq(irq),
        else => unreachable,
    }
}

pub fn findIrqForDevice(device: *DeviceRegion) ?u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.findIrqForDevice(device),
        .aarch64 => aarch64.irq.findIrqForDevice(device),
        else => unreachable,
    };
}

pub fn clearIrqPendingBit(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.clearIrqPendingBit(irq_line),
        .aarch64 => {}, // stub
        else => unreachable,
    }
}

// --- Cache maintenance -------------------------------------------------

/// Synchronize the instruction cache with the data cache after writing
/// new executable code to memory. On x86-64 this is a no-op (coherent
/// I-cache). On aarch64 the I/D caches are separate and loader code must
/// explicitly invalidate the I-cache before fetching freshly written
/// instructions, or stale bytes can be decoded as garbage.
pub fn syncInstructionCache() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => asm volatile (
            \\ic ialluis
            \\dsb ish
            \\isb
            ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// Clean the data cache over the given byte range to the Point of
/// Unification. On x86-64 this is a no-op (coherent caches). On aarch64
/// this is required after writing freshly loaded ELF code through the
/// physmap (D-cache) view: until the lines are pushed past the unified
/// PoU, a subsequent `ic ivau`/`ic ialluis` cannot make the new
/// instruction bytes visible to instruction fetch, and the user's
/// entry point fetches stale (typically zero) bytes — manifesting as
/// repeating instruction-abort exceptions on every ERET.
///
/// ARM ARM B2.4.6 / D5.10.2: data-to-instruction cache coherency.
pub fn cleanDcacheToPou(start: u64, len: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            if (len == 0) return;
            // Conservative 64-byte cache line for Cortex-A72/A76. The
            // exact line size is in CTR_EL0.DminLine; using 64 bytes
            // simply over-cleans on cores with smaller lines, which is
            // safe.
            const line: u64 = 64;
            const end = start + len;
            var addr = start & ~(line - 1);
            while (addr < end) : (addr += line) {
                asm volatile ("dc cvau, %[a]"
                    :
                    : [a] "r" (addr),
                    : .{ .memory = true });
            }
            asm volatile ("dsb ish" ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

/// Clean + invalidate the data cache over the given byte range to the
/// point of coherency. On x86-64 this is a no-op (coherent D-cache). On
/// aarch64 this is required when memory is reconfigured from Normal
/// Non-cacheable to Normal Write-Back (e.g., when the kernel installs
/// its own MAIR_EL1 over UEFI's), otherwise stale cache lines from a
/// prior cacheable view can shadow freshly written NC data.
pub fn cleanInvalidateDcacheRange(start: u64, len: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            // Drain any pending Normal Non-cacheable stores from the
            // write buffer to RAM before we start cleaning the cache.
            // Without this, NC writes may still be in flight when DC
            // CIVAC runs, and subsequent WB reads can race past the
            // pending writes.
            asm volatile ("dsb sy" ::: .{ .memory = true });
            // 64-byte cache line on Cortex-A72. Use a conservative
            // fixed line size rather than reading CTR_EL0 here.
            const line: u64 = 64;
            const end = start + len;
            var addr = start & ~(line - 1);
            while (addr < end) : (addr += line) {
                asm volatile ("dc civac, %[a]"
                    :
                    : [a] "r" (addr),
                    : .{ .memory = true });
            }
            asm volatile (
                \\dsb sy
                \\isb
                ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

// --- FPU state (per-thread FP/SIMD save/restore) -----------------------

/// Initialise an FPU buffer to the architectural reset state for a
/// brand-new thread (FCW/MXCSR defaults on x64; FPCR/FPSR defaults
/// on aarch64). Called once from `Thread.create`.
pub fn fpuStateInit(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuStateInit(area),
        .aarch64 => aarch64.cpu.fpuStateInit(area),
        else => unreachable,
    }
}

/// Save the current core's FP/SIMD register file into `area`.
/// `area` must be 64-byte aligned and at least 576 bytes (FXSAVE format
/// on x64; V0-V31 + FPCR + FPSR on aarch64).
pub fn fpuSave(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuSave(area),
        .aarch64 => aarch64.cpu.fpuSave(area),
        else => unreachable,
    }
}

/// Restore the FP/SIMD register file from `area`. Same alignment and
/// format requirements as `fpuSave`.
pub fn fpuRestore(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuRestore(area),
        .aarch64 => aarch64.cpu.fpuRestore(area),
        else => unreachable,
    }
}

/// Re-enable user-mode FP access on the local core after a trap was
/// serviced. x64: clear CR0.TS via CLTS. aarch64: set CPACR_EL1.FPEN
/// to 0b11 (EL0 and EL1 both allowed).
pub fn fpuClearTrap() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuClearTrap(),
        .aarch64 => aarch64.cpu.fpuClearTrap(),
        else => unreachable,
    }
}

/// Synchronously flush `thread`'s FP state from the source core's
/// registers into `thread.fpu_state`. Called by the destination core
/// when work-stealing has migrated `thread` and a subsequent
/// `fpuRestore` would otherwise read stale buffer contents. Sends an
/// IPI and spins until the source core acknowledges.
pub fn fpuFlushIpi(target_core: u8, thread: *Thread) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuFlushIpi(target_core, thread),
        .aarch64 => aarch64.cpu.fpuFlushIpi(target_core, thread),
        else => unreachable,
    }
}

// --- Power / shutdown / entropy ----------------------------------------

pub const PowerAction = switch (builtin.cpu.arch) {
    .x86_64 => x64.power.PowerAction,
    .aarch64 => aarch64.power.PowerAction,
    else => unreachable,
};

pub const CpuPowerAction = switch (builtin.cpu.arch) {
    .x86_64 => x64.power.CpuPowerAction,
    .aarch64 => aarch64.power.CpuPowerAction,
    else => unreachable,
};

pub fn powerAction(action: PowerAction) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.power.powerAction(action),
        .aarch64 => aarch64.power.powerAction(action),
        else => unreachable,
    };
}

pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.power.cpuPowerAction(action, value),
        .aarch64 => aarch64.power.cpuPowerAction(action, value),
        else => unreachable,
    };
}

/// Read a hardware-random word. RDRAND on x86-64, RNDR on aarch64.
/// Returns null if the instruction failed (entropy pool stall) or is
/// unsupported on this CPU.
pub fn getRandom() ?u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdrand(),
        .aarch64 => aarch64.cpu.rndr(),
        else => unreachable,
    };
}

/// Probe CPU feature bits backing `arch.memory.zeroPage`. Called once
/// from the PMM initialization path before any freed page is zeroed.
pub fn initZeroPageFeatures() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.initZeroPageFeatures(),
        .aarch64 => aarch64.cpu.initZeroPageFeatures(),
        else => unreachable,
    }
}

// --- Per-core hardware state (freq / temp / C-state) -------------------

/// One-time bring-up on the bootstrap core. Called from `kMain` after
/// pmuInit and before `sched.globalInit`.
pub fn sysInfoInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoInit(),
        .aarch64 => aarch64.sysinfo.sysInfoInit(),
        else => unreachable,
    }
}

/// Per-core bring-up. Runs on every core from `sched.perCoreInit`
/// alongside `pmuPerCoreInit`.
pub fn sysInfoPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoPerCoreInit(),
        .aarch64 => aarch64.sysinfo.sysInfoPerCoreInit(),
        else => unreachable,
    }
}

/// Sample this core's frequency / temperature / C-state into its cache
/// slot. Called from schedTimerHandler on every scheduler tick. Must run
/// on the target core because the underlying MSR reads are core-local.
pub fn sampleCoreHwState() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sampleCoreHwState(),
        .aarch64 => aarch64.sysinfo.sampleCoreHwState(),
        else => unreachable,
    }
}

/// Read the cached current frequency of `core_id` in hertz. Up to one
/// scheduler tick stale for remote cores.
pub fn getCoreFreq(core_id: u64) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreFreq(core_id),
        .aarch64 => aarch64.sysinfo.getCoreFreq(core_id),
        else => unreachable,
    };
}

/// Read the cached current temperature of `core_id` in milli-celsius.
pub fn getCoreTemp(core_id: u64) u32 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreTemp(core_id),
        .aarch64 => aarch64.sysinfo.getCoreTemp(core_id),
        else => unreachable,
    };
}

/// Read the cached current C-state level of `core_id`. 0 means active;
/// higher values indicate progressively deeper idle states.
pub fn getCoreState(core_id: u64) u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreState(core_id),
        .aarch64 => aarch64.sysinfo.getCoreState(core_id),
        else => unreachable,
    };
}
