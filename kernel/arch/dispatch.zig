const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const BootInfo = zag.boot.protocol.BootInfo;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Range = zag.utils.range.Range;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const PmuCounterConfig = zag.syscall.pmu.PmuCounterConfig;
const PmuInfo = zag.syscall.pmu.PmuInfo;
const PmuSample = zag.syscall.pmu.PmuSample;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const Timer = zag.arch.timer.Timer;
const VAddr = zag.memory.address.VAddr;

/// Number of general-purpose registers saved in a fault snapshot.
/// x86-64: 15 (rax-r15 minus rsp). aarch64: 31 (x0-x30).
pub const fault_gpr_count: usize = switch (builtin.cpu.arch) {
    .x86_64 => 15,
    .aarch64 => 31,
    else => unreachable,
};

/// Size of the register portion of a FaultMessage: ip + flags + sp + GPRs.
pub const fault_regs_size: usize = (3 + fault_gpr_count) * @sizeOf(u64);

/// Total size of a FaultMessage written to userspace (32-byte header + regs).
pub const fault_msg_size: usize = 32 + fault_regs_size;

/// Architecture-neutral snapshot of a faulted thread's registers.
/// Used by fault delivery to serialize register state without the
/// generic kernel referencing arch-specific register names.
pub const FaultRegSnapshot = struct {
    ip: u64,
    flags: u64,
    sp: u64,
    gprs: [fault_gpr_count]u64,
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

// ── Syscall / IPC Register Abstraction ───────────────────────────────────
// These helpers let generic kernel code access syscall arguments and IPC
// payload registers without naming architecture-specific register fields.

pub const SyscallArgs = struct {
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
};

pub fn getSyscallArgs(ctx: *const ArchCpuContext) SyscallArgs {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{
            .num = ctx.regs.rax,
            .arg0 = ctx.regs.rdi,
            .arg1 = ctx.regs.rsi,
            .arg2 = ctx.regs.rdx,
            .arg3 = ctx.regs.r10,
            .arg4 = ctx.regs.r8,
        },
        .aarch64 => .{
            .num = ctx.regs.x8,
            .arg0 = ctx.regs.x0,
            .arg1 = ctx.regs.x1,
            .arg2 = ctx.regs.x2,
            .arg3 = ctx.regs.x3,
            .arg4 = ctx.regs.x4,
        },
        else => unreachable,
    };
}

pub fn getIpcHandle(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r13,
        .aarch64 => ctx.regs.x5,
        else => unreachable,
    };
}

pub fn getIpcMetadata(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r14,
        .aarch64 => ctx.regs.x6,
        else => unreachable,
    };
}

pub fn setIpcMetadata(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r14 = value,
        .aarch64 => ctx.regs.x6 = value,
        else => unreachable,
    }
}

pub fn getIpcPayloadWords(ctx: *const ArchCpuContext) [5]u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ ctx.regs.rdi, ctx.regs.rsi, ctx.regs.rdx, ctx.regs.r8, ctx.regs.r9 },
        .aarch64 => .{ ctx.regs.x0, ctx.regs.x1, ctx.regs.x2, ctx.regs.x3, ctx.regs.x4 },
        else => unreachable,
    };
}

pub fn copyIpcPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.copyIpcPayload(dst, src, word_count),
        .aarch64 => aarch64.interrupts.copyIpcPayload(dst, src, word_count),
        else => unreachable,
    };
}

pub const IpcPayloadSnapshot = struct { words: [5]u64 };

pub fn saveIpcPayload(ctx: *const ArchCpuContext) IpcPayloadSnapshot {
    return .{ .words = getIpcPayloadWords(ctx) };
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, snap: IpcPayloadSnapshot) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.restoreIpcPayload(ctx, snap.words),
        .aarch64 => aarch64.interrupts.restoreIpcPayload(ctx, snap.words),
        else => unreachable,
    }
}

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

// ── Address Space Layout ────────────────────────────────────────────────
// Architecture-specific virtual address space boundaries. These define
// the user/kernel split, physmap location, and kernel code range.

pub const addr_space = switch (builtin.cpu.arch) {
    .x86_64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0xFFFF_8000_0000_0000,
        };
        pub const kernel: Range = .{
            .start = 0xFFFF_8000_0000_0000,
            .end = 0xFFFF_8400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        pub const kernel_code: Range = .{
            .start = 0xFFFF_FFFF_8000_0000,
            .end = 0xFFFF_FFFF_C000_0000,
        };
    },
    .aarch64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0x0001_0000_0000_0000,
        };
        // Kernel heap/data (above kernel_code).
        pub const kernel: Range = .{
            .start = 0xFFFF_0000_4000_0000,
            .end = 0xFFFF_0400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        // Kernel text/rodata (bottom of TTBR1 range).
        pub const kernel_code: Range = .{
            .start = 0xFFFF_0000_0000_0000,
            .end = 0xFFFF_0000_4000_0000,
        };
    },
    else => unreachable,
};

/// ASLR range for userspace allocations (subset of addr_space.user).
pub const user_aslr: Range = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    .aarch64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    else => unreachable,
};

/// Align a stack pointer for the target architecture's calling convention.
/// x86-64: 16-byte aligned minus 8 (simulates the return address push by `call`).
/// aarch64: 16-byte aligned (SP must be 16-byte aligned at all times).
pub fn isRelativeRelocation(rela_type: u32) bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => rela_type == @intFromEnum(std.elf.R_X86_64.RELATIVE),
        .aarch64 => rela_type == @intFromEnum(std.elf.R_AARCH64.RELATIVE),
        else => unreachable,
    };
}

/// Classification of ELF relocation types for KASLR slide application.
pub const RelocAction = enum { skip, abs64, abs32, unsupported };

/// Classify a relocation type for KASLR processing.
pub fn classifyRelocation(rtype: u32) RelocAction {
    return switch (builtin.cpu.arch) {
        .x86_64 => {
            if (rtype == @intFromEnum(std.elf.R_X86_64.PC32) or
                rtype == @intFromEnum(std.elf.R_X86_64.PLT32) or
                rtype == @intFromEnum(std.elf.R_X86_64.NONE)) return .skip;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"64")) return .abs64;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"32S")) return .abs32;
            return .unsupported;
        },
        .aarch64 => {
            const R = std.elf.R_AARCH64;
            // PC-relative: no adjustment needed (both sides move by slide).
            // LO12: low 12 bits unchanged with page-aligned slide.
            if (rtype == @intFromEnum(R.NONE) or
                rtype == @intFromEnum(R.PREL32) or
                rtype == @intFromEnum(R.PREL64) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21_NC) or
                rtype == @intFromEnum(R.ADR_PREL_LO21) or
                rtype == @intFromEnum(R.ADD_ABS_LO12_NC) or
                rtype == @intFromEnum(R.CALL26) or
                rtype == @intFromEnum(R.JUMP26) or
                rtype == @intFromEnum(R.LDST8_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST16_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST32_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST64_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST128_ABS_LO12_NC)) return .skip;
            if (rtype == @intFromEnum(R.ABS64) or
                rtype == @intFromEnum(R.RELATIVE)) return .abs64;
            if (rtype == @intFromEnum(R.ABS32)) return .abs32;
            return .unsupported;
        },
        else => unreachable,
    };
}

pub fn alignStack(stack_top: VAddr) VAddr {
    const aligned = std.mem.alignBackward(u64, stack_top.addr, 16);
    const adjusted = switch (builtin.cpu.arch) {
        .x86_64 => aligned - 8,
        .aarch64 => aligned,
        else => unreachable,
    };
    return VAddr.fromInt(adjusted);
}

/// Install an early fault handler for boot-time exception capture.
/// Used by the bootloader to catch faults during the exitBootServices →
/// kernel handoff window. On x86-64 this is a no-op (UEFI's exception
/// handler is adequate); on aarch64 it installs a minimal VBAR_EL1 that
/// dumps ESR_EL1, FAR_EL1, ELR_EL1 to the PL011 UART and halts.
pub fn installEarlyFaultHandler() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => aarch64.early_fault.installEarlyVbar(),
        else => unreachable,
    }
}

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
                    : .{ .memory = true }
                );
            }
            asm volatile (
                \\dsb sy
                \\isb
                ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

/// Map any device MMIO the early fault handler needs to reach into the
/// kernel page tables. On x86-64 this is a no-op (IO is via port
/// instructions, no translation needed). On aarch64 this identity-maps
/// the PL011 UART so the early fault handler can dump registers even
/// after UEFI's TTBR0 identity mapping has been flushed or dropped.
pub fn mapEarlyDebugDevices(
    addr_space_root: VAddr,
    allocator: std.mem.Allocator,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => try aarch64.early_fault.mapUart(addr_space_root, allocator),
        else => unreachable,
    }
}

/// Called by the kernel entry point after the bootloader has already set SP
/// to the kernel stack (via switchStackAndCall). Jumps to the trampoline
/// with boot_info as the first argument.
pub inline fn kEntry(boot_info: *BootInfo, ktrampoline: *const fn (*BootInfo) callconv(cc()) noreturn) noreturn {
    // The bootloader already switched SP. Just tail-call the trampoline.
    ktrampoline(boot_info);
}

pub fn cc() std.builtin.CallingConvention {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .x86_64_sysv = .{} },
        .aarch64 => .{ .aarch64_aapcs = .{} },
        else => unreachable,
    };
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
                : .{ .rsp = true, .rbp = true, .rdi = true }
            );
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
                : .{ .x0 = true, .memory = true }
            );
        },
        else => unreachable,
    }
    unreachable;
}

pub fn init() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.init.init(),
        .aarch64 => aarch64.init.init(),
        else => unreachable,
    }
}

pub fn parseFirmwareTables(xsdp_paddr: PAddr) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.acpi.parseAcpi(xsdp_paddr),
        .aarch64 => try aarch64.acpi.parseAcpi(xsdp_paddr),
        else => unreachable,
    }
}

pub fn getAddrSpaceRoot() PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.getAddrSpaceRoot(),
        .aarch64 => return aarch64.paging.getAddrSpaceRoot(),
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

pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPage(addr_space_root, phys, virt, perms),
        .aarch64 => try aarch64.paging.mapPage(addr_space_root, phys, virt, perms),
        else => unreachable,
    }
}

pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    allocator: std.mem.Allocator,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, allocator),
        .aarch64 => try aarch64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, allocator),
        else => unreachable,
    }
}

pub fn freeUserAddrSpace(addr_space_root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.freeUserAddrSpace(addr_space_root),
        .aarch64 => aarch64.paging.freeUserAddrSpace(addr_space_root),
        else => unreachable,
    }
}

pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.unmapPage(addr_space_root, virt),
        .aarch64 => return aarch64.paging.unmapPage(addr_space_root, virt),
        else => unreachable,
    }
}

pub fn updatePagePerms(
    addr_space_root: PAddr,
    virt: VAddr,
    new_perms: MemoryPerms,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.updatePagePerms(addr_space_root, virt, new_perms),
        .aarch64 => aarch64.paging.updatePagePerms(addr_space_root, virt, new_perms),
        else => unreachable,
    }
}

pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.resolveVaddr(addr_space_root, virt),
        .aarch64 => return aarch64.paging.resolveVaddr(addr_space_root, virt),
        else => unreachable,
    }
}

pub fn swapAddrSpace(root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.swapAddrSpace(root),
        .aarch64 => aarch64.paging.swapAddrSpace(root),
        else => unreachable,
    }
}

/// Read the Memory Attribute Indirection Register.
/// On aarch64: MAIR_EL1. On x86-64: returns 0 (not applicable).
pub fn readMair() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => 0,
        .aarch64 => asm volatile ("mrs %[ret], mair_el1"
            : [ret] "=r" (-> u64),
        ),
        else => unreachable,
    };
}

/// Read the Translation Control Register.
/// On aarch64: TCR_EL1. On x86-64: returns 0.
pub fn readTcr() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => 0,
        .aarch64 => asm volatile ("mrs %[ret], tcr_el1"
            : [ret] "=r" (-> u64),
        ),
        else => unreachable,
    };
}

/// Write a single character to the platform's early debug output.
/// On x86-64: serial port 0x3F8. On aarch64: PL011 at physmap + 0x09000000.
/// Used before the serial driver is initialized. The physmap VA is used
/// because the identity mapping may have been dropped.
pub inline fn earlyDebugChar(c: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile ("outb %[val], %[port]"
                :
                : [val] "{al}" (c),
                  [port] "N{dx}" (@as(u16, 0x3F8)),
            );
        },
        .aarch64 => {
            // PL011 at physical 0x09000000 via TTBR0 identity mapping
            // (UEFI firmware) or via mapEarlyDebugDevices() which
            // identity-maps it into our kernel page table too.
            const uart: *volatile u32 = @ptrFromInt(0x09000000);
            uart.* = c;
        },
        else => unreachable,
    }
}

pub fn earlyDebugHex(v: u64) void {
    var shift: u6 = 60;
    while (true) {
        const nibble: u8 = @intCast((v >> shift) & 0xF);
        const ch: u8 = if (nibble < 10) '0' + nibble else 'A' + (nibble - 10);
        earlyDebugChar(ch);
        if (shift == 0) break;
        shift -= 4;
    }
}

/// Enable kernel-space translation. On aarch64 this configures TCR_EL1 to
/// enable TTBR1 walks with 48-bit VA and 4KB granule. On x86-64 this is a
/// no-op since CR3 already covers the full address space.
pub fn enableKernelTranslation() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            aarch64.paging.initMairIndices();
            aarch64.paging.enableKernelTranslation();
        },
        else => unreachable,
    }
}

/// Set the memory attribute indirection register to our expected values.
/// On aarch64 this writes MAIR_EL1 (index 0 = Device, index 1 = Normal WB).
/// Must be called after UEFI boot services exit, before jumping to the kernel.
/// On x86-64 this is a no-op (PAT is set up by the kernel).
pub fn setMemoryAttributes() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => aarch64.paging.setMair(),
        else => unreachable,
    }
}

/// Whether the kernel page table root is the same as the user table.
/// On x86-64 (single CR3) the bootloader must copy the UEFI identity map
/// into the new kernel table. On aarch64 (split TTBR0/TTBR1) the kernel
/// table is independent and should start clean.
pub const kernel_shares_user_table: bool = switch (builtin.cpu.arch) {
    .x86_64 => true,
    .aarch64 => false,
    else => unreachable,
};

/// Return the physical address of the kernel page table root.
/// On x86-64 this is the same as getAddrSpaceRoot() since CR3 covers both
/// halves. On aarch64 this reads TTBR1_EL1 (upper/kernel VA range).
pub fn getKernelAddrSpaceRoot() PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.getAddrSpaceRoot(),
        .aarch64 => aarch64.paging.getKernelAddrSpaceRoot(),
        else => unreachable,
    };
}

/// Set the kernel page table root.
/// On x86-64 this is swapAddrSpace (same CR3). On aarch64 this writes
/// TTBR1_EL1 (upper/kernel VA range).
pub fn setKernelAddrSpace(root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.swapAddrSpace(root),
        .aarch64 => aarch64.paging.setKernelAddrSpace(root),
        else => unreachable,
    }
}

pub fn coreCount() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreCount(),
        .aarch64 => aarch64.gic.coreCount(),
        else => unreachable,
    };
}

pub fn coreID() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreID(),
        .aarch64 => aarch64.gic.coreID(),
        else => unreachable,
    };
}

pub fn copyKernelMappings(root: VAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.copyKernelMappings(root),
        .aarch64 => aarch64.paging.copyKernelMappings(root),
        else => unreachable,
    }
}

pub fn dropIdentityMapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.dropIdentityMapping(),
        .aarch64 => aarch64.paging.dropIdentityMapping(),
        else => unreachable,
    }
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

pub fn serializeFaultRegs(ctx: *const ArchCpuContext) FaultRegSnapshot {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.serializeFaultRegs(ctx),
        .aarch64 => aarch64.interrupts.serializeFaultRegs(ctx),
        else => unreachable,
    };
}

pub fn getSyscallReturn(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.rax,
        .aarch64 => ctx.regs.x0,
        else => unreachable,
    };
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setSyscallReturn(ctx, value),
        .aarch64 => aarch64.interrupts.setSyscallReturn(ctx, value),
        else => unreachable,
    }
}

pub fn getPreemptionTimer() Timer {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.timers.getPreemptionTimer(),
        .aarch64 => return aarch64.timers.getPreemptionTimer(),
        else => unreachable,
    }
}

pub fn getMonotonicClock() Timer {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.timers.getMonotonicClock(),
        .aarch64 => return aarch64.timers.getMonotonicClock(),
        else => unreachable,
    }
}

pub fn smpInit() !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.smp.smpInit(),
        .aarch64 => try aarch64.smp.smpInit(),
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

const sched_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.sched),
    // ARM GIC SGI 0 — Software Generated Interrupts use IDs 0-15.
    .aarch64 => 0,
    else => unreachable,
};

pub fn triggerSchedulerInterrupt(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendIpiToCore(core_id, sched_ipi_vector),
        .aarch64 => aarch64.gic.sendIpiToCore(core_id, sched_ipi_vector),
        else => unreachable,
    }
}

pub fn readTimestamp() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdtscLFenced(),
        .aarch64 => aarch64.cpu.readCntvct(),
        else => unreachable,
    };
}

/// Read a value from an x86 I/O port.
/// Intel SDM Vol 1, §18.2 "I/O Port Addressing" — IN instruction reads 8, 16,
/// or 32 bits from the port address specified in DX (or an immediate byte).
pub fn ioportIn(port: u16, width: u8) u32 {
    return switch (builtin.cpu.arch) {
        .x86_64 => switch (width) {
            1 => @as(u32, x64.cpu.inb(port)),
            2 => @as(u32, x64.cpu.inw(port)),
            4 => x64.cpu.ind(port),
            else => unreachable,
        },
        else => unreachable,
    };
}

/// Write a value to an x86 I/O port.
/// Intel SDM Vol 1, §18.2 "I/O Port Addressing" — OUT instruction writes 8,
/// 16, or 32 bits to the port address specified in DX (or an immediate byte).
pub fn ioportOut(port: u16, width: u8, value: u32) void {
    switch (builtin.cpu.arch) {
        .x86_64 => switch (width) {
            1 => x64.cpu.outb(@truncate(value), port),
            2 => x64.cpu.outw(@truncate(value), port),
            4 => x64.cpu.outd(value, port),
            else => unreachable,
        },
        else => unreachable,
    }
}

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.serial.print(format, args),
        .aarch64 => aarch64.serial.print(format, args),
        else => unreachable,
    }
}

pub fn isDmaRemapAvailable() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.isAvailable(),
        .aarch64 => aarch64.iommu.isAvailable(),
        else => unreachable,
    };
}

pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.mapDmaPages(device, shm),
        .aarch64 => aarch64.iommu.mapDmaPages(device, shm),
        else => unreachable,
    };
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.unmapDmaPages(device, dma_base, num_pages),
        .aarch64 => aarch64.iommu.unmapDmaPages(device, dma_base, num_pages),
        else => unreachable,
    }
}

pub fn enableDmaRemapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.enableTranslation(),
        .aarch64 => aarch64.iommu.enableTranslation(),
        else => unreachable,
    }
}

// --- VM (hardware virtualization) dispatch ---

// --- KVM types dispatched from arch/x64/kvm/ ---

pub const Vm = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vm.Vm,
    .aarch64 => struct {
        pub fn destroy(_: *@This()) void {}
    },
    else => @compileError("unsupported arch for VM"),
};

pub const VmAllocator = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vm.VmAllocator,
    .aarch64 => struct {
        backing: std.mem.Allocator = undefined,
        pub fn init(alloc: std.mem.Allocator) !@This() { return .{ .backing = alloc }; }
        pub fn allocator(self: @This()) std.mem.Allocator { return self.backing; }
    },
    else => @compileError("unsupported arch for VM"),
};

pub const VCpuAllocator = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vcpu.VCpuAllocator,
    .aarch64 => struct {
        backing: std.mem.Allocator = undefined,
        pub fn init(alloc: std.mem.Allocator) !@This() { return .{ .backing = alloc }; }
        pub fn allocator(self: @This()) std.mem.Allocator { return self.backing; }
    },
    else => @compileError("unsupported arch for VM"),
};

pub const GuestState = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestState,
    .aarch64 => aarch64.vm.GuestState,
    else => @compileError("unsupported arch for VM"),
};

pub const VmExitInfo = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.VmExitInfo,
    .aarch64 => aarch64.vm.VmExitInfo,
    else => @compileError("unsupported arch for VM"),
};

pub const GuestInterrupt = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestInterrupt,
    .aarch64 => aarch64.vm.GuestInterrupt,
    else => @compileError("unsupported arch for VM"),
};

pub const GuestException = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestException,
    .aarch64 => aarch64.vm.GuestException,
    else => @compileError("unsupported arch for VM"),
};

pub const VmPolicy = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.VmPolicy,
    .aarch64 => aarch64.vm.VmPolicy,
    else => @compileError("unsupported arch for VM"),
};

pub const FxsaveArea = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.FxsaveArea,
    .aarch64 => aarch64.vm.FxsaveArea,
    else => @compileError("unsupported arch for VM"),
};

pub fn fxsaveInit() FxsaveArea {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.fxsaveInit(),
        .aarch64 => aarch64.vm.fxsaveInit(),
        else => @compileError("unsupported arch for VM"),
    };
}

pub fn vmInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmInit(),
        .aarch64 => aarch64.vm.vmInit(),
        else => unreachable,
    }
}

pub fn vmPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmPerCoreInit(),
        .aarch64 => aarch64.vm.vmPerCoreInit(),
        else => unreachable,
    }
}

pub fn vmSupported() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmSupported(),
        .aarch64 => aarch64.vm.vmSupported(),
        else => unreachable,
    };
}

pub fn vmResume(guest_state: *GuestState, vm_structures: PAddr, guest_fxsave: *align(16) FxsaveArea) VmExitInfo {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmResume(guest_state, vm_structures, guest_fxsave),
        .aarch64 => @panic("unimplemented"),
        else => unreachable,
    };
}

pub fn vmAllocStructures() ?PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmAllocStructures(),
        .aarch64 => null,
        else => unreachable,
    };
}

pub fn vmFreeStructures(paddr: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmFreeStructures(paddr),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn mapGuestPage(vm_structures: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.vm.mapGuestPage(vm_structures, guest_phys, host_phys, rights),
        .aarch64 => @panic("unimplemented"),
        else => unreachable,
    }
}

pub fn unmapGuestPage(vm_structures: PAddr, guest_phys: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.unmapGuestPage(vm_structures, guest_phys),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn vmInjectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.injectInterrupt(guest_state, interrupt),
        .aarch64 => {},
        else => unreachable,
    }
}

pub fn vmInjectException(guest_state: *GuestState, exception: GuestException) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.injectException(guest_state, exception),
        .aarch64 => {},
        else => unreachable,
    }
}

/// Modify MSR passthrough bits in the VM's MSR permission map.
/// On AMD SVM: AMD APM Vol 2, §15.10 "MSR Intercepts" — the MSRPM is an 8-KB
/// bitmap; two bits per MSR (bit 0 = read intercept, bit 1 = write intercept);
/// 0 = passthrough, 1 = intercept. MSRs 0x0000–0x1FFF at byte offset 0x000;
/// MSRs 0xC0000000–0xC0001FFF at byte offset 0x800.
/// On Intel VMX: Intel SDM Vol 3C, §24.6.9 "MSR-Bitmap Address" — a 4-KB
/// bitmap with four 1-KB regions for RDMSR/WRMSR on low/high MSR ranges.
pub fn vmMsrPassthrough(vm_structures: PAddr, msr_num: u32, allow_read: bool, allow_write: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.msrPassthrough(vm_structures, msr_num, allow_read, allow_write),
        .aarch64 => {},
        else => unreachable,
    }
}




// --- PMU (performance monitoring unit) dispatch (systems.md §arch-interface, §pmu) ---

pub const PmuState = switch (builtin.cpu.arch) {
    .x86_64 => x64.pmu.PmuState,
    .aarch64 => aarch64.pmu.PmuState,
    else => @compileError("unsupported arch for PMU"),
};

/// Compile-time ceiling on the number of counter slots in `PmuSample`.
/// Duplicated from `zag.syscall.pmu.MAX_COUNTERS` so the arch dispatch
/// layer does not force its callers to pull in `zag.syscall.pmu` just to
/// size a stack buffer.
pub const pmu_max_counters: usize = 8;

pub fn pmuInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuInit(),
        .aarch64 => aarch64.pmu.pmuInit(),
        else => unreachable,
    }
}

pub fn pmuPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuPerCoreInit(),
        .aarch64 => aarch64.pmu.pmuPerCoreInit(),
        else => unreachable,
    }
}

pub fn pmuGetInfo() PmuInfo {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuGetInfo(),
        .aarch64 => aarch64.pmu.pmuGetInfo(),
        else => unreachable,
    };
}

pub fn pmuSave(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuSave(state),
        .aarch64 => aarch64.pmu.pmuSave(state),
        else => unreachable,
    }
}

pub fn pmuRestore(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuRestore(state),
        .aarch64 => aarch64.pmu.pmuRestore(state),
        else => unreachable,
    }
}

pub fn pmuStart(state: *PmuState, configs: []const PmuCounterConfig) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.pmu.pmuStart(state, configs),
        .aarch64 => try aarch64.pmu.pmuStart(state, configs),
        else => unreachable,
    }
}

pub fn pmuRead(state: *PmuState, sample: *PmuSample) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuRead(state, sample),
        .aarch64 => aarch64.pmu.pmuRead(state, sample),
        else => unreachable,
    }
}

pub fn pmuReset(state: *PmuState, configs: []const PmuCounterConfig) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.pmu.pmuReset(state, configs),
        .aarch64 => try aarch64.pmu.pmuReset(state, configs),
        else => unreachable,
    }
}

pub fn pmuStop(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuStop(state),
        .aarch64 => aarch64.pmu.pmuStop(state),
        else => unreachable,
    }
}

/// Stamp `state` with `configs` without touching any hardware registers.
/// Used by the generic PMU syscall layer when an external profiler calls
/// pmu_start / pmu_reset on a non-running target thread; the target's
/// next `pmuRestore` programs the hardware when it is rescheduled.
pub fn pmuConfigureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuConfigureState(state, configs),
        .aarch64 => aarch64.pmu.pmuConfigureState(state, configs),
        else => unreachable,
    }
}

/// Zero `state` for a non-running target without touching any hardware
/// registers. Used by pmu_stop / Thread.deinit on remote targets and on
/// thread teardown.
pub fn pmuClearState(state: *PmuState) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pmu.pmuClearState(state),
        .aarch64 => aarch64.pmu.pmuClearState(state),
        else => unreachable,
    }
}

// --- Wall clock (systems.md §wall-clock) ---

pub fn readRtc() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.rtc.readRtc(),
        .aarch64 => 0,
        else => unreachable,
    };
}

// --- Randomness (systems.md §randomness) ---

pub fn getRandom() ?u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdrand(),
        .aarch64 => aarch64.cpu.rndr(),
        else => unreachable,
    };
}

// --- IRQ notification (systems.md §irq-delivery) ---

pub fn maskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq),
        .aarch64 => aarch64.irq.maskIrq(irq),
        else => unreachable,
    }
}

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

pub fn registerIrqOwner(irq_line: u8, proc: *zag.proc.process.Process, slot_index: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.registerIrqOwner(irq_line, proc, slot_index),
        .aarch64 => {}, // stub
        else => unreachable,
    }
}

// --- Power control (systems.md §power) ---

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

// --- System info (sys_info) dispatch (systems.md §arch-interface, §sysinfo) ---

/// One-time system-info bring-up on the bootstrap core. Called from `kMain`
/// after `arch.pmuInit()` and before `sched.globalInit()`.
pub fn sysInfoInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoInit(),
        .aarch64 => aarch64.sysinfo.sysInfoInit(),
        else => unreachable,
    }
}

/// Per-core system-info bring-up. Runs on every core from `sched.perCoreInit`
/// alongside `arch.pmuPerCoreInit`.
pub fn sysInfoPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoPerCoreInit(),
        .aarch64 => aarch64.sysinfo.sysInfoPerCoreInit(),
        else => unreachable,
    }
}

/// Sample this core's frequency / temperature / C-state into its cache slot.
/// Called from `schedTimerHandler` on every scheduler tick. Must run on the
/// target core because the underlying MSR reads are core-local.
pub fn sampleCoreHwState() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sampleCoreHwState(),
        .aarch64 => aarch64.sysinfo.sampleCoreHwState(),
        else => unreachable,
    }
}

/// Read the cached current frequency of `core_id` in hertz. Up to one
/// scheduler tick stale for remote cores. See systems.md §sysinfo for the
/// tick-sampled cache design.
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

// --- KVM syscall dispatch ---
// These dispatch the syscall-facing KVM operations through the arch boundary.
// The KVM implementation lives in arch/x64/kvm/ and is inherently x86-specific;
// only this thin syscall interface is abstracted.

const ArchCpuContextLocal = ArchCpuContext;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Process = zag.proc.process.Process;

pub fn kvmVmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.vmCreate(proc, vcpu_count, policy_ptr),
        else => -14, // E_NOSYS
    };
}

pub fn kvmGuestMap(proc: *Process, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.guestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights),
        else => -14,
    };
}

pub fn kvmVmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContextLocal, vm_handle: u64, buf_ptr: u64, blocking: bool) SyscallResult {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking),
        else => .{ .ret = -14 },
    };
}

pub fn kvmVmReply(proc: *Process, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmReply(proc, vm_handle, exit_token, action_ptr),
        else => -14,
    };
}

pub fn kvmVcpuSetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuSetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn kvmVcpuGetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuGetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn kvmVcpuRun(proc: *Process, thread_handle: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuRun(proc, thread_handle),
        else => -14,
    };
}

pub fn kvmVcpuInterrupt(proc: *Process, thread_handle: u64, interrupt_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuInterrupt(proc, thread_handle, interrupt_ptr),
        else => -14,
    };
}

pub fn kvmMsrPassthrough(proc: *Process, vm_handle: u64, msr_num: u32, allow_read: bool, allow_write: bool) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.msrPassthrough(proc, vm_handle, msr_num, allow_read, allow_write),
        else => -14,
    };
}

pub fn kvmIoapicAssertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.ioapicAssertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

pub fn kvmIoapicDeassertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.ioapicDeassertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

pub fn kvmVcpuFromThread(vm_obj: *Vm, thread: *Thread) ?*x64.kvm.vcpu.VCpu {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuFromThread(vm_obj, thread),
        else => null,
    };
}

pub fn kvmSetVmAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.allocator = alloc,
        else => {},
    }
}

pub fn kvmSetVcpuAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.allocator = alloc,
        else => {},
    }
}
