const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const BootInfo = zag.boot.protocol.BootInfo;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const Timer = zag.arch.timer.Timer;
const VAddr = zag.memory.address.VAddr;

pub inline fn kEntry(boot_info: *BootInfo, ktrampoline: *const fn (*BootInfo) callconv(cc()) noreturn) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\movq %[sp], %%rsp
                \\movq %%rsp, %%rbp
                \\movq %[arg], %%rdi
                \\jmp *%[ktrampoline]
                :
                : [sp] "r" (boot_info.stack_top.addr),
                  [arg] "r" (@intFromPtr(boot_info)),
                  [ktrampoline] "r" (@intFromPtr(ktrampoline)),
                : .{ .rsp = true, .rbp = true, .rdi = true }
            );
        },
        .aarch64 => {},
        else => unreachable,
    }
    unreachable;
}

pub fn cc() std.builtin.CallingConvention {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .x86_64_sysv = .{} },
        .aarch64 => .{ .aarch64_aapcs = .{} },
        else => unreachable,
    };
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

pub fn coreCount() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreCount(),
        .aarch64 => aarch64.apic.coreCount(),
        else => unreachable,
    };
}

pub fn coreID() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.coreID(),
        .aarch64 => aarch64.apic.coreID(),
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

pub fn triggerSchedulerInterrupt(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            if (core_id == x64.apic.coreID()) {
                x64.apic.sendSelfIpi(@intFromEnum(x64.interrupts.IntVecs.sched));
            } else {
                x64.apic.sendIpi(
                    @intCast(x64.apic.lapics.?[core_id].apic_id),
                    @intFromEnum(x64.interrupts.IntVecs.sched),
                );
            }
        },
        .aarch64 => {
            if (core_id == aarch64.apic.coreID()) {
                aarch64.apic.sendSelfIpi(@intFromEnum(aarch64.interrupts.IntVecs.sched));
            } else {
                aarch64.apic.sendIpi(
                    @intCast(aarch64.apic.lapics.?[core_id].apic_id),
                    @intFromEnum(aarch64.interrupts.IntVecs.sched),
                );
            }
        },
        else => unreachable,
    }
}

pub fn readTimestamp() u64 {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.cpu.rdtscLFenced(),
        .aarch64 => return 0,
        else => unreachable,
    }
}

pub fn shutdown() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.qemuShutdown(),
        .aarch64 => aarch64.cpu.halt(),
        else => unreachable,
    }
}

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
        .aarch64 => false,
        else => unreachable,
    };
}

pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.mapDmaPages(device, shm),
        .aarch64 => @panic("unimplemented"),
        else => unreachable,
    };
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.unmapDmaPages(device, dma_base, num_pages),
        .aarch64 => @panic("unimplemented"),
        else => unreachable,
    }
}

pub fn enableDmaRemapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.enableTranslation(),
        .aarch64 => @panic("unimplemented"),
        else => unreachable,
    }
}

// --- VM (hardware virtualization) dispatch ---

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

/// Modify MSR passthrough bits in the VM's MSRPM.
pub fn vmMsrPassthrough(vm_structures: PAddr, msr_num: u32, allow_read: bool, allow_write: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.msrPassthrough(vm_structures, msr_num, allow_read, allow_write),
        .aarch64 => {},
        else => unreachable,
    }
}
