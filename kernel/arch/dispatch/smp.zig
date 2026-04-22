const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const Thread = zag.sched.thread.Thread;

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

pub fn smpInit() !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.smp.smpInit(),
        .aarch64 => try aarch64.smp.smpInit(),
        else => unreachable,
    }
}

pub fn triggerSchedulerInterrupt(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendSchedulerIpi(core_id),
        .aarch64 => aarch64.gic.sendSchedulerIpi(core_id),
        else => unreachable,
    }
}

/// Fast-path self-scheduler-interrupt for the local core. On x86-64 the
/// helper executes `int 0xFE` directly — a software interrupt dispatched
/// through the IDT without a vm-exit, unlike the APIC self-IPI which
/// requires a WRMSR. On aarch64 there is no analogous cheap path, so the
/// helper just sends an SGI to the local core.
pub inline fn triggerSchedulerInterruptSelf() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendSchedulerIpiSelf(),
        .aarch64 => aarch64.gic.sendSchedulerIpiSelf(),
        else => unreachable,
    }
}

/// Kprof-dump IPI vector. Chosen in the same reserved high-vector band
/// as the scheduler / TLB-shootdown / spurious vectors so it stays out
/// of the device IRQ range.
const kprof_dump_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.kprof_dump),
    // ARM GIC SGI 1 — SGI 0 is claimed by the scheduler IPI.
    .aarch64 => 1,
    else => unreachable,
};

/// Send a kprof-dump IPI to every core except the caller. Invoked by the
/// dumping core inside `kprof.dump.end()` to quiesce every other CPU
/// before serial-dumping the per-CPU logs.
pub fn broadcastKprofIpi() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const self_id = x64.apic.coreID();
            const lapics = x64.apic.lapics orelse return;
            for (lapics, 0..) |la, i| {
                if (i == self_id) continue;
                x64.apic.sendIpi(@intCast(la.apic_id), kprof_dump_ipi_vector);
            }
        },
        .aarch64 => {
            const self_id = aarch64.gic.coreID();
            const n = aarch64.gic.coreCount();
            var i: u64 = 0;
            while (i < n) {
                if (i != self_id) {
                    aarch64.gic.sendIpiToCore(i, kprof_dump_ipi_vector);
                }
                i += 1;
            }
        },
        else => unreachable,
    }
}

