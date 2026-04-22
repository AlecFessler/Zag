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

/// Fast-path self-scheduler-interrupt for the local core. Used by `yield()`
/// to skip the APIC self-IPI path, which on x2APIC issues a WRMSR that
/// typically causes a KVM vm-exit (~5K cycles round trip). On x86-64 we
/// instead execute `int 0xFE` — a software interrupt directly dispatched
/// through the IDT in guest mode without a vm-exit. On aarch64 there is no
/// analogous cheap path, so we fall back to the GIC SGI sender.
pub inline fn triggerSchedulerInterruptSelf() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int $0xFE" ::: .{ .memory = true }),
        .aarch64 => aarch64.gic.sendIpiToCore(coreID(), sched_ipi_vector),
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
