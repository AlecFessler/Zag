const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

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

// ── Spec v3 SMP primitives ───────────────────────────────────────────

/// Cross-core wake reuses the scheduler-rearm vector on x86: an idle
/// core parked in HLT exits on any IDT-dispatched interrupt and re-runs
/// the scheduler regardless of which vector poked it. On aarch64 SGIs
/// 0 and 1 are already taken by the scheduler and kprof-dump paths, so
/// the wake path claims SGI 2.
const wake_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.sched),
    .aarch64 => 2,
    else => unreachable,
};

/// TLB-shootdown IPI vector. x86 has a dedicated entry in the reserved
/// high-vector band; aarch64 uses SGI 3 (SGIs 0/1/2 are scheduler /
/// kprof-dump / wake).
const tlb_shootdown_ipi_vector: u8 = switch (builtin.cpu.arch) {
    .x86_64 => @intFromEnum(x64.interrupts.IntVecs.tlb_shootdown),
    .aarch64 => 3,
    else => unreachable,
};

/// Wake an idle remote core so it picks up freshly enqueued work.
/// Spec §[execution_context] cross-core enqueue.
pub fn sendWakeIpi(core_id: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.sendIpiToCore(core_id, wake_ipi_vector),
        .aarch64 => aarch64.gic.sendIpiToCore(core_id, wake_ipi_vector),
        else => unreachable,
    }
}

/// Send a TLB shootdown IPI to every core in `core_mask` (bit N = 1 ⇒
/// core N). Receivers run the per-arch shootdown handler against the
/// pending range queue. Used by `paging.shootdownTlbRange` /
/// `shootdownTlbAll`.
pub fn sendTlbShootdownIpi(core_mask: u64) void {
    var mask = core_mask;
    while (mask != 0) {
        const core_id: u64 = @ctz(mask);
        mask &= mask - 1;
        switch (builtin.cpu.arch) {
            .x86_64 => x64.apic.sendIpiToCore(core_id, tlb_shootdown_ipi_vector),
            .aarch64 => aarch64.gic.sendIpiToCore(core_id, tlb_shootdown_ipi_vector),
            else => unreachable,
        }
    }
}
