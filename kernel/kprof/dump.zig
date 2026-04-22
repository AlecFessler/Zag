//! Rolling serial dump for the kernel profiling log.
//!
//! Emits greppable [KPROF] lines describing every record in every
//! per-CPU log, plus the tracepoint id-to-name table, in a format
//! the host post-processor can parse unambiguously.
//!
//! Dump ordering: logs are printed in ascending core-id order so the
//! output is stable across runs. Each dump cycle is framed by a
//! `[KPROF] begin …` / `[KPROF] done` pair so `flamegraph.py` (and
//! any future consumer) can concatenate multiple cycles from one
//! long session without misattributing samples.
//!
//! IPI stop-the-world: the core that wins the `log_mod.ending`
//! cmpxchg broadcasts a kprof-dump IPI to every other core. Remote
//! cores enter `parkForDump()` via the IPI handler, bump
//! `log_mod.parked_cores`, snapshot `log_mod.epoch`, and spin until
//! epoch changes. The dumper spins until every other core has parked,
//! then serial-dumps every log in core-id order, resets each log
//! back to empty, clears the per-session flags, and finally bumps
//! `epoch` — which releases the parked cores. All cores then resume
//! normal execution; the next fill cycle triggers the next dump.
//!
//! Concurrent claim: a core that loses the `ending` cmpxchg returns
//! immediately rather than parking. Emits are gated on
//! `log.active`, which the dumper has already cleared, so any
//! in-flight `emit()` on the losing core either slips in a last
//! record before the store is visible (fine — gets captured in this
//! dump) or sees active=false and short-circuits (also fine —
//! dropped at source, not a race).

const log_mod = @import("log.zig");
const mode = @import("mode.zig");
const record_mod = @import("record.zig");
const trace_id_mod = @import("trace_id.zig");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug_info = zag.utils.debug_info;

const Record = record_mod.Record;

/// Run one rolling dump cycle: quiesce every other core, serial-dump
/// all logs, reset them, and release. Returns normally so the caller
/// (scheduler timer tick or root-exit hook) can continue.
///
/// A core that loses the `ending` cmpxchg returns immediately; emits
/// on that core already see `active=false` once the dumper stores it,
/// so draining in-flight records via parking isn't necessary.
pub fn end(reason: EndReason) void {
    if (!mode.any_enabled) return;

    if (@cmpxchgStrong(bool, &log_mod.ending, false, true, .acq_rel, .monotonic) != null) {
        return;
    }

    @atomicStore(bool, &log_mod.active, false, .release);

    arch.smp.broadcastKprofIpi();

    const expected: u32 = @intCast(log_mod.n_cpus -| 1);
    while (@atomicLoad(u32, &log_mod.parked_cores, .acquire) < expected) {
        arch.cpu.cpuRelax();
    }

    dumpHeader(reason);
    dumpNameTable();
    dumpAllLogs();
    dumpFooter();

    // Reset per-CPU logs so the next cycle can start clean. Every
    // store happens before the epoch bump, so parked cores that
    // observe the new epoch are guaranteed to see empty logs too.
    var i: usize = 0;
    while (i < log_mod.n_cpus) {
        @atomicStore(u64, &log_mod.cpu_logs[i].head, 0, .release);
        @atomicStore(u64, &log_mod.cpu_logs[i].overflowed, 0, .release);
        i += 1;
    }
    @atomicStore(u32, &log_mod.terminate_requested, 0, .release);
    @atomicStore(u32, &log_mod.parked_cores, 0, .release);
    @atomicStore(bool, &log_mod.active, true, .release);
    @atomicStore(bool, &log_mod.ending, false, .release);

    // Bump epoch last — this is the signal that releases parked
    // cores. Anything in the reset block above must be visible by
    // the time a parked core exits its wait loop.
    _ = @atomicRmw(u64, &log_mod.epoch, .Add, 1, .acq_rel);
}

/// Called from the kprof-dump IPI handler on non-dumping cores.
/// Records this core as parked, snapshots the current epoch, then
/// spins until the dumper bumps epoch. Returns from the IPI handler
/// so the core resumes whatever it was running when the IPI arrived.
///
/// Invariant: the epoch load happens *before* the parked_cores
/// increment is made visible, so the dumper's "wait for parked_cores
/// >= threshold" check guarantees every parked core has already
/// snapshotted the pre-bump epoch. No parked core will ever read the
/// post-bump epoch into `my_epoch` and then wait forever.
pub fn parkForDump() void {
    if (!mode.any_enabled) return;
    const my_epoch = @atomicLoad(u64, &log_mod.epoch, .acquire);
    _ = @atomicRmw(u32, &log_mod.parked_cores, .Add, 1, .acq_rel);
    while (@atomicLoad(u64, &log_mod.epoch, .acquire) == my_epoch) {
        arch.cpu.cpuRelax();
    }
}

pub const EndReason = enum {
    root_exit,
    log_full,
};

fn dumpHeader(reason: EndReason) void {
    const reason_str = switch (reason) {
        .root_exit => "root_exit",
        .log_full => "log_full",
    };
    arch.boot.print("[KPROF] begin cpus={d} mode={s} reason={s}\n", .{
        log_mod.n_cpus,
        @tagName(mode.active),
        reason_str,
    });
}

fn dumpNameTable() void {
    for (trace_id_mod.names) |entry| {
        arch.boot.print("[KPROF] name id={d} name={s}\n", .{
            @intFromEnum(entry.id),
            entry.name,
        });
    }
}

fn dumpAllLogs() void {
    var i: usize = 0;
    while (i < log_mod.n_cpus) {
        dumpOneLog(i);
        i += 1;
    }
}

fn dumpOneLog(cpu: usize) void {
    const log = &log_mod.cpu_logs[cpu];
    const head = @atomicLoad(u64, &log.head, .acquire);
    const overflowed = @atomicLoad(u64, &log.overflowed, .acquire);
    const bytes_used = @min(head, log.limit);
    const n_records = bytes_used / @sizeOf(Record);

    arch.boot.print("[KPROF] cpu_begin cpu={d} records={d} overflowed={d}\n", .{
        cpu,
        n_records,
        overflowed,
    });

    var idx: usize = 0;
    while (idx < n_records) {
        const slot: *const Record = @ptrFromInt(log.base + idx * @sizeOf(Record));
        const sym = resolveSym(slot.ip);
        if (comptime mode.trace_enabled) {
            arch.boot.print(
                "[KPROF] rec cpu={d} tsc={d} kind={d} id={d} ip=0x{x} arg=0x{x} cyc={d} cmiss={d} bmiss={d} sym={s}\n",
                .{
                    slot.cpu,
                    slot.tsc,
                    slot.kind,
                    slot.id,
                    slot.ip,
                    slot.arg,
                    slot.cycles,
                    slot.cache_misses,
                    slot.branch_misses,
                    sym,
                },
            );
        } else {
            arch.boot.print(
                "[KPROF] rec cpu={d} tsc={d} kind={d} id={d} ip=0x{x} arg=0x{x} sym={s}\n",
                .{
                    slot.cpu,
                    slot.tsc,
                    slot.kind,
                    slot.id,
                    slot.ip,
                    slot.arg,
                    sym,
                },
            );
        }
        idx += 1;
    }

    arch.boot.print("[KPROF] cpu_end cpu={d}\n", .{cpu});
}

fn dumpFooter() void {
    arch.boot.print("[KPROF] done\n", .{});
}

/// Resolve a post-KASLR runtime address to a function name using the
/// kernel's own DWARF (same path `panic.zig` uses). Returns `"?"` when
/// debug info isn't loaded or the address falls outside the kernel
/// image — e.g. a caller frame that walked into user/userspace stack
/// slop or a stale return address the unwinder couldn't sanitize.
fn resolveSym(ip: u64) []const u8 {
    if (ip == 0) return "?";
    const dbg = debug_info.global_ptr orelse return "?";
    if (ip < debug_info.kaslr_slide) return "?";
    return dbg.getSymbolName(ip - debug_info.kaslr_slide) orelse "?";
}
