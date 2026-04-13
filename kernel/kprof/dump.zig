//! Session-end serial dump for the kernel profiling log.
//!
//! Emits greppable [KPROF] lines describing every record in every
//! per-CPU log, plus the tracepoint id-to-name table, in a format
//! the host post-processor can parse unambiguously.
//!
//! Dump ordering: logs are printed in ascending core-id order so the
//! output is stable across runs. A single atomic bitmap tracks which
//! CPU logs have been dumped (see `dumped_mask`); in the current
//! single-dumper v1 this is cosmetic, but the bitmap anchors the
//! eventual multi-CPU coordinated dump.
//!
//! TODO: add an IPI-based stop-the-world to guarantee no in-flight
//! emit records are lost when a dump begins. Current v1 tolerates a
//! small tail-end loss window.

const log_mod = @import("log.zig");
const mode = @import("mode.zig");
const record_mod = @import("record.zig");
const trace_id_mod = @import("trace_id.zig");
const zag = @import("zag");

const arch = zag.arch.dispatch;

const Record = record_mod.Record;

var dumped_mask: u64 = 0;

/// Terminate the profiling session and dump every CPU's log to serial.
///
/// Can be called from either the "any log full" detector or from the
/// root process exit hook. The first caller wins; subsequent calls are
/// no-ops.
pub fn end(reason: EndReason) void {
    if (!mode.any_enabled) return;

    if (@cmpxchgStrong(bool, &log_mod.ending, false, true, .acq_rel, .monotonic) != null) {
        return; // another core already ended the session
    }

    @atomicStore(bool, &log_mod.active, false, .release);

    dumpHeader(reason);
    dumpNameTable();
    dumpAllLogs();
    dumpFooter();
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
    arch.print("[KPROF] begin cpus={d} mode={s} reason={s}\n", .{
        log_mod.n_cpus,
        @tagName(mode.active),
        reason_str,
    });
}

fn dumpNameTable() void {
    for (trace_id_mod.names) |entry| {
        arch.print("[KPROF] name id={d} name={s}\n", .{
            @intFromEnum(entry.id),
            entry.name,
        });
    }
}

fn dumpAllLogs() void {
    var i: usize = 0;
    while (i < log_mod.n_cpus) : (i += 1) {
        const bit: u64 = @as(u64, 1) << @intCast(i);
        const prev = @atomicRmw(u64, &dumped_mask, .Or, bit, .acq_rel);
        if (prev & bit != 0) continue; // already dumped
        dumpOneLog(i);
    }
}

fn dumpOneLog(cpu: usize) void {
    const log = &log_mod.cpu_logs[cpu];
    const head = @atomicLoad(u64, &log.head, .acquire);
    const overflowed = @atomicLoad(u64, &log.overflowed, .acquire);
    const bytes_used = @min(head, log.limit);
    const n_records = bytes_used / @sizeOf(Record);

    arch.print("[KPROF] cpu_begin cpu={d} records={d} overflowed={d}\n", .{
        cpu,
        n_records,
        overflowed,
    });

    var idx: usize = 0;
    while (idx < n_records) : (idx += 1) {
        const slot: *const Record = @ptrFromInt(log.base + idx * @sizeOf(Record));
        arch.print(
            "[KPROF] rec cpu={d} tsc={d} kind={d} id={d} rip=0x{x} arg=0x{x}\n",
            .{
                slot.cpu,
                slot.tsc,
                slot.kind,
                slot.id,
                slot.rip,
                slot.arg,
            },
        );
    }

    arch.print("[KPROF] cpu_end cpu={d}\n", .{cpu});
}

fn dumpFooter() void {
    arch.print("[KPROF] done\n", .{});
}
