//! Per-CPU kernel profiling log.
//!
//! Each CPU owns a pre-mapped, fixed-size bump log. Tracepoint and
//! sample records are appended via `emit`. The session ends when any
//! CPU fills its log, or when the root process exits — whichever
//! comes first — at which point all CPUs quiesce and dump their logs
//! to serial in core-id order.
//!
//! The bump pointer is advanced via an atomic RMW (monotonic) on
//! `head`. This is single-producer from the main thread side, but
//! the NMI sampling handler may reenter on the same CPU. Atomic RMW
//! makes the NMI-vs-main race correct without any additional lock.
//!
//! The backing storage is allocated once from the kernel heap at
//! `init()` and pre-faulted so no page faults can occur during
//! profiling (NMI context cannot fault).

const mode = @import("mode.zig");
const record_mod = @import("record.zig");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const heap = zag.memory.init;
const paging = zag.memory.paging;

const Record = record_mod.Record;

/// Hard upper bound on CPUs the profiling log array supports.
/// Zag targets small systems; 32 is well above current coreCount().
pub const MAX_CPUS: usize = 32;

/// Bytes per per-CPU log.
pub const LOG_SIZE_BYTES: usize = 32 * 1024 * 1024;
pub const RECORDS_PER_LOG: usize = LOG_SIZE_BYTES / @sizeOf(Record);

pub const CpuLog = extern struct {
    base: u64 align(64),   // virtual base of this CPU's log buffer
    head: u64,             // byte offset; atomic RMW bumped
    limit: u64,            // byte size of the mapped buffer
    overflowed: u64,       // non-zero once head reached limit
};

pub var cpu_logs: [MAX_CPUS]CpuLog align(64) = [_]CpuLog{.{
    .base = 0,
    .head = 0,
    .limit = 0,
    .overflowed = 0,
}} ** MAX_CPUS;

/// Number of per-CPU logs actually initialized (== coreCount at init time).
pub var n_cpus: usize = 0;

/// True once logs are allocated and accepting records.
/// Set by `start()`, cleared by `end()`.
pub var active: bool = false;

/// True once `end()` has begun. Prevents re-entering the dump path.
pub var ending: bool = false;

/// Allocate and pre-fault per-CPU log buffers. Must run after
/// `zag.memory.init.initHeap()` so the kernel heap is live. No-op when
/// profiling is compiled out.
pub fn init() !void {
    if (!mode.any_enabled) return;

    const cores = arch.coreCount();
    if (cores > MAX_CPUS) @panic("kprof: coreCount exceeds MAX_CPUS");
    n_cpus = @intCast(cores);

    const allocator = heap.heap_allocator;
    for (0..n_cpus) |i| {
        const buf = try allocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(4096), LOG_SIZE_BYTES);

        // Pre-fault every page so NMI context never triggers a page
        // fault against an uncommitted heap page.
        var off: usize = 0;
        while (off < LOG_SIZE_BYTES) {
            buf[off] = 0;
            off += paging.PAGE4K;
        }

        cpu_logs[i] = .{
            .base = @intFromPtr(buf.ptr),
            .head = 0,
            .limit = LOG_SIZE_BYTES,
            .overflowed = 0,
        };
    }
}

/// Begin accepting records. Call after boot completes, right before
/// the root process resumes on its first scheduling tick.
pub fn start() void {
    if (!mode.any_enabled) return;
    if (n_cpus == 0) return;
    @atomicStore(bool, &active, true, .release);
}

/// Append one record to the current CPU's log.
///
/// Callable from NMI context. Will not fault — `init()` pre-faults
/// every backing page, and the bump pointer never advances past
/// the pre-mapped range.
///
/// On the first overflow, sets the CPU's `overflowed` flag and
/// silently drops the record. The session-end path polls this
/// and triggers `end()` on first observed overflow.
pub inline fn emit(rec: Record) void {
    if (!mode.any_enabled) return;
    if (!@atomicLoad(bool, &active, .acquire)) return;

    const log = &cpu_logs[rec.cpu];
    const off = @atomicRmw(u64, &log.head, .Add, @sizeOf(Record), .monotonic);
    if (off + @sizeOf(Record) > log.limit) {
        @atomicStore(u64, &log.overflowed, 1, .release);
        return;
    }
    const slot: *Record = @ptrFromInt(log.base + off);
    slot.* = rec;
}

/// Returns true if any CPU's log is full.
pub fn anyOverflowed() bool {
    for (cpu_logs[0..n_cpus]) |*log| {
        if (@atomicLoad(u64, &log.overflowed, .acquire) != 0) return true;
    }
    return false;
}
