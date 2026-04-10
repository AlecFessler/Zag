const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;
const E_INVAL: i64 = -1;

/// Probed dynamically at runtime — see `probeCoreCount`. Treated as storage
/// because `pinWorker` reads it after the probe completes in `main`.
var NUM_CORES: u64 = 0;

var pinned_count: u64 align(8) = 0;
var next_core: u64 align(8) = 0;

var probe_tid: u64 align(8) = 0;

fn probeHelper() void {
    @atomicStore(u64, &probe_tid, @bitCast(syscall.thread_self()), .release);
    _ = syscall.futex_wake(&probe_tid, 1);
    while (true) syscall.thread_yield();
}

/// Probe the system's core count without disturbing the main thread's
/// affinity. Spawns a helper, calls `set_affinity_thread` on *it* with
/// single-bit masks until the kernel rejects one.
fn probeCoreCount() u64 {
    _ = syscall.thread_create(&probeHelper, 0, 4);
    t.waitUntilNonZero(&probe_tid);
    const handle = @atomicLoad(u64, &probe_tid, .acquire);
    var i: u6 = 0;
    while (i < 63) : (i += 1) {
        const mask: u64 = @as(u64, 1) << i;
        if (syscall.set_affinity_thread(handle, mask) != E_OK) return @intCast(i);
    }
    return 64;
}

fn pinWorker() void {
    const core = @atomicRmw(u64, &next_core, .Add, 1, .seq_cst);
    _ = syscall.set_affinity(@as(u64, 1) << @intCast(core));
    _ = syscall.pin_exclusive();
    _ = @atomicRmw(u64, &pinned_count, .Add, 1, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&pinned_count), 10);
    // Keep the thread alive — exit would unpin the core.
    while (true) syscall.thread_yield();
}

/// §4.15.5 — `pin_exclusive` that would pin all cores returns `E_INVAL`.
///
/// Spawns `NUM_CORES - 1` worker threads that each pin a distinct core. The
/// main thread then targets the remaining (last) core, which would make the
/// total number of pinned cores equal to the machine's core count — forbidden.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    NUM_CORES = probeCoreCount();
    var i: u64 = 0;
    while (i < NUM_CORES - 1) : (i += 1) {
        _ = syscall.thread_create(&pinWorker, 0, 4);
    }
    t.waitUntilAtLeast(&pinned_count, NUM_CORES - 1);

    const last_core_mask: u64 = @as(u64, 1) << @intCast(NUM_CORES - 1);
    _ = syscall.set_affinity(last_core_mask);
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.5", E_INVAL, ret);
    syscall.shutdown();
}
