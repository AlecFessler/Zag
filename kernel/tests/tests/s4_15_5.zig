const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// QEMU is invoked with `-smp cores=4`. Keep this centralized so the threads
/// below are easy to update if the CI topology changes.
const NUM_CORES: u64 = 4;

var pinned_count: u64 align(8) = 0;
var next_core: u64 align(8) = 0;

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
