const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

var pinned: u64 align(8) = 0;

fn pinCore0() void {
    _ = syscall.set_affinity(0b1);
    _ = syscall.pin_exclusive();
    @atomicStore(u64, &pinned, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&pinned), 1);
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.15.6 — `pin_exclusive` on already-pinned core returns `E_BUSY`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&pinCore0, 0, 4);
    t.waitUntilNonZero(&pinned);
    // Now try to pin core 0 from main thread.
    _ = syscall.set_affinity(0b1);
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.6", E_BUSY, ret);
    syscall.shutdown();
}
