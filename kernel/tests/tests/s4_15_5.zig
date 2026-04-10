const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

var pinned: u64 align(8) = 0;

fn pinCore1() void {
    _ = syscall.set_affinity(0b10);
    _ = syscall.set_priority(syscall.PRIORITY_PINNED);
    @atomicStore(u64, &pinned, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&pinned), 1);
    // Stay alive to hold the pin.
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.15.5 — `set_priority(.pinned)` returns `E_BUSY` if all cores in the affinity mask are already owned by pinned threads.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Helper thread pins core 1.
    _ = syscall.thread_create(&pinCore1, 0, 4);
    t.waitUntilNonZero(&pinned);

    // Main thread: affinity only core 1, try to pin → E_BUSY.
    _ = syscall.set_affinity(0b10);
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    t.expectEqual("§4.15.5", E_BUSY, ret);
    syscall.shutdown();
}
