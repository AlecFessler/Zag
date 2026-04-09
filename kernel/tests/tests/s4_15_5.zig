const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

var pinned_count: u64 align(8) = 0;

fn pinAndSignal(core: u64) void {
    _ = syscall.set_affinity(@as(u64, 1) << @intCast(core));
    _ = syscall.pin_exclusive();
    // Atomic increment via CAS loop
    while (true) {
        const current = @as(*volatile u64, @ptrCast(&pinned_count)).*;
        const desired = current + 1;
        const result = @cmpxchgWeak(u64, &pinned_count, current, desired, .seq_cst, .seq_cst);
        if (result == null) break;
    }
    _ = syscall.futex_wake(@ptrCast(&pinned_count), 10);
    // Keep thread alive — exit would unpin.
    while (true) {
        syscall.thread_yield();
    }
}

fn pinCore0() void {
    pinAndSignal(0);
}

fn pinCore1() void {
    pinAndSignal(1);
}

fn pinCore2() void {
    pinAndSignal(2);
}

/// §4.15.5 — `pin_exclusive` that would pin all cores returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&pinCore0, 0, 4);
    _ = syscall.thread_create(&pinCore1, 0, 4);
    _ = syscall.thread_create(&pinCore2, 0, 4);
    t.waitUntilAtLeast(&pinned_count, 3);
    _ = syscall.set_affinity(0b1000);
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.5", E_INVAL, ret);
    syscall.shutdown();
}
