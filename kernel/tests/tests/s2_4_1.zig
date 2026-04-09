const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var result: u64 align(8) = 0;

fn threadEntry() void {
    // The arg value (0xBEEF) should be in rdi.
    const arg = asm volatile (""
        : [ret] "={rdi}" (-> u64),
    );
    result = arg;
    _ = syscall.futex_wake(@ptrCast(&result), 1);
}

/// §2.4.1 — `thread_create` creates a new thread that begins executing at `entry_addr` with the specified `arg` value.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&threadEntry, 0xBEEF, 4);
    t.waitUntilNonZero(&result);
    if (result == 0xBEEF) {
        t.pass("§2.4.1");
    } else {
        t.fail("§2.4.1");
    }
    syscall.shutdown();
}
