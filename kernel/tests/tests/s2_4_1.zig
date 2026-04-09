const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    syscall.thread_exit();
}

/// §2.4.1 — `thread_create` returns the new thread's handle ID (positive u64) on success rather than `E_OK`.
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&worker, 0, 4);
    // Must be a positive handle ID, not 0 (E_OK) and not negative (error).
    if (ret > 0) {
        t.pass("§2.4.1");
    } else {
        t.failWithVal("§2.4.1", 1, ret);
    }
    syscall.shutdown();
}
