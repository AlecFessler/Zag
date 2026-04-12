const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    syscall.thread_exit();
}

/// §2.2.40 — `thread_create` returns the new thread's handle ID (positive u64) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret > 0) {
        t.pass("§2.2.40");
    } else {
        t.fail("§2.2.40");
    }
    syscall.shutdown();
}
