const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    syscall.thread_exit();
}

/// §4.11.1 — `thread_create` returns the new thread's handle ID (positive u64) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret > 0) {
        t.pass("§4.11.1");
    } else {
        t.fail("§4.11.1");
    }
    syscall.shutdown();
}
