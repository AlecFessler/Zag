const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    syscall.thread_exit();
}

/// §4.11.1 — `thread_create` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&threadFn, 0, 4);
    t.expectEqual("§4.11.1", 0, ret);
    syscall.shutdown();
}
