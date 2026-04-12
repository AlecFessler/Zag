const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

fn threadFn() void {}

/// §2.2.43 — `thread_create` with zero stack pages returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&threadFn, 0, 0);
    t.expectEqual("§2.2.43", E_INVAL, ret);
    syscall.shutdown();
}
