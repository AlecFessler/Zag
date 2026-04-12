const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.46 — `thread_yield` returns `E_OK`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_yield_raw();
    t.expectEqual("§2.2.46", 0, ret);
    syscall.shutdown();
}
