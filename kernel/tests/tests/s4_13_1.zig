const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.13.1 — `thread_yield` returns `E_OK`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_yield_raw();
    t.expectEqual("§4.13.1", 0, ret);
    syscall.shutdown();
}
