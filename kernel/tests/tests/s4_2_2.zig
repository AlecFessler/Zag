const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.2.2 — `write` with `len == 0` is a no-op returning 0.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const msg = "x";
    const ret = syscall.write_raw(@intFromPtr(msg.ptr), 0);
    t.expectEqual("§4.2.2", 0, ret);
    syscall.shutdown();
}
