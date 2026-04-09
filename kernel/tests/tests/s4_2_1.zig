const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.2.1 — `write` returns the number of bytes written.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const msg = "hello";
    const ret = syscall.write_raw(@intFromPtr(msg.ptr), msg.len);
    t.expectEqual("§4.2.1", @as(i64, @intCast(msg.len)), ret);
    syscall.shutdown();
}
