const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §5.5.3 — `write` with `len > 4096` returns `E_INVAL`.
///
/// Must pass a valid user pointer so the kernel does not short-circuit with
/// E_BADADDR before reaching the length check.
var local_buf: [8192]u8 align(16) = .{0} ** 8192;

pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.write_raw(@intFromPtr(&local_buf), 4097);
    t.expectEqual("§5.5.3", E_INVAL, ret);
    syscall.shutdown();
}
