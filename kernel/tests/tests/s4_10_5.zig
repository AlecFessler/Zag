const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.10.5 — `proc_create` with invalid ELF returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Pass garbage data as ELF.
    var garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ** 16;
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ret = syscall.proc_create(@intFromPtr(&garbage), garbage.len, child_rights.bits());
    t.expectEqual("§4.10.5", E_INVAL, ret);
    syscall.shutdown();
}
