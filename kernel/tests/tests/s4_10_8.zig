const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

/// §4.10.8 — `proc_create` with invalid `elf_ptr` returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ret = syscall.proc_create(0xDEAD0000, 4096, child_rights.bits());
    t.expectEqual("§4.10.8", E_BADADDR, ret);
    syscall.shutdown();
}
