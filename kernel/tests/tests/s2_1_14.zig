const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.14 — Root service's slot 0 has all ProcessRights bits set at boot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const slot0 = view[0];
    const all_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
        .restart = true,
        .mem_shm_create = true,
        .device_own = true,
        .fault_handler = true,
        .pmu = true,
    };
    if (slot0.entry_type == perm_view.ENTRY_TYPE_PROCESS and slot0.rights == @as(u16, @bitCast(all_rights))) {
        t.pass("§2.1.14");
    } else {
        t.fail("§2.1.14");
    }
    syscall.shutdown();
}
