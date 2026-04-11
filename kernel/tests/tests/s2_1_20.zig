const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.20 — Slot 0 (`HANDLE_SELF`) rights are encoded as `ProcessRights`; all other process handle slots use `ProcessHandleRights`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Slot 0 should be ProcessRights (all bits set for root service).
    const all_proc_rights: u16 = @bitCast(perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
        .restart = true,
        .mem_shm_create = true,
        .device_own = true,
        .fault_handler = true,
    });
    const slot0_ok = view[0].handle == 0 and view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[0].rights == all_proc_rights;

    // Spawn a child and check the child handle uses ProcessHandleRights.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));
    const full_handle_rights: u16 = @bitCast(perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    });
    var child_slot_ok = false;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            child_slot_ok = view[i].rights == full_handle_rights;
            break;
        }
    }
    if (slot0_ok and child_slot_ok) {
        t.pass("§2.1.20");
    } else {
        t.fail("§2.1.20");
    }
    syscall.shutdown();
}
