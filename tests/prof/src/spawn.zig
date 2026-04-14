const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

/// kprof workload — stresses sys_proc_create + sys_thread_exit + process
/// teardown by repeatedly spawning a trivial exit-immediately child and
/// waiting for its DEAD_PROCESS entry before spawning the next one.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = (perms.ProcessRights{}).bits();

    while (true) {
        const rc: i64 = syscall.proc_create(
            @intFromPtr(children.child_exit.ptr),
            children.child_exit.len,
            child_rights,
        );
        if (rc < 0) {
            syscall.thread_yield();
            continue;
        }
        const child_handle: u64 = @bitCast(rc);

        var slot: usize = 128;
        for (0..128) |i| {
            if (view[i].handle == child_handle) {
                slot = i;
                break;
            }
        }
        if (slot == 128) continue;

        while (view[slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            syscall.thread_yield();
        }
        _ = syscall.revoke_perm(child_handle);
    }
}
