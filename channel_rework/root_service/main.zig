const lib = @import("lib");

const channel = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;

pub const is_root = true;

pub fn main(perm_view_addr: u64) void {
    channel.perm_view_addr = perm_view_addr;
    syscall.write("root: starting\n");

    const child_rights = perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
    };

    const id_a = channel.my_semantic_id.newChildID() orelse {
        syscall.write("root: failed to allocate child id a\n");
        return;
    };
    if (syscall.spawn_child(@intFromPtr(embedded.manager_a.ptr), embedded.manager_a.len, child_rights.bits(), id_a) <= 0) {
        syscall.write("root: failed to spawn manager_a\n");
        return;
    }
    syscall.write("root: spawned manager_a\n");

    const id_b = channel.my_semantic_id.newChildID() orelse {
        syscall.write("root: failed to allocate child id b\n");
        return;
    };
    if (syscall.spawn_child(@intFromPtr(embedded.manager_b.ptr), embedded.manager_b.len, child_rights.bits(), id_b) <= 0) {
        syscall.write("root: failed to spawn manager_b\n");
        return;
    }
    syscall.write("root: spawned manager_b\n");

    syscall.write("root: entering protocol loop\n");
    channel.runAsRoot();
}
