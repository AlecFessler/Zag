const lib = @import("lib");

const channel = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("sub_manager: starting\n");

    const child_rights = perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
    };

    const id_1 = channel.my_semantic_id.newChildID() orelse return;
    const proc_1 = syscall.spawn_child(
        @intFromPtr(embedded.leaf_1.ptr),
        embedded.leaf_1.len,
        child_rights.bits(),
        id_1,
    );
    if (proc_1 <= 0) {
        syscall.write("sub_manager: failed to spawn leaf_1\n");
        return;
    }
    syscall.write("sub_manager: spawned leaf_1\n");

    const id_2 = channel.my_semantic_id.newChildID() orelse return;
    const proc_2 = syscall.spawn_child(
        @intFromPtr(embedded.leaf_2.ptr),
        embedded.leaf_2.len,
        child_rights.bits(),
        id_2,
    );
    if (proc_2 <= 0) {
        syscall.write("sub_manager: failed to spawn leaf_2\n");
        return;
    }
    syscall.write("sub_manager: spawned leaf_2\n");

    // Worker thread was already started by _start; main just idles
    while (true) {
        syscall.thread_yield();
    }
}
