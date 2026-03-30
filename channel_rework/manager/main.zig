const lib = @import("lib");

const channel = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("manager: starting\n");

    const child_rights = perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
    };

    const id_1 = channel.my_semantic_id.newChildID() orelse return;
    if (syscall.spawn_child(@intFromPtr(embedded.sub_1.ptr), embedded.sub_1.len, child_rights.bits(), id_1) <= 0) {
        syscall.write("manager: failed to spawn sub_1\n");
        return;
    }
    syscall.write("manager: spawned sub_1\n");

    const id_2 = channel.my_semantic_id.newChildID() orelse return;
    if (syscall.spawn_child(@intFromPtr(embedded.sub_2.ptr), embedded.sub_2.len, child_rights.bits(), id_2) <= 0) {
        syscall.write("manager: failed to spawn sub_2\n");
        return;
    }
    syscall.write("manager: spawned sub_2\n");

    while (true) {
        syscall.thread_yield();
    }
}
