const lib = @import("lib");

const channel = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("app_manager: starting\n");

    // const child_rights = perms.ProcessRights{
    //     .grant_to = true,
    //     .spawn_thread = true,
    //     .spawn_process = true,
    //     .mem_reserve = true,
    //     .shm_create = true,
    //     .restart = true,
    // };

    // Spawn terminal (temporarily disabled for debug)
    // const id = channel.my_semantic_id.newChildID() orelse {
    //     syscall.write("app_manager: failed to allocate terminal id\n");
    //     return;
    // };
    // if (syscall.spawn_child(
    //     @intFromPtr(embedded.terminal.ptr),
    //     embedded.terminal.len,
    //     child_rights.bits(),
    //     id,
    // ) <= 0) {
    //     syscall.write("app_manager: failed to spawn terminal\n");
    //     return;
    // }
    // syscall.write("app_manager: spawned terminal\n");

    while (true) syscall.thread_yield();
}
