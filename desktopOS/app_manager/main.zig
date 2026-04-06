const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    const child_rights = perms.ProcessRights{
        .grant_to_child = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    };

    _ = syscall.spawn_child(
        @intFromPtr(embedded.terminal.ptr),
        embedded.terminal.len,
        child_rights.bits(),
    ) catch return;

    while (true) syscall.thread_yield();
}
