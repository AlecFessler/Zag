const lib = @import("lib");

const embedded = @import("embedded_children");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

pub const is_root = true;

pub fn main(perm_view_addr: u64) void {
    syscall.write("root: starting\n");

    const child_rights = perms.ProcessRights{
        .grant_to_child = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
        .device_own = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    };

    // Spawn service_manager
    const svc_proc = syscall.spawn_child(
        @intFromPtr(embedded.service_manager.ptr),
        embedded.service_manager.len,
        child_rights.bits(),
    );
    if (svc_proc <= 0) {
        syscall.write("root: failed to spawn service_manager\n");
        return;
    }
    syscall.write("root: spawned service_manager\n");

    // Grant all device handles to service_manager
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    const device_grant_rights = (perms.DeviceRegionRights{
        .map = true,
        .grant = true,
        .dma = true,
    }).bits();

    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            _ = syscall.grant_perm(entry.handle, @intCast(svc_proc), device_grant_rights);
        }
    }
    syscall.write("root: device handles granted to service_manager\n");

    // Spawn app_manager
    if (syscall.spawn_child(
        @intFromPtr(embedded.app_manager.ptr),
        embedded.app_manager.len,
        child_rights.bits(),
    ) <= 0) {
        syscall.write("root: failed to spawn app_manager\n");
        return;
    }
    syscall.write("root: spawned app_manager\n");

    while (true) syscall.thread_yield();
}
