const lib = @import("lib");

const embedded = @import("embedded_children");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    syscall.write("service_manager: starting\n");

    const child_rights = perms.ProcessRights{
        .grant_to_child = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
        .device_own = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    };

    // Spawn compositor
    const comp_proc = syscall.spawn_child(
        @intFromPtr(embedded.compositor.ptr),
        embedded.compositor.len,
        child_rights.bits(),
    );
    if (comp_proc <= 0) {
        syscall.write("service_manager: failed to spawn compositor\n");
        return;
    }
    syscall.write("service_manager: spawned compositor\n");

    // Spawn usb_driver
    const usb_proc = syscall.spawn_child(
        @intFromPtr(embedded.usb_driver.ptr),
        embedded.usb_driver.len,
        child_rights.bits(),
    );
    if (usb_proc <= 0) {
        syscall.write("service_manager: failed to spawn usb_driver\n");
        return;
    }
    syscall.write("service_manager: spawned usb_driver\n");

    // Wait for device grants from root, then route to children by device class.
    // Device region grants have move semantics -- each handle can only be
    // granted once before it's removed from our table.
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    const device_grant_rights = (perms.DeviceRegionRights{
        .map = true,
        .grant = true,
        .dma = true,
    }).bits();

    // Wait until at least one device region appears
    while (true) {
        for (view) |*entry| {
            if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
                break;
            }
        } else {
            perm_view.waitForChange(perm_view_addr, 100_000_000);
            continue;
        }
        break;
    }

    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            const class = entry.deviceClass();
            if (class == @intFromEnum(perms.DeviceClass.display)) {
                _ = syscall.grant_perm(entry.handle, @intCast(comp_proc), device_grant_rights);
            } else if (class == @intFromEnum(perms.DeviceClass.usb)) {
                _ = syscall.grant_perm(entry.handle, @intCast(usb_proc), device_grant_rights);
            }
        }
    }
    syscall.write("service_manager: device handles forwarded\n");

    while (true) syscall.thread_yield();
}
