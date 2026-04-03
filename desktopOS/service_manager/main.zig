const lib = @import("lib");

const embedded = @import("embedded_children");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
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

    // Spawn display server
    const comp_proc = syscall.spawn_child(
        @intFromPtr(embedded.display_server.ptr),
        embedded.display_server.len,
        child_rights.bits(),
    ) catch return;

    // Spawn usb_driver
    const usb_proc = syscall.spawn_child(
        @intFromPtr(embedded.usb_driver.ptr),
        embedded.usb_driver.len,
        child_rights.bits(),
    ) catch return;

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
                syscall.grant_perm(entry.handle, comp_proc, device_grant_rights) catch {};
            } else if (class == @intFromEnum(perms.DeviceClass.usb)) {
                syscall.grant_perm(entry.handle, usb_proc, device_grant_rights) catch {};
            }
        }
    }
    while (true) syscall.thread_yield();
}
