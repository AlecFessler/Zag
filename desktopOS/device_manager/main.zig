const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const MAX_DRIVERS = 8;

const MSG_DRIVER_AVAILABLE: u8 = 0x01;
const MSG_SUBSCRIBE_ACTIVE_APP: u8 = 0x03;
const MSG_ACTIVE_APP_CHANGED: u8 = 0x04;
const MSG_SPAWN_APP: u8 = 0x06;

const DriverInfo = struct {
    service_id: u32,
    proc_handle: u64,
    cmd_shm_handle: i64,
    cmd_channel: ?*shm_protocol.CommandChannel = null,
};

var drivers: [MAX_DRIVERS]DriverInfo = undefined;
var num_drivers: u32 = 0;
var mouse_shm_handle: i64 = 0; // Internal mouse channel SHM (usb↔compositor)

fn spawnDriver(
    name: []const u8,
    elf: []const u8,
    service_id: u32,
    child_rights: perms.ProcessRights,
    device_handles: []const DeviceGrant,
) bool {
    const cmd_shm = syscall.shm_create(shm_protocol.COMMAND_SHM_SIZE);
    if (cmd_shm <= 0) {
        syscall.write("device_manager: shm_create failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_protocol.COMMAND_SHM_SIZE, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("device_manager: vm_reserve failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("device_manager: shm_map failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const cmd: *shm_protocol.CommandChannel = @ptrFromInt(vm_result.val2);
    cmd.init();

    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights.bits());
    if (proc_handle <= 0) {
        syscall.write("device_manager: proc_create failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(cmd_shm), @intCast(proc_handle), grant_rights);

    for (device_handles) |dg| {
        _ = syscall.grant_perm(dg.handle, @intCast(proc_handle), dg.rights);
    }

    drivers[num_drivers] = .{
        .service_id = service_id,
        .proc_handle = @intCast(proc_handle),
        .cmd_shm_handle = cmd_shm,
        .cmd_channel = cmd,
    };
    num_drivers += 1;

    syscall.write("device_manager: spawned ");
    syscall.write(name);
    syscall.write("\n");
    return true;
}

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

fn findDriverByService(service_id: u32) ?*DriverInfo {
    for (drivers[0..num_drivers]) |*d| {
        if (d.service_id == service_id) return d;
    }
    return null;
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Detect restart
    const self_entry = &view[0];
    const restart_count = self_entry.processRestartCount();
    if (restart_count > 0) {
        syscall.write("device_manager: restarted\n");
    }

    // Find device handles by class in perm view
    var serial_devices: [4]DeviceGrant = undefined;
    var serial_count: u32 = 0;
    var usb_devices: [4]DeviceGrant = undefined;
    var usb_count: u32 = 0;
    var display_devices: [4]DeviceGrant = undefined;
    var display_count: u32 = 0;
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            const class = entry.deviceClass();
            if (class == @intFromEnum(perms.DeviceClass.serial) and serial_count < serial_devices.len) {
                serial_devices[serial_count] = .{ .handle = entry.handle, .rights = dev_rights };
                serial_count += 1;
            } else if (class == @intFromEnum(perms.DeviceClass.usb) and usb_count < usb_devices.len) {
                usb_devices[usb_count] = .{ .handle = entry.handle, .rights = dev_rights };
                usb_count += 1;
            } else if (class == @intFromEnum(perms.DeviceClass.display) and display_count < display_devices.len) {
                display_devices[display_count] = .{ .handle = entry.handle, .rights = dev_rights };
                display_count += 1;
            }
        }
    }

    // On fresh boot, spawn drivers. On restart, recover child process handles.
    if (restart_count == 0) {
        _ = spawnDriver(
            "serial_driver",
            embedded.serial_driver,
            shm_protocol.ServiceId.SERIAL_DRIVER,
            .{ .grant_to = true, .mem_reserve = true, .device_own = true, .restart = true },
            serial_devices[0..serial_count],
        );
        if (usb_count > 0) {
            _ = spawnDriver(
                "usb_driver",
                embedded.usb_driver,
                shm_protocol.ServiceId.USB_DRIVER,
                .{ .grant_to = true, .mem_reserve = true, .device_own = true, .restart = true, .shm_create = true },
                usb_devices[0..usb_count],
            );
        }
        if (display_count > 0) {
            _ = spawnDriver(
                "compositor",
                embedded.compositor,
                shm_protocol.ServiceId.COMPOSITOR,
                .{ .grant_to = true, .mem_reserve = true, .device_own = true, .restart = true, .shm_create = true },
                display_devices[0..display_count],
            );
        }

        // Create internal mouse channel between USB driver and compositor
        if (findDriverByService(shm_protocol.ServiceId.USB_DRIVER)) |usb_drv| {
            if (findDriverByService(shm_protocol.ServiceId.COMPOSITOR)) |comp_drv| {
                mouse_shm_handle = syscall.shm_create(4 * syscall.PAGE4K);
                const mouse_shm = mouse_shm_handle;
                if (mouse_shm > 0) {
                    const mouse_vm_rights = (perms.VmReservationRights{
                        .read = true,
                        .write = true,
                        .execute = true,
                        .shareable = true,
                    }).bits();
                    const mouse_vm = syscall.vm_reserve(0, 4 * syscall.PAGE4K, mouse_vm_rights);
                    if (mouse_vm.val >= 0) {
                        if (syscall.shm_map(@intCast(mouse_shm), @intCast(mouse_vm.val), 0) == 0) {
                            const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(mouse_vm.val2);
                            _ = channel_mod.Channel.initAsSideA(chan_header, 4 * syscall.PAGE4K);

                            const mouse_grant_rights = (perms.SharedMemoryRights{
                                .read = true,
                                .write = true,
                                .grant = false,
                            }).bits();
                            _ = syscall.grant_perm(@intCast(mouse_shm), usb_drv.proc_handle, mouse_grant_rights);
                            _ = syscall.grant_perm(@intCast(mouse_shm), comp_drv.proc_handle, mouse_grant_rights);

                            _ = syscall.shm_unmap(@intCast(mouse_shm), @intCast(mouse_vm.val));

                            syscall.write("device_manager: mouse channel created\n");
                        }
                    }
                }
            }
        }
    } else {
        // Recover child process handles from perm view
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
                // TODO: recover service_id mapping on restart
                drivers[num_drivers] = .{
                    .service_id = shm_protocol.ServiceId.SERIAL_DRIVER,
                    .proc_handle = entry.handle,
                    .cmd_shm_handle = 0,
                };
                num_drivers += 1;
            }
        }
        if (num_drivers > 0) {
            syscall.write("device_manager: recovered driver handles\n");
        }
    }

    // Request connection to app_manager (brokered by root)
    // On restart, the connection may already be established
    const am_entry = cmd.requestConnection(shm_protocol.ServiceId.APP_MANAGER) orelse return;
    if (!cmd.waitForConnection(am_entry)) return;

    // Track mapped SHM handles
    var mapped_handles: [16]u64 = .{0} ** 16;
    var num_mapped: u32 = 0;

    // Record command channel SHM handle to skip it
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
            recordMapped(&mapped_handles, &num_mapped, e.handle);
            break;
        }
    }

    // Record mouse channel SHM (created by us, also in our perm_view)
    if (mouse_shm_handle > 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 == 4 * syscall.PAGE4K and
                !isHandleMapped(e.handle, mapped_handles[0..num_mapped]))
            {
                recordMapped(&mapped_handles, &num_mapped, e.handle);
                break;
            }
        }
    }

    // Find the app_manager data SHM
    var am_shm_handle: u64 = 0;
    var am_shm_size: u64 = 0;
    while (am_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                !isHandleMapped(e.handle, mapped_handles[0..num_mapped]))
            {
                am_shm_handle = e.handle;
                am_shm_size = e.field0;
                break;
            }
        }
        if (am_shm_handle == 0) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }
    recordMapped(&mapped_handles, &num_mapped, am_shm_handle);

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const am_vm = syscall.vm_reserve(0, am_shm_size, vm_rights);
    if (am_vm.val < 0) return;
    if (syscall.shm_map(am_shm_handle, @intCast(am_vm.val), 0) != 0) return;

    const am_chan_header: *channel_mod.ChannelHeader = @ptrFromInt(am_vm.val2);
    var am_chan = channel_mod.Channel.openAsSideB(am_chan_header) orelse return;

    // Send DRIVER_AVAILABLE for each spawned driver
    for (drivers[0..num_drivers]) |*drv| {
        var avail_msg: [5]u8 = undefined;
        avail_msg[0] = MSG_DRIVER_AVAILABLE;
        const sid = drv.service_id;
        avail_msg[1] = @truncate(sid);
        avail_msg[2] = @truncate(sid >> 8);
        avail_msg[3] = @truncate(sid >> 16);
        avail_msg[4] = @truncate(sid >> 24);
        _ = am_chan.send(&avail_msg);
    }

    // Subscribe to active app changes
    _ = am_chan.send(&[_]u8{MSG_SUBSCRIBE_ACTIVE_APP});

    syscall.write("device_manager: notified app_manager of drivers\n");

    // Track which command channel connections have been processed
    var processed_conns: [shm_protocol.MAX_CONNECTIONS]bool = .{false} ** shm_protocol.MAX_CONNECTIONS;
    // Mark already-connected entries as processed (e.g. data channel with app_manager)
    for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
        if (@atomicLoad(u32, &conn.status, .acquire) == @intFromEnum(shm_protocol.ConnectionStatus.connected)) {
            processed_conns[ci] = true;
        }
    }

    // Main loop: watch for new SHM grants from root (for app-driver connections)
    // and forward them to the appropriate driver
    var am_msg_buf: [64]u8 = undefined;
    while (true) {
        // Check for messages from app_manager (active app changes)
        if (am_chan.recv(&am_msg_buf)) |am_len| {
            if (am_len >= 2 and am_msg_buf[0] == MSG_ACTIVE_APP_CHANGED) {
                const app_idx = am_msg_buf[1];
                // Relay to all driver children via their command channels
                for (drivers[0..num_drivers]) |*drv| {
                    if (drv.cmd_channel) |child_cmd| {
                        @atomicStore(u8, &child_cmd.active_app_index, app_idx, .release);
                        _ = @atomicRmw(u64, &child_cmd.active_app_gen, .Add, 1, .release);
                        _ = syscall.futex_wake(&child_cmd.active_app_gen, 1);
                    }
                }
            }
        }

        // Check command channel for newly connected entries
        for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
            if (processed_conns[ci]) continue;
            if (@atomicLoad(u32, &conn.status, .acquire) != @intFromEnum(shm_protocol.ConnectionStatus.connected)) continue;

            // This connection was just fulfilled by root — find the matching new SHM in perm_view
            for (view) |*e| {
                if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                    e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                    !isHandleMapped(e.handle, mapped_handles[0..num_mapped]))
                {
                    // Route to the correct driver
                    const driver = findDriverByService(conn.service_id) orelse break;
                    const grant_rights = (perms.SharedMemoryRights{
                        .read = true,
                        .write = true,
                        .grant = false,
                    }).bits();
                    _ = syscall.grant_perm(e.handle, driver.proc_handle, grant_rights);
                    syscall.write("device_manager: forwarded SHM to ");
                    if (conn.service_id == shm_protocol.ServiceId.SERIAL_DRIVER) {
                        syscall.write("serial_driver");
                    } else if (conn.service_id == shm_protocol.ServiceId.USB_DRIVER) {
                        syscall.write("usb_driver");
                    } else if (conn.service_id == shm_protocol.ServiceId.COMPOSITOR) {
                        syscall.write("compositor");
                    } else {
                        syscall.write("driver");
                    }
                    syscall.write("\n");
                    recordMapped(&mapped_handles, &num_mapped, e.handle);
                    // Reset entry to available so it can be reused for future connections
                    @atomicStore(u32, &conn.status, @intFromEnum(shm_protocol.ConnectionStatus.available), .release);
                    break;
                }
            }
        }

        // Check for flags from compositor
        if (findDriverByService(shm_protocol.ServiceId.COMPOSITOR)) |comp_drv| {
            if (comp_drv.cmd_channel) |comp_cmd| {
                const flags = @atomicLoad(u32, &comp_cmd.child_flags, .acquire);
                if (flags != 0) {
                    @atomicStore(u32, &comp_cmd.child_flags, 0, .release);
                    if (flags & shm_protocol.CHILD_FLAG_SPAWN_APP != 0) {
                        _ = am_chan.send(&[_]u8{MSG_SPAWN_APP});
                        syscall.write("device_manager: forwarding spawn request\n");
                    }
                    if (flags & shm_protocol.CHILD_FLAG_ACTIVE_CHANGED != 0) {
                        const app_idx = @atomicLoad(u8, &comp_cmd.active_app_index, .acquire);
                        // Relay to all driver children
                        for (drivers[0..num_drivers]) |*drv| {
                            if (drv.cmd_channel) |child_cmd| {
                                @atomicStore(u8, &child_cmd.active_app_index, app_idx, .release);
                                _ = @atomicRmw(u64, &child_cmd.active_app_gen, .Add, 1, .release);
                                _ = syscall.futex_wake(&child_cmd.active_app_gen, 1);
                            }
                        }
                        // Also tell app_manager
                        var changed: [2]u8 = .{ MSG_ACTIVE_APP_CHANGED, app_idx };
                        _ = am_chan.send(&changed);
                    }
                }
            }
        }

        // Wait for notifications from root
        cmd.waitForNotification(10_000_000); // 10ms timeout
    }
}

fn isHandleMapped(handle: u64, mapped: []const u64) bool {
    for (mapped) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handles: *[16]u64, count: *u32, handle: u64) void {
    if (count.* < handles.len) {
        handles[count.*] = handle;
        count.* += 1;
    }
}
