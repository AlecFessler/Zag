const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_DRIVERS = 8;

const MSG_DRIVER_AVAILABLE: u8 = 0x01;

const DriverInfo = struct {
    service_id: u32,
    proc_handle: u64,
    cmd_shm_handle: i64,
};

var drivers: [MAX_DRIVERS]DriverInfo = undefined;
var num_drivers: u32 = 0;

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
        if (am_shm_handle == 0) syscall.thread_yield();
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

    syscall.write("device_manager: notified app_manager of drivers\n");

    // Track which command channel connections have been processed
    var processed_conns: [shm_protocol.MAX_CONNECTIONS]bool = .{false} ** shm_protocol.MAX_CONNECTIONS;
    // Mark already-connected entries as processed (e.g. data channel with app_manager)
    for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
        if (@as(*volatile u32, &conn.status).* == @intFromEnum(shm_protocol.ConnectionStatus.connected)) {
            processed_conns[ci] = true;
        }
    }

    // Main loop: watch for new SHM grants from root (for app-driver connections)
    // and forward them to the appropriate driver
    while (true) {
        // Check command channel for newly connected entries
        for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
            if (processed_conns[ci]) continue;
            if (@as(*volatile u32, &conn.status).* != @intFromEnum(shm_protocol.ConnectionStatus.connected)) continue;

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
                    } else {
                        syscall.write("driver");
                    }
                    syscall.write("\n");
                    recordMapped(&mapped_handles, &num_mapped, e.handle);
                    processed_conns[ci] = true;
                    break;
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
