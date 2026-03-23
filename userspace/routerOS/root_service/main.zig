const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 128;
const MAX_CHILDREN = 8;

const ChildInfo = struct {
    name: []const u8,
    service_id: u32,
    proc_handle: u64,
    cmd_shm_handle: i64,
    cmd_channel: ?*shm_protocol.CommandChannel,
    allowed_connections: u32,
};

var children: [MAX_CHILDREN]ChildInfo = undefined;
var num_children: u32 = 0;

fn findChildByService(service_id: u32) ?*ChildInfo {
    for (children[0..num_children]) |*child| {
        if (child.service_id == service_id) return child;
    }
    return null;
}

fn spawnChild(
    name: []const u8,
    elf: []const u8,
    service_id: u32,
    child_rights: perms.ProcessRights,
    allowed_connections: []const u32,
    perm_view_addr: u64,
    device_handles: []const DeviceGrant,
) bool {
    const cmd_shm = syscall.shm_create(shm_protocol.COMMAND_SHM_SIZE);
    if (cmd_shm <= 0) {
        syscall.write("root: shm_create failed for ");
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
    if (vm_result.val < 0) return false;

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) return false;

    const cmd: *shm_protocol.CommandChannel = @ptrFromInt(vm_result.val2);
    cmd.init();
    for (allowed_connections) |conn| {
        cmd.addAllowedConnection(conn);
    }

    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights.bits());
    if (proc_handle <= 0) {
        syscall.write("root: proc_create failed for ");
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
        const grant_rc = syscall.grant_perm(dg.handle, @intCast(proc_handle), dg.rights);
        if (grant_rc != 0) {
            syscall.write("root: device grant failed for ");
            syscall.write(name);
            syscall.write("\n");
        }
    }

    _ = perm_view_addr;

    children[num_children] = .{
        .name = name,
        .service_id = service_id,
        .proc_handle = @intCast(proc_handle),
        .cmd_shm_handle = cmd_shm,
        .cmd_channel = cmd,
        .allowed_connections = @intCast(allowed_connections.len),
    };
    num_children += 1;

    syscall.write("root: spawned ");
    syscall.write(name);
    syscall.write("\n");
    return true;
}

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

fn findDeviceByClass(perm_view_addr: u64, class: perms.DeviceClass, dtype: perms.DeviceType) ?u64 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(class) and
            entry.deviceType() == @intFromEnum(dtype))
        {
            return entry.handle;
        }
    }
    return null;
}

fn findAllMmioDevicesByClass(perm_view_addr: u64, class: perms.DeviceClass, out: []DeviceGrant) u32 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var count: u32 = 0;
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(class) and
            entry.deviceType() == @intFromEnum(perms.DeviceType.mmio) and
            count < out.len)
        {
            out[count] = .{ .handle = entry.handle, .rights = dev_rights };
            count += 1;
        }
    }
    return count;
}

fn findAllDevicesByClass(perm_view_addr: u64, class: perms.DeviceClass, out: []DeviceGrant) u32 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var count: u32 = 0;
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(class) and
            count < out.len)
        {
            out[count] = .{ .handle = entry.handle, .rights = dev_rights };
            count += 1;
        }
    }
    return count;
}

fn brokerConnection(requester: *ChildInfo, target_service_id: u32) void {
    const target = findChildByService(target_service_id) orelse {
        syscall.write("root: broker target not found\n");
        return;
    };

    const data_shm = syscall.shm_create(4 * syscall.PAGE4K);
    if (data_shm <= 0) {
        syscall.write("root: data shm_create failed\n");
        return;
    }

    const data_vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const data_vm = syscall.vm_reserve(0, 4 * syscall.PAGE4K, data_vm_rights);
    if (data_vm.val < 0) {
        syscall.write("root: data vm_reserve failed\n");
        return;
    }

    const data_map = syscall.shm_map(@intCast(data_shm), @intCast(data_vm.val), 0);
    if (data_map != 0) {
        syscall.write("root: data shm_map failed\n");
        return;
    }

    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(data_vm.val2);
    _ = channel_mod.Channel.initAsSideA(chan_header, 4 * syscall.PAGE4K);

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(data_shm), requester.proc_handle, grant_rights);
    _ = syscall.grant_perm(@intCast(data_shm), target.proc_handle, grant_rights);

    if (requester.cmd_channel) |cmd| {
        if (cmd.findConnectionByService(target_service_id)) |entry| {
            @as(*volatile u64, &entry.shm_handle).* = @intCast(data_shm);
            @as(*volatile u64, &entry.shm_size).* = 4 * syscall.PAGE4K;
            @as(*volatile u32, &entry.status).* = @intFromEnum(shm_protocol.ConnectionStatus.connected);
            cmd.notifyChild();
        }
    }

    if (target.cmd_channel) |cmd| {
        if (cmd.findConnectionByService(requester.service_id)) |entry| {
            @as(*volatile u64, &entry.shm_handle).* = @intCast(data_shm);
            @as(*volatile u64, &entry.shm_size).* = 4 * syscall.PAGE4K;
            @as(*volatile u32, &entry.status).* = @intFromEnum(shm_protocol.ConnectionStatus.connected);
            cmd.notifyChild();
        } else {
            cmd.addAllowedConnection(requester.service_id);
            if (cmd.findConnectionByService(requester.service_id)) |entry| {
                @as(*volatile u64, &entry.shm_handle).* = @intCast(data_shm);
                @as(*volatile u64, &entry.shm_size).* = 4 * syscall.PAGE4K;
                @as(*volatile u32, &entry.status).* = @intFromEnum(shm_protocol.ConnectionStatus.connected);
                cmd.notifyChild();
            }
        }
    }

    _ = syscall.shm_unmap(@intCast(data_shm), @intCast(data_vm.val));
    _ = syscall.revoke_perm(@intCast(data_shm));

    syscall.write("root: brokered connection ");
    syscall.write(requester.name);
    syscall.write(" <-> ");
    syscall.write(target.name);
    syscall.write("\n");
}

fn brokerLoop() void {
    syscall.write("root: entering broker loop\n");

    while (true) {
        var found_request = false;

        for (children[0..num_children]) |*child| {
            const cmd = child.cmd_channel orelse continue;
            // Only iterate over the connections that the root service originally
            // authorized. Ignore any entries the child may have added by writing
            // to shared memory (fixes VULN-I1).
            const authorized_count = @min(child.allowed_connections, shm_protocol.MAX_CONNECTIONS);
            for (cmd.connections[0..authorized_count]) |*entry| {
                if (@as(*volatile u32, &entry.status).* == @intFromEnum(shm_protocol.ConnectionStatus.requested)) {
                    brokerConnection(child, entry.service_id);
                    found_request = true;
                }
            }
        }

        if (!found_request) {
            syscall.thread_yield();
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("routerOS root service starting\n");

    var serial_devices: [4]DeviceGrant = undefined;
    const serial_count = findAllDevicesByClass(perm_view_addr, .serial, &serial_devices);

    var nic_devices: [8]DeviceGrant = undefined;
    const nic_count = findAllMmioDevicesByClass(perm_view_addr, .network, &nic_devices);

    syscall.write("root: found ");
    t.printDec(serial_count);
    syscall.write(" serial, ");
    t.printDec(nic_count);
    syscall.write(" NIC device handles\n");

    const nic_driver_rights = perms.ProcessRights{
        .grant_to = true,
        .mem_reserve = true,
        .shm_create = true,
        .device_own = true,
        .restart = true,
    };

    _ = spawnChild(
        "serial_driver",
        embedded.serial_driver,
        shm_protocol.ServiceId.SERIAL,
        .{ .grant_to = true, .mem_reserve = true, .device_own = true, .restart = true },
        &.{},
        perm_view_addr,
        serial_devices[0..serial_count],
    );

    if (nic_count >= 2) {
        _ = spawnChild(
            "nic_wan",
            embedded.nic_driver,
            shm_protocol.ServiceId.NIC_WAN,
            nic_driver_rights,
            &.{},
            perm_view_addr,
            nic_devices[0..1],
        );

        _ = spawnChild(
            "nic_lan",
            embedded.nic_driver,
            shm_protocol.ServiceId.NIC_LAN,
            nic_driver_rights,
            &.{},
            perm_view_addr,
            nic_devices[1..2],
        );

        _ = spawnChild(
            "router",
            embedded.router,
            shm_protocol.ServiceId.ROUTER,
            .{ .grant_to = true, .mem_reserve = true, .restart = true },
            &.{ shm_protocol.ServiceId.NIC_WAN, shm_protocol.ServiceId.NIC_LAN },
            perm_view_addr,
            &.{},
        );
    } else if (nic_count == 1) {
        _ = spawnChild(
            "nic_driver",
            embedded.nic_driver,
            shm_protocol.ServiceId.NIC_WAN,
            nic_driver_rights,
            &.{},
            perm_view_addr,
            nic_devices[0..1],
        );

        _ = spawnChild(
            "router",
            embedded.router,
            shm_protocol.ServiceId.ROUTER,
            .{ .grant_to = true, .mem_reserve = true, .restart = true },
            &.{shm_protocol.ServiceId.NIC_WAN},
            perm_view_addr,
            &.{},
        );
    }

    _ = spawnChild(
        "console",
        embedded.console,
        shm_protocol.ServiceId.CONSOLE,
        .{ .grant_to = true, .mem_reserve = true, .restart = true },
        &.{ shm_protocol.ServiceId.SERIAL, shm_protocol.ServiceId.ROUTER },
        perm_view_addr,
        &.{},
    );

    brokerLoop();
}
