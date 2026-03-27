const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const std = @import("std");

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
var perm_view_global: u64 = 0;
var watchdog_counter = std.atomic.Value(u32).init(0);

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
}

fn crashReasonName(reason: pv.CrashReason) []const u8 {
    return switch (reason) {
        .none => "none",
        .stack_overflow => "stack_overflow",
        .stack_underflow => "stack_underflow",
        .invalid_read => "invalid_read",
        .invalid_write => "invalid_write",
        .invalid_execute => "invalid_execute",
        .unmapped_access => "unmapped_access",
        .out_of_memory => "out_of_memory",
        .arithmetic_fault => "arithmetic_fault",
        .illegal_instruction => "illegal_instruction",
        .alignment_fault => "alignment_fault",
        .protection_fault => "protection_fault",
        _ => "unknown",
    };
}

fn watchdogThread() void {
    const idx = watchdog_counter.fetchAdd(1, .monotonic);
    if (idx >= num_children) return;
    const child = &children[idx];

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_global);

    // Find the perm view entry for this child's process handle
    var entry_ptr: ?*const pv.UserViewEntry = null;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_PROCESS and e.handle == child.proc_handle) {
            entry_ptr = e;
            break;
        }
    }
    const entry = entry_ptr orelse return;

    var last_field0 = @as(*const volatile u64, @ptrCast(&entry.field0)).*;
    var last_restart_count: u16 = 0;

    while (true) {
        const current_type = @as(*const volatile u8, @ptrCast(&entry.entry_type)).*;
        if (current_type == pv.ENTRY_TYPE_DEAD_PROCESS) {
            const reason = @as(*const pv.UserViewEntry, @ptrCast(entry)).processCrashReason();
            syscall.write("watchdog: ");
            syscall.write(child.name);
            syscall.write(" died, reason=");
            syscall.write(crashReasonName(reason));
            syscall.write("\n");
            return;
        }

        const restart_count = @as(*const pv.UserViewEntry, @ptrCast(entry)).processRestartCount();
        if (restart_count > last_restart_count) {
            const reason = @as(*const pv.UserViewEntry, @ptrCast(entry)).processCrashReason();
            syscall.write("watchdog: ");
            syscall.write(child.name);
            syscall.write(" restarted (count=");
            writeU16(restart_count);
            syscall.write("), reason=");
            syscall.write(crashReasonName(reason));
            syscall.write("\n");
            last_restart_count = restart_count;
        }

        _ = syscall.futex_wait(@ptrCast(&entry.field0), last_field0, std.math.maxInt(u64));
        last_field0 = @as(*const volatile u64, @ptrCast(&entry.field0)).*;
    }
}

fn writeU16(val: u16) void {
    var buf: [5]u8 = undefined;
    var n = val;
    var i: usize = buf.len;
    if (n == 0) {
        syscall.write("0");
        return;
    }
    while (n > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(n % 10));
        n /= 10;
    }
    syscall.write(buf[i..]);
}

fn brokerLoop() void {
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
            // Block until any child sends a connection request (with 10ms timeout
            // to periodically check all children, since we can only wait on one)
            if (num_children > 0) {
                if (children[0].cmd_channel) |cmd| {
                    const current = @atomicLoad(u64, &cmd.wake_flag, .acquire);
                    _ = syscall.futex_wait(&cmd.wake_flag, current, 10_000_000);
                }
            }
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;
    syscall.write("root: starting\n");
    var serial_devices: [4]DeviceGrant = undefined;
    const serial_count = findAllDevicesByClass(perm_view_addr, .serial, &serial_devices);
    syscall.write("root: found serial devices\n");

    var nic_devices: [8]DeviceGrant = undefined;
    const nic_count = findAllMmioDevicesByClass(perm_view_addr, .network, &nic_devices);

    syscall.write("root: spawning serial_driver\n");
    _ = spawnChild(
        "serial_driver",
        embedded.serial_driver,
        shm_protocol.ServiceId.SERIAL,
        .{ .grant_to = true, .mem_reserve = true, .device_own = true, .restart = true },
        &.{},
        perm_view_addr,
        serial_devices[0..serial_count],
    );
    syscall.write("root: spawning router\n");

    // Router process owns NIC devices directly (monolithic NIC+router)
    const router_rights = perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .set_affinity = true,
        .shm_create = true,
        .device_own = true,
        .restart = true,
        .pin_exclusive = true,
    };

    _ = spawnChild(
        "router",
        embedded.router,
        shm_protocol.ServiceId.ROUTER,
        router_rights,
        &.{},
        perm_view_addr,
        nic_devices[0..nic_count],
    );
    syscall.write("root: spawning nfs_client\n");

    _ = spawnChild(
        "nfs_client",
        embedded.nfs_client,
        shm_protocol.ServiceId.NFS_CLIENT,
        .{ .grant_to = true, .mem_reserve = true, .restart = true },
        &.{shm_protocol.ServiceId.ROUTER},
        perm_view_addr,
        &.{},
    );

    _ = spawnChild(
        "ntp_client",
        embedded.ntp_client,
        shm_protocol.ServiceId.NTP_CLIENT,
        .{ .grant_to = true, .mem_reserve = true, .restart = true },
        &.{shm_protocol.ServiceId.ROUTER},
        perm_view_addr,
        &.{},
    );

    _ = spawnChild(
        "http_server",
        embedded.http_server,
        shm_protocol.ServiceId.HTTP_SERVER,
        .{ .grant_to = true, .mem_reserve = true, .restart = true },
        &.{shm_protocol.ServiceId.ROUTER},
        perm_view_addr,
        &.{},
    );

    _ = spawnChild(
        "console",
        embedded.console,
        shm_protocol.ServiceId.CONSOLE,
        .{ .grant_to = true, .mem_reserve = true, .restart = true },
        &.{ shm_protocol.ServiceId.SERIAL, shm_protocol.ServiceId.ROUTER, shm_protocol.ServiceId.NFS_CLIENT, shm_protocol.ServiceId.NTP_CLIENT, shm_protocol.ServiceId.HTTP_SERVER },
        perm_view_addr,
        &.{},
    );

    // Spawn watchdog threads for each child
    var wi: u32 = 0;
    while (wi < num_children) : (wi += 1) {
        _ = syscall.thread_create(&watchdogThread, 0, 4);
    }

    brokerLoop();
}
