const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const fb_proto = lib.framebuffer;
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

/// Route a service_id to the parent process that manages it.
/// Returns null if the service_id is a direct child of root.
fn routeServiceToParent(service_id: u32) ?u32 {
    return switch (service_id) {
        shm_protocol.ServiceId.SERIAL_DRIVER => shm_protocol.ServiceId.DEVICE_MANAGER,
        shm_protocol.ServiceId.USB_DRIVER => shm_protocol.ServiceId.DEVICE_MANAGER,
        shm_protocol.ServiceId.COMPOSITOR => shm_protocol.ServiceId.DEVICE_MANAGER,
        else => null,
    };
}

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

fn findAllDevices(perm_view_addr: u64, out: []DeviceGrant) u32 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var count: u32 = 0;
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and count < out.len) {
            out[count] = .{ .handle = entry.handle, .rights = dev_rights };
            count += 1;
        }
    }
    return count;
}

fn spawnChild(
    name: []const u8,
    elf: []const u8,
    service_id: u32,
    child_rights: perms.ProcessRights,
    allowed_connections: []const u32,
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
    if (vm_result.val < 0) {
        syscall.write("root: vm_reserve failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("root: shm_map failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

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
        _ = syscall.grant_perm(dg.handle, @intCast(proc_handle), dg.rights);
    }

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

fn brokerConnection(requester: *ChildInfo, target_service_id: u32) void {
    // Route: if the target is a grandchild, find its parent (our direct child)
    const routed_id = routeServiceToParent(target_service_id) orelse target_service_id;
    const target = findChildByService(routed_id) orelse {
        syscall.write("root: broker target not found\n");
        return;
    };

    // Use large SHM for compositor (framebuffer), small for data channels
    const is_compositor = (target_service_id == shm_protocol.ServiceId.COMPOSITOR);
    const shm_size: u64 = if (is_compositor) fb_proto.FRAMEBUFFER_SHM_SIZE else 4 * syscall.PAGE4K;

    const data_shm = syscall.shm_create(shm_size);
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
    const data_vm = syscall.vm_reserve(0, shm_size, data_vm_rights);
    if (data_vm.val < 0) {
        syscall.write("root: data vm_reserve failed\n");
        return;
    }

    const data_map = syscall.shm_map(@intCast(data_shm), @intCast(data_vm.val), 0);
    if (data_map != 0) {
        syscall.write("root: data shm_map failed\n");
        return;
    }

    // Only init as ring-buffer channel for non-compositor SHMs
    if (!is_compositor) {
        const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(data_vm.val2);
        _ = channel_mod.Channel.initAsSideA(chan_header, @intCast(shm_size));
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(data_shm), requester.proc_handle, grant_rights);
    _ = syscall.grant_perm(@intCast(data_shm), target.proc_handle, grant_rights);

    // Write connection entry to requester's command channel (under mutex)
    if (requester.cmd_channel) |cmd| {
        cmd.setConnected(target_service_id, @intCast(data_shm), shm_size);
        cmd.notifyChild();
    }

    // Write connection entry to target's command channel (under mutex)
    if (target.cmd_channel) |cmd| {
        // For routed connections (grandchild services), use target_service_id
        // so device_manager knows which driver to forward to.
        // For direct connections, use requester's service_id.
        const lookup_id = if (routed_id != target_service_id) target_service_id else requester.service_id;
        cmd.setConnected(lookup_id, @intCast(data_shm), shm_size);
        cmd.notifyChild();
    }

    _ = syscall.shm_unmap(@intCast(data_shm), @intCast(data_vm.val));
    _ = syscall.revoke_perm(@intCast(data_shm));

    syscall.write("root: brokered connection for ");
    syscall.write(requester.name);
    syscall.write("\n");
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
        .normal_exit => "normal_exit",
        .killed => "killed",
        .revoked => "revoked",
        _ => "unknown",
    };
}

fn watchdogThread() void {
    const idx = watchdog_counter.fetchAdd(1, .monotonic);
    if (idx >= num_children) return;
    const child = &children[idx];

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_global);

    var entry_ptr: ?*const pv.UserViewEntry = null;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_PROCESS and e.handle == child.proc_handle) {
            entry_ptr = e;
            break;
        }
    }
    const entry = entry_ptr orelse return;

    const field0_ptr: *const u64 = @ptrCast(&entry.field0);
    const type_ptr: *const u8 = @ptrCast(&entry.entry_type);
    var last_field0 = @atomicLoad(u64, field0_ptr, .acquire);
    var last_restart_count: u16 = 0;

    while (true) {
        const current_type = @atomicLoad(u8, type_ptr, .acquire);
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
        last_field0 = @atomicLoad(u64, field0_ptr, .acquire);
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
            const authorized_count = @min(child.allowed_connections, shm_protocol.MAX_CONNECTIONS);
            for (cmd.connections[0..authorized_count]) |*entry| {
                if (@atomicLoad(u32, &entry.status, .acquire) == @intFromEnum(shm_protocol.ConnectionStatus.requested)) {
                    brokerConnection(child, entry.service_id);
                    found_request = true;
                }
            }
        }

        if (!found_request) {
            // Short sleep — we need to wake on any child's request.
            // futex_wait on first child with a short timeout, then re-check all.
            syscall.thread_yield();
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;

    // Find all devices — device_manager decides which go to which drivers
    var all_devices: [32]DeviceGrant = undefined;
    const device_count = findAllDevices(perm_view_addr, &all_devices);

    // Spawn device_manager with all device handles
    _ = spawnChild(
        "device_manager",
        embedded.device_manager,
        shm_protocol.ServiceId.DEVICE_MANAGER,
        .{
            .grant_to = true,
            .spawn_process = true,
            .mem_reserve = true,
            .device_own = true,
            .restart = true,
            .shm_create = true,
        },
        &.{
            shm_protocol.ServiceId.APP_MANAGER,
            shm_protocol.ServiceId.COMPOSITOR,
            shm_protocol.ServiceId.SERIAL_DRIVER,
            shm_protocol.ServiceId.USB_DRIVER,
        },
        all_devices[0..device_count],
    );

    // Spawn app_manager with no device handles
    _ = spawnChild(
        "app_manager",
        embedded.app_manager,
        shm_protocol.ServiceId.APP_MANAGER,
        .{
            .grant_to = true,
            .spawn_process = true,
            .mem_reserve = true,
            .restart = true,
            .shm_create = true,
        },
        &.{
            shm_protocol.ServiceId.COMPOSITOR,
            shm_protocol.ServiceId.DEVICE_MANAGER,
            shm_protocol.ServiceId.SERIAL_DRIVER,
            shm_protocol.ServiceId.USB_DRIVER,
        },
        &.{},
    );

    // Spawn watchdog threads
    var wi: u32 = 0;
    while (wi < num_children) : (wi += 1) {
        _ = syscall.thread_create(&watchdogThread, 0, 4);
    }

    brokerLoop();
}
