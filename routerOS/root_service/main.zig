const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const std = @import("std");

const MAX_PERMS = 128;
const MAX_CHILDREN = 16;

const ChildInfo = struct {
    name: []const u8,
    proc_handle: u64,
};

var children: [MAX_CHILDREN]ChildInfo = undefined;
var num_children: u32 = 0;
var perm_view_global: u64 = 0;
var watchdog_counter = std.atomic.Value(u32).init(0);

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

fn spawnChild(
    name: []const u8,
    elf: []const u8,
    child_rights: perms.ProcessRights,
    device_handles: []const DeviceGrant,
) bool {
    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights.bits()) catch {
        syscall.write("root: proc_create failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    };

    for (device_handles) |dg| {
        syscall.grant_perm(dg.handle, proc_handle, dg.rights) catch {
            syscall.write("root: device grant failed for ");
            syscall.write(name);
            syscall.write("\n");
        };
    }

    children[num_children] = .{
        .name = name,
        .proc_handle = proc_handle,
    };
    num_children += 1;

    return true;
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

        syscall.futex_wait(@ptrCast(&entry.field0), last_field0, std.math.maxInt(u64)) catch |err| switch (err) {
            error.Timeout, error.Again => {},
            else => syscall.write("watchdog: futex_wait failed\n"),
        };
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

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;
    var serial_devices: [4]DeviceGrant = undefined;
    const serial_count = findAllDevicesByClass(perm_view_addr, .serial, &serial_devices);

    var nic_devices: [8]DeviceGrant = undefined;
    const nic_count = findAllMmioDevicesByClass(perm_view_addr, .network, &nic_devices);

    const base_rights = perms.ProcessRights{
        .grant_to_child = true,
        .mem_reserve = true,
        .restart = true,
        .shm_create = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    };

    _ = spawnChild("serial_driver", embedded.serial_driver, perms.ProcessRights{
        .grant_to_child = base_rights.grant_to_child,
        .mem_reserve = true,
        .device_own = true,
        .restart = true,
        .shm_create = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    }, serial_devices[0..serial_count]);

    const router_rights = perms.ProcessRights{
        .grant_to_child = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .set_affinity = true,
        .shm_create = true,
        .device_own = true,
        .restart = true,
        .pin_exclusive = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    };

    _ = spawnChild("router", embedded.router, router_rights, nic_devices[0..nic_count]);
    _ = spawnChild("nfs_client", embedded.nfs_client, base_rights, &.{});
    _ = spawnChild("ntp_client", embedded.ntp_client, base_rights, &.{});
    _ = spawnChild("http_server", embedded.http_server, base_rights, &.{});
    _ = spawnChild("console", embedded.console, base_rights, &.{});

    // Spawn watchdog threads for each child
    var wi: u32 = 0;
    while (wi < num_children) : (wi += 1) {
        _ = syscall.thread_create(&watchdogThread, 0, 4) catch 0;
    }

    while (true) syscall.thread_yield();
}
