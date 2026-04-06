const lib = @import("lib");

const channel = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const reload_proto = lib.reload;
const syscall = lib.syscall;
const text_cmd = lib.text_command;

const std = @import("std");

const Channel = channel.Channel;

const MAX_PERMS = 128;
const MAX_CHILDREN = 16;
const MAX_DEVICES = 8;
const DEFAULT_SHM_SIZE: u64 = 4 * syscall.PAGE4K;
const ELF_BUF_SIZE: usize = 256 * 1024;

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

const ChildInfo = struct {
    name: []const u8,
    proc_handle: u64,
    rights: u64,
    devices: [MAX_DEVICES]DeviceGrant,
    device_count: u32,
};

var children: [MAX_CHILDREN]ChildInfo = undefined;
var num_children: u32 = 0;
var perm_view_global: u64 = 0;
var watchdog_counter = std.atomic.Value(u32).init(0);

var console_chan: *Channel = undefined;
var nfs_chan: *Channel = undefined;
var has_console: bool = false;
var has_nfs: bool = false;

var elf_buf: [ELF_BUF_SIZE]u8 = undefined;

fn spawnChild(
    name: []const u8,
    elf: []const u8,
    child_rights: u64,
    device_handles: []const DeviceGrant,
) bool {
    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights) catch {
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

    var child = &children[num_children];
    child.name = name;
    child.proc_handle = proc_handle;
    child.rights = child_rights;
    child.device_count = @intCast(@min(device_handles.len, MAX_DEVICES));
    for (device_handles[0..child.device_count], 0..) |dg, i| {
        child.devices[i] = dg;
    }
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

// ── Reload logic ────────────────────────────────────────────────────

fn findChildByName(name: []const u8) ?u32 {
    for (children[0..num_children], 0..) |*child, i| {
        if (child.name.len == name.len) {
            var match = true;
            for (child.name, name) |a, b| {
                if (a != b) {
                    match = false;
                    break;
                }
            }
            if (match) return @intCast(i);
        }
    }
    return null;
}

fn handleReload(name: []const u8) void {
    const srv = reload_proto.Server.init(console_chan);

    const child_idx = findChildByName(name) orelse {
        srv.sendError("unknown process");
        return;
    };

    // Don't reload root_service's own dependencies mid-operation
    if (eql(name, "console")) {
        srv.sendError("cannot reload console");
        return;
    }

    srv.sendStatus("fetching ELF from NFS...");

    // Request file from NFS client
    var cmd_buf: [256]u8 = undefined;
    const prefix = "cat builds/";
    const suffix = ".elf";
    if (prefix.len + name.len + suffix.len > cmd_buf.len) {
        srv.sendError("name too long");
        return;
    }
    @memcpy(cmd_buf[0..prefix.len], prefix);
    @memcpy(cmd_buf[prefix.len..][0..name.len], name);
    @memcpy(cmd_buf[prefix.len + name.len ..][0..suffix.len], suffix);
    const cmd_len = prefix.len + name.len + suffix.len;

    const nfs_client = text_cmd.Client.init(nfs_chan);
    nfs_client.sendCommand(cmd_buf[0..cmd_len]);

    // Accumulate ELF data
    var elf_len: usize = 0;
    var resp_buf: [2048]u8 = undefined;
    var done = false;
    var got_error = false;
    var attempts: u32 = 0;

    while (!done and attempts < 500) {
        if (nfs_client.recv(&resp_buf)) |msg| {
            switch (msg) {
                .text => |data| {
                    if (elf_len + data.len <= ELF_BUF_SIZE) {
                        @memcpy(elf_buf[elf_len..][0..data.len], data);
                        elf_len += data.len;
                    } else {
                        srv.sendError("ELF too large");
                        // Drain remaining
                        drainNfs(&nfs_client);
                        return;
                    }
                    attempts = 0;
                },
                .end => {
                    done = true;
                },
                .err => |text| {
                    srv.sendError(text);
                    got_error = true;
                    done = true;
                },
                .ack => {
                    attempts = 0;
                },
            }
        } else {
            nfs_client.waitForMessage(100_000_000); // 100ms
            attempts += 1;
        }
    }

    if (!done) {
        srv.sendError("NFS timeout");
        return;
    }
    if (got_error) return;
    if (elf_len == 0) {
        srv.sendError("empty ELF");
        return;
    }

    srv.sendStatus("killing old process...");

    const child = &children[child_idx];
    const old_handle = child.proc_handle;

    // Kill the old process
    syscall.revoke_perm(old_handle);

    // Wait for it to die
    waitForDead(old_handle);

    srv.sendStatus("spawning new process...");

    // Spawn with new ELF
    const new_handle = syscall.proc_create(@intFromPtr(&elf_buf), elf_len, child.rights) catch |err| {
        const err_msg = switch (err) {
            error.InvalidArgument => "proc_create: invalid argument",
            error.PermissionDenied => "proc_create: permission denied",
            error.OutOfMemory => "proc_create: out of memory",
            error.BadAddress => "proc_create: bad address",
            error.MaxCapabilities => "proc_create: max capabilities",
            else => "proc_create: unknown error",
        };
        srv.sendError(err_msg);
        return;
    };

    // Re-grant device permissions
    for (child.devices[0..child.device_count]) |dg| {
        syscall.grant_perm(dg.handle, new_handle, dg.rights) catch {
            syscall.write("root: device re-grant failed\n");
        };
    }

    // Grant NFS channel SHM to the new process if this is nfs_client
    if (eql(name, "nfs_client")) {
        // NFS client needs the root→nfs channel re-granted
        // The SHM handle was already granted at spawn; the new process will pick it up
        // via pollNewShm since it gets a fresh perm_view
    }

    child.proc_handle = new_handle;

    // Spawn a new watchdog thread for the reloaded process
    _ = syscall.thread_create(&watchdogThread, 0, 4) catch 0;

    syscall.write("root: reloaded ");
    syscall.write(name);
    syscall.write("\n");

    srv.sendOk();
}

fn waitForDead(handle: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_global);
    for (view) |*entry| {
        if (entry.handle == handle) {
            const type_ptr: *const u8 = @ptrCast(&entry.entry_type);
            var waits: u32 = 0;
            while (waits < 100) : (waits += 1) {
                const current_type = @atomicLoad(u8, type_ptr, .acquire);
                if (current_type == pv.ENTRY_TYPE_DEAD_PROCESS or
                    current_type == pv.ENTRY_TYPE_EMPTY)
                {
                    return;
                }
                syscall.thread_yield();
            }
            return;
        }
    }
}

fn drainNfs(client: *const text_cmd.Client) void {
    var buf: [2048]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (client.recv(&buf)) |msg| {
            switch (msg) {
                .end => return,
                else => {
                    attempts = 0;
                },
            }
        }
        client.waitForMessage(50_000_000);
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

// ── Main ────────────────────────────────────────────────────────────

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;
    var serial_devices: [4]DeviceGrant = undefined;
    const serial_count = findAllDevicesByClass(perm_view_addr, .serial, &serial_devices);

    var nic_devices: [8]DeviceGrant = undefined;
    const nic_count = findAllMmioDevicesByClass(perm_view_addr, .network, &nic_devices);

    const base_rights = (perms.ProcessRights{
        .grant_to_child = true,
        .mem_reserve = true,
        .restart = true,
        .shm_create = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    }).bits();

    const serial_rights = (perms.ProcessRights{
        .grant_to_child = true,
        .mem_reserve = true,
        .device_own = true,
        .restart = true,
        .shm_create = true,
        .grant_to_broadcast = true,
        .broadcast = true,
    }).bits();

    const router_rights = (perms.ProcessRights{
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
    }).bits();

    _ = spawnChild("serial_driver", embedded.serial_driver, serial_rights, serial_devices[0..serial_count]);
    _ = spawnChild("router", embedded.router, router_rights, nic_devices[0..nic_count]);
    _ = spawnChild("nfs_client", embedded.nfs_client, base_rights, &.{});
    _ = spawnChild("ntp_client", embedded.ntp_client, base_rights, &.{});
    _ = spawnChild("http_server", embedded.http_server, base_rights, &.{});
    _ = spawnChild("console", embedded.console, base_rights, &.{});

    // Create SHM channels to console and nfs_client, grant handles
    const console_idx = findChildByName("console");
    const nfs_idx = findChildByName("nfs_client");

    if (console_idx) |idx| {
        const conn = Channel.connectAsA(
            children[idx].proc_handle,
            .root_service,
            DEFAULT_SHM_SIZE,
        ) catch {
            syscall.write("root: console channel failed\n");
            unreachable;
        };
        console_chan = conn.chan;
        has_console = true;
    }

    if (nfs_idx) |idx| {
        const conn = Channel.connectAsA(
            children[idx].proc_handle,
            .root_service,
            DEFAULT_SHM_SIZE,
        ) catch {
            syscall.write("root: nfs channel failed\n");
            unreachable;
        };
        nfs_chan = conn.chan;
        has_nfs = true;
    }

    // Spawn watchdog threads for each child
    var wi: u32 = 0;
    while (wi < num_children) : (wi += 1) {
        _ = syscall.thread_create(&watchdogThread, 0, 4) catch 0;
    }

    // Main loop: listen for reload commands from console
    var cmd_buf: [256]u8 = undefined;
    while (true) {
        if (has_console) {
            const srv = reload_proto.Server.init(console_chan);
            if (srv.recvCommand(&cmd_buf)) |cmd| {
                switch (cmd) {
                    .reload => |name| {
                        if (has_nfs) {
                            handleReload(name);
                        } else {
                            srv.sendError("NFS not connected");
                        }
                    },
                }
            } else {
                console_chan.waitForMessage(.B, 100_000_000); // 100ms
            }
        } else {
            syscall.thread_yield();
        }
    }
}
