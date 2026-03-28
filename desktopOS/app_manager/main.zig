const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_APPS = 16;
const MAX_BUCKET_ENTRIES = 16;

const MSG_DRIVER_AVAILABLE: u8 = 0x01;
const MSG_CONNECT_REQUEST: u8 = 0x02;

const AppInfo = struct {
    proc_handle: u64,
    cmd_shm_handle: i64,
    cmd_channel: *shm_protocol.CommandChannel,
    allowed_connections: u32,
};

var apps: [MAX_APPS]AppInfo = undefined;
var num_apps: u32 = 0;

// Bucket dispatch: per-driver queue of app proc_handles waiting for a connection
const Bucket = struct {
    entries: [MAX_BUCKET_ENTRIES]u64, // proc_handles
    count: u32,

    fn push(self: *Bucket, proc_handle: u64) void {
        if (self.count < MAX_BUCKET_ENTRIES) {
            self.entries[self.count] = proc_handle;
            self.count += 1;
        }
    }

    fn pop(self: *Bucket) ?u64 {
        if (self.count == 0) return null;
        const handle = self.entries[0];
        // Shift remaining entries
        var i: u32 = 0;
        while (i < self.count - 1) : (i += 1) {
            self.entries[i] = self.entries[i + 1];
        }
        self.count -= 1;
        return handle;
    }
};

// One bucket per known driver service ID (indexed by service_id for simplicity)
const MAX_DRIVER_BUCKETS = 8;
const DriverBucket = struct {
    service_id: u32,
    bucket: Bucket,
};

var driver_buckets: [MAX_DRIVER_BUCKETS]DriverBucket = undefined;
var num_buckets: u32 = 0;

fn findOrCreateBucket(service_id: u32) ?*DriverBucket {
    for (driver_buckets[0..num_buckets]) |*db| {
        if (db.service_id == service_id) return db;
    }
    if (num_buckets >= MAX_DRIVER_BUCKETS) return null;
    driver_buckets[num_buckets] = .{
        .service_id = service_id,
        .bucket = .{ .entries = undefined, .count = 0 },
    };
    num_buckets += 1;
    return &driver_buckets[num_buckets - 1];
}

fn findBucket(service_id: u32) ?*DriverBucket {
    for (driver_buckets[0..num_buckets]) |*db| {
        if (db.service_id == service_id) return db;
    }
    return null;
}

const DeviceGrant = struct {
    handle: u64,
    rights: u64,
};

fn spawnApp(
    name: []const u8,
    elf: []const u8,
    child_rights: perms.ProcessRights,
    allowed_drivers: []const u32,
) bool {
    const cmd_shm = syscall.shm_create(shm_protocol.COMMAND_SHM_SIZE);
    if (cmd_shm <= 0) {
        syscall.write("app_manager: shm_create failed for ");
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
        syscall.write("app_manager: vm_reserve failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("app_manager: shm_map failed for ");
        syscall.write(name);
        syscall.write("\n");
        return false;
    }

    const cmd: *shm_protocol.CommandChannel = @ptrFromInt(vm_result.val2);
    cmd.init();

    // Pre-populate allowed driver service IDs as connection entries
    for (allowed_drivers) |driver_id| {
        cmd.addAllowedConnection(driver_id);
    }

    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights.bits());
    if (proc_handle <= 0) {
        syscall.write("app_manager: proc_create failed for ");
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

    apps[num_apps] = .{
        .proc_handle = @intCast(proc_handle),
        .cmd_shm_handle = cmd_shm,
        .cmd_channel = cmd,
        .allowed_connections = @intCast(allowed_drivers.len),
    };
    num_apps += 1;

    syscall.write("app_manager: spawned ");
    syscall.write(name);
    syscall.write("\n");
    return true;
}

// Track which drivers are available (reported by device_manager)
var available_drivers: [16]u32 = .{0} ** 16;
var num_available_drivers: u32 = 0;

// Track mapped SHM handles
var mapped_handles: [16]u64 = .{0} ** 16;
var num_mapped: u32 = 0;

fn isHandleMapped(handle: u64) bool {
    for (mapped_handles[0..num_mapped]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handle: u64) void {
    if (num_mapped < mapped_handles.len) {
        mapped_handles[num_mapped] = handle;
        num_mapped += 1;
    }
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Detect restart
    const self_entry = &view[0];
    const restart_count = self_entry.processRestartCount();
    if (restart_count > 0) {
        syscall.write("app_manager: restarted\n");
    }

    // Record command channel SHM
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
            recordMapped(e.handle);
            break;
        }
    }

    // On fresh boot, spawn hello_app. On restart, recover child handle from perm view.
    if (restart_count == 0) {
        _ = spawnApp(
            "hello_app",
            embedded.hello_app,
            .{ .grant_to = true, .mem_reserve = true },
            &.{ shm_protocol.ServiceId.SERIAL_DRIVER, shm_protocol.ServiceId.USB_DRIVER },
        );
    } else {
        // Recover child process handles from perm view
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
                // Can't recover the command channel pointer on restart,
                // but the child's SHM handles are still valid
                apps[num_apps] = .{
                    .proc_handle = entry.handle,
                    .cmd_shm_handle = 0,
                    .cmd_channel = undefined,
                    .allowed_connections = 0,
                };
                num_apps += 1;
                break;
            }
        }
        syscall.write("app_manager: recovered hello_app handle\n");
    }

    // Request connection to device_manager (brokered by root)
    const dm_entry = cmd.requestConnection(shm_protocol.ServiceId.DEVICE_MANAGER) orelse return;
    if (!cmd.waitForConnection(dm_entry)) return;

    // Map the data channel with device_manager
    var dm_shm_handle: u64 = 0;
    var dm_shm_size: u64 = 0;
    while (dm_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                !isHandleMapped(e.handle))
            {
                dm_shm_handle = e.handle;
                dm_shm_size = e.field0;
                break;
            }
        }
        if (dm_shm_handle == 0) syscall.thread_yield();
    }
    recordMapped(dm_shm_handle);

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const dm_vm = syscall.vm_reserve(0, dm_shm_size, vm_rights);
    if (dm_vm.val < 0) return;
    if (syscall.shm_map(dm_shm_handle, @intCast(dm_vm.val), 0) != 0) return;

    const dm_chan_header: *channel_mod.ChannelHeader = @ptrFromInt(dm_vm.val2);
    var dm_chan = channel_mod.Channel.openAsSideA(dm_chan_header) orelse return;

    syscall.write("app_manager: connected to device_manager\n");

    // Track which command channel connections have been processed
    var processed_conns: [shm_protocol.MAX_CONNECTIONS]bool = .{false} ** shm_protocol.MAX_CONNECTIONS;
    // Mark already-connected entries as processed (e.g. data channel with device_manager)
    for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
        if (@as(*volatile u32, &conn.status).* == @intFromEnum(shm_protocol.ConnectionStatus.connected)) {
            processed_conns[ci] = true;
        }
    }

    // Main loop: process messages from device_manager and app connection requests
    var msg_buf: [256]u8 = undefined;
    while (true) {
        // Check for messages from device_manager (driver availability)
        if (dm_chan.recv(&msg_buf)) |len| {
            if (len >= 5 and msg_buf[0] == MSG_DRIVER_AVAILABLE) {
                const sid = @as(u32, msg_buf[1]) |
                    (@as(u32, msg_buf[2]) << 8) |
                    (@as(u32, msg_buf[3]) << 16) |
                    (@as(u32, msg_buf[4]) << 24);
                if (num_available_drivers < available_drivers.len) {
                    available_drivers[num_available_drivers] = sid;
                    num_available_drivers += 1;
                }
                syscall.write("app_manager: driver available, service_id=");
                writeU32(sid);
                syscall.write("\n");
            }
        }

        // Check apps' command channels for connection requests
        for (apps[0..num_apps]) |*app| {
            const app_cmd = app.cmd_channel;
            const authorized_count = @min(app.allowed_connections, shm_protocol.MAX_CONNECTIONS);
            for (app_cmd.connections[0..authorized_count]) |*conn| {
                if (@as(*volatile u32, &conn.status).* == @intFromEnum(shm_protocol.ConnectionStatus.requested)) {
                    // App wants a connection to this driver service
                    const driver_sid = conn.service_id;

                    // Policy check: is this driver available?
                    var driver_available = false;
                    for (available_drivers[0..num_available_drivers]) |d| {
                        if (d == driver_sid) {
                            driver_available = true;
                            break;
                        }
                    }
                    if (!driver_available) {
                        // Mark as unavailable — leave as requested, will retry
                        continue;
                    }

                    // Mark as pending so we don't re-request on next loop
                    @as(*volatile u32, &conn.status).* = @intFromEnum(shm_protocol.ConnectionStatus.available);

                    // Push to bucket and request from root
                    const bucket = findOrCreateBucket(driver_sid) orelse continue;
                    bucket.bucket.push(app.proc_handle);

                    // Request this driver connection from root
                    _ = cmd.requestConnection(driver_sid);

                    syscall.write("app_manager: requesting driver for app\n");
                }
            }
        }

        // Check for new SHM grants from root (fulfilled driver connection requests)
        // Match by finding newly connected command channel entries + new SHM in perm_view
        for (cmd.connections[0..cmd.num_connections], 0..) |*conn, ci| {
            if (processed_conns[ci]) continue;
            if (@as(*volatile u32, &conn.status).* != @intFromEnum(shm_protocol.ConnectionStatus.connected)) continue;

            // Find matching new SHM in perm_view
            for (view) |*e| {
                if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                    e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                    !isHandleMapped(e.handle))
                {
                    // Pop the next app from this driver's bucket
                    const bucket = findBucket(conn.service_id) orelse break;
                    const app_proc = bucket.bucket.pop() orelse break;

                    // Grant SHM to the app
                    const grant_rights = (perms.SharedMemoryRights{
                        .read = true,
                        .write = true,
                        .grant = false,
                    }).bits();
                    _ = syscall.grant_perm(e.handle, app_proc, grant_rights);

                    // Notify the app via its command channel
                    for (apps[0..num_apps]) |*app| {
                        if (app.proc_handle == app_proc) {
                            if (app.cmd_channel.findConnectionByService(conn.service_id)) |app_conn| {
                                @as(*volatile u64, &app_conn.shm_handle).* = e.handle;
                                @as(*volatile u64, &app_conn.shm_size).* = e.field0;
                                @as(*volatile u32, &app_conn.status).* = @intFromEnum(shm_protocol.ConnectionStatus.connected);
                                app.cmd_channel.notifyChild();
                            }
                            break;
                        }
                    }

                    syscall.write("app_manager: granted driver SHM to app\n");
                    recordMapped(e.handle);
                    processed_conns[ci] = true;
                    break;
                }
            }
        }

        // Brief wait before next poll
        cmd.waitForNotification(10_000_000); // 10ms
    }
}

fn writeU32(val: u32) void {
    var buf: [10]u8 = undefined;
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
