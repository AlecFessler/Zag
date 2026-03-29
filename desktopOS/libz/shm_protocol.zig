const std = @import("std");
const sync = @import("sync.zig");
const syscall = @import("syscall.zig");
const pv = @import("perm_view.zig");
const perms = @import("perms.zig");

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub const MAX_CONNECTIONS = 8;
pub const COMMAND_SHM_SIZE = 4096;

pub const ConnectionStatus = enum(u32) {
    available = 0,
    requested = 1,
    connected = 2,
};

pub const ConnectionEntry = extern struct {
    service_id: u32,
    status: u32,
    shm_handle: u64,
    shm_size: u64,
    _reserved: u64,
};

pub const CommandChannel = extern struct {
    cmd_mutex: sync.Mutex,
    wake_flag: u64 align(8),
    reply_flag: u64 align(8),
    num_connections: u32,
    child_flags: u32 = 0,
    active_app_gen: u64 align(8) = 0,
    active_app_index: u8 = 0,
    _pad_active: [7]u8 = .{0} ** 7,
    connections: [MAX_CONNECTIONS]ConnectionEntry,

    pub fn init(self: *CommandChannel) void {
        self.cmd_mutex = sync.Mutex.init();
        self.wake_flag = 0;
        self.reply_flag = 0;
        self.num_connections = 0;
        self.child_flags = 0;
        self.active_app_gen = 0;
        self.active_app_index = 0;
        self._pad_active = .{0} ** 7;
        for (&self.connections) |*c| {
            c.* = .{
                .service_id = 0,
                .status = @intFromEnum(ConnectionStatus.available),
                .shm_handle = 0,
                .shm_size = 0,
                ._reserved = 0,
            };
        }
    }

    pub fn addAllowedConnection(self: *CommandChannel, service_id: u32) void {
        if (self.num_connections >= MAX_CONNECTIONS) return;
        self.connections[self.num_connections] = .{
            .service_id = service_id,
            .status = @intFromEnum(ConnectionStatus.available),
            .shm_handle = 0,
            .shm_size = 0,
            ._reserved = 0,
        };
        self.num_connections += 1;
    }

    pub fn requestConnection(self: *CommandChannel, service_id: u32) ?*ConnectionEntry {
        for (self.connections[0..self.num_connections]) |*entry| {
            if (entry.service_id != service_id) continue;
            // Atomic read of status to handle concurrent updates from broker
            const status = @atomicLoad(u32, &entry.status, .acquire);
            if (status == @intFromEnum(ConnectionStatus.connected)) return entry;
            if (status == @intFromEnum(ConnectionStatus.available)) {
                // CAS: only set requested if still available (broker may have set connected)
                if (@cmpxchgStrong(u32, &entry.status, @intFromEnum(ConnectionStatus.available), @intFromEnum(ConnectionStatus.requested), .acq_rel, .acquire)) |actual| {
                    // CAS failed — check if broker already connected it
                    if (actual == @intFromEnum(ConnectionStatus.connected)) return entry;
                    return null; // unexpected state
                }
                _ = @atomicRmw(u64, &self.wake_flag, .Add, 1, .release);
                _ = syscall.futex_wake(&self.wake_flag, 1);
                return entry;
            }
        }
        return null;
    }

    pub fn waitForConnection(self: *CommandChannel, entry: *ConnectionEntry) bool {
        if (@atomicLoad(u32, &entry.status, .acquire) == @intFromEnum(ConnectionStatus.connected))
            return entry.shm_handle != 0;
        while (@atomicLoad(u32, &entry.status, .acquire) != @intFromEnum(ConnectionStatus.connected)) {
            const current = @atomicLoad(u64, &self.reply_flag, .acquire);
            if (@atomicLoad(u32, &entry.status, .acquire) == @intFromEnum(ConnectionStatus.connected)) break;
            _ = syscall.futex_wait(&self.reply_flag, current, MAX_TIMEOUT);
        }
        return entry.shm_handle != 0;
    }

    pub fn waitForAnyRequest(self: *CommandChannel) void {
        const current = @atomicLoad(u64, &self.wake_flag, .acquire);
        _ = syscall.futex_wait(&self.wake_flag, current, MAX_TIMEOUT);
    }

    /// Wait for a broker-established connection notification (signals reply_flag).
    /// Used by target processes that receive connections rather than request them.
    pub fn waitForNotification(self: *CommandChannel, timeout_ns: u64) void {
        const current = @atomicLoad(u64, &self.reply_flag, .acquire);
        _ = syscall.futex_wait(&self.reply_flag, current, timeout_ns);
    }

    pub fn notifyChild(self: *CommandChannel) void {
        _ = @atomicRmw(u64, &self.reply_flag, .Add, 1, .release);
        _ = syscall.futex_wake(&self.reply_flag, 1);
    }

    pub fn findConnectionByService(self: *CommandChannel, service_id: u32) ?*ConnectionEntry {
        for (self.connections[0..self.num_connections]) |*entry| {
            if (entry.service_id == service_id) return entry;
        }
        return null;
    }

    /// Set a connection entry to connected with the given SHM.
    /// Writes shm fields first, then atomically stores connected status.
    pub fn setConnected(self: *CommandChannel, service_id: u32, shm_handle: u64, shm_size: u64) void {
        const entry = self.findConnectionByService(service_id) orelse blk: {
            self.addAllowedConnection(service_id);
            break :blk self.findConnectionByService(service_id) orelse return;
        };
        // Write data fields before status so reader sees valid data after status change
        entry.shm_handle = shm_handle;
        entry.shm_size = shm_size;
        @atomicStore(u32, &entry.status, @intFromEnum(ConnectionStatus.connected), .release);
    }

    pub fn findConnectedShm(self: *CommandChannel, service_id: u32) ?u64 {
        for (self.connections[0..self.num_connections]) |*entry| {
            if (entry.service_id == service_id and entry.status == @intFromEnum(ConnectionStatus.connected)) {
                return entry.shm_handle;
            }
        }
        return null;
    }
};

pub const CHILD_FLAG_SPAWN_APP: u32 = 1;
pub const CHILD_FLAG_ACTIVE_CHANGED: u32 = 2;

pub const ServiceId = struct {
    pub const DEVICE_MANAGER: u32 = 1;
    pub const APP_MANAGER: u32 = 2;
    pub const SERIAL_DRIVER: u32 = 3;
    pub const USB_DRIVER: u32 = 4;
    pub const COMPOSITOR: u32 = 5;
};

pub fn mapCommandChannel(perm_view_addr: u64) ?*CommandChannel {
    const MAX_PERMS = 128;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    while (true) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                shm_handle = entry.handle;
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_handle != 0) break;
        pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }

    if (shm_size < COMMAND_SHM_SIZE) return null;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return null;

    const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return null;

    return @ptrFromInt(vm_result.val2);
}
