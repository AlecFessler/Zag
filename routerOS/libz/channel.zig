const lib = @import("lib.zig");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

pub var perm_view_addr: u64 = 0;

const BROADCAST_TABLE_CAPACITY: usize = 256;

pub const BroadcastEntry = extern struct {
    handle: u64,
    payload: u64,
};

const rw_shareable = (perms.VmReservationRights{
    .read = true,
    .write = true,
    .shareable = true,
}).bits();

const shm_rw_grant = (perms.SharedMemoryRights{
    .read = true,
    .write = true,
    .grant = true,
}).bits();

pub fn alignToPages(size: u64) u64 {
    return (size + syscall.PAGE4K - 1) & ~(syscall.PAGE4K - 1);
}

/// Calls the broadcast syscall with protocol_id in the low byte of the payload.
pub fn broadcast(protocol_id: u8) !void {
    const rc = syscall.broadcast_syscall(@as(u64, protocol_id));
    if (rc == -2) return error.NoPerm;
    if (rc == -4) return error.TableFull;
    if (rc == -1) return error.DuplicatePayload;
    if (rc != 0) return error.Unexpected;
}

/// Scans the broadcast table for an entry whose payload low byte matches
/// the given protocol. Returns the broadcast handle, or null if not found.
pub fn findBroadcastHandle(view_addr: u64, protocol: lib.Protocol) ?u64 {
    const table_vaddr = findBroadcastTableVaddr(view_addr) orelse return null;
    const entries: *const [BROADCAST_TABLE_CAPACITY]BroadcastEntry = @ptrFromInt(table_vaddr);
    for (entries) |entry| {
        if (entry.handle == 0) break;
        if (@as(u8, @truncate(entry.payload)) == @intFromEnum(protocol)) return entry.handle;
    }
    return null;
}

fn findBroadcastTableVaddr(view_addr: u64) ?u64 {
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(view_addr);
    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_BROADCAST_TABLE) return entry.field0;
    }
    return null;
}

pub const Channel = extern struct {
    pub const Side = enum(u1) {
        A,
        B,
    };

    const HEADER_SIZE = 8;

    protocol_id: u8 = 0,
    _reserved: [7]u8 = .{0} ** 7,

    // Cache line 1 — written by A-side producer, read by B-side consumer
    A_tx: u64 = 0,
    A_cached_rx: u64 = 0,
    B_rx: u64 = 0,
    B_cached_tx: u64 = 0,
    _pad1: [64]u8 = .{0} ** 64,

    // Cache line 2 — written by B-side producer, read by A-side consumer
    A_rx: u64 = 0,
    A_cached_tx: u64 = 0,
    B_tx: u64 = 0,
    B_cached_rx: u64 = 0,
    _pad2: [64]u8 = .{0} ** 64,

    // Connection state
    A_connected: u64 = 0,
    B_connected: u64 = 0,

    // Layout
    base1: u64 = 0,
    base2: u64 = 0,
    capacity: u64 = 0,

    pub fn init(region: []u8, protocol: u8) ?*Channel {
        if (region.len <= @sizeOf(Channel)) return null;
        const self: *Channel = @ptrCast(@alignCast(region.ptr));
        self.* = .{};
        const data_size = region.len - @sizeOf(Channel);
        const half = data_size / 2;
        self.protocol_id = protocol;
        self.base1 = @sizeOf(Channel);
        self.base2 = @sizeOf(Channel) + half;
        self.capacity = half;
        self.A_connected = 1;
        return self;
    }

    pub const Connection = struct {
        chan: *Channel,
        shm_handle: u64,
    };

    pub fn connectAsA(target_handle: u64, protocol: lib.Protocol, shm_size: u64) ?Connection {
        const aligned_size = alignToPages(shm_size);
        const shm = syscall.shm_create_with_rights(aligned_size, shm_rw_grant);
        if (shm <= 0) return null;

        const vm_result = syscall.vm_reserve(0, aligned_size, rw_shareable);
        if (vm_result.val < 0) return null;

        if (syscall.shm_map(@intCast(shm), @intCast(vm_result.val), 0) != 0) return null;

        const region: [*]u8 = @ptrFromInt(vm_result.val2);
        const chan = Channel.init(region[0..aligned_size], @intFromEnum(protocol)) orelse return null;

        _ = syscall.grant_perm(@intCast(shm), target_handle, shm_rw_grant);

        return .{ .chan = chan, .shm_handle = @intCast(shm) };
    }

    pub fn connectAsB(shm_handle: u64, shm_size: u64) ?*Channel {
        const aligned_size = alignToPages(shm_size);
        const vm_result = syscall.vm_reserve(0, aligned_size, rw_shareable);
        if (vm_result.val < 0) return null;

        const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
        if (map_rc != 0) return null;

        const chan: *Channel = @ptrFromInt(vm_result.val2);
        @atomicStore(u64, &chan.B_connected, 1, .release);
        return chan;
    }

    fn peerConnected(self: *Channel, side: Side) bool {
        const flag = if (side == .A) &self.B_connected else &self.A_connected;
        return @atomicLoad(u64, flag, .acquire) != 0;
    }

    fn txPtr(self: *Channel, side: Side) *u64 {
        return if (side == .A) &self.A_tx else &self.B_tx;
    }

    fn cachedRxPtr(self: *Channel, side: Side) *u64 {
        return if (side == .A) &self.A_cached_rx else &self.B_cached_rx;
    }

    fn rxPtr(self: *Channel, side: Side) *u64 {
        return if (side == .A) &self.B_rx else &self.A_rx;
    }

    fn cachedTxPtr(self: *Channel, side: Side) *u64 {
        return if (side == .A) &self.B_cached_tx else &self.A_cached_tx;
    }

    fn bufferSlice(self: *Channel, side: Side) [*]u8 {
        const base: [*]u8 = @ptrCast(self);
        const offset = if (side == .A) self.base1 else self.base2;
        return base + offset;
    }

    fn ringWrite(buf: [*]u8, buf_size: u64, pos: u64, data: []const u8) void {
        const start = pos % buf_size;
        const first = buf_size - start;
        if (first >= data.len) {
            @memcpy(buf[start..][0..data.len], data);
        } else {
            @memcpy(buf[start..][0..first], data[0..first]);
            @memcpy(buf[0 .. data.len - first], data[first..]);
        }
    }

    fn ringRead(buf: [*]u8, buf_size: u64, pos: u64, out: []u8) void {
        const start = pos % buf_size;
        const first = buf_size - start;
        if (first >= out.len) {
            @memcpy(out, buf[start..][0..out.len]);
        } else {
            @memcpy(out[0..first], buf[start..][0..first]);
            @memcpy(out[first..], buf[0 .. out.len - first]);
        }
    }

    pub fn sendMessage(self: *Channel, side: Side, msg: []const u8) error{ChannelFull}!void {
        const tx_p = self.txPtr(side);
        const cached_rx_p = self.cachedRxPtr(side);
        const rx_p = self.rxPtr(side);
        const buf = self.bufferSlice(side);
        const buf_size = self.capacity;

        const total = HEADER_SIZE + msg.len;
        const tx = tx_p.*;
        var available = buf_size -% (tx -% cached_rx_p.*);
        if (available < total) {
            cached_rx_p.* = @atomicLoad(u64, rx_p, .acquire);
            available = buf_size -% (tx -% cached_rx_p.*);
            if (available < total) return error.ChannelFull;
        }

        var hdr_buf: [8]u8 = undefined;
        @as(*align(1) u64, @ptrCast(&hdr_buf[0])).* = msg.len;
        ringWrite(buf, buf_size, tx, &hdr_buf);
        ringWrite(buf, buf_size, tx + HEADER_SIZE, msg);

        @atomicStore(u64, tx_p, tx +% total, .release);
        _ = syscall.futex_wake(tx_p, 1);
    }

    /// Block until a message is available from the peer, or timeout expires.
    pub fn waitForMessage(self: *Channel, side: Side, timeout_ns: u64) void {
        const other: Side = if (side == .A) .B else .A;
        const peer_tx_p = self.txPtr(other);
        const cached_tx_p = self.cachedTxPtr(other);
        const current_tx = @atomicLoad(u64, peer_tx_p, .acquire);
        if (current_tx != cached_tx_p.*) return;
        _ = syscall.futex_wait(peer_tx_p, current_tx, timeout_ns);
    }

    pub fn receiveMessage(self: *Channel, side: Side, out: []u8) error{Disconnected}!?u64 {
        const other: Side = if (side == .A) .B else .A;
        const rx_p = self.rxPtr(other);
        const cached_tx_p = self.cachedTxPtr(other);
        const tx_p = self.txPtr(other);
        const buf = self.bufferSlice(other);
        const buf_size = self.capacity;

        const rx = rx_p.*;
        var data_avail = cached_tx_p.* -% rx;
        if (data_avail < HEADER_SIZE) {
            cached_tx_p.* = @atomicLoad(u64, tx_p, .acquire);
            data_avail = cached_tx_p.* -% rx;
            if (data_avail < HEADER_SIZE) {
                if (!self.peerConnected(side)) return error.Disconnected;
                return null;
            }
        }

        var hdr_buf: [8]u8 = undefined;
        ringRead(buf, buf_size, rx, &hdr_buf);
        const msg_len = @as(*align(1) const u64, @ptrCast(&hdr_buf[0])).*;

        if (data_avail < HEADER_SIZE + msg_len) {
            cached_tx_p.* = @atomicLoad(u64, tx_p, .acquire);
            data_avail = cached_tx_p.* -% rx;
            if (data_avail < HEADER_SIZE + msg_len) return null;
        }

        if (msg_len > out.len) {
            @atomicStore(u64, rx_p, rx +% HEADER_SIZE +% msg_len, .release);
            return null;
        }

        ringRead(buf, buf_size, rx + HEADER_SIZE, out[0..msg_len]);
        @atomicStore(u64, rx_p, rx +% HEADER_SIZE +% msg_len, .release);
        return msg_len;
    }

    pub fn disconnect(self: *Channel, side: Side, shm_handle: u64, vm_handle: u64) void {
        const flag = if (side == .A) &self.A_connected else &self.B_connected;
        @atomicStore(u64, flag, 0, .release);
        _ = syscall.revoke_perm(shm_handle);
        _ = syscall.revoke_perm(vm_handle);
    }
};
