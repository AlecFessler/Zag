const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const sync = lib.sync;
const syscall = lib.syscall;

// These are pub for access by syscall.zig (spawn_child) and start.zig (init).
// Not part of the application-facing API.
pub var parent_command_channel: ?*CommandChannel = null;
pub var child_command_channels: [63]?*CommandChannel = .{null} ** 63;
pub var child_discovery_tables: [63]?*DiscoveryTable = .{null} ** 63;
pub var child_proc_handles: [63]u64 = .{0} ** 63;
pub var my_semantic_id: SemanticID = .{};
pub var perm_view_addr: u64 = 0;

var discovery_table_shm_handle: u64 = 0;

// Known SHM handles for detecting newly granted ones
var known_shm_handles: [128]u64 = .{0} ** 128;
var known_shm_count: u8 = 0;

// Append-only buffer of all discovery entries propagated to children.
// Worker thread appends (release store on len), main thread reads in spawn_child (acquire load).
var propagated_entries: [256]DiscoveryTable.Entry = undefined;
var propagated_entries_len: u8 = 0;

pub fn addKnownShmHandle(handle: u64) void {
    if (known_shm_count < 128) {
        known_shm_handles[known_shm_count] = handle;
        known_shm_count += 1;
    }
}

fn isKnownShmHandle(handle: u64) bool {
    for (known_shm_handles[0..known_shm_count]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn appendPropagatedEntry(entry: DiscoveryTable.Entry) void {
    const idx = @atomicLoad(u8, &propagated_entries_len, .monotonic);
    if (idx >= 255) return;
    propagated_entries[idx] = entry;
    @atomicStore(u8, &propagated_entries_len, idx + 1, .release);
}

/// Copies all propagated entries into a newly created child's discovery table.
/// Called from spawn_child on the main thread.
pub fn copyPropagatedEntries(dt: *DiscoveryTable) void {
    const len = @atomicLoad(u8, &propagated_entries_len, .acquire);
    for (propagated_entries[0..len]) |entry| {
        dt.seq.writeBegin();
        _ = dt.addEntry(entry) catch {
            dt.seq.writeEnd();
            continue;
        };
        dt.seq.writeEnd();
    }
}

// Futex-based channel wait array (32 slots)
const WAIT_SLOT_FREE: u64 = 0;
const WAIT_SLOT_WAITING: u64 = 1;
const WAIT_SLOT_ARRIVED: u64 = 2;

const WaitSlot = struct {
    state: u64 align(8),
    channel_id: u64,
    channel_ptr: u64, // pointer to mapped Channel, set by worker
};

var wait_slots: [32]WaitSlot = .{WaitSlot{ .state = WAIT_SLOT_FREE, .channel_id = 0, .channel_ptr = 0 }} ** 32;

// Pending delivered channels (arrived before awaitChannel was called)
const PendingChannel = struct { channel_id: u64, channel_ptr: u64 };
var pending_channels: [32]PendingChannel = .{PendingChannel{ .channel_id = 0, .channel_ptr = 0 }} ** 32;
var pending_channel_count: u8 = 0;

/// Block until a channel with the given channel_id is delivered by the worker thread.
/// Returns null on timeout. Uses futex with periodic re-checks to avoid missed-wake races.
fn awaitChannel(channel_id: u64, timeout_ns: u64) ?*Channel {
    // Check pending channels first (arrived before we registered)
    const pcount = @atomicLoad(u8, &pending_channel_count, .acquire);
    for (0..pcount) |i| {
        if (pending_channels[i].channel_id == channel_id) {
            const ptr: *Channel = @ptrFromInt(pending_channels[i].channel_ptr);
            // Remove by swapping with last
            const last = @atomicLoad(u8, &pending_channel_count, .acquire) - 1;
            pending_channels[i] = pending_channels[last];
            @atomicStore(u8, &pending_channel_count, last, .release);
            return ptr;
        }
    }

    // Find a free slot
    var slot_idx: ?usize = null;
    for (&wait_slots, 0..) |*slot, i| {
        if (@atomicLoad(u64, &slot.state, .monotonic) == WAIT_SLOT_FREE) {
            slot.channel_id = channel_id;
            @atomicStore(u64, &slot.state, WAIT_SLOT_WAITING, .release);
            slot_idx = i;
            break;
        }
    }
    const idx = slot_idx orelse return null; // all slots busy
    const slot = &wait_slots[idx];

    // Futex wait loop with periodic timeouts (10ms) to avoid missed-wake race
    const check_interval: u64 = 10_000_000; // 10ms
    var remaining = timeout_ns;
    while (remaining > 0) {
        const wait_time = @min(check_interval, remaining);
        const state = @atomicLoad(u64, &slot.state, .acquire);
        if (state == WAIT_SLOT_ARRIVED) {
            const ptr: *Channel = @ptrFromInt(slot.channel_ptr);
            @atomicStore(u64, &slot.state, WAIT_SLOT_FREE, .release);
            return ptr;
        }
        _ = syscall.futex_wait(&slot.state, WAIT_SLOT_WAITING, wait_time);
        remaining -|= wait_time;
    }

    // Timeout — check one last time
    if (@atomicLoad(u64, &slot.state, .acquire) == WAIT_SLOT_ARRIVED) {
        const ptr: *Channel = @ptrFromInt(slot.channel_ptr);
        @atomicStore(u64, &slot.state, WAIT_SLOT_FREE, .release);
        return ptr;
    }
    @atomicStore(u64, &slot.state, WAIT_SLOT_FREE, .release);
    return null;
}

/// Called by the worker thread when a channel is delivered to wake the waiting main thread.
fn deliverChannel(channel_id: u64, channel_ptr: *Channel) void {
    for (&wait_slots) |*slot| {
        if (@atomicLoad(u64, &slot.state, .acquire) == WAIT_SLOT_WAITING and
            slot.channel_id == channel_id)
        {
            slot.channel_ptr = @intFromPtr(channel_ptr);
            @atomicStore(u64, &slot.state, WAIT_SLOT_ARRIVED, .release);
            _ = syscall.futex_wake(&slot.state, 1);
            return;
        }
    }
    // No wait slot — buffer for later awaitChannel call
    const idx = @atomicLoad(u8, &pending_channel_count, .monotonic);
    if (idx < 32) {
        pending_channels[idx] = .{ .channel_id = channel_id, .channel_ptr = @intFromPtr(channel_ptr) };
        @atomicStore(u8, &pending_channel_count, idx + 1, .release);
    }
}

pub fn alignToPages(size: u64) u64 {
    return (size + syscall.PAGE4K - 1) & ~(syscall.PAGE4K - 1);
}

const rw_shareable = (perms.VmReservationRights{
    .read = true,
    .write = true,
    .shareable = true,
}).bits();

const ro_shareable = (perms.VmReservationRights{
    .read = true,
    .write = false,
    .shareable = true,
}).bits();

const shm_rw_grant = (perms.SharedMemoryRights{
    .read = true,
    .write = true,
    .grant = true,
}).bits();

/// Wait for both DT and CC SHM handles, map each, identify by content, and assign.
/// The CommandChannel has self_semantic_id at a known offset; the DiscoveryTable has
/// my_semantic_id. We distinguish them by size: map with CC size (larger), check if
/// the CommandChannel's self_semantic_id has depth > 0 (set by parent before grant).
/// Called by _start for non-root processes.
pub fn initParentSHMs(view: *const [128]perm_view.UserViewEntry) void {
    // Wait for 2 SHM entries
    var handles: [2]u64 = .{ 0, 0 };
    var found: u8 = 0;
    while (found < 2) {
        for (view) |*entry| {
            if (entry.entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
                var already = false;
                for (handles[0..found]) |h| {
                    if (h == entry.handle) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    handles[found] = entry.handle;
                    found += 1;
                    if (found >= 2) break;
                }
            }
        }
        if (found < 2) syscall.thread_yield();
    }

    // Map both with CC size (larger of the two) to inspect content
    const dt_size = alignToPages(@sizeOf(DiscoveryTable));

    // Identify SHMs by size from perm_view field0 (SHM size).
    // DT is 1 page, CC is larger.
    for (handles[0..2], 0..) |handle, hi| {
        addKnownShmHandle(handle);

        // Find the entry to get the size
        var shm_size: u64 = 0;
        for (view) |*entry| {
            if (entry.entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY and entry.handle == handle) {
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_size == 0) continue;
        _ = hi;

        const vm = syscall.vm_reserve(0, shm_size, rw_shareable);
        if (vm.val < 0) continue;
        if (syscall.shm_map(handle, @intCast(vm.val), 0) != 0) continue;

        if (shm_size == dt_size) {
            discovery_table = @ptrFromInt(vm.val2);
            discovery_table_shm_handle = handle;
        } else {
            parent_command_channel = @ptrFromInt(vm.val2);
        }
    }
}

/// NOTE: THIS WILL HAVE TO CHANGE, WILL HAVE TO MAP BOTH AND IDENTIFY IT WITH ID
/// also needs to set childs semantic id
/// Creates a command channel SHM, maps it locally, grants it to the child process,
/// and stores it in child_command_channels. Called by syscall.proc_create wrapper on success.
pub fn initChildCommandChannel(child_index: u8, child_id: SemanticID, proc_handle: u64) ?*CommandChannel {
    const shm_size = alignToPages(@sizeOf(CommandChannel));
    const cmd_shm = syscall.shm_create_with_rights(shm_size, (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits());
    if (cmd_shm <= 0) {
        syscall.write("initChildCC: shm_create failed\n");
        return null;
    }
    addKnownShmHandle(@intCast(cmd_shm));

    const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
    if (vm_result.val < 0) {
        syscall.write("initChildCC: vm_reserve failed\n");
        return null;
    }

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("initChildCC: shm_map failed\n");
        return null;
    }

    const cmd_chan: *CommandChannel = @ptrFromInt(vm_result.val2);
    cmd_chan.* = .{};
    cmd_chan.self_semantic_id = child_id; // Set BEFORE grant so child can read it after mapping

    _ = syscall.grant_perm(@intCast(cmd_shm), proc_handle, shm_rw_grant);

    child_command_channels[child_index - 1] = cmd_chan;
    return cmd_chan;
}

/// Communication channel between all parent and children processes for the shared memory discovery and brokering protocol implementations
pub const CommandChannel = extern struct {
    pub const CommandID = enum(u8) {
        make_discoverable,
        request_channel,
        new_discovery_entry,
        forward_channel_handle,
        evict_discovery_entry,
        _,
    };

    pub const Command = extern struct {
        payload: [3]u64,
        id: CommandID,
    };

    // A direction: child -> parent (child enqueues, parent dequeues)
    A_tx: u8 = 0,
    A_cached_rx: u8 = 0,
    _pad1: [62]u8 = .{0} ** 62,
    A_rx: u8 = 0,
    A_cached_tx: u8 = 0,
    _pad2: [62]u8 = .{0} ** 62,

    // B direction: parent -> child (parent enqueues, child dequeues)
    B_tx: u8 = 0,
    B_cached_rx: u8 = 0,
    _pad3: [62]u8 = .{0} ** 62,
    B_rx: u8 = 0,
    B_cached_tx: u8 = 0,
    _pad4: [62]u8 = .{0} ** 62,

    A_buffer: [256]Command = undefined,
    B_buffer: [256]Command = undefined,
    self_semantic_id: SemanticID = .{},

    comptime {
        if (@offsetOf(CommandChannel, "A_tx") / 64 == @offsetOf(CommandChannel, "A_rx") / 64)
            @compileError("A_tx and A_rx must be on different cache lines");
        if (@offsetOf(CommandChannel, "B_tx") / 64 == @offsetOf(CommandChannel, "B_rx") / 64)
            @compileError("B_tx and B_rx must be on different cache lines");
    }

    /// Enqueue on A-side (child -> parent). Called by child.
    pub fn enqueueA(self: *CommandChannel, cmd: Command) !void {
        const next_wr = self.A_tx +% 1;
        if (next_wr == self.A_cached_rx) {
            self.A_cached_rx = @atomicLoad(u8, &self.A_rx, .acquire);
            if (next_wr == self.A_cached_rx) return error.CommandChannelFull;
        }
        self.A_buffer[self.A_tx] = cmd;
        @atomicStore(u8, &self.A_tx, next_wr, .release);
    }

    /// Dequeue from A-side (child -> parent). Called by parent.
    pub fn dequeueA(self: *CommandChannel) ?Command {
        if (self.A_rx == self.A_cached_tx) {
            self.A_cached_tx = @atomicLoad(u8, &self.A_tx, .acquire);
            if (self.A_rx == self.A_cached_tx) return null;
        }
        const cmd = self.A_buffer[self.A_rx];
        @atomicStore(u8, &self.A_rx, self.A_rx +% 1, .release);
        return cmd;
    }

    /// Enqueue on B-side (parent -> child). Called by parent.
    pub fn enqueueB(self: *CommandChannel, cmd: Command) !void {
        const next_wr = self.B_tx +% 1;
        if (next_wr == self.B_cached_rx) {
            self.B_cached_rx = @atomicLoad(u8, &self.B_rx, .acquire);
            if (next_wr == self.B_cached_rx) return error.CommandChannelFull;
        }
        self.B_buffer[self.B_tx] = cmd;
        @atomicStore(u8, &self.B_tx, next_wr, .release);
    }

    /// Dequeue from B-side (parent -> child). Called by child.
    pub fn dequeueB(self: *CommandChannel) ?Command {
        if (self.B_rx == self.B_cached_tx) {
            self.B_cached_tx = @atomicLoad(u8, &self.B_tx, .acquire);
            if (self.B_rx == self.B_cached_tx) return null;
        }
        const cmd = self.B_buffer[self.B_rx];
        @atomicStore(u8, &self.B_rx, self.B_rx +% 1, .release);
        return cmd;
    }

    pub fn makeDiscoverableCommand(
        self_id: SemanticID,
        msg_ttl: u64,
        protocol: ProtocolID,
    ) Command {
        return .{
            .payload = .{ self_id.toInt(), msg_ttl, @intFromEnum(protocol) },
            .id = .make_discoverable,
        };
    }

    pub fn requestChannelCommand(
        self_id: SemanticID,
        target_id: SemanticID,
        channel_id: u64,
        shm_size: u64,
    ) Command {
        return .{
            .payload = .{ self_id.toInt(), target_id.toInt(), channel_id | (shm_size << 32) },
            .id = .request_channel,
        };
    }

    pub fn newDiscoveryEntryCommand(entry_index: u64) Command {
        return .{
            .payload = .{ entry_index, 0, 0 },
            .id = .new_discovery_entry,
        };
    }

    pub fn forwardChannelHandleCommand(channel_id: u64, target_id: SemanticID, shm_size: u64) Command {
        return .{
            .payload = .{ channel_id, target_id.toInt(), shm_size },
            .id = .forward_channel_handle,
        };
    }

    pub fn evictDiscoveryEntryCommand(semantic_id: SemanticID) Command {
        return .{
            .payload = .{ semantic_id.toInt(), 0, 0 },
            .id = .evict_discovery_entry,
        };
    }
};

pub var discovery_table: ?*DiscoveryTable = null;

/// Identifies a shared memory protocol api defined in libz
pub const ProtocolID = enum(u8) {
    default,
    _,
};

/// A discovery table is read only memory for the process that owns it, and rw for its parent
pub const DiscoveryTable = extern struct {
    pub const Entry = extern struct {
        id: SemanticID,
        proto: ProtocolID,
    };

    seq: sync.Seqlock = sync.Seqlock.init(),
    my_semantic_id: SemanticID,
    child_tables: [63]*DiscoveryTable, // a table is only valid if the (child index - 1) is set in the child indices bitmap
    entries: [256]Entry = .{Entry{ .id = .{}, .proto = @enumFromInt(0) }} ** 256,
    entries_len: u8 = 0,

    /// Evict entries matching target_id or its subtree. Caller must hold seqlock write.
    pub fn evictEntry(self: *DiscoveryTable, target_id: SemanticID) void {
        var i: usize = 0;
        while (i < self.entries_len) {
            const entry = self.entries[i];
            if (SemanticID.eql(target_id, entry.id) or SemanticID.isAncestor(target_id, entry.id)) {
                self.entries_len -= 1;
                self.entries[i] = self.entries[self.entries_len];
            } else {
                i += 1;
            }
        }
    }

    /// Add a discovery entry. Caller must hold seqlock write. Returns the index of the new entry.
    pub fn addEntry(self: *DiscoveryTable, entry: Entry) !u8 {
        const len = @atomicLoad(u8, &self.entries_len, .monotonic);
        if (len >= 255) return error.TableFull;
        self.entries[len] = entry;
        @atomicStore(u8, &self.entries_len, len + 1, .release);
        return len;
    }

    /// Read the table with seqlock protection. Copies entries into `out`, returns count.
    /// Retries if a write was in progress.
    pub fn readTable(self: *DiscoveryTable, out: []Entry) u8 {
        while (true) {
            const gen = self.seq.readBegin();
            const len = @atomicLoad(u8, &self.entries_len, .acquire);
            const out_max: u8 = if (out.len > 255) 255 else @intCast(out.len);
            const copy_len = @min(len, out_max);
            for (0..copy_len) |i| {
                out[i] = self.entries[i];
            }
            if (!self.seq.readRetry(gen)) return copy_len;
        }
    }
};

/// Tracks allocated child indices (1-63). Bit 0 is permanently set because
/// index 0 cannot be used — a zero byte in SemanticID means "no more levels."
/// When a child process dies, its bit must be reset to 0.
var child_indices_bitmap: u64 = 1;

fn nextAvailableChildIndex() ?u8 {
    const free = ~child_indices_bitmap;
    if (free == 0) return null;
    const index: u6 = @intCast(@ctz(free));
    child_indices_bitmap |= @as(u64, 1) << index;
    return @intCast(index);
}

pub const SemanticID = extern struct {
    bytes: [8]u8 = .{0} ** 8,

    comptime {
        if (@sizeOf(SemanticID) != 8) @compileError("SemanticID must be exactly 8 bytes");
    }

    /// Number of levels deep (index of first zero byte). O(1) via SWAR.
    pub fn depth(self: SemanticID) u4 {
        const v: u64 = @bitCast(self.bytes);
        const lo: u64 = 0x0101010101010101;
        const hi: u64 = 0x8080808080808080;
        const zero_bytes = (v -% lo) & ~v & hi;
        if (zero_bytes == 0) return 8;
        return @intCast(@ctz(zero_bytes) >> 3);
    }

    /// True if b is in the subtree rooted at a (a is a strict ancestor of b). O(1).
    pub fn isAncestor(a: SemanticID, b: SemanticID) bool {
        const a_int: u64 = @bitCast(a.bytes);
        const b_int: u64 = @bitCast(b.bytes);
        const d = a.depth();
        if (d >= 8) return false;
        const shift: u6 = @intCast(@as(u7, d) * 8);
        const mask = (@as(u64, 1) << shift) -% 1;
        // a's prefix must match b, and b must have a non-zero byte at depth d
        return (a_int ^ b_int) & mask == 0 and (b_int >> shift) & 0xFF != 0;
    }

    /// Allocate the next available child index and return a new SemanticID for it.
    /// Returns null if all 63 child slots are exhausted (indices 1-63).
    pub fn newChildID(self: SemanticID) ?SemanticID {
        const index = nextAvailableChildIndex() orelse return null;
        var result = self;
        result.bytes[self.depth()] = index;
        return result;
    }

    /// True if a and b refer to the same node.
    pub fn eql(a: SemanticID, b: SemanticID) bool {
        return a.toInt() == b.toInt();
    }

    /// Cast to u64 for use as a key or in syscalls.
    pub fn toInt(self: SemanticID) u64 {
        return @bitCast(self.bytes);
    }

    pub fn fromInt(val: u64) SemanticID {
        return .{ .bytes = @bitCast(val) };
    }
};

pub const Channel = extern struct {
    pub const ChannelAB = enum(u1) {
        A,
        B,
    };

    const HEADER_SIZE = 16; // checksum (8) + len (8), serialized into the ring buffer

    A_tx: u64 = 0,
    A_cached_rx: u64 = 0,
    B_rx: u64 = 0,
    B_cached_tx: u64 = 0,
    _pad1: [64]u8 = .{0} ** 64,

    A_rx: u64 = 0,
    A_cached_tx: u64 = 0,
    B_tx: u64 = 0,
    B_cached_rx: u64 = 0,
    _pad2: [64]u8 = .{0} ** 64,

    base: u64 = 0,
    mid: u64 = 0,

    // unique identifier set by A side to tell B what the channel is for, 0 means not yet initialized
    channel_id: u64 = 0,
    // semantic IDs of both sides, written by the LCA broker during channel creation
    semantic_id_a: u64 = 0, // requester (side A)
    semantic_id_b: u64 = 0, // target (side B)

    /// Places the Channel header at the start of `region`, splits the remainder
    /// in half for A's and B's ring buffers. Returns a pointer to the Channel.
    pub fn init(region: []u8) ?*Channel {
        if (region.len <= @sizeOf(Channel)) return null;
        const self: *Channel = @ptrCast(@alignCast(region.ptr));
        self.* = .{};
        self.base = @intFromPtr(region.ptr) + @sizeOf(Channel);
        self.mid = (region.len - @sizeOf(Channel)) / 2;
        return self;
    }

    fn txPtr(self: *Channel, id: ChannelAB) *u64 {
        return if (id == .A) &self.A_tx else &self.B_tx;
    }
    fn cachedRxPtr(self: *Channel, id: ChannelAB) *u64 {
        return if (id == .A) &self.A_cached_rx else &self.B_cached_rx;
    }
    fn rxPtr(self: *Channel, id: ChannelAB) *u64 {
        return if (id == .A) &self.B_rx else &self.A_rx;
    }
    fn cachedTxPtr(self: *Channel, id: ChannelAB) *u64 {
        return if (id == .A) &self.B_cached_tx else &self.A_cached_tx;
    }

    fn bufferSlice(self: *Channel, id: ChannelAB) [*]u8 {
        // Compute base relative to self, not from stored absolute VA
        // (the stored VA is from the creator's address space, unusable in other processes)
        const base: [*]u8 = @ptrFromInt(@intFromPtr(self) + @sizeOf(Channel));
        return if (id == .A) base else base + self.mid;
    }

    fn checksum(data: []const u8) u64 {
        const aligned = @as([*]align(1) const u64, @ptrCast(data.ptr))[0 .. data.len / 8];
        var sum: u64 = 0;
        for (aligned) |word| sum +%= word;
        var tail: u64 = 0;
        for (data[aligned.len * 8 ..]) |b| {
            tail = (tail << 8) | b;
        }
        return sum +% tail;
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

    pub fn enqueue(
        self: *Channel,
        id: ChannelAB,
        msg: []const u8,
    ) !void {
        const tx_p = self.txPtr(id);
        const cached_rx_p = self.cachedRxPtr(id);
        const rx_p = self.rxPtr(id);
        const buf = self.bufferSlice(id);
        const buf_size = self.mid;

        const total = HEADER_SIZE + msg.len;
        const tx = tx_p.*;
        var available = buf_size -% (tx -% cached_rx_p.*);
        if (available < total) {
            cached_rx_p.* = @atomicLoad(u64, rx_p, .acquire);
            available = buf_size -% (tx -% cached_rx_p.*);
            if (available < total) return error.ChannelFull;
        }

        const cksum = checksum(msg);
        var hdr_buf: [16]u8 = undefined;
        @as(*align(1) u64, @ptrCast(&hdr_buf[0])).* = cksum;
        @as(*align(1) u64, @ptrCast(&hdr_buf[8])).* = msg.len;
        ringWrite(buf, buf_size, tx, &hdr_buf);

        ringWrite(buf, buf_size, tx + HEADER_SIZE, msg);

        @atomicStore(u64, tx_p, tx +% total, .release);
    }

    pub fn dequeue(
        self: *Channel,
        id: ChannelAB,
        out: []u8,
    ) ?u64 {
        const other: ChannelAB = if (id == .A) .B else .A;
        const rx_p = self.rxPtr(other);
        const cached_tx_p = self.cachedTxPtr(other);
        const tx_p = self.txPtr(other);
        const buf = self.bufferSlice(other);
        const buf_size = self.mid;

        const rx = rx_p.*;
        var data_avail = cached_tx_p.* -% rx;
        if (data_avail < HEADER_SIZE) {
            cached_tx_p.* = @atomicLoad(u64, tx_p, .acquire);
            data_avail = cached_tx_p.* -% rx;
            if (data_avail < HEADER_SIZE) return null;
        }

        var hdr_buf: [16]u8 = undefined;
        ringRead(buf, buf_size, rx, &hdr_buf);
        const expected_cksum = @as(*align(1) const u64, @ptrCast(&hdr_buf[0])).*;
        const msg_len = @as(*align(1) const u64, @ptrCast(&hdr_buf[8])).*;

        if (data_avail < HEADER_SIZE + msg_len) {
            cached_tx_p.* = @atomicLoad(u64, tx_p, .acquire);
            data_avail = cached_tx_p.* -% rx;
            if (data_avail < HEADER_SIZE + msg_len) return null;
        }

        if (msg_len > out.len) {
            // Message too large for buffer — skip it to unblock the ring
            @atomicStore(u64, rx_p, rx +% HEADER_SIZE +% msg_len, .release);
            return null;
        }

        ringRead(buf, buf_size, rx + HEADER_SIZE, out[0..msg_len]);

        const actual_cksum = checksum(out[0..msg_len]);
        if (actual_cksum != expected_cksum) {
            syscall.write("channel: checksum mismatch\n");
            @atomicStore(u64, rx_p, rx +% HEADER_SIZE +% msg_len, .release);
            return null;
        }

        @atomicStore(u64, rx_p, rx +% HEADER_SIZE +% msg_len, .release);
        return msg_len;
    }

    /// Connect as side A (requester). Maps the SHM, verifies the channel_id
    /// matches (already set by the broker). Returns the Channel pointer.
    pub fn connectAsA(shm_handle: u64, expected_channel_id: u64) ?*Channel {
        const shm_size = alignToPages(4 * syscall.PAGE4K);
        const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
        if (vm_result.val < 0) return null;

        const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
        // E_INVAL (-1) means already mapped — that's fine
        if (map_rc != 0 and map_rc != -1) return null;

        const self: *Channel = @ptrFromInt(vm_result.val2);
        if (self.channel_id != expected_channel_id) return null;
        return self;
    }

    /// Connect as side B (target/listener). Maps the SHM, reads channel_id
    /// to identify the protocol. Does NOT re-initialize the channel.
    pub fn connectAsB(shm_handle: u64) ?*Channel {
        const shm_size = alignToPages(4 * syscall.PAGE4K);
        const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
        if (vm_result.val < 0) return null;

        const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
        // E_INVAL (-1) means already mapped (LCA-is-target case) — that's fine
        if (map_rc != 0 and map_rc != -1) return null;

        return @ptrFromInt(vm_result.val2);
    }
};

// ─── Public API ──────────────────────────────────────────────────────

/// Register this process as discoverable with the given protocol and TTL.
/// TTL controls how many hops up the tree the message travels; every process
/// in the subtree rooted at the ancestor TTL levels up will see this entry.
pub fn makeDiscoverable(protocol: ProtocolID, ttl: u64) !void {
    const pcc = parent_command_channel orelse return error.NoParent;
    try pcc.enqueueA(CommandChannel.makeDiscoverableCommand(my_semantic_id, ttl, protocol));
}

/// Find a process advertising `protocol` in the discovery table, request a
/// channel with `channel_id`, and block (futex) until it's established.
/// Returns the connected Channel or null on timeout.
pub fn requestConnection(protocol: ProtocolID, channel_id: u64, shm_size: u64, timeout_ns: u64) ?*Channel {
    const target_id = discoverTarget(protocol) orelse return null;
    sendChannelRequest(target_id, channel_id, shm_size) catch return null;
    return awaitChannel(channel_id, timeout_ns);
}

/// Find a process advertising `protocol`, send the channel request, and
/// return immediately. Call `pollConnection` to check if the channel arrived.
pub fn requestConnectionAsync(protocol: ProtocolID, channel_id: u64, shm_size: u64) !void {
    const target_id = discoverTarget(protocol) orelse return error.NotFound;
    try sendChannelRequest(target_id, channel_id, shm_size);
}

/// Check if a previously requested channel has been delivered.
/// Returns the Channel if ready, null if still pending.
pub fn pollConnection(channel_id: u64) ?*Channel {
    // Check pending buffer
    const pcount = @atomicLoad(u8, &pending_channel_count, .acquire);
    for (0..pcount) |i| {
        if (pending_channels[i].channel_id == channel_id) {
            const ptr: *Channel = @ptrFromInt(pending_channels[i].channel_ptr);
            const last = pcount - 1;
            pending_channels[i] = pending_channels[last];
            @atomicStore(u8, &pending_channel_count, last, .release);
            return ptr;
        }
    }
    // Check wait slots
    for (&wait_slots) |*slot| {
        if (@atomicLoad(u64, &slot.state, .acquire) == WAIT_SLOT_ARRIVED and
            slot.channel_id == channel_id)
        {
            const ptr: *Channel = @ptrFromInt(slot.channel_ptr);
            @atomicStore(u64, &slot.state, WAIT_SLOT_FREE, .release);
            return ptr;
        }
    }
    return null;
}

/// Return any pending incoming channel regardless of channel_id. Non-blocking.
pub fn pollAnyIncoming() ?*Channel {
    const pcount = @atomicLoad(u8, &pending_channel_count, .acquire);
    if (pcount == 0) return null;
    const ptr: *Channel = @ptrFromInt(pending_channels[0].channel_ptr);
    const last = pcount - 1;
    pending_channels[0] = pending_channels[last];
    @atomicStore(u8, &pending_channel_count, last, .release);
    return ptr;
}

/// Run the protocol loop as the root service (no parent, no worker thread needed).
/// Call this from root service main after spawning all children.
pub fn runAsRoot() void {
    protocolLoop();
}

/// Channel brokering and discovery protocol worker thread.
/// Started by _start before app.main. Polls command channels and handles the protocol.
pub fn workerMain() void {
    protocolLoop();
}

// ─── Internal helpers for public API ────────────────────────────────

/// Poll discovery table until an entry with matching protocol appears.
/// Returns null only if discovery_table itself is null (root process).
fn discoverTarget(protocol: ProtocolID) ?SemanticID {
    while (true) {
        if (discovery_table) |dt| {
            var entries: [256]DiscoveryTable.Entry = undefined;
            const count = dt.readTable(&entries);
            for (entries[0..count]) |entry| {
                if (entry.proto == protocol) return entry.id;
            }
        }
        syscall.thread_yield();
    }
}

/// Block until an incoming channel with the given channel_id is delivered.
/// Used by the target side (the process that made itself discoverable).
pub fn awaitIncoming(channel_id: u64, timeout_ns: u64) ?*Channel {
    return awaitChannel(channel_id, timeout_ns);
}

/// Called by start.zig after initParentSHMs to read semantic ID from command channel.
pub fn initSemanticId() void {
    if (parent_command_channel) |pcc| {
        my_semantic_id = pcc.self_semantic_id;
    }
}

fn sendChannelRequest(target_id: SemanticID, channel_id: u64, shm_size: u64) !void {
    const pcc = parent_command_channel orelse return error.NoParent;
    try pcc.enqueueA(CommandChannel.requestChannelCommand(my_semantic_id, target_id, channel_id, shm_size));
}

fn protocolLoop() void {
    while (true) {
        var did_work = false;

        // Poll parent command channel B-side (parent -> us)
        if (parent_command_channel) |pcc| {
            if (pcc.dequeueB()) |cmd| {
                did_work = true;
                handleParentCommand(cmd);
            }
        }

        // Poll all child command channels A-side (child -> us)
        for (&child_command_channels, 0..) |*maybe_cc, i| {
            if (maybe_cc.*) |cc| {
                if (cc.dequeueA()) |cmd| {
                    did_work = true;
                    handleChildCommand(cmd, @intCast(i));
                }
            }
        }

        // Check for dead children
        checkDeadChildren();

        if (!did_work) {
            syscall.thread_yield();
        }
    }
}

fn handleParentCommand(cmd: CommandChannel.Command) void {
    switch (cmd.id) {
        .new_discovery_entry => handleNewDiscoveryEntry(cmd),
        .forward_channel_handle => handleForwardChannelHandle(cmd),
        .evict_discovery_entry => handleEvictDiscoveryEntry(cmd),
        else => {},
    }
}

fn handleChildCommand(cmd: CommandChannel.Command, child_index: u8) void {
    _ = child_index;
    switch (cmd.id) {
        .make_discoverable => handleMakeDiscoverable(cmd),
        .request_channel => handleRequestChannel(cmd),
        else => {},
    }
}

fn handleMakeDiscoverable(cmd: CommandChannel.Command) void {
    const sem_id = SemanticID.fromInt(cmd.payload[0]);
    const ttl = cmd.payload[1];
    const proto: ProtocolID = @enumFromInt(@as(u8, @truncate(cmd.payload[2])));
    const entry = DiscoveryTable.Entry{ .id = sem_id, .proto = proto };
    // Add to all children's discovery tables and notify them
    for (&child_discovery_tables, 0..) |*maybe_dt, i| {
        if (maybe_dt.*) |dt| {
            dt.seq.writeBegin();
            const idx = dt.addEntry(entry) catch {
                dt.seq.writeEnd();
                continue;
            };
            dt.seq.writeEnd();

            if (child_command_channels[i]) |cc| {
                cc.enqueueB(CommandChannel.newDiscoveryEntryCommand(idx)) catch {};
            }
        }
    }

    // Record so late-spawned children get this entry
    appendPropagatedEntry(entry);

    // Forward up with decremented TTL
    if (ttl > 1) {
        if (parent_command_channel) |pcc| {
            pcc.enqueueA(CommandChannel.makeDiscoverableCommand(sem_id, ttl - 1, proto)) catch {};
        }
    }
}

fn handleNewDiscoveryEntry(cmd: CommandChannel.Command) void {
    const entry_index: u8 = @truncate(cmd.payload[0]);

    // Read the entry from our own discovery table (protected by seqlock)
    const my_dt = discovery_table orelse return;
    const mutable_dt: *DiscoveryTable = @constCast(my_dt);
    var entry: DiscoveryTable.Entry = undefined;
    while (true) {
        const gen = mutable_dt.seq.readBegin();
        if (entry_index >= mutable_dt.entries_len) return;
        entry = mutable_dt.entries[entry_index];
        if (!mutable_dt.seq.readRetry(gen)) break;
    }

    // Copy to all children's discovery tables and notify
    for (&child_discovery_tables, 0..) |*maybe_cdt, i| {
        if (maybe_cdt.*) |cdt| {
            cdt.seq.writeBegin();
            const idx = cdt.addEntry(entry) catch {
                cdt.seq.writeEnd();
                continue;
            };
            cdt.seq.writeEnd();

            if (child_command_channels[i]) |cc| {
                cc.enqueueB(CommandChannel.newDiscoveryEntryCommand(idx)) catch {};
            }
        }
    }

    // Record so late-spawned children get this entry
    appendPropagatedEntry(entry);
}

fn handleRequestChannel(cmd: CommandChannel.Command) void {
    const src_id = SemanticID.fromInt(cmd.payload[0]);
    const target_id = SemanticID.fromInt(cmd.payload[1]);
    const channel_id = cmd.payload[2] & 0xFFFFFFFF;
    const requested_size = cmd.payload[2] >> 32;
    const shm_size = if (requested_size > 0) alignToPages(requested_size) else alignToPages(4 * syscall.PAGE4K);

    if (SemanticID.eql(my_semantic_id, target_id)) {
        brokerChannelAsTarget(src_id, channel_id, shm_size);
    } else if (SemanticID.isAncestor(my_semantic_id, target_id)) {
        brokerChannel(src_id, target_id, channel_id, shm_size);
    } else {
        if (parent_command_channel) |pcc| {
            pcc.enqueueA(cmd) catch {};
        }
    }
}

fn brokerChannelAsTarget(src_id: SemanticID, channel_id: u64, shm_size: u64) void {
    const shm = syscall.shm_create_with_rights(shm_size, shm_rw_grant);
    if (shm <= 0) return;

    // Map it to initialize the Channel header
    const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
    if (vm_result.val < 0) return;
    if (syscall.shm_map(@intCast(shm), @intCast(vm_result.val), 0) != 0) return;

    const region: [*]u8 = @ptrFromInt(vm_result.val2);
    const chan = Channel.init(region[0..shm_size]) orelse return;
    chan.channel_id = channel_id;
    chan.semantic_id_a = @bitCast(src_id.bytes);
    chan.semantic_id_b = @bitCast(my_semantic_id.bytes);

    addKnownShmHandle(@intCast(shm));

    // Find which child leads to src and grant + forward
    for (&child_command_channels, 0..) |*maybe_cc, i| {
        if (maybe_cc.*) |cc| {
            if (SemanticID.eql(cc.self_semantic_id, src_id) or
                SemanticID.isAncestor(cc.self_semantic_id, src_id))
            {
                _ = syscall.grant_perm(@intCast(shm), child_proc_handles[i], shm_rw_grant);
                cc.enqueueB(CommandChannel.forwardChannelHandleCommand(channel_id, src_id, shm_size)) catch {};
                break;
            }
        }
    }

    // Deliver to ourselves (target) — channel is already mapped
    deliverChannel(channel_id, chan);
}

fn brokerChannel(src_id: SemanticID, target_id: SemanticID, channel_id: u64, shm_size: u64) void {
    const shm = syscall.shm_create_with_rights(shm_size, shm_rw_grant);
    if (shm <= 0) return;

    // Map to initialize Channel header
    const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
    if (vm_result.val < 0) return;
    if (syscall.shm_map(@intCast(shm), @intCast(vm_result.val), 0) != 0) return;

    const region: [*]u8 = @ptrFromInt(vm_result.val2);
    const chan = Channel.init(region[0..shm_size]) orelse return;
    chan.channel_id = channel_id;
    chan.semantic_id_a = @bitCast(src_id.bytes);
    chan.semantic_id_b = @bitCast(target_id.bytes);
    addKnownShmHandle(@intCast(shm));

    // Grant to child leading to src
    for (&child_command_channels, 0..) |*maybe_cc, i| {
        if (maybe_cc.*) |cc| {
            if (SemanticID.eql(cc.self_semantic_id, src_id) or
                SemanticID.isAncestor(cc.self_semantic_id, src_id))
            {
                _ = syscall.grant_perm(@intCast(shm), child_proc_handles[i], shm_rw_grant);
                cc.enqueueB(CommandChannel.forwardChannelHandleCommand(channel_id, src_id, shm_size)) catch {};
                break;
            }
        }
    }

    // Grant to child leading to target
    for (&child_command_channels, 0..) |*maybe_cc, i| {
        if (maybe_cc.*) |cc| {
            if (SemanticID.eql(cc.self_semantic_id, target_id) or
                SemanticID.isAncestor(cc.self_semantic_id, target_id))
            {
                _ = syscall.grant_perm(@intCast(shm), child_proc_handles[i], shm_rw_grant);
                cc.enqueueB(CommandChannel.forwardChannelHandleCommand(channel_id, target_id, shm_size)) catch {};
                break;
            }
        }
    }

    // Unmap and revoke own access
    // TODO: shm_unmap + revoke_perm once we track the vm handle
}

fn handleForwardChannelHandle(cmd: CommandChannel.Command) void {
    const channel_id = cmd.payload[0];
    const target_id = SemanticID.fromInt(cmd.payload[1]);
    const shm_size = if (cmd.payload[2] > 0) cmd.payload[2] else alignToPages(4 * syscall.PAGE4K);

    // Find the SHM matching this channel_id in perm_view.
    // Multiple SHMs may arrive simultaneously, so we must check channel_id
    // to avoid grabbing the wrong one.
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    var shm_handle: u64 = 0;
    var matched_chan: *Channel = undefined;
    var matched_vm: u64 = 0;
    var attempts: u32 = 0;

    while (shm_handle == 0 and attempts < 1000) : (attempts += 1) {
        for (view) |*entry| {
            if (entry.entry_type != perm_view.ENTRY_TYPE_SHARED_MEMORY or isKnownShmHandle(entry.handle))
                continue;

            // Try mapping this SHM to check its channel_id
            const vm_result = syscall.vm_reserve(0, shm_size, rw_shareable);
            if (vm_result.val < 0) continue;

            const map_rc = syscall.shm_map(entry.handle, @intCast(vm_result.val), 0);
            if (map_rc != 0 and map_rc != -1) continue;

            const chan: *Channel = @ptrFromInt(vm_result.val2);
            if (chan.channel_id == channel_id) {
                shm_handle = entry.handle;
                matched_chan = chan;
                matched_vm = vm_result.val2;
                break;
            }
            // Wrong SHM — leave it for another forward to claim
        }
        if (shm_handle == 0) syscall.thread_yield();
    }

    if (shm_handle == 0) return;
    addKnownShmHandle(shm_handle);

    if (SemanticID.eql(my_semantic_id, target_id)) {
        deliverChannel(channel_id, matched_chan);
    } else {
        for (&child_command_channels, 0..) |*maybe_cc, i| {
            if (maybe_cc.*) |cc| {
                if (SemanticID.eql(cc.self_semantic_id, target_id) or
                    SemanticID.isAncestor(cc.self_semantic_id, target_id))
                {
                    _ = syscall.grant_perm(shm_handle, child_proc_handles[i], shm_rw_grant);
                    cc.enqueueB(CommandChannel.forwardChannelHandleCommand(channel_id, target_id, shm_size)) catch {};
                    _ = syscall.revoke_perm(shm_handle);
                    break;
                }
            }
        }
    }
}

fn handleEvictDiscoveryEntry(cmd: CommandChannel.Command) void {
    const dead_id = SemanticID.fromInt(cmd.payload[0]);

    // Evict from all children's discovery tables and forward down
    for (&child_discovery_tables, 0..) |*maybe_dt, i| {
        if (maybe_dt.*) |dt| {
            dt.seq.writeBegin();
            dt.evictEntry(dead_id);
            dt.seq.writeEnd();
        }

        if (child_command_channels[i]) |cc| {
            cc.enqueueB(CommandChannel.evictDiscoveryEntryCommand(dead_id)) catch {};
        }
    }
}

fn checkDeadChildren() void {
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    if (perm_view_addr == 0) return;

    for (view) |*entry| {
        if (entry.entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) continue;

        // Check if this is one of our children
        for (&child_proc_handles, 0..) |*handle, i| {
            if (handle.* != 0 and handle.* == entry.handle) {
                const dead_id = if (child_command_channels[i]) |cc| cc.self_semantic_id else continue;

                // Evict from all other children's tables
                for (&child_discovery_tables, 0..) |*maybe_dt, j| {
                    if (j == i) continue;
                    if (maybe_dt.*) |dt| {
                        dt.seq.writeBegin();
                        dt.evictEntry(dead_id);
                        dt.seq.writeEnd();
                    }

                    if (child_command_channels[j]) |cc| {
                        cc.enqueueB(CommandChannel.evictDiscoveryEntryCommand(dead_id)) catch {};
                    }
                }

                // Clean up the dead child's slot
                child_command_channels[i] = null;
                child_discovery_tables[i] = null;
                handle.* = 0;
                // Reset bitmap bit (child_index = i + 1)
                child_indices_bitmap &= ~(@as(u64, 1) << @intCast(i + 1));
                break;
            }
        }
    }
}
