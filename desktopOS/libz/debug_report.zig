const perms = @import("perms.zig");
const pv = @import("perm_view.zig");
const syscall = @import("syscall.zig");

pub const DEBUG_SHM_SIZE: u64 = 2 * syscall.PAGE4K;
pub const DEBUG_MAGIC: u64 = 0x5A41475F44425547;
pub const MAX_EVENTS = 96;

// ── Process IDs ──────────────────────────────────────────────────
pub const PID_ROOT: u8 = 1;
pub const PID_DEVICE_MANAGER: u8 = 2;
pub const PID_APP_MANAGER: u8 = 3;
pub const PID_SERIAL: u8 = 4;
pub const PID_USB: u8 = 5;
pub const PID_COMPOSITOR: u8 = 6;
pub const PID_TERMINAL: u8 = 7;

pub fn pidName(pid: u8) []const u8 {
    return switch (pid) {
        PID_ROOT => "root",
        PID_DEVICE_MANAGER => "dm",
        PID_APP_MANAGER => "am",
        PID_SERIAL => "serial",
        PID_USB => "usb",
        PID_COMPOSITOR => "comp",
        PID_TERMINAL => "term",
        else => "???",
    };
}

// ── Event Types ──────────────────────────────────────────────────
pub const EVT_MAPPED_DEBUG: u8 = 0x01;
pub const EVT_CONN_REQUESTED: u8 = 0x02;
pub const EVT_SHM_CREATED: u8 = 0x03;
pub const EVT_SHM_PASSED: u8 = 0x04;
pub const EVT_SHM_RECEIVED: u8 = 0x05;
pub const EVT_SHM_MAPPED: u8 = 0x06;
pub const EVT_ENTERING_LOOP: u8 = 0x07;

pub fn evtName(evt: u8) []const u8 {
    return switch (evt) {
        EVT_MAPPED_DEBUG => "debug_mapped",
        EVT_CONN_REQUESTED => "conn_req",
        EVT_SHM_CREATED => "shm_created",
        EVT_SHM_PASSED => "shm_passed",
        EVT_SHM_RECEIVED => "shm_recv",
        EVT_SHM_MAPPED => "shm_mapped",
        EVT_ENTERING_LOOP => "main_loop",
        else => "unknown",
    };
}

// ── Event Entry (64 bytes) ───────────────────────────────────────
pub const DebugEvent = extern struct {
    sequence: u64 align(8), // nonzero after write complete; value = slot_index + 1
    process_id: u8,
    event_type: u8,
    _pad: [6]u8,
    payload: [48]u8, // null-terminated text

    pub fn payloadSlice(self: *const DebugEvent) []const u8 {
        var len: usize = 0;
        while (len < 48 and self.payload[len] != 0) : (len += 1) {}
        return self.payload[0..len];
    }
};

// ── MPSC Debug Report Header ─────────────────────────────────────
pub const DebugReport = extern struct {
    magic: u64,
    write_idx: u64 align(8), // producers: atomicRmw(.Add) to reserve slot
    read_idx: u64 align(8), // consumer: tracks read position
    _reserved: [40]u8,
    events: [MAX_EVENTS]DebugEvent,

    pub fn init(self: *DebugReport) void {
        self.magic = DEBUG_MAGIC;
        self.write_idx = 0;
        self.read_idx = 0;
        self._reserved = .{0} ** 40;
        for (&self.events) |*ev| {
            ev.sequence = 0;
            ev.process_id = 0;
            ev.event_type = 0;
            ev._pad = .{0} ** 6;
            ev.payload = .{0} ** 48;
        }
    }

    pub fn isValid(self: *const DebugReport) bool {
        return self.magic == DEBUG_MAGIC;
    }

    /// MPSC-safe: atomically reserves a slot, writes event, then publishes via sequence.
    pub fn log(self: *DebugReport, pid: u8, evt: u8, text: []const u8) void {
        const idx = @atomicRmw(u64, &self.write_idx, .Add, 1, .acq_rel);
        const slot = idx % MAX_EVENTS;
        const ev = &self.events[slot];
        ev.process_id = pid;
        ev.event_type = evt;
        ev._pad = .{0} ** 6;
        const len = @min(text.len, 48 - 1);
        @memcpy(ev.payload[0..len], text[0..len]);
        ev.payload[len] = 0;
        // Zero-fill remainder
        if (len + 1 < 48) {
            for (ev.payload[len + 1 .. 48]) |*b| b.* = 0;
        }
        @atomicStore(u64, &ev.sequence, idx + 1, .release);
    }

    /// Consumer: read event at read_idx if ready. Returns null if not yet written.
    pub fn read(self: *const DebugReport, idx: u64) ?*const DebugEvent {
        const slot = idx % MAX_EVENTS;
        const ev = &self.events[slot];
        const seq = @atomicLoad(u64, &ev.sequence, .acquire);
        if (seq != idx + 1) return null;
        return ev;
    }
};

/// Create a debug SHM, map it locally, initialize it.
pub fn createDebugShm() struct { handle: i64, report: ?*DebugReport } {
    const handle = syscall.shm_create(DEBUG_SHM_SIZE);
    if (handle <= 0) return .{ .handle = 0, .report = null };

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, DEBUG_SHM_SIZE, vm_rights);
    if (vm.val < 0) return .{ .handle = handle, .report = null };
    if (syscall.shm_map(@intCast(handle), @intCast(vm.val), 0) != 0) return .{ .handle = handle, .report = null };

    const report: *DebugReport = @ptrFromInt(vm.val2);
    report.init();
    return .{ .handle = handle, .report = report };
}

pub const DebugShmResult = struct {
    report: *DebugReport,
    handle: u64,
};

/// Find and map a debug SHM from perm_view (child side).
pub fn findDebugShm(view: *const [128]pv.UserViewEntry, known_handles: []const u64) ?DebugShmResult {
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 == DEBUG_SHM_SIZE) {
            var known = false;
            for (known_handles) |h| {
                if (h == e.handle) {
                    known = true;
                    break;
                }
            }
            if (known) continue;

            const vm_rights = (perms.VmReservationRights{
                .read = true,
                .write = true,
                .shareable = true,
            }).bits();
            const vm = syscall.vm_reserve(0, DEBUG_SHM_SIZE, vm_rights);
            if (vm.val < 0) return null;
            if (syscall.shm_map(e.handle, @intCast(vm.val), 0) != 0) return null;

            const report: *DebugReport = @ptrFromInt(vm.val2);
            if (report.isValid()) return .{ .report = report, .handle = e.handle };
        }
    }
    return null;
}
