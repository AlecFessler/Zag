const std = @import("std");
const zag = @import("zag");

const secure_slab = zag.memory.allocators.secure_slab;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.proc.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const Vm = zag.arch.dispatch.vm.Vm;

pub const FaultReason = enum(u5) {
    none = 0,
    stack_overflow = 1,
    stack_underflow = 2,
    invalid_read = 3,
    invalid_write = 4,
    invalid_execute = 5,
    unmapped_access = 6,
    out_of_memory = 7,
    arithmetic_fault = 8,
    illegal_instruction = 9,
    alignment_fault = 10,
    protection_fault = 11,
    normal_exit = 12,
    killed = 13,
    breakpoint = 14,
    pmu_overflow = 15,
    _,
};

pub const CrashReason = FaultReason;

pub const DeadProcessInfo = struct {
    fault_reason: FaultReason,
    restart_count: u16,
};

pub const ProcessRights = packed struct(u16) {
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    restart: bool = false,
    mem_shm_create: bool = false,
    device_own: bool = false,
    fault_handler: bool = false,
    pmu: bool = false,
    set_time: bool = false,
    power: bool = false,
    vm_create: bool = false,
    _reserved: u4 = 0,
};

pub const VmReservationRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    shareable: bool = false,
    mmio: bool = false,
    write_combining: bool = false,
    _reserved: u2 = 0,
};

pub const SharedMemoryRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    grant: bool = false,
    _reserved: u4 = 0,
};

pub const DeviceRegionRights = packed struct(u8) {
    map: bool = false,
    grant: bool = false,
    dma: bool = false,
    irq: bool = false,
    _reserved: u4 = 0,
};

pub const ProcessHandleRights = packed struct(u16) {
    send_words: bool = false,
    send_shm: bool = false,
    send_process: bool = false,
    send_device: bool = false,
    kill: bool = false,
    grant: bool = false,
    fault_handler: bool = false,
    _reserved: u9 = 0,
};

pub const ThreadHandleRights = packed struct(u8) {
    @"suspend": bool = false,
    @"resume": bool = false,
    kill: bool = false,
    _reserved_bit3: bool = false,
    pmu: bool = false,
    _reserved: u3 = 0,

    pub const full = ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = true,
        .pmu = true,
    };
};

pub const PermissionEntry = struct {
    handle: u64,
    object: KernelObject,
    rights: u16,
    exclude_oneshot: bool = false,
    exclude_permanent: bool = false,
    /// Snapshot of the backing SecureSlab slot's generation taken when
    /// this handle was issued. `getPermByHandleLocked` refuses to return
    /// the entry if the current gen no longer matches — the slot has
    /// been freed (and possibly reallocated) since issuance, so the
    /// handle is stale. Sentinel 0 = no gen tracking (used for variants
    /// that don't reference a slab-allocated object: vm_reservation,
    /// empty).
    expected_gen: u32 = 0,

    pub fn processRights(self: @This()) ProcessRights {
        return @bitCast(self.rights);
    }

    pub fn shmRights(self: @This()) SharedMemoryRights {
        return @bitCast(@as(u8, @truncate(self.rights)));
    }

    pub fn deviceRights(self: @This()) DeviceRegionRights {
        return @bitCast(@as(u8, @truncate(self.rights)));
    }

    pub fn processHandleRights(self: @This()) ProcessHandleRights {
        return @bitCast(self.rights);
    }

    pub fn threadHandleRights(self: @This()) ThreadHandleRights {
        return @bitCast(@as(u8, @truncate(self.rights)));
    }
};

pub const VmReservationObject = struct {
    max_rights: VmReservationRights,
    original_start: VAddr,
    original_size: u64,
};

pub const KernelObject = union(enum) {
    process: *Process,
    dead_process: *Process,
    vm_reservation: VmReservationObject,
    shared_memory: *SharedMemory,
    device_region: *DeviceRegion,
    thread: *Thread,
    vm: *Vm,
    empty: void,

    /// Read the current SecureSlab generation for the backing slot of
    /// the variants that reference a slab-allocated `*T`. Used when
    /// issuing a capability handle to snapshot the gen, and when
    /// verifying a handle at lookup.
    pub fn currentGen(self: @This()) u32 {
        return switch (self) {
            .process => |p| @truncate(secure_slab.genOf(Process, p)),
            .dead_process => |p| @truncate(secure_slab.genOf(Process, p)),
            .thread => |t| @truncate(secure_slab.genOf(Thread, t)),
            .shared_memory => |s| @truncate(secure_slab.genOf(SharedMemory, s)),
            .device_region => |d| @truncate(secure_slab.genOf(DeviceRegion, d)),
            .vm => |v| @truncate(secure_slab.genOf(Vm, v)),
            .vm_reservation, .empty => 0,
        };
    }
};

pub const UserViewEntryType = enum(u8) {
    process = 0,
    vm_reservation = 1,
    shared_memory = 2,
    device_region = 3,
    dead_process = 5,
    thread = 6,
    vm = 7,
};

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    _reserved_byte: u8 = 0,
    rights: u16,
    _pad: [4]u8 = .{ 0, 0, 0, 0 },
    field0: u64,
    field1: u64,

    pub const EMPTY: UserViewEntry = .{
        .handle = std.math.maxInt(u64),
        .entry_type = 0xFF,
        .rights = 0,
        .field0 = 0,
        .field1 = 0,
    };

    fn processField0(fault_reason: FaultReason, restart_count: u16) u64 {
        return @as(u64, @intFromEnum(fault_reason)) |
            (@as(u64, restart_count) << 16);
    }

    /// For thread entries, field0 exposes the thread's stable kernel-assigned
    /// thread id (`tid`). Transient scheduling state (.running/.ready/.blocked)
    /// is intentionally NOT exposed — syncing it would require cross-core
    /// cache bouncing on every dispatch. The observable state transitions
    /// that matter to userspace (.faulted, .suspended, .exited) have their
    /// own channels (fault_recv, syscall return codes, perm entry removal).
    /// For thread entries, field0 packs: tid (bits 0-31), exclude_oneshot (bit 32),
    /// exclude_permanent (bit 33).
    fn threadField0(t: *Thread, entry: PermissionEntry) u64 {
        return @as(u64, @as(u32, @truncate(t.tid))) |
            (@as(u64, @intFromBool(entry.exclude_oneshot)) << 32) |
            (@as(u64, @intFromBool(entry.exclude_permanent)) << 33);
    }

    /// For thread entries, field1 exposes the pinned core ID when the thread
    /// is pinned, or zero when not pinned.
    fn threadField1(t: *Thread) u64 {
        if (t.priority == .pinned) {
            const affinity = t.core_affinity orelse return 0;
            return @ctz(affinity);
        }
        return 0;
    }

    pub fn fromKernelEntry(entry: PermissionEntry) UserViewEntry {
        return switch (entry.object) {
            .process => |p| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.process),
                .rights = entry.rights,
                .field0 = processField0(p.fault_reason, p.restart_count),
                .field1 = 0,
            },
            .dead_process => |p| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.dead_process),
                .rights = entry.rights,
                .field0 = processField0(p.fault_reason, p.restart_count),
                .field1 = 0,
            },
            .vm_reservation => |vm| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.vm_reservation),
                .rights = entry.rights,
                .field0 = vm.original_start.addr,
                .field1 = vm.original_size,
            },
            .shared_memory => |shm| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.shared_memory),
                .rights = entry.rights,
                .field0 = shm.size(),
                .field1 = 0,
            },
            .device_region => |dr| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.device_region),
                .rights = entry.rights,
                .field0 = @as(u64, @intFromEnum(dr.device_type)) |
                    (@as(u64, @intFromEnum(dr.device_class)) << 8) |
                    (if (dr.device_type == .mmio)
                        @as(u64, @truncate(dr.access.mmio.size)) << 32
                    else
                        @as(u64, dr.access.port_io.port_count) << 32),
                .field1 = if (dr.device_class == .display) blk: {
                    const d = dr.detail.display;
                    break :blk @as(u64, d.fb_width) |
                        (@as(u64, d.fb_height) << 16) |
                        (@as(u64, d.fb_stride) << 32) |
                        (@as(u64, d.fb_pixel_format) << 48);
                } else blk: {
                    const p = dr.detail.pci;
                    break :blk @as(u64, p.vendor) |
                        (@as(u64, p.device) << 16) |
                        (@as(u64, p.class) << 32) |
                        (@as(u64, p.subclass) << 40) |
                        (@as(u64, p.bus) << 48) |
                        (@as(u64, p.dev) << 53) |
                        (@as(u64, p.func) << 58);
                },
            },
            .thread => |t| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.thread),
                .rights = entry.rights,
                .field0 = threadField0(t, entry),
                .field1 = threadField1(t),
            },
            .vm => .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.vm),
                .rights = entry.rights,
                .field0 = 0,
                .field1 = 0,
            },
            .empty => EMPTY,
        };
    }
};

/// Returns true if every bit set in `requested` is also set in `allowed`.
pub fn isSubset(requested: u16, allowed: u16) bool {
    return (requested & ~allowed) == 0;
}
