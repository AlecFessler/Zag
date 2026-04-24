const std = @import("std");
const zag = @import("zag");

const secure_slab = zag.memory.allocators.secure_slab;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.proc.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
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
    process: SlabRef(Process),
    dead_process: SlabRef(Process),
    vm_reservation: VmReservationObject,
    shared_memory: SlabRef(SharedMemory),
    device_region: SlabRef(DeviceRegion),
    thread: SlabRef(Thread),
    vm: SlabRef(Vm),
    empty: void,

    /// Check whether the slab slot backing this handle is still live
    /// with the generation captured at issuance. Variants without a
    /// slab-backed slot (`vm_reservation`, `empty`) are always fresh.
    pub fn isFresh(self: @This()) bool {
        return switch (self) {
            .process => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .dead_process => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .thread => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .shared_memory => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .device_region => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .vm => |r| r.gen == r.ptr._gen_lock.currentGen(),
            .vm_reservation, .empty => true,
        };
    }

    /// Spin-CAS-acquire the gen-lock on the backing slab slot, using
    /// the gen captured inside the variant's SlabRef. On success the
    /// caller holds exclusive access to the object and must pair this
    /// with a `releaseLock` on the same variant. Returns `StaleHandle`
    /// if the slot has been freed since issuance. No-op for variants
    /// that do not reference a slab-allocated object.
    pub fn acquireLock(self: @This()) secure_slab.AccessError!void {
        switch (self) {
            .process => |r| _ = try r.lock(),
            .dead_process => |r| _ = try r.lock(),
            .thread => |r| _ = try r.lock(),
            .shared_memory => |r| _ = try r.lock(),
            .device_region => |r| _ = try r.lock(),
            .vm => |r| _ = try r.lock(),
            .vm_reservation, .empty => {},
        }
    }

    /// Release the gen-lock acquired via `acquireLock`. Must be paired
    /// with a successful `acquireLock` on the same variant.
    pub fn releaseLock(self: @This()) void {
        switch (self) {
            .process => |r| r.unlock(),
            .dead_process => |r| r.unlock(),
            .thread => |r| r.unlock(),
            .shared_memory => |r| r.unlock(),
            .device_region => |r| r.unlock(),
            .vm => |r| r.unlock(),
            .vm_reservation, .empty => {},
        }
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
            .process => |r| blk: {
                const p = r.ptr;
                break :blk .{
                    .handle = entry.handle,
                    .entry_type = @intFromEnum(UserViewEntryType.process),
                    .rights = entry.rights,
                    .field0 = processField0(p.fault_reason, p.restart_count),
                    .field1 = 0,
                };
            },
            .dead_process => |r| blk: {
                const p = r.ptr;
                break :blk .{
                    .handle = entry.handle,
                    .entry_type = @intFromEnum(UserViewEntryType.dead_process),
                    .rights = entry.rights,
                    .field0 = processField0(p.fault_reason, p.restart_count),
                    .field1 = 0,
                };
            },
            .vm_reservation => |vm| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.vm_reservation),
                .rights = entry.rights,
                .field0 = vm.original_start.addr,
                .field1 = vm.original_size,
            },
            .shared_memory => |r| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.shared_memory),
                .rights = entry.rights,
                .field0 = r.ptr.size(),
                .field1 = 0,
            },
            .device_region => |r| blk: {
                const dr = r.ptr;
                break :blk .{
                    .handle = entry.handle,
                    .entry_type = @intFromEnum(UserViewEntryType.device_region),
                    .rights = entry.rights,
                    .field0 = @as(u64, @intFromEnum(dr.device_type)) |
                        (@as(u64, @intFromEnum(dr.device_class)) << 8) |
                        (if (dr.device_type == .mmio)
                            @as(u64, @truncate(dr.access.mmio.size)) << 32
                        else
                            @as(u64, dr.access.port_io.port_count) << 32),
                    .field1 = if (dr.device_class == .display) inner: {
                        const d = dr.detail.display;
                        break :inner @as(u64, d.fb_width) |
                            (@as(u64, d.fb_height) << 16) |
                            (@as(u64, d.fb_stride) << 32) |
                            (@as(u64, d.fb_pixel_format) << 48);
                    } else inner: {
                        const p = dr.detail.pci;
                        break :inner @as(u64, p.vendor) |
                            (@as(u64, p.device) << 16) |
                            (@as(u64, p.class) << 32) |
                            (@as(u64, p.subclass) << 40) |
                            (@as(u64, p.bus) << 48) |
                            (@as(u64, p.dev) << 53) |
                            (@as(u64, p.func) << 58);
                    },
                };
            },
            .thread => |r| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.thread),
                .rights = entry.rights,
                .field0 = threadField0(r.ptr, entry),
                .field1 = threadField1(r.ptr),
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
