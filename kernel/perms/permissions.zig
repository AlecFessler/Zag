const std = @import("std");
const zag = @import("zag");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.sched.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

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
    shm_create: bool = false,
    device_own: bool = false,
    pin_exclusive: bool = false,
    fault_handler: bool = false,
    _reserved: u7 = 0,
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
    _reserved: u5 = 0,
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
    set_affinity: bool = false,
    _reserved: u4 = 0,

    pub const full = ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = true,
        .set_affinity = true,
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

pub const CorePinObject = struct {
    core_id: u64,
    thread_tid: u64,
};

pub const KernelObject = union(enum) {
    process: *Process,
    dead_process: *Process,
    vm_reservation: VmReservationObject,
    shared_memory: *SharedMemory,
    device_region: *DeviceRegion,
    core_pin: CorePinObject,
    thread: *Thread,
    empty: void,
};

pub const UserViewEntryType = enum(u8) {
    process = 0,
    vm_reservation = 1,
    shared_memory = 2,
    device_region = 3,
    core_pin = 4,
    dead_process = 5,
    thread = 6,
};

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    _pad0: u8 = 0,
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

    fn threadField0(t: *Thread) u64 {
        const state_val: u8 = switch (t.state) {
            .ready => 0,
            .running => 1,
            .blocked => 2,
            .faulted => 3,
            .suspended => 4,
            .exited => 5,
        };
        const core_id: u8 = if (t.core_affinity) |mask| @intCast(@as(u7, @truncate(@ctz(mask)))) else 0;
        return @as(u64, state_val) | (@as(u64, core_id) << 8);
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
            .core_pin => |cp| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.core_pin),
                .rights = entry.rights,
                .field0 = cp.core_id,
                .field1 = cp.thread_tid,
            },
            .thread => |t| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.thread),
                .rights = entry.rights,
                .field0 = threadField0(t),
                .field1 = 0,
            },
            .empty => EMPTY,
        };
    }
};
