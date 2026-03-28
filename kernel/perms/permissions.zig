const std = @import("std");
const zag = @import("zag");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.sched.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const VAddr = zag.memory.address.VAddr;

pub const CrashReason = enum(u5) {
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
    revoked = 14,
    _,
};

pub const DeadProcessInfo = struct {
    crash_reason: CrashReason,
    restart_count: u16,
};

pub const ProcessRights = packed struct(u16) {
    grant_to: bool = false,
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    restart: bool = false,
    shm_create: bool = false,
    device_own: bool = false,
    shutdown: bool = false,
    pin_exclusive: bool = false,
    _reserved: u6 = 0,
};

pub const VmReservationRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    shareable: bool = false,
    mmio: bool = false,
    _reserved: u3 = 0,
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

pub const PermissionEntry = struct {
    handle: u64,
    object: KernelObject,
    rights: u16,

    pub fn processRights(self: @This()) ProcessRights {
        return @bitCast(self.rights);
    }

    pub fn shmRights(self: @This()) SharedMemoryRights {
        return @bitCast(@as(u8, @truncate(self.rights)));
    }

    pub fn deviceRights(self: @This()) DeviceRegionRights {
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
    dead_process: DeadProcessInfo,
    vm_reservation: VmReservationObject,
    shared_memory: *SharedMemory,
    device_region: *DeviceRegion,
    core_pin: CorePinObject,
    empty: void,
};

pub const UserViewEntryType = enum(u8) {
    process = 0,
    vm_reservation = 1,
    shared_memory = 2,
    device_region = 3,
    core_pin = 4,
    dead_process = 5,
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

    fn processField0(crash_reason: CrashReason, restart_count: u16) u64 {
        return @as(u64, @intFromEnum(crash_reason)) |
            (@as(u64, restart_count) << 16);
    }

    pub fn fromKernelEntry(entry: PermissionEntry) UserViewEntry {
        return switch (entry.object) {
            .process => |p| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.process),
                .rights = entry.rights,
                .field0 = processField0(p.crash_reason, p.restart_count),
                .field1 = 0,
            },
            .dead_process => |dp| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.dead_process),
                .rights = entry.rights,
                .field0 = processField0(dp.crash_reason, dp.restart_count),
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
                        @as(u64, @truncate(dr.size)) << 32
                    else
                        @as(u64, dr.port_count) << 32),
                .field1 = if (dr.device_class == .display)
                    @as(u64, dr.fb_width) |
                        (@as(u64, dr.fb_height) << 16) |
                        (@as(u64, dr.fb_stride) << 32) |
                        (@as(u64, dr.fb_pixel_format) << 48)
                else
                    @as(u64, dr.pci_vendor) |
                        (@as(u64, dr.pci_device) << 16) |
                        (@as(u64, dr.pci_class) << 32) |
                        (@as(u64, dr.pci_subclass) << 40) |
                        (@as(u64, dr.pci_bus) << 48) |
                        (@as(u64, dr.pci_dev) << 53) |
                        (@as(u64, dr.pci_func) << 58),
            },
            .core_pin => |cp| .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.core_pin),
                .rights = entry.rights,
                .field0 = cp.core_id,
                .field1 = cp.thread_tid,
            },
            .empty => EMPTY,
        };
    }
};
