const std = @import("std");
const zag = @import("zag");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.sched.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const VAddr = zag.memory.address.VAddr;

pub const ProcessRights = packed struct(u8) {
    grant_to: bool = false,
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    restart: bool = false,
    shm_create: bool = false,
    device_own: bool = false,
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
    _reserved: u6 = 0,
};

pub const PermissionEntry = struct {
    handle: u64,
    object: KernelObject,
    rights: u8,

    pub fn processRights(self: @This()) ProcessRights {
        return @bitCast(self.rights);
    }

    pub fn vmRights(self: @This()) VmReservationRights {
        return @bitCast(self.rights);
    }

    pub fn shmRights(self: @This()) SharedMemoryRights {
        return @bitCast(self.rights);
    }

    pub fn deviceRights(self: @This()) DeviceRegionRights {
        return @bitCast(self.rights);
    }
};

pub const VmReservationObject = struct {
    max_rights: VmReservationRights,
    original_start: VAddr,
    original_size: u64,
};

pub const KernelObject = union(enum) {
    process: *Process,
    vm_reservation: VmReservationObject,
    shared_memory: *SharedMemory,
    device_region: *DeviceRegion,
    empty: void,
};

pub const UserViewEntryType = enum(u8) {
    process = 0,
    vm_reservation = 1,
    shared_memory = 2,
    device_region = 3,
};

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    rights: u8,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    field0: u64,
    field1: u64,

    pub const EMPTY: UserViewEntry = .{
        .handle = std.math.maxInt(u64),
        .entry_type = 0xFF,
        .rights = 0,
        .field0 = 0,
        .field1 = 0,
    };

    pub fn fromKernelEntry(entry: PermissionEntry) UserViewEntry {
        return switch (entry.object) {
            .process => .{
                .handle = entry.handle,
                .entry_type = @intFromEnum(UserViewEntryType.process),
                .rights = entry.rights,
                .field0 = 0,
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
                .field0 = dr.size,
                .field1 = 0,
            },
            .empty => EMPTY,
        };
    }
};
