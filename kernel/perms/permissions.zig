const zag = @import("zag");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Process = zag.sched.process.Process;
const SharedMemory = zag.memory.shared.SharedMemory;
const VAddr = zag.memory.address.VAddr;

pub const ProcessRights = packed struct(u8) {
    grant_to: bool = false,
    destroy: bool = false,
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    _reserved: u2 = 0,
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
    read: bool = false,
    write: bool = false,
    grant: bool = false,
    _reserved: u5 = 0,
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
