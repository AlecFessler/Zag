const zag = @import("zag");

const Process = zag.sched.process.Process;
const VmReservation = zag.memory.vmm.VmReservation;
const SharedMemory = zag.memory.shared.SharedMemory;

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
    _reserved: u5 = 0,
};

pub const SharedMemoryRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    grant: bool = false,
    _reserved: u4 = 0,
};

pub const PermissionEntry = struct {
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
};

pub const KernelObject = union(enum) {
    process: *Process,
    vm_reservation: *VmReservation,
    shared_memory: *SharedMemory,
    empty: void,
};
