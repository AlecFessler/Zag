pub const VmReservationRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    shareable: bool = false,
    mmio: bool = false,
    _reserved: u3 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};

pub const ProcessRights = packed struct(u8) {
    grant_to: bool = false,
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    restart: bool = false,
    shm_create: bool = false,
    device_own: bool = false,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};

pub const SharedMemoryRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    grant: bool = false,
    _reserved: u4 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};

pub const DeviceRegionRights = packed struct(u8) {
    map: bool = false,
    grant: bool = false,
    _reserved: u6 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};
