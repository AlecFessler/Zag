pub const VmReservationRights = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    shareable: bool = false,
    mmio: bool = false,
    write_combining: bool = false,
    _reserved: u2 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};

pub const ProcessRights = packed struct(u16) {
    grant_to_child: bool = false,
    spawn_thread: bool = false,
    spawn_process: bool = false,
    mem_reserve: bool = false,
    set_affinity: bool = false,
    restart: bool = false,
    shm_create: bool = false,
    device_own: bool = false,
    pin_exclusive: bool = false,
    grant_to_broadcast: bool = false,
    broadcast: bool = false,
    _reserved: u5 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u16, @bitCast(self)));
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

pub const DeviceType = enum(u8) {
    mmio = 0,
    port_io = 1,
};

pub const DeviceClass = enum(u8) {
    network = 0,
    serial = 1,
    storage = 2,
    display = 3,
    timer = 4,
    usb = 5,
    unknown = 0xFF,
};

pub const DeviceRegionRights = packed struct(u8) {
    map: bool = false,
    grant: bool = false,
    dma: bool = false,
    _reserved: u5 = 0,

    pub fn bits(self: @This()) u64 {
        return @intCast(@as(u8, @bitCast(self)));
    }
};
