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

pub const DeviceClass = enum(u8) {
    network = 0,
    serial = 1,
    storage = 2,
    display = 3,
    timer = 4,
    usb = 5,
    unknown = 0xFF,
};
